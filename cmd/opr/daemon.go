package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oprand/opr/aggregator/aspop"
	"github.com/oprand/opr/aggregator/fdns"
	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/aggregator/geoip"
	"github.com/oprand/opr/aggregator/geonames"
	"github.com/oprand/opr/aggregator/peeringdb"
	"github.com/oprand/opr/aggregator/rdns"
	"github.com/oprand/opr/aggregator/registry"
	"github.com/oprand/opr/aggregator/rpki"
	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/opconfig"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/clickhouse"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

const (
	// queueIdle is how long a queue job (fdns.resolve, rdns.crawl-ptr, rdap)
	// waits before claiming again once its queue drained or its worker
	// returned. Short so new seed rows are picked up quickly.
	queueIdle = 30 * time.Second
	// geofeedIdle is the same for the geofeeds crawl, whose due set only
	// changes on the refresh-older-than window or a new bulk harvest.
	geofeedIdle = 5 * time.Minute
	// whoisSaverWait is how long the whois job's defer waits for
	// SavingDoneSignal after Close. Nested inside processShutdownWait.
	whoisSaverWait = 30 * time.Second
	// processShutdownWait is how long DoAggregationForever waits for every
	// job goroutine after cancel before closing the shared pool. It must
	// exceed whoisSaverWait so waitForWhoisSaver can finish inside the
	// whois job before defer st.Close(). Jobs whose HTTP still ignores
	// cancel (or only cancels partially) can outlive this budget.
	processShutdownWait = 60 * time.Second
)

// Daemon is `opr run`: one goroutine per enabled job from opr.config.toml.
// Secrets come from the environment; nothing here reads --dsn.
type Daemon struct {
	logger *zap.Logger
	cfg    *opconfig.Config
	dsn    string
	// chPassword is OPR_CLICKHOUSE_PASSWORD, may be empty.
	chPassword string
	// pdbAPIKey is OPR_PEERINGDB_APIKEY, may be empty.
	pdbAPIKey string
}

// runDaemon is the `run` Action. Order matters: resolve and load the
// config, then require OPR_DSN, then migrate once, then start loops.
// Nothing connects anywhere before OPR_DSN is checked.
func runDaemon(c *cli.Context) error {
	if c.Args().Present() {
		return fmt.Errorf("opr run takes no arguments, got %q", c.Args().First())
	}
	if strings.TrimSpace(c.String("dsn")) != "" {
		return fmt.Errorf("opr run does not accept --dsn; set the %s environment variable", opconfig.EnvDSN)
	}

	path, err := opconfig.ResolvePath(c.String("config"))
	if err != nil {
		return err
	}
	cfg, err := opconfig.Load(path)
	if err != nil {
		return err
	}

	dsn := strings.TrimSpace(os.Getenv(opconfig.EnvDSN))
	if dsn == "" {
		return fmt.Errorf("opr run requires the %s environment variable (Postgres connection string)", opconfig.EnvDSN)
	}

	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr")
	logger.Info("loaded daemon config", zap.String("path", path))
	warnConfigFileMode(logger, path)

	dm := &Daemon{
		logger:     logger,
		cfg:        cfg,
		dsn:        dsn,
		chPassword: os.Getenv(opconfig.EnvClickHousePassword),
		pdbAPIKey:  os.Getenv(opconfig.EnvPeeringDBAPIKey),
	}
	return dm.DoAggregationForever()
}

// DoAggregationForever migrates once, starts every enabled job, and blocks
// until SIGINT/SIGTERM. Loops are independent goroutines that share one
// postgres.Store: a multi-hour bulk dump must not stall RDAP, and a daily
// seed must not wait on either. Loops must not close the store. After
// cancel, this waits for every started goroutine or processShutdownWait,
// whichever comes first, then closes the pool.
func (dm *Daemon) DoAggregationForever() error {
	dm.logger.Info("starting in daemon mode", zap.Int("pid", os.Getpid()))

	if !dm.cfg.AnyEnabled() {
		return fmt.Errorf("every job is disabled in the config; nothing to run")
	}

	if err := postgres.RunMigrations(dm.logger.Named("store"), dm.dsn); err != nil {
		return err
	}

	st, err := postgres.New(dm.logger.Named("store"), dm.dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := dm.cfg
	var wg sync.WaitGroup
	start := func(name string, enabled bool, loop func(ctx context.Context, logger *zap.Logger, st *postgres.Store)) {
		logger := dm.logger.Named(name)
		if !enabled {
			logger.Info("job disabled in config")
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					logger.Info("job stopped")
					return
				}
				panicked := false
				func() {
					defer func() {
						if r := recover(); r != nil {
							panicked = true
							logger.Error("job panicked; retrying after idle", zap.Any("panic", r))
						}
					}()
					loop(ctx, logger, st)
				}()
				if !panicked {
					logger.Info("job stopped")
					return
				}
				select {
				case <-ctx.Done():
					logger.Info("job stopped")
					return
				case <-time.After(queueIdle):
				}
			}
		}()
	}

	start("rdap", cfg.RDAP.Enabled || cfg.RDAP.Ipnet, dm.runRDAP)
	start("seed", cfg.Seed.Enabled, dm.runSeed)
	start("whoisdb", cfg.WhoisDB.Enabled, dm.runWhoisDB)
	start("geonames", cfg.GeoNames.Enabled, dm.runGeoNames)
	start("peeringdb", cfg.PeeringDB.Enabled, dm.runPeeringDB)
	start("aspop", cfg.ASPop.Enabled, dm.runASPop)
	start("geoip.lacnic", cfg.GeoIP.Enabled, dm.runGeoIPLacnic)
	start("geoip.ipmap", cfg.GeoIP.Enabled, dm.runGeoIPIPMap)
	start("geoip.anycast", cfg.GeoIP.Enabled, dm.runGeoIPAnycast)
	start("geoip.geofeeds", cfg.GeoIP.Enabled, dm.runGeoIPGeofeeds)
	start("rpki", cfg.RPKI.Enabled, dm.runRPKI)
	start("fdns.ingest-lists", cfg.FDNS.IngestLists.Enabled, dm.runFDNSIngestLists)
	start("fdns.resolve", cfg.FDNS.Resolve.Enabled, dm.runFDNSResolve)
	start("fdns.ingest-cc", cfg.FDNS.IngestCC.Enabled, dm.runFDNSIngestCC)
	start("fdns.seed-queue", cfg.FDNS.SeedQueue.Enabled, dm.runFDNSSeedQueue)
	start("rdns.ingest", cfg.RDNS.Ingest.Enabled, dm.runRDNSIngest)
	start("rdns.crawl-ptr", cfg.RDNS.CrawlPTR.Enabled, dm.runRDNSCrawlPTR)

	<-ctx.Done()
	dm.logger.Info("received stop system signal", zap.Error(ctx.Err()))

	stopped := make(chan struct{})
	go func() {
		wg.Wait()
		close(stopped)
	}()
	// processShutdownWait > whoisSaverWait so the nested whois defer can
	// finish before this returns and defer st.Close() runs. Jobs that still
	// ignore cancel can outlive the wait and hit a closed pool.
	select {
	case <-stopped:
		dm.logger.Info("jobs stopped")
	case <-time.After(processShutdownWait):
		dm.logger.Warn("shutdown timed out waiting for jobs", zap.Duration("timeout", processShutdownWait))
	}
	return nil
}

// clickhouseURL returns [clickhouse].url unless OPR_CLICKHOUSE_URL is set.
// The password is never read from the file or from this URL. Userinfo is
// rejected; use OPR_CLICKHOUSE_PASSWORD instead.
func clickhouseURL(fileURL string) (string, error) {
	raw := fileURL
	label := "clickhouse.url"
	if env := strings.TrimSpace(os.Getenv(opconfig.EnvClickHouseURL)); env != "" {
		raw = env
		label = opconfig.EnvClickHouseURL
	}
	if err := opconfig.RejectClickHouseURLUserinfo(raw, label); err != nil {
		return "", err
	}
	return raw, nil
}

func (dm *Daemon) clickhouseClient() (*clickhouse.Client, error) {
	ch := dm.cfg.ClickHouse
	u, err := clickhouseURL(ch.URL)
	if err != nil {
		return nil, err
	}
	return clickhouse.New(u, ch.Database, ch.User, dm.chPassword, ch.Timeout.Std()), nil
}

// warnConfigFileMode logs when the loaded config is group- or world-accessible.
// It does not refuse to start. 0600 (and anything tighter for group/other) is quiet.
func warnConfigFileMode(logger *zap.Logger, path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	logger.Warn("config file is group- or world-readable; chmod 600 and do not commit it",
		zap.String("path", path),
		zap.String("mode", perm.String()),
	)
}

// runPeriodic runs job now, then again every interval, until ctx is
// cancelled. One select per iteration; no time.Sleep, no second wait.
// Errors are logged and the next run still happens.
func runPeriodic(ctx context.Context, logger *zap.Logger, interval time.Duration, job func(ctx context.Context) error) {
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		logger.Info("job starting")
		if err := job(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("job failed; retrying next interval", zap.Error(err), zap.Duration("interval", interval))
		} else {
			logger.Info("job finished", zap.Duration("took", time.Since(started)), zap.Duration("next_in", interval))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// runQueue runs a queue worker until ctx is cancelled. The workers here
// (fdns resolve, rdns crawl-ptr, geofeeds, rdap StartCrawlWorkers) return
// when their queue drains or on error, so this restarts them after idle.
func runQueue(ctx context.Context, logger *zap.Logger, idle time.Duration, job func(ctx context.Context) error) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := job(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("queue worker exited with error; restarting after idle", zap.Error(err), zap.Duration("idle", idle))
		} else {
			logger.Info("queue drained; claiming again after idle", zap.Duration("idle", idle))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(idle):
		}
	}
}

// runRDAP is [rdap]: StartCrawlWorkers for autnum (rdap.enabled) and ipnet
// (rdap.ipnet). The workers themselves loop claim → process → idle until
// cancel.
func (dm *Daemon) runRDAP(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	rc := dm.cfg.RDAP
	kinds := crawlKindsFromConfig(rc)
	if len(kinds) == 0 {
		return
	}

	var aggr *registry.RegistryAggregator
	for {
		if ctx.Err() != nil {
			return
		}
		var err error
		aggr, err = registry.New(logger, st, registry.Options{
			OnlyRegistries: rc.OnlyRegistries,
			Proxies:        rc.Proxies,
		})
		if err == nil {
			break
		}
		logger.Error("failed to create registry aggregator; retrying after idle", zap.Error(err), zap.Duration("idle", queueIdle))
		select {
		case <-ctx.Done():
			return
		case <-time.After(queueIdle):
		}
	}
	aggr.ApplyRDAPWorkerRegistryDefaults(rc.OnlyRegistries, rc.IncludeBulkGaps)

	crawlCfg := registry.CrawlConfig{
		Lease: rc.Lease.Std(),
		Batch: rc.Batch,
		Once:  false,
	}
	logger.Info("starting rdap crawl workers (durable queue, Once=false)", zap.Strings("kinds", kinds))
	runQueue(ctx, logger, queueIdle, func(ctx context.Context) error {
		return aggr.StartCrawlWorkers(ctx, kinds, crawlCfg)
	})
}

// crawlKindsFromConfig maps [rdap] onto StartCrawlWorkers kinds: enabled
// starts autnum, ipnet starts ipnet. Both share each RIR's AdaptiveLimiter.
func crawlKindsFromConfig(rc opconfig.RDAP) []string {
	var kinds []string
	if rc.Enabled {
		kinds = append(kinds, postgres.CrawlKindAutnum)
	}
	if rc.Ipnet {
		kinds = append(kinds, postgres.CrawlKindIpnet)
	}
	return kinds
}

// runSeed is [seed]: the same path as `registry-crawl seed` (NRO refresh,
// autnum + ipnet SQL seeds, RouteViews RIBs unless skip-ribs) on interval.
func (dm *Daemon) runSeed(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	sc := dm.cfg.Seed

	opts := seedOptions{
		Registries:        sc.OnlyRegistries, // empty = all five
		SkipRIBs:          sc.SkipRIBs,
		DelegatedStatsURL: sc.DelegatedStatsURL,
	}
	runPeriodic(ctx, logger, sc.Interval.Std(), func(ctx context.Context) error {
		return seedCrawlTargets(ctx, logger, st, opts)
	})
}

// waitForWhoisSaver closes the record channel and waits for SaveWhoisRecords
// to finish, or whoisSaverWait. Both the daemon loop and `registry-crawl bulk`
// call it on every return, including errors. In the daemon this wait is nested
// inside the whois job counted by the outer processShutdownWait.
func waitForWhoisSaver(logger *zap.Logger, aggr *whoisdb.WhoisDBAggregator) {
	aggr.Close()
	select {
	case <-aggr.SavingDoneSignal:
	case <-time.After(whoisSaverWait):
		logger.Warn("timed out waiting for whois record saver", zap.Duration("timeout", whoisSaverWait))
	}
}

// runWhoisDB is [whoisdb]: DoWhoisDBAggregationOnce every period. The
// record saver goroutine lives for the whole loop; Close ends it.
func (dm *Daemon) runWhoisDB(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	wc := dm.cfg.WhoisDB

	aggr := whoisdb.New(logger, st, whoisdb.Options{
		Period:           wc.Period.Std(),
		BufferMaxSize:    wc.BufferMaxSize,
		WithRouteObjects: wc.WithRouteObjects,
		PrefetchDepth:    wc.Prefetch,
		AsNamesURL:       wc.AsnamesURL,
	})
	go aggr.SaveWhoisRecords()
	defer waitForWhoisSaver(logger, aggr)

	runPeriodic(ctx, logger, wc.Period.Std(), func(ctx context.Context) error {
		err := aggr.DoWhoisDBAggregationOnce(ctx)
		aggr.StatusMetadata.NextFetchTime = time.Now().Add(wc.Period.Std())
		return err
	})
}

// runGeoNames is [geonames]: gn.Run(ctx) on interval.
func (dm *Daemon) runGeoNames(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	gn := geonames.New(logger, st)
	interval := dm.cfg.GeoNames.Interval.Std()
	runPeriodic(ctx, logger, interval, func(ctx context.Context) error {
		err := gn.Run(ctx)
		gn.StatusMetadata.NextFetchTime = time.Now().Add(interval)
		return err
	})
}

// runPeeringDB is [peeringdb]: DoPeeringDbSync on interval; API key from
// OPR_PEERINGDB_APIKEY.
func (dm *Daemon) runPeeringDB(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	pc := dm.cfg.PeeringDB

	s := peeringdb.New(logger, st, dm.pdbAPIKey, pc.Force)
	s.CrawlInterval = pc.Interval.Std()
	runPeriodic(ctx, logger, pc.Interval.Std(), func(ctx context.Context) error {
		err := s.DoPeeringDbSync(ctx)
		s.StatusMetadata.NextFetchTime = time.Now().Add(pc.Interval.Std())
		return err
	})
}

// runASPop is [aspop]: FetchAsnPopulation on interval.
func (dm *Daemon) runASPop(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	ac := dm.cfg.ASPop

	aggr := aspop.New(logger, st)
	aggr.CrawlInterval = ac.Interval.Std()
	runPeriodic(ctx, logger, ac.Interval.Std(), func(ctx context.Context) error {
		err := aggr.FetchAsnPopulation(ctx)
		aggr.StatusMetadata.NextFetchTime = time.Now().Add(ac.Interval.Std())
		return err
	})
}

// runGeoIPLacnic is [geoip] lacnic-interval: the LACNIC inetnum CSV.
func (dm *Daemon) runGeoIPLacnic(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	gi := geoip.New(logger, st)
	runPeriodic(ctx, logger, dm.cfg.GeoIP.LacnicInterval.Std(), func(ctx context.Context) error {
		return gi.FetchIpGeolocationFromLacnic(ctx)
	})
}

// runGeoIPIPMap is [geoip] ipmap-interval: the RIPE IPmap dump. An empty
// dump keeps the previous rows and is not an error.
func (dm *Daemon) runGeoIPIPMap(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	gi := geoip.New(logger, st)
	runPeriodic(ctx, logger, dm.cfg.GeoIP.IPMapInterval.Std(), func(ctx context.Context) error {
		err := gi.FetchIPMAP(ctx, dm.cfg.GeoIP.IPMapForce, geoip.IPMAPDumpURL)
		if errors.Is(err, geoip.ErrIPMAPEmpty) {
			logger.Warn("ripe ipmap dump had no valid prefixes; previous rows kept", zap.Error(err))
			return nil
		}
		return err
	})
}

// runGeoIPAnycast is [geoip] anycast-interval: bgptools anycatch CSVs.
func (dm *Daemon) runGeoIPAnycast(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	gi := geoip.New(logger, st)
	runPeriodic(ctx, logger, dm.cfg.GeoIP.AnycastInterval.Std(), func(ctx context.Context) error {
		return gi.FetchAnycast(ctx, dm.cfg.GeoIP.AnycastForce)
	})
}

// runGeoIPGeofeeds is [geoip] worker-count / geofeed-refresh-older-than:
// geofeeds.Crawler with Once=false. Run drains the due URLs and returns,
// so it is restarted after geofeedIdle until cancel.
func (dm *Daemon) runGeoIPGeofeeds(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	gc := dm.cfg.GeoIP

	cr := &geofeeds.Crawler{
		Store:      st,
		HTTPClient: &http.Client{Timeout: geofeeds.DefaultHTTPTimeout},
		Logger:     logger,
		Workers:    gc.WorkerCount,
		Refresh:    gc.GeofeedRefreshOlderThan.Std(),
		Force:      false,
		Once:       false,
	}
	runQueue(ctx, logger, geofeedIdle, cr.Run)
}

// runRPKI is [rpki]: Ingest from routinator-addr (then the fallback) on
// interval. A failed fetch keeps the last vrp / aspa snapshot.
func (dm *Daemon) runRPKI(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	rc := dm.cfg.RPKI

	in := rpki.NewIngestor(logger, st, &http.Client{Timeout: 10 * time.Minute})
	runPeriodic(ctx, logger, rc.Interval.Std(), func(ctx context.Context) error {
		if err := in.Ingest(ctx, rc.RoutinatorAddr, rc.RoutinatorFallbackAddr); err != nil {
			return fmt.Errorf("rpki ingest failed; last vrp/aspa snapshot kept: %w", err)
		}
		return nil
	})
}

// runFDNSIngestLists is [fdns.ingest-lists]: Tranco / Umbrella / CrUX on
// interval. ETag skip, never --force.
func (dm *Daemon) runFDNSIngestLists(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	lc := dm.cfg.FDNS.IngestLists
	runPeriodic(ctx, logger, lc.Interval.Std(), func(ctx context.Context) error {
		lists, err := fdnsLists(lc.TrancoURL, lc.UmbrellaURL, lc.CruxURL, lc.Only)
		if err != nil {
			return fmt.Errorf("invalid fdns.ingest-lists config: %w", err)
		}
		in := fdns.NewIngestor(logger, st, &http.Client{Timeout: 15 * time.Minute}, lists)
		return in.Ingest(ctx)
	})
}

// runFDNSResolve is [fdns.resolve]: the continuous fdns_resolve_queue
// worker. Resolve returns when ClaimDue comes back empty, so it is
// restarted after queueIdle until cancel.
func (dm *Daemon) runFDNSResolve(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	rc := dm.cfg.FDNS.Resolve
	workerID := fmt.Sprintf("%s-%d", fdns.DefaultResolveWorkerID, os.Getpid())
	runQueue(ctx, logger, queueIdle, func(ctx context.Context) error {
		resolverAddrs, err := fdns.ParseResolverAddrs(rc.Resolver)
		if err != nil {
			return fmt.Errorf("invalid fdns.resolve.resolver: %w", err)
		}
		res := fdns.NewResolver(logger, st)
		res.QPS = rc.QPS
		res.ResolverAddrs = resolverAddrs
		res.AF = rc.AF
		res.Timeout = rc.Timeout.Std()
		res.Lease = rc.Lease.Std()
		res.BatchSize = rc.Batch
		res.WorkerID = workerID
		return res.Resolve(ctx)
	})
}

// runFDNSIngestCC is [fdns.ingest-cc]: one Common Crawl Host Index load
// into ClickHouse on interval. The ClickHouse password is
// OPR_CLICKHOUSE_PASSWORD. Parquet already on disk is kept for resume.
func (dm *Daemon) runFDNSIngestCC(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	cc := dm.cfg.FDNS.IngestCC

	runPeriodic(ctx, logger, cc.Interval.Std(), func(ctx context.Context) error {
		ch, err := dm.clickhouseClient()
		if err != nil {
			return err
		}
		in := fdns.NewCCIngestor(logger, st, &http.Client{})
		in.CH = ch
		in.Crawl = strings.TrimSpace(cc.Crawl)
		in.ParquetDir = cc.ParquetDir
		in.Force = false
		in.SkipDownload = false
		in.KeepParquet = cc.KeepParquet
		return in.Ingest(ctx)
	})
}

// runFDNSSeedQueue is [fdns.seed-queue]: ClickHouse fdns_cc_host into
// Postgres fdns_host_name + fdns_resolve_queue on interval, honoring
// queue-high-water.
func (dm *Daemon) runFDNSSeedQueue(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	sq := dm.cfg.FDNS.SeedQueue

	runPeriodic(ctx, logger, sq.Interval.Std(), func(ctx context.Context) error {
		ch, err := dm.clickhouseClient()
		if err != nil {
			return err
		}
		s := fdns.NewQueueSeeder(logger, st, ch)
		s.MinFetch200 = sq.MinFetch200
		s.MinHCRank10 = sq.MinHCRank10
		s.MinPRank10 = sq.MinPRank10
		s.TLDs = sq.TLD
		s.Crawl = strings.TrimSpace(sq.Crawl)
		s.Limit = sq.Limit
		s.Order = sq.Order
		s.QueueHighWater = sq.QueueHighWater
		s.DryRun = false
		s.StaleAfter = sq.StaleAfter.Std()
		return s.Seed(ctx)
	})
}

// runRDNSIngest is [rdns.ingest]: RIR zone files, IANA parent zones, and
// WHOIS enrich on interval.
func (dm *Daemon) runRDNSIngest(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	ic := dm.cfg.RDNS.Ingest
	runPeriodic(ctx, logger, ic.Interval.Std(), func(ctx context.Context) error {
		sources, err := rdnsSources(rdnsZoneURLs{
			AFRINIC: ic.AFRINICURL,
			APNIC:   ic.APNICURL,
			ARIN:    ic.ARINURL,
			LACNIC:  ic.LACNICURL,
			RIPE:    ic.RIPEURL,
		}, ic.OnlyRegistries)
		if err != nil {
			return fmt.Errorf("invalid rdns.ingest config: %w", err)
		}
		in := rdns.NewIngestor(logger, st, &http.Client{Timeout: 15 * time.Minute}, sources)
		in.Force = false
		in.SkipIANA = ic.SkipIANA
		in.IANAInAddrURL = ic.IANAInAddrURL
		in.IANAIP6URL = ic.IANAIP6URL
		in.SkipWhois = ic.SkipWhois
		in.WhoisDumps = rdnsWhoisDumps(ic.RIPEDomainURL, ic.APNICDomainURL, ic.AFRINICDBURL, ic.OnlyRegistries, sources)
		in.SkipLacnic = ic.SkipLacnicWhois || !rdnsSourceSelected(sources, opconst.LACNIC)
		in.LacnicDBURL = ic.LacnicDBURL
		return in.Ingest(ctx)
	})
}

// runRDNSCrawlPTR is [rdns.crawl-ptr]: the unscoped /24 block queue (no
// prefix, zone, or limit). Crawl returns when no block is claimable, so it
// is restarted after queueIdle until cancel.
func (dm *Daemon) runRDNSCrawlPTR(ctx context.Context, logger *zap.Logger, st *postgres.Store) {
	pc := dm.cfg.RDNS.CrawlPTR
	lockedBy := fmt.Sprintf("crawl-ptr-%d", os.Getpid())
	runQueue(ctx, logger, queueIdle, func(ctx context.Context) error {
		only, err := rdnsOnlyRegistries(pc.OnlyRegistries)
		if err != nil {
			return fmt.Errorf("invalid rdns.crawl-ptr.only-registries: %w", err)
		}
		cr := rdns.NewPTRCrawler(logger, st)
		cr.OnlyRegistries = only
		cr.QPS = pc.QPS
		cr.Timeout = pc.Timeout.Std()
		cr.LockedBy = lockedBy
		return cr.Crawl(ctx)
	})
}
