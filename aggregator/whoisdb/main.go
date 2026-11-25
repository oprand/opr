package whoisdb

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/oprand/opr/aggregator"
	"github.com/oprand/opr/aggregator/asnames"
	"github.com/oprand/opr/store/postgres"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/text/encoding/charmap"
)

// Options are the knobs of `registry-crawl bulk` and the daemon's whoisdb
// job. Zero values fall back to the one-shot flag defaults.
type Options struct {
	// Period between runs (daemon only; --whoisdb-period).
	Period time.Duration
	// BufferMaxSize is how many records to buffer before a COPY (--whoisdb-buffer-max-size).
	BufferMaxSize int
	// WithRouteObjects runs pass 2, IRR route/route6 (--with-whoisdb-route-fetch).
	WithRouteObjects bool
	// PrefetchDepth bounds concurrent dump downloads (--whoisdb-prefetch).
	PrefetchDepth int
	// AsNamesURL is the RIPE asnames.txt source (--asnames-url).
	AsNamesURL string
}

// New builds an aggregator on an existing logger and store. The caller
// owns the store; Close only closes the record channel.
func New(logger *zap.Logger, store *postgres.Store, opts Options) *WhoisDBAggregator {
	if logger == nil {
		logger = zap.NewNop()
	}
	if opts.Period <= 0 {
		opts.Period = time.Hour
	}
	if opts.BufferMaxSize < 1 {
		opts.BufferMaxSize = 5000
	}
	if opts.PrefetchDepth < 1 {
		opts.PrefetchDepth = 1
	}
	if opts.AsNamesURL == "" {
		opts.AsNamesURL = asnames.DefaultURL
	}
	recordBufferSize := opts.BufferMaxSize

	return &WhoisDBAggregator{
		Name:             WhoisDB,
		CrawlInterval:    opts.Period,
		Logger:           logger,
		PrefetchDepth:    opts.PrefetchDepth,
		Store:            store,
		HTTPClient:       &http.Client{Timeout: 20 * time.Minute},
		RecordChan:       make(chan whoisdb_store.WhoisRecord),
		WithRouteFetch:   opts.WithRouteObjects,
		ForceSaveSignal:  make(chan struct{}),
		SavingDoneSignal: make(chan struct{}),
		Geofeeds:         mapset.NewSet[string](),
		BufferMaxSize:    recordBufferSize,
		AsNamesURL:       opts.AsNamesURL,
		BufferASN:        make([]*whoisdb_store.WhoisAutNum, 0, recordBufferSize),
		BufferInetNum:    make([]*whoisdb_store.WhoisInetNum, 0, recordBufferSize),
		BufferInet6Num:   make([]*whoisdb_store.WhoisInet6Num, 0, recordBufferSize),
		BufferOrg:        make([]*whoisdb_store.WhoisOrganization, 0, recordBufferSize),
		BufferRole:       make([]*whoisdb_store.WhoisRole, 0, recordBufferSize),
		BufferAsSet:      make([]*whoisdb_store.WhoisAsSet, 0, recordBufferSize),
		BufferAsBlock:    make([]*whoisdb_store.WhoisAsBlock, 0, recordBufferSize),
		BufferIrt:        make([]*whoisdb_store.WhoisIrt, 0, recordBufferSize),
		StatusMetadata: WhoisDBStatusMetadata{
			URLs: make(map[string]*WhoisDBURLStatus),
		},
	}
}

// NewWhoisDBAggregator is the one-shot constructor: logger, store and
// options from the CLI flags, migrations applied.
func NewWhoisDBAggregator(c *cli.Context) (*WhoisDBAggregator, error) {

	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return nil, err
	}

	logger = logger.Named("whoisdb")

	DSN := c.String("postgres-db")
	if !strings.HasPrefix(DSN, "postgres://") && !strings.HasPrefix(DSN, "postgresql://") {
		return nil, fmt.Errorf("--postgres-db value must start with `postgres://` or `postgresql://`")
	}
	pgStore, err := postgres.New(logger.Named("store"), DSN)
	if err != nil {
		return nil, err
	}
	// Check the database is at last schema version, upgrade if necessary
	err = postgres.RunMigrations(logger.Named("store"), DSN)
	if err != nil {
		logger.Error("error running migrations", zap.Error(err))
		return nil, err
	}

	return New(logger, pgStore, Options{
		Period:           c.Duration("whoisdb-period"),
		BufferMaxSize:    c.Int("whoisdb-buffer-max-size"),
		WithRouteObjects: c.Bool("with-whoisdb-route-fetch"),
		PrefetchDepth:    c.Int("whoisdb-prefetch"),
		AsNamesURL:       c.String("asnames-url"),
	}), nil
}

func (wdb *WhoisDBAggregator) GetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if wdb.StatusMetadata.IsRunning {
		wdb.StatusMetadata.IsHealthy = nil
		wdb.StatusMetadata.TotalGeofeedCount = wdb.Geofeeds.Cardinality()
	} else {
		// Check if all urls are healthy
		isHealthy := true
		for _, urlStatus := range wdb.StatusMetadata.URLs {
			// if any url is not healthy, set isHealthy to false
			if urlStatus.IsHealthy == nil || !*urlStatus.IsHealthy {
				isHealthy = false
				break
			}
		}
		wdb.StatusMetadata.IsHealthy = &isHealthy
	}
	// Encode and send status metadata
	json.NewEncoder(w).Encode(wdb.StatusMetadata)
}

func (wdb *WhoisDBAggregator) ResetStatus() {
	wdb.StatusMetadata = WhoisDBStatusMetadata{
		URLs: make(map[string]*WhoisDBURLStatus),
	}
}

// registrationRecordTypes is the pass 1 object set.
var registrationRecordTypes = []opconst.RecordType{
	opconst.RecordTypeAutNum,
	opconst.RecordTypeInet6Num,
	opconst.RecordTypeInetNum,
	opconst.RecordTypeOrg,
	opconst.RecordTypeRole,
	opconst.RecordTypeAsSet,
	opconst.RecordTypeAsBlock,
	opconst.RecordTypeIrt,
}

// routeRecordTypes is the pass 2 object set and must stay route-only. Widening
// it to autnum/inetnum/org/role would let a third-party IRR overwrite
// authoritative RIR rows - see the comment on routeSources.
var routeRecordTypes = []opconst.RecordType{
	opconst.RecordTypeRoute,
	opconst.RecordTypeRoute6,
}

// Pass 1: registration objects. ARIN and LACNIC dumps are parsed and saved
// here too, but never marked as crawl_target coverage - see
// bulkDumpCoverageRegistries.
var registrationSources = []whoisDBSource{
	// Some asian countries have their own whois db
	{url: "https://ftp.apnic.net/apnic/dbase/data/jpnic.db.gz", isAuthoritative: true, source: opconst.JPNIC},
	{url: "https://ftp.apnic.net/apnic/dbase/data/twnic.db.gz", isAuthoritative: true, source: opconst.TWNIC},
	{url: "https://ftp.apnic.net/apnic/dbase/data/krnic.db.gz", isAuthoritative: true, source: opconst.KRNIC},
	// APNIC, most asian countries above will have their data overitten by APNIC data.
	// This is fine and deliberate.
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.role.gz", isAuthoritative: true, source: opconst.APNIC},
	// Split dumps omit person: from aut-num/role files; admin-c/tech-c nic-hdls often point at person objects.
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.person.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.as-set.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.as-block.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.irt.gz", isAuthoritative: true, source: opconst.APNIC},
	// AFRINIC
	{url: "https://ftp.afrinic.net/dbase/afrinic.db.gz", isAuthoritative: true, source: opconst.AFRINIC},
	// ARIN
	{url: "https://ftp.arin.net/pub/rr/arin.db.gz", isAuthoritative: true, source: opconst.ARIN},
	// LACNIC. Its dump is published as ISO-8859-1, unlike every other
	// source here, so pin the decoder rather than guessing per line.
	{url: "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz", isAuthoritative: true, source: opconst.LACNIC, charset: CharsetISO8859},
	// RIPE
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.role.gz", isAuthoritative: true, source: opconst.RIPE},
	// Split dumps omit person: from aut-num/role files; admin-c/tech-c nic-hdls often point at person objects.
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.person.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.as-set.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.as-block.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.irt.gz", isAuthoritative: true, source: opconst.RIPE},
}

// routeSources is the pass 2 source list.
//
// These files also contain aut-nums, and routeRecordTypes is what keeps them
// out. Never widen that list: whoisdb_autnum is UNIQUE(aut_num) with source
// outside the key, and dedupWhoisAutNum keys on the ASN alone, so a RADB or
// AltDB `aut-num:` block would overwrite the authoritative RIR row for that ASN.
// whoisdb_route/route6 are keyed (route, source, origin), so the same prefix
// from several sources and several origins coexists correctly.
var routeSources = []whoisDBSource{
	{url: "https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz", isAuthoritative: true, source: opconst.LACNIC, charset: CharsetISO8859},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz", isAuthoritative: true, source: opconst.RIPE},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.route.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz", isAuthoritative: true, source: opconst.APNIC},
	{url: "ftp://irr-mirror.idnic.net:21/idnic.db.gz", isAuthoritative: true, source: "IDNIC"},
	{url: "ftp://ftp.nic.ad.jp:21/jpirr/jpirr.db.gz", isAuthoritative: true, source: "JPIRR"},
	// Non authoritative but still useful
	{url: "ftp://ftp.radb.net:21/radb/dbase/radb.db.gz", isAuthoritative: false, source: "RADB"},
	{url: "ftp://ftp.radb.net:21/radb/dbase/reach.db.gz", isAuthoritative: false, source: "Telstraglobal"},
	{url: "ftp://ftp.altdb.net:21/pub/altdb/altdb.db.gz", isAuthoritative: false, source: "AltDB"},
	{url: "ftp://whois.in.bell.ca:21/bell.db.gz", isAuthoritative: false, source: "Bell"},
	{url: "ftp://irr.bboi.net:21/bboi.db.gz", isAuthoritative: false, source: "BBOI"},
	{url: "https://whois.canarie.ca/dbase/canarie.db.gz", isAuthoritative: false, source: "CANARIE"},
	{url: "ftp://rr.level3.net:21/level3.db.gz", isAuthoritative: false, source: "Level3"},
	{url: "ftp://ftp.nestegg.net:21/irr/nestegg.db.gz", isAuthoritative: false, source: "Nestegg"},
	{url: "https://rr1.ntt.net/nttcomRR/nttcom.db.gz", isAuthoritative: false, source: "NTT"},
	{url: "ftp://ftp.panix.com:21/pub/rrdb/panix.db.gz", isAuthoritative: false, source: "PANIX"},
	{url: "ftp://ftp.bgp.net.br:21/tc.db.gz", isAuthoritative: false, source: "TC"},
	// ARIN and AFRINIC ship one mixed dump each, already fetched in
	// pass 1 where the registration-object whitelist drops their
	// `route:` blocks. Without these two entries their IRR routes are
	// never stored at all. Same URL, disjoint object types, so the file
	// is downloaded twice on purpose.
	{url: "https://ftp.arin.net/pub/rr/arin.db.gz", isAuthoritative: true, source: opconst.ARIN},
	{url: "https://ftp.afrinic.net/dbase/afrinic.db.gz", isAuthoritative: true, source: opconst.AFRINIC},
}

func (wdb *WhoisDBAggregator) DoWhoisDBAggregationOnce(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Reset status metadata to default values for new job
	wdb.ResetStatus()

	wdb.StatusMetadata.StartTime = time.Now()
	wdb.StatusMetadata.IsRunning = true
	defer func() {
		wdb.StatusMetadata.IsRunning = false
		duration := time.Since(wdb.StatusMetadata.StartTime)
		wdb.StatusMetadata.TotalJobDuration = duration
		wdb.StatusMetadata.TotalGeofeedCount = wdb.Geofeeds.Cardinality()
	}()

	// Download and parse whois db files, only care about aut-nums, inet6nums, inetnums, orgs and roles.
	// runStarted is the prune watermark: SaveGeofeeds stamps last_seen_in_whois
	// with now(), so this must be taken before pass 1 (and before upsert).
	runStarted := time.Now()
	registrationJobs := newPass(registrationSources, registrationRecordTypes)
	wdb.runPass(ctx, registrationJobs)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Upsert the geofeed URL catalog from pass 1 only. Pass 2 (routes) is not
	// saved. Do not seed crawl_target kind=geofeed — CSV fetch is
	// `geoip crawl-geofeeds` over geofeeds.url. Stale prune still marks leftover
	// kind=geofeed crawl_target rows gone after a complete pass-1 harvest.
	urls := wdb.Geofeeds.ToSlice()
	wdb.Logger.Info("saving geofeeds", zap.Int("count", len(urls)))
	err := wdb.Store.SaveGeofeeds(ctx, urls)
	if err != nil {
		wdb.Logger.Error("error saving geofeeds", zap.Error(err))
	}
	if reason := geofeedPruneSkipReason(registrationJobs, wdb.StatusMetadata.URLs, urls, err); reason != "" {
		wdb.Logger.Info("skipping stale geofeed prune", zap.String("reason", reason))
	} else if deleted, gone, pruneErr := wdb.Store.PruneStaleGeofeeds(ctx, runStarted, urls); pruneErr != nil {
		wdb.Logger.Error("error pruning stale geofeeds", zap.Error(pruneErr))
	} else {
		wdb.Logger.Info("pruned stale geofeeds",
			zap.Int64("deleted", deleted),
			zap.Int64("marked_gone", gone),
		)
	}
	wdb.Geofeeds.Clear()
	wdb.Logger.Info("saved geofeeds")
	if err := ctx.Err(); err != nil {
		return err
	}
	if wdb.WithRouteFetch {
		// Download and parse whois db files, only care about route and route6
		routeJobs := newPass(routeSources, routeRecordTypes)
		forceRefetchDuplicates(registrationJobs, routeJobs)
		wdb.runPass(ctx, routeJobs)
		if err := ctx.Err(); err != nil {
			return err
		}
	} else {
		wdb.Logger.Info("skipping route fetch")
	}

	// Coverage backfill. Per-buffer marking only happens on the save path, so a
	// run where every dump was ETag-skipped would leave crawl_target rows
	// pending and the RDAP worker would re-fetch space the dumps already cover.
	// Reconciling from what is stored is correct either way.
	wdb.backfillBulkCoverage(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Name+country for autnums no dump covers. Not a coverage mark: asnames
	// rows persist source='' so they cannot satisfy crawl_target.
	wdb.backfillASNames(ctx)

	// wdb.Logger.Info("closing whoisdb record channel")
	// close(wdb.RecordChan)
	// wdb.Logger.Info("whoisdb record channel closed")

	// Wait for all whoisdb rows to be saved
	// wdb.Logger.Info("waiting for whoisdb rows to be saved")
	// <-wdb.SavingDoneSignal
	// wdb.Logger.Info("whoisdb rows saved, refreshing asn materialized view")

	return ctx.Err()
}

// newPass builds the job list for one pass: every source, one accepted-type
// set. The parse loop consumes jobs in this order.
func newPass(sources []whoisDBSource, accepted []opconst.RecordType) []prefetchJob {
	jobs := make([]prefetchJob, 0, len(sources))
	for _, src := range sources {
		jobs = append(jobs, prefetchJob{src: src, accepted: accepted})
	}
	return jobs
}

// parsePrefetched parses one already-downloaded source and saves its records.
// Called only from the runPass loop, one file at a time, so it keeps sole
// ownership of the parse pipeline: it is the only writer of RecordChan and the
// only sender of ForceSaveSignal.
func (wdb *WhoisDBAggregator) parsePrefetched(ctx context.Context, res *prefetchResult) error {
	src := res.job.src
	urlStatus := res.status
	logger := wdb.Logger.With(zap.String("url", src.url))

	defer func() {
		urlStatus.IsRunning = false
		urlStatus.JobDuration = time.Since(urlStatus.StartTime)
	}()

	if res.unchanged {
		// Nothing was downloaded. Report what the database already holds.
		savedRecordsCount, err := wdb.Store.FetchWhoisDBRecordsTypeCountBySource(ctx, src.source, int(wdb.CrawlInterval.Hours()))
		if err != nil {
			logger.Error("error getting whoisdb file from db", zap.Error(err))
		}
		// assume file is healthy by default if we got latest version
		isHealthy := true
		urlStatus.IsHealthy = &isHealthy
		// but record as not saved during this job
		urlStatus.IsSaved = false
		urlStatus.SavedRecordsCount = savedRecordsCount
		return nil
	}

	if res.path == "" {
		if res.err != nil {
			logger.Error("skipping whoisdb file, download failed", zap.Error(res.err))
			return res.err
		}
		logger.Error("skipping whoisdb file, nothing downloaded")
		return fmt.Errorf("no body downloaded for %s", src.url)
	}

	f, err := os.Open(res.path)
	if err != nil {
		logger.Error("error opening prefetched whoisdb file", zap.Error(err))
		urlStatus.FetchError = err.Error()
		return err
	}
	defer f.Close()

	gzipReader, err := gzip.NewReader(f)
	if err != nil {
		logger.Error("error creating gzip reader", zap.Error(err))
		urlStatus.FetchError = err.Error()
		return fmt.Errorf("error creating gzip reader")
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)

	geofeedCountBefore := wdb.Geofeeds.Cardinality()

	startParseTime := time.Now()
	parsedRecordsCount := wdb.ParseWhoisDBFile(ctx, scanner, res.job.accepted, &src, WithCharset(res.charset))
	logger.Info("parsed whoisdb file",
		zap.String("duration", time.Since(startParseTime).String()),
		zap.String("charset", res.charset),
		zap.Int64("autnum_count", parsedRecordsCount[opconst.RecordTypeAutNum]),
		zap.Int64("inetnum_count", parsedRecordsCount[opconst.RecordTypeInetNum]),
		zap.Int64("inet6num_count", parsedRecordsCount[opconst.RecordTypeInet6Num]),
		zap.Int64("org_count", parsedRecordsCount[opconst.RecordTypeOrg]),
		zap.Int64("role_count", parsedRecordsCount[opconst.RecordTypeRole]),
		zap.Int64("as_set_count", parsedRecordsCount[opconst.RecordTypeAsSet]),
		zap.Int64("as_block_count", parsedRecordsCount[opconst.RecordTypeAsBlock]),
		zap.Int64("irt_count", parsedRecordsCount[opconst.RecordTypeIrt]),
		zap.Int64("route_count", parsedRecordsCount[opconst.RecordTypeRoute]),
		zap.Int64("route6_count", parsedRecordsCount[opconst.RecordTypeRoute6]),
		zap.Int("total_cumulative_geofeeds", wdb.Geofeeds.Cardinality()),
	)
	if err := ctx.Err(); err != nil {
		return err
	}

	// ParseWhoisDBFile already sent one force-save. SaveWhoisRecords is a single
	// goroutine on an unbuffered channel, so this second send only completes
	// once that first flush has returned - which is what makes it safe to commit
	// the ETag below. Do not drop it. Cancel must not block on a full channel,
	// and a partial parse must not commit the ETag.
	if err := wdb.sendForceSave(ctx); err != nil {
		return err
	}

	newGeofeedCount := wdb.Geofeeds.Cardinality()
	urlStatus.GeofeedCount = newGeofeedCount - geofeedCountBefore

	// Save the new Etag only now, after the records are flushed, so a crash mid
	// run leaves the file looking changed and it gets re-parsed next time.
	wdb.Store.SaveResponseMetadata(res.metadata)

	savedRecordsCount, err := wdb.Store.FetchWhoisDBRecordsTypeCountBySource(ctx, src.source, int(wdb.CrawlInterval.Hours()))
	if err != nil {
		logger.Error("error getting whoisdb file from db", zap.Error(err))
	}
	isHealthy := aggregator.IsFileHealthy(savedRecordsCount, parsedRecordsCount, res.job.accepted)
	urlStatus.IsHealthy = &isHealthy
	urlStatus.IsSaved = isHealthy
	urlStatus.ParsedRecordsCount = parsedRecordsCount
	urlStatus.SavedRecordsCount = savedRecordsCount

	return nil
}

// backfillBulkCoverage reconciles crawl_target against what whoisdb actually
// holds for the complete-dump registries. It runs at the end of every bulk run,
// including runs where every file was ETag-skipped and nothing went through the
// save path. ARIN and LACNIC are excluded by bulkDumpCoverageRegistries.
func (wdb *WhoisDBAggregator) backfillBulkCoverage(ctx context.Context) {
	sources := BulkDumpCoverageRegistries()

	start := time.Now()
	autnums, err := wdb.Store.MarkAutnumCoveredFromWhoisDB(ctx, sources)
	if err != nil {
		wdb.Logger.Error("error backfilling autnum crawl target coverage", zap.Error(err))
	} else {
		wdb.Logger.Info("backfilled autnum crawl target coverage",
			zap.Int("count", autnums),
			zap.Strings("registries", sources),
			zap.String("duration", time.Since(start).String()),
		)
	}

	start = time.Now()
	ipnets, err := wdb.Store.MarkIpnetCoveredFromWhoisDB(ctx, sources)
	if err != nil {
		wdb.Logger.Error("error backfilling ipnet crawl target coverage", zap.Error(err))
	} else {
		wdb.Logger.Info("backfilled ipnet crawl target coverage",
			zap.Int("count", ipnets),
			zap.Strings("registries", sources),
			zap.String("duration", time.Since(start).String()),
		)
	}
}

// backfillASNames fills as_name/country_code for still-pending autnums from
// RIPE asnames.txt. It runs after coverage backfill so dump-owned ASNs are
// already marked done and excluded from the pending set. Failure here must
// not fail the bulk run: dumps and coverage already landed.
func (wdb *WhoisDBAggregator) backfillASNames(ctx context.Context) {
	url := wdb.AsNamesURL
	if url == "" {
		url = asnames.DefaultURL
	}
	start := time.Now()
	n, err := asnames.Backfill(ctx, wdb.Logger, wdb.Store, wdb.HTTPClient, url)
	if err != nil {
		wdb.Logger.Error("error backfilling asnames for pending autnums", zap.Error(err), zap.String("url", url))
		return
	}
	wdb.Logger.Info("backfilled asnames for pending autnums",
		zap.Int("count", n),
		zap.String("url", url),
		zap.String("duration", time.Since(start).String()),
	)
}

func (wdb *WhoisDBAggregator) Close() {
	wdb.Logger.Debug("closing whoisdb record channel")
	close(wdb.RecordChan)
	wdb.Logger.Info("whoisdb record channel closed")
}

func (wdb *WhoisDBAggregator) SaveWhoisRecords() {
	defer oplog.Recover(wdb.Logger, "whois record saver panicked")

	wdb.Logger.Info("starting to save whois records")

outerLoop:
	for {

		select {
		// Buffer all records per type, and save when buffer is full
		case rec, ok := <-wdb.RecordChan:
			if !ok {
				break outerLoop
			}

			switch rec.GetRecordType() {

			case opconst.RecordTypeAutNum:
				asn, ok := rec.(*whoisdb_store.WhoisAutNum)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisASN", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(asn)
				wdb.BufferASN = append(wdb.BufferASN, asn)
				if len(wdb.BufferASN) >= wdb.BufferMaxSize {
					if err := wdb.saveAutnumBuffer(wdb.BufferASN); err != nil {
						wdb.Logger.Error("error saving whois asn records", zap.Error(err))
					}
					wdb.BufferASN = make([]*whoisdb_store.WhoisAutNum, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeInetNum:
				inetNum, ok := rec.(*whoisdb_store.WhoisInetNum)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisInetNum", zap.Any("item", rec))
					continue outerLoop
				}
				if inetNum.Netblock == nil {
					wdb.Logger.Warn("whois inetnum has no netblock",
						zap.String("record_type", string(rec.GetRecordType())),
					)
				}
				stampBulkDump(inetNum)
				wdb.BufferInetNum = append(wdb.BufferInetNum, inetNum)
				if len(wdb.BufferInetNum) >= wdb.BufferMaxSize {
					if err := wdb.saveInetnumBuffer(wdb.BufferInetNum); err != nil {
						wdb.Logger.Error("error saving whois inetnum records", zap.Error(err))
					}
					wdb.BufferInetNum = make([]*whoisdb_store.WhoisInetNum, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeInet6Num:
				inet6Num, ok := rec.(*whoisdb_store.WhoisInet6Num)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisInet6Num", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(inet6Num)
				wdb.BufferInet6Num = append(wdb.BufferInet6Num, inet6Num)
				if len(wdb.BufferInet6Num) >= wdb.BufferMaxSize {
					if err := wdb.saveInet6numBuffer(wdb.BufferInet6Num); err != nil {
						wdb.Logger.Error("error saving whois inet6num records", zap.Error(err))
					}
					wdb.BufferInet6Num = make([]*whoisdb_store.WhoisInet6Num, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeOrg:
				org, ok := rec.(*whoisdb_store.WhoisOrganization)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisOrganization", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(org)
				wdb.BufferOrg = append(wdb.BufferOrg, org)
				if len(wdb.BufferOrg) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisOrganization(context.Background(), wdb.BufferOrg)
					wdb.BufferOrg = make([]*whoisdb_store.WhoisOrganization, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeRole:
				role, ok := rec.(*whoisdb_store.WhoisRole)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisRole", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(role)
				wdb.BufferRole = append(wdb.BufferRole, role)
				if len(wdb.BufferRole) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisRole(context.Background(), wdb.BufferRole)
					wdb.BufferRole = make([]*whoisdb_store.WhoisRole, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeAsSet:
				asSet, ok := rec.(*whoisdb_store.WhoisAsSet)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisAsSet", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(asSet)
				wdb.BufferAsSet = append(wdb.BufferAsSet, asSet)
				if len(wdb.BufferAsSet) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisAsSet(context.Background(), wdb.BufferAsSet)
					wdb.BufferAsSet = make([]*whoisdb_store.WhoisAsSet, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeAsBlock:
				asBlock, ok := rec.(*whoisdb_store.WhoisAsBlock)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisAsBlock", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(asBlock)
				wdb.BufferAsBlock = append(wdb.BufferAsBlock, asBlock)
				if len(wdb.BufferAsBlock) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisAsBlock(context.Background(), wdb.BufferAsBlock)
					wdb.BufferAsBlock = make([]*whoisdb_store.WhoisAsBlock, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeIrt:
				irt, ok := rec.(*whoisdb_store.WhoisIrt)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisIrt", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(irt)
				wdb.BufferIrt = append(wdb.BufferIrt, irt)
				if len(wdb.BufferIrt) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisIrt(context.Background(), wdb.BufferIrt)
					wdb.BufferIrt = make([]*whoisdb_store.WhoisIrt, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeRoute:
				route, ok := rec.(*whoisdb_store.WhoisRoute)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisRoute", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(route)
				wdb.BufferRoute = append(wdb.BufferRoute, route)
				if len(wdb.BufferRoute) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisRoute(context.Background(), wdb.BufferRoute)
					wdb.BufferRoute = make([]*whoisdb_store.WhoisRoute, 0, wdb.BufferMaxSize)
				}

			case opconst.RecordTypeRoute6:
				route6, ok := rec.(*whoisdb_store.WhoisRoute6)
				if !ok {
					wdb.Logger.Debug("item at index is not a WhoisRoute6", zap.Any("item", rec))
					continue outerLoop
				}
				stampBulkDump(route6)
				wdb.BufferRoute6 = append(wdb.BufferRoute6, route6)
				if len(wdb.BufferRoute6) >= wdb.BufferMaxSize {
					wdb.Store.SaveWhoisRoute6(context.Background(), wdb.BufferRoute6)
					wdb.BufferRoute6 = make([]*whoisdb_store.WhoisRoute6, 0, wdb.BufferMaxSize)
				}
			}
		// save regardless of buffer size when requested
		case <-wdb.ForceSaveSignal:
			wdb.Logger.Info("force saving records")
			// asn
			err := wdb.saveAutnumBuffer(wdb.BufferASN)
			if err != nil {
				wdb.Logger.Error("error saving whois asn records", zap.Error(err))
			}
			wdb.BufferASN = make([]*whoisdb_store.WhoisAutNum, 0, wdb.BufferMaxSize)
			// inetnum
			err = wdb.saveInetnumBuffer(wdb.BufferInetNum)
			if err != nil {
				wdb.Logger.Error("error saving whois inetnum records", zap.Error(err))
			}
			wdb.BufferInetNum = make([]*whoisdb_store.WhoisInetNum, 0, wdb.BufferMaxSize)
			// inet6num
			err = wdb.saveInet6numBuffer(wdb.BufferInet6Num)
			if err != nil {
				wdb.Logger.Error("error saving whois inet6num records", zap.Error(err))
			}
			wdb.BufferInet6Num = make([]*whoisdb_store.WhoisInet6Num, 0, wdb.BufferMaxSize)
			// org
			err = wdb.Store.SaveWhoisOrganization(context.Background(), wdb.BufferOrg)
			if err != nil {
				wdb.Logger.Error("error saving whois org records", zap.Error(err))
			}
			wdb.BufferOrg = make([]*whoisdb_store.WhoisOrganization, 0, wdb.BufferMaxSize)
			// role
			err = wdb.Store.SaveWhoisRole(context.Background(), wdb.BufferRole)
			if err != nil {
				wdb.Logger.Error("error saving whois role records", zap.Error(err))
			}
			wdb.BufferRole = make([]*whoisdb_store.WhoisRole, 0, wdb.BufferMaxSize)
			// as-set / as-block / irt — dump ingest only; no crawl_target marks
			err = wdb.Store.SaveWhoisAsSet(context.Background(), wdb.BufferAsSet)
			if err != nil {
				wdb.Logger.Error("error saving whois as-set records", zap.Error(err))
			}
			wdb.BufferAsSet = make([]*whoisdb_store.WhoisAsSet, 0, wdb.BufferMaxSize)
			err = wdb.Store.SaveWhoisAsBlock(context.Background(), wdb.BufferAsBlock)
			if err != nil {
				wdb.Logger.Error("error saving whois as-block records", zap.Error(err))
			}
			wdb.BufferAsBlock = make([]*whoisdb_store.WhoisAsBlock, 0, wdb.BufferMaxSize)
			err = wdb.Store.SaveWhoisIrt(context.Background(), wdb.BufferIrt)
			if err != nil {
				wdb.Logger.Error("error saving whois irt records", zap.Error(err))
			}
			wdb.BufferIrt = make([]*whoisdb_store.WhoisIrt, 0, wdb.BufferMaxSize)
			// route
			err = wdb.Store.SaveWhoisRoute(context.Background(), wdb.BufferRoute)
			if err != nil {
				wdb.Logger.Error("error saving whois route records", zap.Error(err))
			}
			wdb.BufferRoute = make([]*whoisdb_store.WhoisRoute, 0, wdb.BufferMaxSize)
			// route6
			err = wdb.Store.SaveWhoisRoute6(context.Background(), wdb.BufferRoute6)
			if err != nil {
				wdb.Logger.Error("error saving whois route6 records", zap.Error(err))
			}
			wdb.BufferRoute6 = make([]*whoisdb_store.WhoisRoute6, 0, wdb.BufferMaxSize)

		}

	}

	wdb.Logger.Info("channel closed, saving remaining records")

	if len(wdb.BufferASN) > 0 {
		wdb.Logger.Info("saving remaining asn records", zap.Int("count", len(wdb.BufferASN)))
		err := wdb.saveAutnumBuffer(wdb.BufferASN)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois asn records", zap.Error(err))
		}
	}

	if len(wdb.BufferInetNum) > 0 {
		wdb.Logger.Info("saving remaining inetnum records", zap.Int("count", len(wdb.BufferInetNum)))
		err := wdb.saveInetnumBuffer(wdb.BufferInetNum)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois inetnum records", zap.Error(err))
		}
	}

	if len(wdb.BufferInet6Num) > 0 {
		wdb.Logger.Info("saving remaining inet6num records", zap.Int("count", len(wdb.BufferInet6Num)))
		err := wdb.saveInet6numBuffer(wdb.BufferInet6Num)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois inet6num records", zap.Error(err))
		}
	}

	if len(wdb.BufferOrg) > 0 {
		wdb.Logger.Info("saving remaining org records", zap.Int("count", len(wdb.BufferOrg)))
		err := wdb.Store.SaveWhoisOrganization(context.Background(), wdb.BufferOrg)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois org records", zap.Error(err))
		}
	}

	if len(wdb.BufferRole) > 0 {
		wdb.Logger.Info("saving remaining role records", zap.Int("count", len(wdb.BufferRole)))
		err := wdb.Store.SaveWhoisRole(context.Background(), wdb.BufferRole)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois role records", zap.Error(err))
		}
	}

	if len(wdb.BufferAsSet) > 0 {
		wdb.Logger.Info("saving remaining as-set records", zap.Int("count", len(wdb.BufferAsSet)))
		err := wdb.Store.SaveWhoisAsSet(context.Background(), wdb.BufferAsSet)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois as-set records", zap.Error(err))
		}
	}

	if len(wdb.BufferAsBlock) > 0 {
		wdb.Logger.Info("saving remaining as-block records", zap.Int("count", len(wdb.BufferAsBlock)))
		err := wdb.Store.SaveWhoisAsBlock(context.Background(), wdb.BufferAsBlock)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois as-block records", zap.Error(err))
		}
	}

	if len(wdb.BufferIrt) > 0 {
		wdb.Logger.Info("saving remaining irt records", zap.Int("count", len(wdb.BufferIrt)))
		err := wdb.Store.SaveWhoisIrt(context.Background(), wdb.BufferIrt)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois irt records", zap.Error(err))
		}
	}

	if len(wdb.BufferRoute) > 0 {
		wdb.Logger.Info("saving remaining route records", zap.Int("count", len(wdb.BufferRoute)))
		err := wdb.Store.SaveWhoisRoute(context.Background(), wdb.BufferRoute)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois route records", zap.Error(err))
		}
	}

	if len(wdb.BufferRoute6) > 0 {
		wdb.Logger.Info("saving remaining route6 records", zap.Int("count", len(wdb.BufferRoute6)))
		err := wdb.Store.SaveWhoisRoute6(context.Background(), wdb.BufferRoute6)
		if err != nil {
			wdb.Logger.Error("error saving remaining whois route6 records", zap.Error(err))
		}
	}

	wdb.Logger.Info("sending saving done signal")
	wdb.SavingDoneSignal <- struct{}{}

}

type fetchStamper interface {
	StampFetch(string)
}

// stampBulkDump marks a dump-ingested object as observed via an RIR/NIR WHOIS
// dump, not a live RDAP query. Flush/EOF paths save already-stamped buffers.
func stampBulkDump(rec fetchStamper) {
	rec.StampFetch(whoisdb_store.FetchMethodBulkDump)
}

// bulkDumpCoverageRegistries is the ordered set of registries whose WHOIS
// dumps are complete enough to treat as the source of truth for autnums
// and inetnums. After a successful save, matching crawl_target rows are
// marked done so RDAP workers skip them.
//
// ARIN and LACNIC are intentionally absent: their public dumps miss most
// objects (ARIN's file is IRR-oriented). Those dumps are still parsed and
// saved, but RDAP must cover their autnums and prefixes.
var bulkDumpCoverageRegistries = []string{
	opconst.RIPE,
	opconst.APNIC,
	opconst.AFRINIC,
	opconst.JPNIC,
	opconst.KRNIC,
	opconst.TWNIC,
}

var bulkDumpCoverage = func() map[string]struct{} {
	m := make(map[string]struct{}, len(bulkDumpCoverageRegistries))
	for _, r := range bulkDumpCoverageRegistries {
		m[r] = struct{}{}
	}
	return m
}()

// nirParent aliases postgres.NIRParent so grouping next to bulkDumpCoverage
// uses the same NIR→parent RIR map as the end-of-run whoisdb backfill.
// Store cannot import this package (cycle); store is the source of truth.
var nirParent = postgres.NIRParent

// BulkDumpCoverageRegistries returns the complete-dump RIRs/NIRs used for
// autnum and ipnet crawl_target coverage. Callers must not mutate the result.
func BulkDumpCoverageRegistries() []string {
	return slices.Clone(bulkDumpCoverageRegistries)
}

// RegistrationDumpFiles is the pass-1 WHOIS URL list status joins to
// remote_files_metadata. A missing URL is never fetched. ARIN/LACNIC are
// included (saved) but Coverage is false.
func RegistrationDumpFiles() []postgres.BulkFileRef {
	out := make([]postgres.BulkFileRef, len(registrationSources))
	for i, s := range registrationSources {
		out[i] = postgres.BulkFileRef{
			URL:      s.url,
			Source:   s.source,
			Coverage: IsBulkDumpCoverage(s.source),
		}
	}
	return out
}

// IsBulkDumpCoverage reports whether registry is in the complete-dump set.
func IsBulkDumpCoverage(registry string) bool {
	_, ok := bulkDumpCoverage[registry]
	return ok
}

// saveAutnumBuffer persists a batch of dump autnums, then marks crawl_target
// coverage for registries whose dumps are complete (see bulkDumpCoverage).
func (wdb *WhoisDBAggregator) saveAutnumBuffer(buf []*whoisdb_store.WhoisAutNum) error {
	if err := wdb.Store.SaveWhoisAutNum(context.Background(), buf); err != nil {
		return err
	}
	wdb.markAutnumCoveredByBulk(buf)
	return nil
}

// saveInetnumBuffer persists a batch of dump inetnums, then marks ipnet
// crawl_target coverage for complete-dump registries only.
func (wdb *WhoisDBAggregator) saveInetnumBuffer(buf []*whoisdb_store.WhoisInetNum) error {
	if err := wdb.Store.SaveWhoisInetNum(context.Background(), buf); err != nil {
		return err
	}
	wdb.markIpnetCoveredByBulkInetnum(buf)
	return nil
}

// saveInet6numBuffer persists a batch of dump inet6nums, then marks ipnet
// crawl_target coverage for complete-dump registries only.
func (wdb *WhoisDBAggregator) saveInet6numBuffer(buf []*whoisdb_store.WhoisInet6Num) error {
	if err := wdb.Store.SaveWhoisInet6Num(context.Background(), buf); err != nil {
		return err
	}
	wdb.markIpnetCoveredByBulkInet6num(buf)
	return nil
}

// markAutnumCoveredByBulk groups saved autnums by WhoisAutNum.Source and
// upserts crawl_target done for coverage registries only. NIR sources are
// also marked under their parent RIR (see nirParent) so NRO-seeded
// registry=APNIC rows are satisfied. Nil/unknown source and AutNum 0 are
// skipped, matching SaveWhoisAutNum. WhoisAutNum.Source is not rewritten.
func (wdb *WhoisDBAggregator) markAutnumCoveredByBulk(autnums []*whoisdb_store.WhoisAutNum) {
	byRegistry := make(map[string][]uint32)
	for _, a := range autnums {
		if a == nil {
			continue
		}
		appendCoveredAutnum(byRegistry, a.Source, a.AutNum)
	}
	ctx := context.Background()
	for registry, asns := range byRegistry {
		if err := wdb.Store.MarkAutnumCoveredByBulk(ctx, asns, registry); err != nil {
			wdb.Logger.Error("error marking autnum crawl targets covered by bulk dump",
				zap.Error(err),
				zap.String("registry", registry),
				zap.Int("count", len(asns)),
			)
		}
	}
}

// appendCoveredAutnum groups an ASN under its dump source and, for NIRs,
// also under the parent RIR. Skips AutNum 0, nil/unknown source, and
// incomplete dumps (ARIN/LACNIC).
func appendCoveredAutnum(byRegistry map[string][]uint32, source *string, asn uint32) {
	if source == nil || asn == 0 {
		return
	}
	src := *source
	if _, ok := bulkDumpCoverage[src]; !ok {
		return
	}
	byRegistry[src] = append(byRegistry[src], asn)
	if parent, ok := nirParent[src]; ok {
		byRegistry[parent] = append(byRegistry[parent], asn)
	}
}

// markIpnetCoveredByBulkInetnum groups saved inetnums by Source and upserts
// crawl_target done (kind=ipnet, key=canonical CIDR) for coverage registries
// only. NIR sources are also marked under their parent RIR (see nirParent).
// Nil netblock or source is skipped, matching SaveWhoisInetNum.
func (wdb *WhoisDBAggregator) markIpnetCoveredByBulkInetnum(items []*whoisdb_store.WhoisInetNum) {
	byRegistry := make(map[string][]string)
	for _, n := range items {
		if n == nil {
			continue
		}
		if n.Netblock == nil {
			continue
		}
		appendCoveredIpnetCIDR(byRegistry, n.Source, n.Netblock.String())
	}
	wdb.markIpnetCoveredByBulk(byRegistry)
}

// markIpnetCoveredByBulkInet6num is the inet6num counterpart of
// markIpnetCoveredByBulkInetnum.
func (wdb *WhoisDBAggregator) markIpnetCoveredByBulkInet6num(items []*whoisdb_store.WhoisInet6Num) {
	byRegistry := make(map[string][]string)
	for _, n := range items {
		if n == nil || n.Netblock == nil {
			continue
		}
		appendCoveredIpnetCIDR(byRegistry, n.Source, n.Netblock.String())
	}
	wdb.markIpnetCoveredByBulk(byRegistry)
}

func appendCoveredIpnetCIDR(byRegistry map[string][]string, source *string, cidr string) {
	if source == nil || cidr == "" {
		return
	}
	src := *source
	if _, ok := bulkDumpCoverage[src]; !ok {
		return
	}
	byRegistry[src] = append(byRegistry[src], cidr)
	if parent, ok := nirParent[src]; ok {
		byRegistry[parent] = append(byRegistry[parent], cidr)
	}
}

func (wdb *WhoisDBAggregator) markIpnetCoveredByBulk(byRegistry map[string][]string) {
	ctx := context.Background()
	for registry, cidrs := range byRegistry {
		if err := wdb.Store.MarkIpnetCoveredByBulk(ctx, cidrs, registry); err != nil {
			wdb.Logger.Error("error marking ipnet crawl targets covered by bulk dump",
				zap.Error(err),
				zap.String("registry", registry),
				zap.Int("count", len(cidrs)),
			)
		}
	}
}

// decodeLine converts one dump line to UTF-8 under the given charset.
//
// CharsetAuto exists because the source list is mixed and the choice is not
// cosmetic in either direction: decoding an already-UTF-8 line as ISO-8859-1
// double-encodes every non-ASCII name, while leaving a genuine ISO-8859-1 line
// alone produces invalid UTF-8 that a UTF8 Postgres database refuses to postgres.
// Valid UTF-8 is left untouched; anything else is ISO-8859-1, which is a total
// mapping and so cannot fail.
func decodeLine(line, charset string) string {
	switch charset {
	case CharsetUTF8:
		return line
	case CharsetISO8859:
		decoded, err := charmap.ISO8859_1.NewDecoder().String(line)
		if err != nil {
			return line
		}
		return decoded
	default:
		if utf8.ValidString(line) {
			return line
		}
		decoded, err := charmap.ISO8859_1.NewDecoder().String(line)
		if err != nil {
			return line
		}
		return decoded
	}
}

// sendRecord delivers one parsed record unless ctx is already done. A cancel
// must not block on a full RecordChan.
func (wdb *WhoisDBAggregator) sendRecord(ctx context.Context, rec whoisdb_store.WhoisRecord) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case wdb.RecordChan <- rec:
		return nil
	}
}

// sendForceSave asks the saver to flush. A cancel must not block on a full
// ForceSaveSignal.
func (wdb *WhoisDBAggregator) sendForceSave(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case wdb.ForceSaveSignal <- struct{}{}:
		return nil
	}
}

// ParseWhoisDBFile parses a whoisdb file and returns the number of records parsed.
// Parsed records are sent to the RecordChan channel. ctx is checked between
// lines so a file already on disk stops being parsed when the job is cancelled.
func (wdb *WhoisDBAggregator) ParseWhoisDBFile(ctx context.Context, fileScanner *bufio.Scanner, recordTypeAccepted []opconst.RecordType, whoisFileURL *whoisDBSource, optFuncs ...ParseOption) map[opconst.RecordType]int64 {
	if ctx == nil {
		ctx = context.Background()
	}

	cfg := parseConfig{charset: CharsetAuto}
	for _, optFunc := range optFuncs {
		optFunc(&cfg)
	}

	logger := wdb.Logger.With(zap.String("url", whoisFileURL.url))

	urlStatus := wdb.StatusMetadata.URLs[statusKey(whoisFileURL.url, recordTypeAccepted)]
	if urlStatus == nil {
		urlStatus = &WhoisDBURLStatus{URL: whoisFileURL.url}
	}

	var record whoisdb_store.WhoisRecord
	var lineno uint64
	var prevItem string

	recordCounts := make(map[opconst.RecordType]int64)
	urlStatus.ParsedRecordsCount = recordCounts

	for {
		if err := ctx.Err(); err != nil {
			return recordCounts
		}

		lineno += 1
		urlStatus.LineCount += 1

		r := fileScanner.Scan()
		if !r {
			if aggregator.IsWhoisDBRecordValid(record) {
				if err := wdb.sendRecord(ctx, record); err != nil {
					return recordCounts
				}
			}
			if fileScanner.Err() != nil {
				logger.Error("error with filescanner reading whoisdb file", zap.Error(fileScanner.Err()), zap.Uint64("lineno", lineno))
				urlStatus.FetchError = fileScanner.Err().Error()
			}
			break
		}

		line := fileScanner.Text()

		// Skip any comment line
		if len(strings.TrimSpace(line)) > 0 && strings.TrimSpace(line)[0] == '#' {
			continue
		}

		// Detect end of block and save record
		if line == "\n" || strings.TrimSpace(line) == "" {
			if aggregator.IsWhoisDBRecordValid(record) {
				if err := wdb.sendRecord(ctx, record); err != nil {
					return recordCounts
				}
			}
			// reset record and prevItem for next block
			record = nil
			prevItem = ""
		}

		// Look for a new block if we are not inside a block already
		// Some record starting key (like organization) are also valid inside a block (like inetnum)
		if record == nil {
			if strings.HasPrefix(line, "inetnum: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisInetNum{})
				record.HandleInetNum(line)
				prevItem = "inetnum"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "inet6num: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisInet6Num{})
				record.HandleInet6Num(line)
				prevItem = "inet6num"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "aut-num: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisAutNum{})
				record.HandleAutNum(line)
				prevItem = "aut-num"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "organisation: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisOrganization{})
				record.HandleOrganization(line)
				prevItem = "organisation"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "role: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisRole{})
				record.HandleRole(line)
				prevItem = "role"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "person: ") {
				// person: and role: share nic-hdl; persist as WhoisRole so
				// admin-c/tech-c lookups hit whoisdb_role (whoisdb_person is unused).
				role := &whoisdb_store.WhoisRole{}
				role.HandlePerson(line)
				record = whoisdb_store.WhoisRecord(role)
				prevItem = "person"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "as-set: ") {
				asSet := &whoisdb_store.WhoisAsSet{}
				asSet.HandleAsSet(line)
				record = whoisdb_store.WhoisRecord(asSet)
				prevItem = "as-set"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "as-block: ") {
				asBlock := &whoisdb_store.WhoisAsBlock{}
				asBlock.HandleAsBlock(line)
				record = whoisdb_store.WhoisRecord(asBlock)
				prevItem = "as-block"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "irt: ") {
				irt := &whoisdb_store.WhoisIrt{}
				irt.HandleIrt(line)
				record = whoisdb_store.WhoisRecord(irt)
				prevItem = "irt"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "route: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisRoute{})
				record.HandleRoute(line)
				prevItem = "route"
				recordCounts[record.GetRecordType()] += 1
			} else if strings.HasPrefix(line, "route6: ") {
				record = whoisdb_store.WhoisRecord(&whoisdb_store.WhoisRoute6{})
				record.HandleRoute6(line)
				prevItem = "route6"
				recordCounts[record.GetRecordType()] += 1
			}
			// goto next line
			continue
		}

		// if record not in the accepted list, skip it
		if !slices.Contains(recordTypeAccepted, record.GetRecordType()) {
			record = nil
			continue
		}

		line = decodeLine(line, cfg.charset)

		// When inside a block
		switch {
		case strings.HasPrefix(line, "country:"):
			record.HandleCountryCode(line)
			prevItem = "country"
		case strings.HasPrefix(line, "as-name:"):
			record.HandleAsName(line)
			prevItem = "as-name"
		case strings.HasPrefix(line, "netname:"):
			record.HandleNetName(line)
			prevItem = "netname"
		case strings.HasPrefix(line, "geofeed:"):
			if whoisFileURL.isAuthoritative {
				wdb.applyGeofeedFromLine(record, line, true)
			}
			prevItem = "geofeed"
		case strings.HasPrefix(line, "Comment:"), strings.HasPrefix(line, "comment:"):
			if whoisFileURL.isAuthoritative {
				wdb.applyGeofeedFromLine(record, line, false)
			}
			prevItem = "Comment"
		case strings.HasPrefix(line, "descr:"):
			record.HandleDescr(line)
			if whoisFileURL.isAuthoritative {
				wdb.applyGeofeedFromLine(record, line, false)
			}
			prevItem = "descr"
		case strings.HasPrefix(line, "geoloc:"):
			record.HandleGeoloc(line)
			prevItem = "geoloc"
		case strings.HasPrefix(line, "language:"):
			record.HandleLanguage(line)
			prevItem = "language"
		case strings.HasPrefix(line, "sponsoring-org:"):
			record.HandleSponsoringOrg(line)
			prevItem = "sponsoring-org"
		case strings.HasPrefix(line, "org:"):
			record.HandleOrg(line)
			prevItem = "org"
		case strings.HasPrefix(line, "admin-c:"):
			record.HandleAdminC(line)
			prevItem = "admin-c"
		case strings.HasPrefix(line, "tech-c:"):
			record.HandleTechC(line)
			prevItem = "tech-c"
		case strings.HasPrefix(line, "abuse-c:"):
			record.HandleAbuseC(line)
			prevItem = "abuse-c"
		case strings.HasPrefix(line, "status:"):
			record.HandleStatus(line)
			prevItem = "status"
		case strings.HasPrefix(line, "remarks:"):
			record.HandleRemarks(line)
			if whoisFileURL.isAuthoritative {
				wdb.applyGeofeedFromLine(record, line, false)
			}
			prevItem = "remarks"
		case strings.HasPrefix(line, "notify:"):
			record.HandleNotify(line)
			prevItem = "notify"
		case strings.HasPrefix(line, "mnt-by:"):
			record.HandleMntBy(line)
			prevItem = "mnt-by"
		case strings.HasPrefix(line, "mnt-lower:"):
			record.HandleMntLower(line)
			prevItem = "mnt-lower"
		case strings.HasPrefix(line, "mnt-routes:"):
			record.HandleMntRoutes(line)
			prevItem = "mnt-routes"
		case strings.HasPrefix(line, "mnt-domains:"):
			record.HandleMntDomains(line)
			prevItem = "mnt-domains"
		case strings.HasPrefix(line, "mnt-ref:"):
			record.HandleMntRef(line)
			prevItem = "mnt-ref"
		case strings.HasPrefix(line, "mnt-irt:"):
			record.HandleMntIrt(line)
			prevItem = "mnt-irt"
		case strings.HasPrefix(line, "changed:"):
			record.HandleChanged(line)
			prevItem = "changed"
		case strings.HasPrefix(line, "last-modified:"):
			record.HandleLastModified(line)
			prevItem = "last-modified"
		case strings.HasPrefix(line, "created:"):
			record.HandleCreated(line)
			prevItem = "created"
		case strings.HasPrefix(line, "source:"):
			record.HandleSource(line)
			prevItem = "source"
		case strings.HasPrefix(line, "address:"):
			record.HandleAddress(line)
			prevItem = "address"
		case strings.HasPrefix(line, "phone:"):
			record.HandlePhone(line)
			prevItem = "phone"
		case strings.HasPrefix(line, "fax-no:"):
			record.HandleFaxNo(line)
			prevItem = "fax-no"
		case strings.HasPrefix(line, "e-mail:"):
			record.HandleEmail(line)
			prevItem = "e-mail"
		case strings.HasPrefix(line, "mp-default:"):
			record.HandleMpDefault(line)
			prevItem = "mp-default"
		case strings.HasPrefix(line, "default:"):
			record.HandleDefault(line)
			prevItem = "default"
		case strings.HasPrefix(line, "nic-hdl:"):
			record.HandleNicHdl(line)
			prevItem = "nic-hdl"
		case strings.HasPrefix(line, "abuse-mailbox:"):
			record.HandleAbuseMailbox(line)
			prevItem = "abuse-mailbox"
		case strings.HasPrefix(line, "city:"):
			record.HandleCity(line)
			prevItem = "city"
		case strings.HasPrefix(line, "mp-import:"):
			record.HandleMpImport(line)
			prevItem = "mp-import"
		case strings.HasPrefix(line, "mp-export:"):
			record.HandleMpExport(line)
			prevItem = "mp-export"
		case strings.HasPrefix(line, "import:"):
			record.HandleImport(line)
			prevItem = "import"
		case strings.HasPrefix(line, "export:"):
			record.HandleExport(line)
			prevItem = "export"
		case strings.HasPrefix(line, "assignment-size:"):
			record.HandleAssignmentSize(line)
			prevItem = "assignment-size"
		case strings.HasPrefix(line, "members:"):
			if asSet, ok := record.(*whoisdb_store.WhoisAsSet); ok {
				asSet.HandleMembers(line)
			}
			prevItem = "members"
		case strings.HasPrefix(line, "mbrs-by-ref:"):
			if asSet, ok := record.(*whoisdb_store.WhoisAsSet); ok {
				asSet.HandleMbrsByRef(line)
			}
			prevItem = "mbrs-by-ref"
		case strings.HasPrefix(line, "auth:"):
			if irt, ok := record.(*whoisdb_store.WhoisIrt); ok {
				irt.HandleAuth(line)
			}
			prevItem = "auth"
		case strings.HasPrefix(line, "member-of:"):
			record.HandleMemberOf(line)
			prevItem = "member-of"
		case strings.HasPrefix(line, "org-name:"):
			record.HandleOrgName(line)
			prevItem = "org-name"
		case strings.HasPrefix(line, "org-type:"):
			record.HandleOrgType(line)
			prevItem = "org-type"
		case strings.HasPrefix(line, "origin:"):
			record.HandleOrigin(line)
			prevItem = "origin"
		default:
			// Handle case when data continues on new line
			// See aut-num import: and export: lines,
			// or descr: and remarks: for ARIN aut-num
			if prevItem != "" {
				record.HandleMultiLine(prevItem, line)
				if whoisFileURL.isAuthoritative && isGeofeedContinuationAttr(prevItem) {
					wdb.applyGeofeedFromLine(record, line, prevItem == "geofeed")
				}
			} else {
				logger.Warn("unknown line",
					zap.String("line", line),
					zap.String("record_type", string(record.GetRecordType())),
					zap.Uint64("lineno", lineno),
				)
			}
		}

	}

	// For saving remaining records when finished to parse
	// a full file. Cancel must not block on a full channel.
	if err := wdb.sendForceSave(ctx); err != nil {
		return recordCounts
	}

	return recordCounts

}
