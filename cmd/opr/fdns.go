package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/fdns"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func fdnsCommand() *cli.Command {
	return &cli.Command{
		Name:     "fdns",
		Category: commandCategoryData,
		Usage:    "Popular-hostname ingest and A/AAAA resolve into fdns_host_name / fdns_host_ip. Every subcommand but status also runs under opr run ([fdns.*]).",
		Description: `Pick a subcommand. Lists and seed-queue fill fdns_resolve_queue; resolve drains it; ingest-cc loads Common Crawl Host Index into ClickHouse fdns_cc_host (run opr clickhouse migrate first).

Needs: Postgres (--postgres-db, else OPR_POSTGRES_DB, else postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable) except ingest-cc (optional, ETag metadata only when --postgres-db or OPR_POSTGRES_DB is set). seed-queue and ingest-cc also need ClickHouse flags.`,
		Subcommands: []*cli.Command{
			{
				Name:  "ingest-lists",
				Usage: "Download Tranco / Umbrella / CrUX, upsert fdns_host_name and enqueue fdns_resolve_queue. ETag skip unless --force.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Re-download even when the ETag is unchanged (needed after a metadata wipe)",
					},
					&cli.StringSliceFlag{
						Name:  "only",
						Usage: "Only ingest these lists. Valid names: tranco, umbrella, crux",
					},
					&cli.StringFlag{
						Name:  "tranco-url",
						Usage: "Tranco top-1m.csv.zip URL",
						Value: fdns.DefaultTrancoURL,
					},
					&cli.StringFlag{
						Name:  "umbrella-url",
						Usage: "Cisco Umbrella top-1m.csv.zip URL",
						Value: fdns.DefaultUmbrellaURL,
					},
					&cli.StringFlag{
						Name:  "crux-url",
						Usage: "CrUX current.csv.gz URL",
						Value: fdns.DefaultCrUXURL,
					},
				},
				Action: runFDNSIngestLists,
			},
			{
				Name:  "resolve",
				Usage: "A/AAAA scan of fdns_resolve_queue into fdns_host_ip (source=dns). Defaults to five public resolvers. In opr run this is the continuous [fdns.resolve] job.",
				Description: `Does: claim due names (FOR UPDATE SKIP LOCKED), query A/AAAA, write fdns_host_ip (source=dns). Does not scan all of fdns_host_name — only the queue filled by ingest-lists / seed-queue.

Needs: Postgres. Default --resolver (repeatable or comma-separated; any value replaces defaults): 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222, 74.82.42.42. --qps is per resolver; public resolvers will rate-limit a full scan — use --resolver 127.0.0.1 for local-only.

When: after names are enqueued; continuous under opr run. NXDOMAIN/NODATA stamp resolved_at and DELETE the queue row; SERVFAIL/timeouts retry. --stale-after is unused at claim time (re-run seed-queue or ingest-lists --force to refresh).`,
				Flags: []cli.Flag{
					&cli.Float64Flag{
						Name:  "qps",
						Usage: "Max DNS queries per second per resolver (not for the whole pool). Default 500. Public resolvers will rate-limit a full catalog scan.",
						Value: fdns.DefaultResolveQPS,
					},
					&cli.StringSliceFlag{
						Name:  "resolver",
						Usage: "Recursive resolver IP or host:port (repeatable or comma-separated). Passing any value replaces the default five. Default: 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222, 74.82.42.42. A full scan will get rate-limited; pass --resolver 127.0.0.1 for local-only.",
						Value: cli.NewStringSlice(fdns.DefaultResolverAddrs...),
					},
					&cli.StringFlag{
						Name:  "af",
						Usage: "Address family to query: 4, 6, or both",
						Value: "both",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "Max names to query this run (0 = no cap)",
					},
					&cli.DurationFlag{
						Name:  "stale-after",
						Usage: "Unused by resolve. Freshness is applied when names are enqueued. Re-run seed-queue or ingest-lists --force to refresh. Kept for CLI compatibility.",
						Value: fdns.DefaultResolveStaleAfter,
					},
					&cli.DurationFlag{
						Name:  "timeout",
						Usage: "Per-query DNS timeout",
						Value: fdns.DefaultResolveTimeout,
					},
					&cli.DurationFlag{
						Name:  "lease",
						Usage: "How long a claimed fdns_resolve_queue row stays locked before another worker may steal it",
						Value: fdns.DefaultResolveLease,
					},
					&cli.IntFlag{
						Name:  "batch",
						Usage: "How many fdns_resolve_queue rows to claim per round",
						Value: fdns.DefaultResolveBatch,
					},
					&cli.StringFlag{
						Name:  "worker-id",
						Usage: "locked_by value written on claim (ops/debug)",
					},
				},
				Action: runFDNSResolve,
			},
			{
				Name:  "seed-queue",
				Usage: "Filter ClickHouse fdns_cc_host into Postgres fdns_host_name + fdns_resolve_queue. In opr run this is the periodic [fdns.seed-queue] job.",
				Description: `Does: copy a filtered slice of ClickHouse fdns_cc_host into Postgres fdns_host_name (source=cc; NormalizeHostname for IDNA parity) and fdns_resolve_queue. ingest-cc does not write hostnames — this subcommand does.

Needs: Postgres (--postgres-db, else OPR_POSTGRES_DB, else the local default) and ClickHouse. Run opr clickhouse migrate first (version assert only here).

When: after ingest-cc. --order key pages with fdns:cc-seed-cursor; --order rank is top-N. --queue-high-water skips/caps when approximate fdns_resolve_queue size (pg_class.reltuples) is already high.`,
				Flags: append([]cli.Flag{
					&cli.Int64Flag{
						Name:  "min-fetch-200",
						Usage: "Keep hosts with fetch_200 >= N (0 = no filter)",
					},
					&cli.Float64Flag{
						Name:  "min-hcrank10",
						Usage: "Keep hosts with hcrank10 >= N (0 = no filter)",
					},
					&cli.Float64Flag{
						Name:  "min-prank10",
						Usage: "Keep hosts with prank10 >= N (0 = no filter)",
					},
					&cli.StringSliceFlag{
						Name:  "tld",
						Usage: "Only these url_host_tld values (repeatable)",
					},
					&cli.StringFlag{
						Name:  "crawl",
						Usage: "Only this crawl id (CC-MAIN-YYYY-NN). Empty = no crawl filter",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "Max ClickHouse rows this run",
						Value: fdns.DefaultSeedQueueLimit,
					},
					&cli.StringFlag{
						Name:  "order",
						Usage: "Page order: key (url_host_tld, host_name cursor) or rank (hcrank10/prank10, no cursor)",
						Value: "key",
					},
					&cli.IntFlag{
						Name:  "queue-high-water",
						Usage: "Skip seeding if approximate fdns_resolve_queue size (pg_class.reltuples, locked+unlocked, not due) is already >= N. This run inserts at most N minus that approximate size. 0 = disabled",
					},
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Print count/sample; do not write Postgres",
					},
					&cli.DurationFlag{
						Name:  "stale-after",
						Usage: "Skip enqueueing names whose resolved_at is newer than this. 0 = only never-resolved. Default 168h.",
						Value: fdns.DefaultResolveStaleAfter,
					},
				}, clickhouseFlags()...),
				Action: runFDNSSeedQueue,
			},
			{
				Name:  "ingest-cc",
				Usage: "Discover, download, and load one Common Crawl Host Index crawl into ClickHouse fdns_cc_host. In opr run this is the periodic [fdns.ingest-cc] job.",
				Description: `Does: discover a Host Index crawl (default latest in v2.paths.gz), GET ~30 Parquet parts into --parquet-dir (~7–9 GiB), POST each part into ClickHouse, then EXCHANGE TABLES into fdns_cc_host. Writes no Postgres hostnames — use seed-queue next.

Needs: ClickHouse HTTP. Run opr clickhouse migrate first. --postgres-db optional (ETag resume metadata only).

When: before seed-queue / resolve of CC names. Resume skips matching ETag+size unless --force; --skip-download verifies local parquet only.`,
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:  "crawl",
						Usage: "Crawl id (CC-MAIN-YYYY-NN). Default: latest crawl id present in Host Index v2.paths.gz.",
					},
					&cli.StringFlag{
						Name:  "parquet-dir",
						Usage: "Directory for Host Index Parquet (paths under this root). Default: UserCacheDir/opr/cc-host-index.",
						Value: fdns.DefaultParquetDir(),
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Re-GET parquet even when stored ETag and local size match",
					},
					&cli.BoolFlag{
						Name:  "skip-download",
						Usage: "Do not GET parquet; require files already present with matching size/ETag",
					},
					&cli.BoolFlag{
						Name:  "keep-parquet",
						Usage: "Keep downloaded parquet files after a successful ClickHouse load (default true)",
						Value: true,
					},
				}, clickhouseFlags()...),
				Action: runFDNSIngestCC,
			},
			{
				Name:  "status",
				Usage: "Print read-only list clocks, unique names, resolved vs pending, fdns_host_ip counts. Not implemented yet.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "json",
						Usage: "Dump the same snapshot as JSON",
					},
					&cli.DurationFlag{
						Name:  "stale-after",
						Usage: "Flag list clocks as STALE when older than this. Default 168h.",
						Value: 168 * time.Hour,
					},
				},
				Action: runFDNSNotImplemented("status"),
			},
		},
	}
}

func runFDNSNotImplemented(name string) cli.ActionFunc {
	return func(c *cli.Context) error {
		return fmt.Errorf("fdns %s is not implemented yet", name)
	}
}

func runFDNSIngestCC(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.fdns.ingest-cc")

	parquetDir := strings.TrimSpace(c.String("parquet-dir"))
	if parquetDir == "" {
		return fmt.Errorf("fdns ingest-cc: --parquet-dir is required")
	}

	var in *fdns.CCIngestor
	if dsn := strings.TrimSpace(c.String("postgres-db")); dsn != "" {
		if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
			return err
		}
		pg, err := postgres.New(logger.Named("store"), dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
		in = fdns.NewCCIngestor(logger, pg, &http.Client{})
	} else {
		logger.Info("fdns ingest-cc running without Postgres; ETag resume metadata will not be stored")
		in = fdns.NewCCIngestor(logger, nil, &http.Client{})
	}
	in.CH = clickhouseClientFromCLI(c)
	in.Crawl = strings.TrimSpace(c.String("crawl"))
	in.ParquetDir = parquetDir
	in.Force = c.Bool("force")
	in.SkipDownload = c.Bool("skip-download")
	in.KeepParquet = c.Bool("keep-parquet")
	if err := in.Ingest(c.Context); err != nil {
		logger.Error("fdns ingest-cc finished with errors; parquet already on disk is kept for resume", zap.Error(err))
		return err
	}
	return nil
}

func runFDNSIngestLists(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.fdns.ingest-lists")

	lists, err := fdnsListsFromCLI(c)
	if err != nil {
		return err
	}

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	in := fdns.NewIngestor(logger, st, &http.Client{Timeout: 15 * time.Minute}, lists)
	in.Force = c.Bool("force")
	if err := in.Ingest(c.Context); err != nil {
		logger.Error("fdns ingest-lists finished with errors; last good rows kept for lists that did not persist", zap.Error(err))
		return err
	}
	logger.Info("fdns ingest-lists finished")
	return nil
}

func runFDNSResolve(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.fdns.resolve")

	if _, _, err := fdns.ParseAF(c.String("af")); err != nil {
		return err
	}
	resolverAddrs, err := fdns.ParseResolverAddrs(c.StringSlice("resolver"))
	if err != nil {
		return err
	}
	if qps := c.Float64("qps"); qps < 0 {
		return fmt.Errorf("fdns resolve: --qps must be >= 0")
	}

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	res := fdns.NewResolver(logger, st)
	res.QPS = c.Float64("qps")
	res.ResolverAddrs = resolverAddrs
	res.AF = c.String("af")
	res.Limit = c.Int("limit")
	res.StaleAfter = c.Duration("stale-after")
	res.Timeout = c.Duration("timeout")
	res.Lease = c.Duration("lease")
	res.BatchSize = c.Int("batch")
	res.WorkerID = strings.TrimSpace(c.String("worker-id"))
	if res.WorkerID == "" {
		res.WorkerID = fmt.Sprintf("%s-%d", fdns.DefaultResolveWorkerID, os.Getpid())
	}
	if err := res.Resolve(c.Context); err != nil {
		logger.Error("fdns resolve finished with errors", zap.Error(err))
		return err
	}
	return nil
}

func runFDNSSeedQueue(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.fdns.seed-queue")

	dsn := strings.TrimSpace(c.String("postgres-db"))
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	s := fdns.NewQueueSeeder(logger, st, clickhouseClientFromCLI(c))
	s.MinFetch200 = c.Int64("min-fetch-200")
	s.MinHCRank10 = c.Float64("min-hcrank10")
	s.MinPRank10 = c.Float64("min-prank10")
	s.TLDs = c.StringSlice("tld")
	s.Crawl = strings.TrimSpace(c.String("crawl"))
	s.Limit = c.Int("limit")
	s.Order = c.String("order")
	s.QueueHighWater = c.Int("queue-high-water")
	s.DryRun = c.Bool("dry-run")
	s.StaleAfter = c.Duration("stale-after")
	if err := s.Seed(c.Context); err != nil {
		logger.Error("fdns seed-queue finished with errors", zap.Error(err))
		return err
	}
	return nil
}

func fdnsListsFromCLI(c *cli.Context) ([]fdns.List, error) {
	return fdnsLists(c.String("tranco-url"), c.String("umbrella-url"), c.String("crux-url"), c.StringSlice("only"))
}

// fdnsLists is shared by `fdns ingest-lists` and the daemon's
// fdns.ingest-lists job: DefaultLists with URL overrides, filtered by only
// (empty = all three; a single comma-separated value is split).
func fdnsLists(trancoURL, umbrellaURL, cruxURL string, only []string) ([]fdns.List, error) {
	all := fdns.DefaultLists()
	for i := range all {
		switch all[i].Name {
		case fdns.SourceTranco:
			if trancoURL != "" {
				all[i].URL = trancoURL
			}
		case fdns.SourceUmbrella:
			if umbrellaURL != "" {
				all[i].URL = umbrellaURL
			}
		case fdns.SourceCrux:
			if cruxURL != "" {
				all[i].URL = cruxURL
			}
		}
	}
	if len(only) == 1 && strings.Contains(only[0], ",") {
		only = strings.Split(only[0], ",")
	}
	return fdns.SelectLists(all, only)
}
