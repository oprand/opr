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
		Usage:    "Ingest popular hostnames (Tranco, Umbrella, CrUX) into fdns_host_name for later A/AAAA resolve. Each subcommand also runs as a job in opr run ([fdns.*] tables).",
		Description: `Ingest popular hostnames (Tranco, Umbrella, CrUX) into fdns_host_name for later A/AAAA resolve.

Subcommands:
  ingest-lists  Download Tranco / Umbrella / CrUX, upsert fdns_host_name and enqueue fdns_resolve_queue. ETag skip. --force. --only=tranco,umbrella,crux
  resolve       A/AAAA for names claimed from fdns_resolve_queue (SKIP LOCKED). Upserts fdns_host_ip source=dns. Default resolvers are five public recursives (1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222, 74.82.42.42).
  ingest-cc     Discover latest Host Index crawl from v2.paths.gz, download Parquet (~7–9 GiB), POST every part at ClickHouse (un-SURT + validate during the insert), EXCHANGE TABLES into fdns_cc_host. No Postgres hostname writes.
  seed-queue    Filter ClickHouse fdns_cc_host into Postgres fdns_host_name (source=cc) + fdns_resolve_queue. Asserts ClickHouse SchemaVersion; run opr clickhouse migrate first.
  status        Read-only board (list clocks, pending resolve, counts by source). Not implemented yet. Stays one-shot.

Bare "opr fdns" prints this help.`,
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
				Description: `Claim due names from fdns_resolve_queue with FOR UPDATE SKIP LOCKED and query A and/or AAAA.

Writes fdns_host_ip rows (name, ip, source=dns) for answers. NXDOMAIN and NODATA still stamp fdns_host_name.resolved_at, store zero dns IPs, and DELETE the queue row so the same name is not retried until seed-queue or list ingest enqueues it again. SERVFAIL, REFUSED, and timeouts do not stamp resolved_at; locked_at is cleared so the name is retried. CNAME is followed by the recursive resolver; only A/AAAA addresses are stored.

List ingest and seed-queue enqueue fdns_resolve_queue (resolve does not scan the whole fdns_host_name catalog). --lease / --batch / --worker-id match other SKIP LOCKED workers.

Default --resolver is five public recursives: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9), 208.67.222.222 (OpenDNS), 74.82.42.42 (Hurricane Electric). Repeatable (--resolver a --resolver b) or comma-separated. Passing --resolver at least once replaces the defaults (they are not merged). A full catalog scan will get rate-limited; pass --resolver 127.0.0.1 for local-only.

--qps is per resolver (pool cap is --qps times resolver count; default 500 per resolver). --af=4|6|both (default both). --limit caps names this run (tests/smoke). --stale-after is unused at claim time (kept so existing scripts do not fail); enqueue-time freshness from seed-queue / ingest-lists decides who is in the queue. Successful resolve DELETEs the queue row, so a later resolved_at window cannot reclaim it. Re-run seed-queue or ingest-lists --force to refresh.`,
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
				Description: `Copy a filtered slice of ClickHouse fdns_cc_host into Postgres. ingest-cc does not write fdns_host_name; this command does (source=cc union, Tranco ranks kept). Each name is re-normalized with Go NormalizeHostname for IDNA parity with list ingest, then COPY/upserted and inserted into fdns_resolve_queue ON CONFLICT DO NOTHING, skipping names already resolved and still fresh.

--order key (default) pages on (url_host_tld, host_name) matching the table sort key and persists the cursor in remote_files_metadata as fdns:cc-seed-cursor. --order rank is top-N by hcrank10/prank10 with no cursor, paged in the same COPY batch size via LIMIT/OFFSET so a 5M --limit is not loaded at once. --tld is repeatable. Empty --crawl does not filter crawl. --queue-high-water skips seeding when the approximate fdns_resolve_queue size (pg_class.reltuples: ANALYZE lag, locked+unlocked, not due) is already >= N (0 = disabled) and caps this run's inserts to N minus that approximate size. --dry-run prints a count/sample and writes nothing to Postgres.

Run opr clickhouse migrate first. This command only asserts the schema version and exits if it does not match. --dsn is required.`,
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
				Description: `Discover a Host Index crawl id (default: latest crawl id present in https://data.commoncrawl.org/projects/host-index-testing/v2.paths.gz) and GET that crawl's ~30 Parquet parts from https://data.commoncrawl.org into --parquet-dir.

Host Index testing v2 may lag monthly crawls (paths list only crawls that have been indexed). Resume: skip files whose stored ETag and Content-Length already match local size unless --force. Missing or zero Content-Length never skips. --skip-download verifies existing files and does not GET parquet (fails if any file is missing or size-mismatched). Parallel GETs are capped (6). The ClickHouse load starts only after a complete download (or verified --skip-download).

Load POSTs each verified part at the ClickHouse HTTP interface. ClickHouse un-SURTs surt_host_name, drops names that fail the validDNSName regex, and keeps the 42 physical Host Index columns. crawl is a hive path segment, not a Parquet column; the insert sets it from the manifest id. Parts land in fdns_cc_host_load and are recorded in fdns_cc_load_part, so a failed run retries only the parts that did not land; a complete load ends with EXCHANGE TABLES fdns_cc_host AND fdns_cc_host_load, so the live table is never empty. Writes no Postgres hostname rows and no fdns_host_ip: opr fdns seed-queue is what moves a filtered slice into Postgres. --dsn is optional here and is used only to persist ETag resume metadata.

Run opr clickhouse migrate first. This command only asserts the schema version and exits if it does not match.

--parquet-dir defaults to UserCacheDir()/opr/cc-host-index (separate from any old URL-index cache). Plan on ~7–9 GiB parquet. --keep-parquet (default true) retains it after a successful load.`,
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
	if dsn := strings.TrimSpace(c.String("dsn")); dsn != "" {
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

	dsn := c.String("dsn")
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

	dsn := c.String("dsn")
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

	dsn := strings.TrimSpace(c.String("dsn"))
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
