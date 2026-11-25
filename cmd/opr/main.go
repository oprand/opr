package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oprand/opr/aggregator/asnames"
	"github.com/oprand/opr/aggregator/aspop"
	"github.com/oprand/opr/aggregator/geonames"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/aggregator/peeringdb"
	"github.com/oprand/opr/aggregator/registry"
	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/opconfig"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/internal/version"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
)

// commandCategoryManagement and commandCategoryData are the groups `opr help`
// prints. Schema commands stay out of the ingest list. The headings are
// uppercase because urfave prints Category as the group label.
const (
	commandCategoryManagement = "MANAGEMENT"
	commandCategoryData       = "DATA"
)

// urfave/cli v2.27 prints Command.Category in `opr help`, and on a leaf
// command, but the subcommand template skips it. This is that template with
// the same CATEGORY block the leaf template uses, so `opr postgres --help`
// shows MANAGEMENT. Nested help uses "subcommand" (not "command") so
// `opr geoip ipmap` reads as a subcommand of geoip.
//
// USAGE prefers Command.UsageText (set by applyHelpUsageTexts) so every
// line includes [global options]. The else branch is a safety net for
// auto-registered help commands that never get UsageText.
const subcommandHelpTemplate = `NAME:
   {{template "helpNameTemplate" .}}

USAGE:
   {{if .UsageText}}{{wrap .UsageText 3}}{{else}}opr [global options] {{.Name}}{{if .VisibleCommands}} [subcommand]{{end}} [options]{{end}}{{if .Category}}

CATEGORY:
   {{.Category}}{{end}}{{if .Description}}

DESCRIPTION:
   {{template "descriptionTemplate" .}}{{end}}{{if .VisibleCommands}}

SUBCOMMANDS:{{template "visibleCommandCategoryTemplate" .}}{{end}}{{if .VisibleFlagCategories}}

OPTIONS:{{template "visibleFlagCategoryTemplate" .}}{{else if .VisibleFlags}}

OPTIONS:{{template "visibleFlagTemplate" .}}{{end}}
`

// commandHelpTemplate is the leaf-command template with the same
// [global options] USAGE preference as parent (subcommand) help.
const commandHelpTemplate = `NAME:
   {{template "helpNameTemplate" .}}

USAGE:
   {{if .UsageText}}{{wrap .UsageText 3}}{{else}}opr [global options] {{.Name}} [options]{{end}}{{if .Category}}

CATEGORY:
   {{.Category}}{{end}}{{if .Description}}

DESCRIPTION:
   {{template "descriptionTemplate" .}}{{end}}{{if .VisibleFlagCategories}}

OPTIONS:{{template "visibleFlagCategoryTemplate" .}}{{else if .VisibleFlags}}

OPTIONS:{{template "visibleFlagTemplate" .}}{{end}}
`

func init() {
	cli.SubcommandHelpTemplate = subcommandHelpTemplate
	cli.CommandHelpTemplate = commandHelpTemplate
	maxprocs.Set(maxprocs.Logger(func(string, ...interface{}) {}))
}

// applyHelpUsageTexts sets UsageText on every registered command so printed
// USAGE matches root help: `opr [global options] <command> [subcommand] [options]`.
// Second-level slots are labeled "subcommand". ArgsUsage (e.g. help's
// [command]) wins over the generic [options] suffix when set.
func applyHelpUsageTexts(cmds []*cli.Command, trail []string) {
	for _, cmd := range cmds {
		path := append(append([]string(nil), trail...), cmd.Name)
		rest := strings.Join(path, " ")
		switch {
		case strings.TrimSpace(cmd.ArgsUsage) != "":
			cmd.UsageText = "opr [global options] " + rest + " " + strings.TrimSpace(cmd.ArgsUsage)
		case len(cmd.Subcommands) > 0:
			cmd.UsageText = "opr [global options] " + rest + " [subcommand] [options]"
		default:
			cmd.UsageText = "opr [global options] " + rest + " [options]"
		}
		applyHelpUsageTexts(cmd.Subcommands, path)
	}
}

// oprHelpCommand is a local copy of urfave/cli's default help command.
// The library command is unexported, has no category, and is appended at
// Setup, so it prints outside DATA and MANAGEMENT. Registering this copy
// keeps that global untouched and places help in MANAGEMENT.
// urfave skips its automatic --help flag once a help command exists;
// newCLIApp adds the flag so `opr --help` still works.
func oprHelpCommand() *cli.Command {
	return &cli.Command{
		Name:      "help",
		Aliases:   []string{"h"},
		Category:  commandCategoryManagement,
		Usage:     "Shows a list of commands or help for one command",
		ArgsUsage: "[command]",
		Action:    runCLIHelp,
	}
}

// runCLIHelp follows urfave's help action. Arguments are captured before
// moving to the parent context, so `opr help postgres` shows postgres and
// `opr help` shows the app. Lineage is the exported view of that parent.
func runCLIHelp(c *cli.Context) error {
	argsPresent := c.Args().Present()
	firstArg := c.Args().First()
	if c.Command != nil && (c.Command.Name == "help" || c.Command.Name == "h") {
		if lineage := c.Lineage(); len(lineage) > 1 {
			c = lineage[1]
		}
	}
	if argsPresent {
		return cli.ShowCommandHelp(c, firstArg)
	}
	if lineage := c.Lineage(); len(lineage) < 2 || lineage[1].App == nil {
		return cli.ShowAppHelp(c)
	}
	return cli.ShowSubcommandHelp(c)
}

func run() error {
	return newCLIApp().Run(os.Args)
}

func newCLIApp() *cli.App {
	cliapp := cli.NewApp()
	cliapp.Name = "opr"
	cliapp.Usage = "opr network data aggregator"
	cliapp.Version = fmt.Sprintf("0.0.1 - Commit: %s", version.GitCommitHash)
	cliapp.EnableBashCompletion = true

	cliapp.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "postgres-db",
			Usage: "PostgreSQL connection string. Eg: `postgresql://usr:pwd@ip:port/dbname?opt=val`. Required for every command except `run` (reads OPR_POSTGRES_DB only), `clickhouse`, `fdns ingest-cc` (ETag metadata only, and only when set), and help. One-shots fall back to OPR_POSTGRES_DB when this flag is empty.",
			// Not Required: urfave checkRequiredFlags runs on the root command
			// before it dispatches a subcommand, so a required global flag
			// blocks ClickHouse-only commands. requirePostgresDSN enforces it.
		},
	}
	cliapp.Before = requirePostgresDSN
	// Append common logger options
	cliapp.Flags = append(cliapp.Flags, oplog.LoggerFlags()...)
	// HelpFlag is not auto-added once a help command is already registered.
	if cli.HelpFlag != nil {
		cliapp.Flags = append(cliapp.Flags, cli.HelpFlag)
	}
	fetchRegistriesDataFlags := []cli.Flag{
		&cli.BoolFlag{
			Name:  "rdap-ipnet",
			Usage: "Start crawl_target ipnet RDAP workers (same process as autnum; share that RIR's AdaptiveLimiter). --kind is the selector and this flag appends ipnet if missing. Not IRR route objects (that is bulk --with-whoisdb-route-fetch). In opr run this is registry-crawl.worker.ipnet",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "rdap-autnum",
			Usage: "Start crawl_target autnum RDAP workers. --kind is the selector and this flag appends autnum if missing. In opr run this is registry-crawl.worker.enabled",
			Value: false,
		},
		&cli.StringSliceFlag{
			Name:  "proxies",
			Usage: "List of proxies to use for fetching data",
			Value: &cli.StringSlice{},
		},
		&cli.StringSliceFlag{
			Name:  "only-registries",
			Usage: "Only fetch data from these registries. Valid names: " + strings.Join([]string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}, ", "),
			Value: &cli.StringSlice{},
		},
	}
	syncPeeringdbFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "apikey",
			Usage: "PeeringDB API Key",
			Value: "",
		},
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Re-download even when the ETag is unchanged (needed after a metadata wipe / truncated tables)",
		},
	}
	whoisdbFlags := []cli.Flag{
		&cli.DurationFlag{
			Name:  "whoisdb-period",
			Usage: "Period between whoisdb fetch jobs",
			Value: 1 * time.Hour,
		},
		&cli.IntFlag{
			Name:  "whoisdb-buffer-max-size",
			Usage: "Maximum number of whoisdb records to buffer before saving to database",
			Value: 5000,
		},
		&cli.BoolFlag{
			Name:  "with-whoisdb-route-fetch",
			Usage: "Whether or not to fetch route data",
			Value: true,
		},
		&cli.IntFlag{
			Name:  "whoisdb-prefetch",
			Usage: "How many whois dumps to download ahead of the parser. Bounds concurrent downloads and temp files on disk; parsing and saving stay sequential",
			Value: whoisdb.DefaultPrefetchDepth,
		},
	}
	asnamesFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "asnames-url",
			Usage:   "Override the RIPE asnames.txt source URL",
			Value:   asnames.DefaultURL,
			EnvVars: []string{"OPR_ASNAMES_URL"},
		},
	}
	whoisdbFlags = append(whoisdbFlags, asnamesFlags...)
	nroFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "delegated-stats-url",
			Usage:   "Override the NRO delegated-stats source URL",
			Value:   nro.DefaultDelegatedStatsURL,
			EnvVars: []string{"OPR_DELEGATED_STATS_URL"},
		},
	}

	rdapQueueFlags := []cli.Flag{
		&cli.BoolFlag{
			Name:  "include-bulk-gaps",
			Usage: "Also claim leftover pending autnums on RIPE/APNIC/AFRINIC (bulk dumps normally mark those done). Ignored if --only-registries is set",
		},
		&cli.DurationFlag{
			Name:  "lease",
			Usage: "How long a claimed crawl_target row stays locked before another worker may steal it",
			Value: 2 * time.Minute,
		},
		&cli.IntFlag{
			Name:  "batch",
			Usage: "How many crawl_target rows to claim per round. Default 1 so one in-flight ASN matches the per-RIR AIMD limiter; batch>1 holds extra leases while processing sequentially",
			Value: 1,
		},
	}

	runCommand := cli.Command{
		Name:     "run",
		Aliases:  []string{"r"},
		Category: commandCategoryData,
		Usage:    "Run every enabled ingest job from opr.config.toml until SIGINT/SIGTERM. Only flag: --config. Secrets come from OPR_POSTGRES_DB, OPR_CLICKHOUSE_PASSWORD, OPR_PEERINGDB_APIKEY.",
		Description: `Start one goroutine per job enabled in the TOML file and run until SIGINT or SIGTERM.

Config path: --config, else OPR_CONFIG, else ~/.config/opr.config.toml. The file must exist; copy opr.example.toml there. Every job table has enabled (default true); omitted keys keep the one-shot flag defaults. Unknown keys are errors.

Secrets are never read from the file: OPR_POSTGRES_DB (required), OPR_CLICKHOUSE_PASSWORD, OPR_PEERINGDB_APIKEY. --postgres-db is not accepted on run.

Jobs: rdap (autnum + ipnet queue workers), seed, whoisdb, geonames, peeringdb, aspop, geoip (lacnic, ipmap, anycast, geofeeds), rpki, fdns.ingest-lists, fdns.resolve, fdns.ingest-cc, fdns.seed-queue, rdns.ingest, rdns.crawl-ptr. Status boards, geonames flags, mark-ipnet-bulk, asnames, geoip prune, and the postgres/clickhouse schema commands stay one-shot.`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Path to opr.config.toml. Overrides OPR_CONFIG; default ~/.config/opr.config.toml",
			},
		},
		Action: runDaemon,
	}

	asPopCommand := cli.Command{
		Name:     "aspop",
		Category: commandCategoryData,
		Usage:    "Fetch ASN population per country data from APNIC project (https://stats.labs.apnic.net/cgi-bin/aspop)",
		Action: func(c *cli.Context) error {

			aggr, err := aspop.NewAsPopAggregator(c)
			if err != nil {
				return err
			}
			defer aggr.Close()

			return aggr.FetchAsnPopulation(c.Context)

		},
	}

	syncPeeringDb := cli.Command{
		Name:        "peeringdb",
		Aliases:     []string{"pdb"},
		Category:    commandCategoryData,
		Usage:       "Download official PeeringDB JSON dumps and COPY-swap peeringdb_* tables. Needs Postgres (--apikey or OPR_PEERINGDB_APIKEY).",
		Description: "Bare peeringdb ingests. Subcommand status is a read-only board (no downloads).",
		Flags:       syncPeeringdbFlags,
		Action:      runPeeringDBIngest,
		Subcommands: []*cli.Command{
			peeringdbStatusCommand(),
		},
	}

	rdapWorkerFlags := append([]cli.Flag{}, fetchRegistriesDataFlags...)
	rdapWorkerFlags = append(rdapWorkerFlags, rdapQueueFlags...)
	rdapWorkerFlags = append(rdapWorkerFlags,
		&cli.StringFlag{
			Name:  "kind",
			Usage: "Which crawl_target kind to claim: autnum or ipnet. Omit to run both. Autnum and ipnet for the same RIR share that RIR's AdaptiveLimiter",
		},
		&cli.BoolFlag{
			Name:  "once",
			Usage: "Claim until selected kind queues are empty then exit, instead of running until SIGINT",
		},
	)

	geonamesCommand := cli.Command{
		Name:        "geonames",
		Aliases:     []string{"gn"},
		Category:    commandCategoryData,
		Usage:       "Download GeoNames dumps, COPY-swap split tables, and rebuild geonames_lookup. Needs Postgres.",
		Description: "Bare geonames ingests. Subcommands status and flags are read-only boards (no downloads).",
		Action:      runGeoNamesIngest,
		Subcommands: []*cli.Command{
			geonamesStatusCommand(),
			geonamesFlagsCommand(),
		},
	}

	registryCrawlCommand := cli.Command{
		Name:        "registry-crawl",
		Category:    commandCategoryData,
		Usage:       "Seed crawl_target, ingest bulk whois dumps, and run the durable RDAP queue. Needs Postgres.",
		Description: "Typical order: seed → bulk → worker. status is read-only. Subcommand details are under each name.",
		Subcommands: []*cli.Command{
			{
				Name:   "bulk",
				Usage:  "Fetch bulk whois dumps from each RIR/NIR plus route objects from every IRR (including the ARIN and AFRINIC mixed dumps), save them, and mark RIPE/APNIC/AFRINIC/NIR autnums and inetnums covered in crawl_target so RDAP skips them. Coverage is reconciled at the end of every run, so ETag-skipped files still count. Then backfill as_name/country from RIPE asnames.txt for still-pending autnums (not a coverage mark). ARIN/LACNIC dumps are still saved but never marked (incomplete). In opr run this is the periodic [registry-crawl.bulk] job.",
				Flags:  whoisdbFlags,
				Action: runWhoisDBAggregation,
			},
			{
				Name:   "worker",
				Usage:  "Claim crawl_target autnum and/or ipnet rows and fetch them via RDAP (--kind autnum|ipnet, omit for both). Defaults to ARIN+LACNIC because RIPE/APNIC/AFRINIC are bulk-covered (already done). --include-bulk-gaps claims leftover pending on other RIRs. --only-registries wins. In opr run this is the continuous [registry-crawl.worker] job.",
				Flags:  rdapWorkerFlags,
				Action: runRDAPRegistryWorker,
			},
			{
				Name:  "seed",
				Usage: "Refresh NRO delegated-stats, then enqueue crawl_target from that snapshot (one pending autnum job per allocated/assigned ASN, one pending ipnet job per canonical CIDR of the ARIN/LACNIC delegated ranges) plus the ARIN/LACNIC prefixes announced in RouteViews RIBs. Enqueue only: downloads no whois dumps and writes no prefix data. In opr run this is the periodic [registry-crawl.seed] job.",
				Flags: append([]cli.Flag{
					&cli.StringSliceFlag{
						Name:  "only-registries",
						Usage: "Only seed these registries. Valid names: " + strings.Join(validCrawlRegistries, ", "),
						Value: &cli.StringSlice{},
					},
					&cli.BoolFlag{
						Name:  "skip-ribs",
						Usage: "Skip the RouteViews RIB pass for a fast NRO-only seed",
					},
				}, nroFlags...),
				Action: runRegistryCrawlSeed,
			},
			{
				Name:   "asnames",
				Usage:  "Backfill as_name and country_code on still-pending crawl_target autnums from RIPE asnames.txt. Does not mark coverage. Also runs at the end of `registry-crawl bulk`.",
				Flags:  asnamesFlags,
				Action: runASNamesBackfill,
			},
			{
				Name:  "mark-ipnet-bulk",
				Usage: "Backfill crawl_target ipnet coverage as done from whoisdb_inetnum/whoisdb_inet6num for complete-dump registries (RIPE/APNIC/AFRINIC/JPNIC/KRNIC/TWNIC). Does not re-download dumps. Use after a prior `registry-crawl bulk`, or pass --cidr/--registry for a smoke test.",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "only-registries",
						Usage: "Only mark these coverage registries. Valid names: " + strings.Join(whoisdb.BulkDumpCoverageRegistries(), ", "),
						Value: &cli.StringSlice{},
					},
					&cli.StringSliceFlag{
						Name:  "cidr",
						Usage: "Mark these CIDRs directly (smoke/backfill of a few rows). Requires --registry. Skips the whoisdb table scan.",
						Value: &cli.StringSlice{},
					},
					&cli.StringFlag{
						Name:  "registry",
						Usage: "Registry for --cidr (must be a complete-dump coverage registry)",
					},
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Log counts without writing crawl_target",
					},
				},
				Action: runMarkIpnetBulk,
			},
			registryCrawlStatusCommand(),
		},
	}

	cliapp.Commands = []*cli.Command{
		&runCommand,
		&asPopCommand,
		&syncPeeringDb,
		rpkiCommand(),
		rdnsCommand(),
		fdnsCommand(),
		clickhouseCommand(),
		postgresCommand(),
		oprHelpCommand(),
		geoIPCommand(),
		&geonamesCommand,
		&registryCrawlCommand,
	}
	applyHelpUsageTexts(cliapp.Commands, nil)

	return cliapp

}

// requirePostgresDSN enforces --postgres-db for commands that talk to Postgres.
// urfave's unexported checkRequiredFlags runs on the root command before it
// dispatches a subcommand, so a Required global flag would also reject
// `opr clickhouse` and `opr fdns ingest-cc`. Help does not connect, so
// `opr help` and `opr postgres --help` do not need --postgres-db. `postgres migrate`
// and `postgres version` still do. Zero positional args is bare `opr`, which
// shows the same app help after this hook returns. An empty arg list must
// pass here or that path exits on a missing --postgres-db.
//
// One-shots fall back to OPR_POSTGRES_DB when --postgres-db is empty. `run` is skipped
// here entirely: it reads OPR_POSTGRES_DB itself and rejects --postgres-db, so the flag
// is never confused with the environment (see runDaemon).
func requirePostgresDSN(c *cli.Context) error {
	if !c.Args().Present() {
		return nil
	}
	args := c.Args().Slice()
	if isRunCommand(args) || helpRequested(args) {
		return nil
	}
	if strings.TrimSpace(c.String("postgres-db")) == "" {
		if env := strings.TrimSpace(os.Getenv(opconfig.EnvDSN)); env != "" {
			return c.Set("postgres-db", env)
		}
		if postgresDSNOptional(args) {
			return nil
		}
		return fmt.Errorf("Required flag %q not set", "postgres-db")
	}
	return nil
}

// isRunCommand is true when the first positional argument is the daemon
// command or its alias.
func isRunCommand(args []string) bool {
	return len(args) > 0 && (args[0] == "run" || args[0] == "r")
}

// helpRequested is true for the help command and for --help / -h on any
// command. A bare "h" counts only as the help alias in the first position,
// so a later flag value of "h" still requires --postgres-db.
func helpRequested(args []string) bool {
	if len(args) > 0 && (args[0] == "help" || args[0] == "h") {
		return true
	}
	for _, a := range args {
		switch a {
		case "--help", "-h", "help":
			return true
		}
	}
	return false
}

func postgresDSNOptional(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "clickhouse":
		return true
	case "fdns":
		return len(args) >= 2 && args[1] == "ingest-cc"
	default:
		return false
	}
}

// rejectUnknownGeoNamesSubcommand stops urfave/cli v2 falling through to
// ingest when args.First() is not a registered subcommand (e.g. `gn stat`).
func rejectUnknownGeoNamesSubcommand(c *cli.Context) error {
	if c.Args().Present() {
		return fmt.Errorf("unknown geonames subcommand %q", c.Args().First())
	}
	return nil
}

// rejectUnknownPeeringDBSubcommand stops urfave/cli v2 falling through to
// ingest when args.First() is not a registered subcommand (e.g. `pdb stat`).
func rejectUnknownPeeringDBSubcommand(c *cli.Context) error {
	if c.Args().Present() {
		return fmt.Errorf("unknown peeringdb subcommand %q", c.Args().First())
	}
	return nil
}

func runPeeringDBIngest(c *cli.Context) error {
	if err := rejectUnknownPeeringDBSubcommand(c); err != nil {
		return err
	}
	s, err := peeringdb.NewPeeringDBClient(c)
	if err != nil {
		return err
	}
	defer s.Store.Close()
	return s.DoPeeringDbSync(c.Context)
}

func runGeoNamesIngest(c *cli.Context) error {
	if err := rejectUnknownGeoNamesSubcommand(c); err != nil {
		return err
	}
	geoNames, err := geonames.NewGeoNames(c)
	if err != nil {
		return err
	}
	defer geoNames.Store.Close()
	return geoNames.RunOnce()
}

// validCrawlRegistries is the set --only-registries accepts across the
// registry-crawl subcommands.
var validCrawlRegistries = []string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}

// runRegistryCrawlSeed is `registry-crawl seed`: it refreshes NRO then
// enqueues. crawl_target is the sole table it writes - no whois dumps
// (that is `registry-crawl bulk`), no RDAP (that is `registry-crawl
// worker`), and nothing in prefix / prefix_consolidated.
//
// Two barriers. Barrier 1 always downloads the NRO snapshot (daemon
// style: a failed download keeps the last delegated_stats rows). Barrier
// 2 runs the SQL seeds and the RIB pass concurrently: they share no
// input, and the RIB pass is minutes of network and CPU while the SQL
// seeds are seconds.
func runRegistryCrawlSeed(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.registry-crawl")

	registries := c.StringSlice("only-registries")
	for _, r := range registries {
		if !slices.Contains(validCrawlRegistries, r) {
			return fmt.Errorf("unknown registry name: %s. Valid names: %s", r, strings.Join(validCrawlRegistries, ", "))
		}
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

	return seedCrawlTargets(context.Background(), logger, st, seedOptions{
		Registries:        registries,
		SkipRIBs:          c.Bool("skip-ribs"),
		DelegatedStatsURL: c.String("delegated-stats-url"),
	})
}

// seedOptions are the knobs of `registry-crawl seed` and the daemon's
// [registry-crawl.seed] job.
type seedOptions struct {
	// Registries is --only-registries / empty for all five.
	Registries []string
	// SkipRIBs skips the RouteViews RIB pass (--skip-ribs /
	// registry-crawl.seed.skip-ribs).
	SkipRIBs bool
	// DelegatedStatsURL is the NRO snapshot source.
	DelegatedStatsURL string
}

// seedCrawlTargets is the shared body of `registry-crawl seed` and the
// daemon seed loop: NRO refresh, then autnum + ipnet SQL seeds and the
// RouteViews RIB pass. The caller owns st and has run migrations.
func seedCrawlTargets(ctx context.Context, logger *zap.Logger, st *postgres.Store, opts seedOptions) error {
	registries := opts.Registries
	if opts.DelegatedStatsURL == "" {
		opts.DelegatedStatsURL = nro.DefaultDelegatedStatsURL
	}

	// Barrier 1, sequential. Share the store; nro.Aggregator.Close would close it.
	nroAggr := nro.New(logger, st, opts.DelegatedStatsURL)
	if err := nroAggr.DownloadAndLoad(ctx); err != nil {
		// Keep the last snapshot; seed still helps if delegated_stats
		// already has rows from a previous successful load.
		logger.Error("NRO delegated-stats load failed; keeping last snapshot", zap.Error(err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	nroCount, err := st.CountDelegatedStats(ctx)
	if err != nil {
		return err
	}
	if nroCount == 0 {
		return fmt.Errorf("delegated_stats is empty after NRO refresh; cannot seed crawl_target")
	}
	logger.Info("nro snapshot ready", zap.Int64("delegated_stats_rows", nroCount))

	// Barrier 2, two independent tracks.
	var (
		wg     sync.WaitGroup
		sqlErr error
		ribErr error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer oplog.RecoverInto(logger, "seed autnum/ipnet panicked", &sqlErr)

		inserted, err := st.SeedAutnumTargets(ctx, registries)
		if err != nil {
			sqlErr = err
			return
		}
		logger.Info("seeded autnum crawl targets",
			zap.Int64("inserted", inserted), zap.Strings("registries", registries))

		// ARIN/LACNIC only, whatever --only-registries says: the other three
		// RIRs' inetnums come from their complete bulk dumps.
		ipnets, err := st.SeedIpnetFromNRO(ctx, registries)
		if err != nil {
			sqlErr = err
			return
		}
		logger.Info("seeded ipnet crawl targets from nro delegated ranges",
			zap.Int64("inserted", ipnets))
	}()

	ipnetRegistries := postgres.IpnetSeedRegistriesFor(registries)
	switch {
	case opts.SkipRIBs:
		logger.Info("skip-ribs is set, no routeviews rib pass")
	case len(ipnetRegistries) == 0:
		logger.Info("no seedable ipnet registry selected, no routeviews rib pass",
			zap.Strings("only_registries", registries),
			zap.Strings("seedable", postgres.IpnetSeedRegistries))
	default:
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer oplog.RecoverInto(logger, "seed routeviews rib panicked", &ribErr)

			seeder, err := registry.NewRibSeeder(logger, st, nil)
			if err != nil {
				ribErr = err
				return
			}
			if _, err := seeder.SeedIpnetFromRIBs(ctx, ipnetRegistries); err != nil {
				ribErr = err
			}
		}()
	}

	wg.Wait()
	if err := errors.Join(sqlErr, ribErr); err != nil {
		return err
	}

	for _, kind := range []string{postgres.CrawlKindAutnum, postgres.CrawlKindIpnet} {
		status, err := st.CrawlStatus(ctx, kind)
		if err != nil {
			return err
		}
		if len(status) == 0 {
			logger.Warn("crawl_target has no rows for kind", zap.String("kind", kind))
		}
		for _, row := range status {
			logger.Info("crawl_target status",
				zap.String("kind", kind),
				zap.String("registry", row.Registry),
				zap.String("state", row.State),
				zap.Int64("count", row.Count),
			)
		}
	}
	return nil
}

// runWhoisDBAggregation is `registry-crawl bulk`.
func runWhoisDBAggregation(c *cli.Context) error {
	aggr, err := whoisdb.NewWhoisDBAggregator(c)
	if err != nil {
		return err
	}

	// Start goroutine listening on chan to save records to database.
	// Close and the saver wait run on every return, including errors.
	go aggr.SaveWhoisRecords()
	defer waitForWhoisSaver(aggr.Logger, aggr)

	err = aggr.DoWhoisDBAggregationOnce(c.Context)
	if err != nil {
		return err
	}

	aggr.Logger.Info("whoisdb aggregation completed")
	return nil
}

// runRDAPRegistryWorker is `registry-crawl worker`.
// --kind selects autnum, ipnet, or both (omit). Default registries are
// ARIN+LACNIC so we do not re-fetch bulk-covered RIPE/APNIC/AFRINIC;
// --include-bulk-gaps or --only-registries override that. --rdap-ipnet
// appends ipnet (and --rdap-autnum appends autnum) if --kind did not
// already include it.
func runRDAPRegistryWorker(c *cli.Context) error {
	kinds, err := registry.ParseCrawlKinds(c.String("kind"))
	if err != nil {
		return err
	}
	if c.Bool("rdap-ipnet") && !slices.Contains(kinds, postgres.CrawlKindIpnet) {
		kinds = append(kinds, postgres.CrawlKindIpnet)
	}
	if c.Bool("rdap-autnum") && !slices.Contains(kinds, postgres.CrawlKindAutnum) {
		kinds = append(kinds, postgres.CrawlKindAutnum)
	}

	aggr, err := registry.NewRegistryAggregator(c)
	if err != nil {
		return err
	}
	defer aggr.Close()

	aggr.ApplyRDAPWorkerRegistryDefaults(c.StringSlice("only-registries"), c.Bool("include-bulk-gaps"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := aggr.StartCrawlWorkers(ctx, kinds, registry.CrawlConfig{
		Lease: c.Duration("lease"),
		Batch: c.Int("batch"),
		Once:  c.Bool("once"),
	}); err != nil && !errors.Is(err, context.Canceled) {
		aggr.Logger.Error("error while running rdap crawl workers", zap.Error(err))
		return err
	}

	return nil
}

func main() {

	const exitFail = 1

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "exiting with an error: %s\n", err)
		os.Exit(exitFail)
	}

}
