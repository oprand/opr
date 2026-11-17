package main

import (
	"fmt"

	"github.com/oprand/opr/internal/opconfig"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/clickhouse"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func clickhouseCommand() *cli.Command {
	migrateFlags := append(clickhouseFlags(), &cli.BoolFlag{
		Name:  "dry-run",
		Usage: "Print the pending migration versions without applying them",
	})
	return &cli.Command{
		Name:     "clickhouse",
		Category: commandCategoryManagement,
		Usage:    "Management command that only touches the ClickHouse schema (fdns_cc_host and friends). Never runs implicitly.",
		Description: `Management command that only touches the ClickHouse schema that holds the Common Crawl Host Index. It does not ingest.

Unlike the Postgres migrations, which every command runs on startup, these are explicit: ClickHouse has no transactional DDL and reshaping a large MergeTree is a maintenance operation, not something to do at process start. fdns ingest-cc and fdns seed-queue only assert the version and tell you to run migrate.

Subcommands:
  migrate  Apply pending migrations in version order. --dry-run prints the pending versions instead.
  version  Print the applied schema version, its dirty flag, and the version this binary expects.

Bare "opr clickhouse" prints this help.`,
		Subcommands: []*cli.Command{
			{
				Name:   "migrate",
				Usage:  "Apply pending ClickHouse migrations in version order. Each migration is a single idempotent statement.",
				Flags:  migrateFlags,
				Action: runClickHouseMigrate,
			},
			{
				Name:   "version",
				Usage:  "Print the applied ClickHouse schema version, its dirty flag, and the version this binary expects.",
				Flags:  clickhouseFlags(),
				Action: runClickHouseVersion,
			},
		},
	}
}

// clickhouseFlags are shared by every command that talks to ClickHouse.
func clickhouseFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "clickhouse-url",
			Usage:   "ClickHouse HTTP interface base URL",
			Value:   clickhouse.DefaultURL,
			EnvVars: []string{opconfig.EnvClickHouseURL},
		},
		&cli.StringFlag{
			Name:  "clickhouse-database",
			Usage: "ClickHouse database holding fdns_cc_host",
			Value: clickhouse.DefaultDatabase,
		},
		&cli.StringFlag{
			Name:  "clickhouse-user",
			Usage: "ClickHouse user for the HTTP interface",
			Value: clickhouse.DefaultUser,
		},
		&cli.StringFlag{
			Name:    "clickhouse-password",
			Usage:   "ClickHouse password for the HTTP interface",
			EnvVars: []string{opconfig.EnvClickHousePassword},
		},
		&cli.DurationFlag{
			Name:  "clickhouse-timeout",
			Usage: "Per-request timeout for ClickHouse HTTP calls (one Parquet part POST runs for minutes)",
			Value: clickhouse.DefaultTimeout,
		},
	}
}

func clickhouseClientFromCLI(c *cli.Context) *clickhouse.Client {
	return clickhouse.New(
		c.String("clickhouse-url"),
		c.String("clickhouse-database"),
		c.String("clickhouse-user"),
		c.String("clickhouse-password"),
		c.Duration("clickhouse-timeout"),
	)
}

func runClickHouseMigrate(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.clickhouse.migrate")

	ch := clickhouseClientFromCLI(c)
	if c.Bool("dry-run") {
		pending, err := ch.PendingMigrations(c.Context)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			logger.Info("clickhouse has no pending migrations", zap.Uint("version", clickhouse.LatestVersion()))
			return nil
		}
		for _, m := range pending {
			logger.Info("clickhouse migration pending",
				zap.Uint("version", m.Version), zap.String("name", m.Name))
		}
		return nil
	}

	if err := ch.Migrate(c.Context, logger); err != nil {
		logger.Error("clickhouse migrate failed", zap.Error(err))
		return err
	}
	return nil
}

func runClickHouseVersion(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.clickhouse.version")

	ch := clickhouseClientFromCLI(c)
	version, dirty, err := ch.SchemaVersion(c.Context)
	if err != nil {
		return err
	}
	fmt.Printf("clickhouse schema version %d (dirty=%t), binary expects %d\n",
		version, dirty, clickhouse.LatestVersion())
	logger.Debug("clickhouse schema version",
		zap.Uint("version", version),
		zap.Bool("dirty", dirty),
		zap.Uint("expected", clickhouse.LatestVersion()))
	return nil
}
