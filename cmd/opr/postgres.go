package main

import (
	"fmt"

	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func postgresCommand() *cli.Command {
	return &cli.Command{
		Name:     "postgres",
		Category: commandCategoryManagement,
		Usage:    "Management command for the Postgres schema (opr_migrations). Other commands still migrate on startup.",
		Description: `Touches only the Postgres schema bookkeeping table opr_migrations. It does not ingest.

Use migrate/version to apply or inspect without starting an ingest. Postgres is --postgres-db, else OPR_POSTGRES_DB, else postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable.`,
		Subcommands: []*cli.Command{
			{
				Name:   "migrate",
				Usage:  "Apply pending Postgres migrations. Prints the schema version; already-at-latest changes nothing.",
				Action: runPostgresMigrate,
			},
			{
				Name:   "version",
				Usage:  "Print the applied Postgres schema version, its dirty flag, and the version this binary expects. Does not migrate.",
				Action: runPostgresVersion,
			},
		},
	}
}

func runPostgresMigrate(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.postgres.migrate")
	return postgres.RunMigrations(logger, c.String("postgres-db"))
}

func runPostgresVersion(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.postgres.version")

	version, dirty, err := postgres.SchemaVersion(c.Context, c.String("postgres-db"))
	if err != nil {
		return err
	}
	fmt.Printf("postgres schema version %d (dirty=%t), binary expects %d\n",
		version, dirty, postgres.LatestVersion())
	logger.Debug("postgres schema version",
		zap.Uint("version", version),
		zap.Bool("dirty", dirty),
		zap.Uint("expected", postgres.LatestVersion()))
	return nil
}
