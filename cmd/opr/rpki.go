package main

import (
	"net/http"
	"time"

	"github.com/oprand/opr/aggregator/rpki"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func rpkiCommand() *cli.Command {
	return &cli.Command{
		Name:     "rpki",
		Category: commandCategoryData,
		Usage:    "Ingest Routinator jsonext into vrp and aspa. Prefix/ASN pages read Postgres; this command does not stamp BGP prefixes.",
		Description: `Ingest Routinator jsonext into vrp and aspa. Prefix/ASN pages read Postgres; this command does not stamp BGP prefixes.

Subcommands:
  ingest  GET /jsonext from --routinator-addr, then --routinator-fallback-addr, COPY-swap vrp and aspa.

Bare "opr rpki" prints this help.`,
		Subcommands: []*cli.Command{
			{
				Name:  "ingest",
				Usage: "GET /jsonext from Routinator and COPY-swap vrp and aspa. Empty roas keep the last snapshot.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "routinator-addr",
						Usage: "Primary Routinator HTTP base",
						Value: rpki.DefaultRoutinatorAddr,
					},
					&cli.StringFlag{
						Name:  "routinator-fallback-addr",
						Usage: "Optional spare Routinator HTTP base if the primary fails",
					},
				},
				Action: runRPKIIngest,
			},
		},
	}
}

func runRPKIIngest(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.rpki.ingest")

	dsn := c.String("dsn")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	in := rpki.NewIngestor(logger, st, &http.Client{Timeout: 10 * time.Minute})
	if err := in.Ingest(c.Context, c.String("routinator-addr"), c.String("routinator-fallback-addr")); err != nil {
		logger.Error("rpki ingest failed; last vrp/aspa snapshot kept", zap.Error(err))
		return err
	}
	logger.Info("rpki ingest finished")
	return nil
}
