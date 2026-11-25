package main

import (
	"context"
	"net/http"
	"time"

	"github.com/oprand/opr/aggregator/asnames"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func runASNamesBackfill(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.asnames")

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	url := c.String("asnames-url")
	_, err = asnames.Backfill(context.Background(), logger, st, &http.Client{Timeout: 10 * time.Minute}, url)
	return err
}
