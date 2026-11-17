package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/aggregator/geoip"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func geoIPCommand() *cli.Command {
	return &cli.Command{
		Name:     "geoip",
		Aliases:  []string{"gi"},
		Category: commandCategoryData,
		Usage:    "Geolocation ingest from the geofeeds catalog (RFC 9632), LACNIC, RIPE IPmap, and bgptools anycast. Not RDAP; not crawl_target. Needs Postgres.",
		Description: `Pick a subcommand. crawl-geofeeds / lacnic / ipmap / anycast write rows; prune cleans orphans; status is read-only.

When: after geofeeds catalog rows exist (registry-crawl bulk harvest) for crawl-geofeeds/prune; lacnic/ipmap/anycast are independent dumps.`,
		Subcommands: []*cli.Command{
			{
				Name:  "crawl-geofeeds",
				Usage: "One HTTP GET per unique catalog URL (not per inetnum). 304 / fresh Cache-Control skips parse. New URLs first. 404/non-CSV quarantines the URL and does not wipe geoip. Does not fetch LACNIC. In opr run this is the continuous [geoip.crawl-geofeeds] job.",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "worker-count",
						Usage: "Number of worker goroutines for downloading/parsing geofeed URLs",
						Value: geofeeds.DefaultWorkerCount,
					},
					&cli.DurationFlag{
						Name:  "refresh-older-than",
						Usage: "Re-fetch when last_fetched_at is older than this and Cache-Control did not set cache_until (default 168h)",
						Value: geofeeds.DefaultRefreshOlderThan,
					},
					&cli.BoolFlag{
						Name:  "once",
						Usage: "Claim and process one due batch, then exit (default drains currently due URLs)",
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Skip If-None-Match / If-Modified-Since validators",
					},
				},
				Action: runGeoIPCrawlGeofeeds,
			},
			{
				Name:  "prune",
				Usage: "Deletes geoip rows whose source_url is gone from geofeeds. Does not download. Catalog URL prune stays in registry-crawl bulk after a complete pass-1 harvest.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Count orphans without deleting",
					},
					&cli.StringFlag{
						Name:  "source",
						Usage: "Which geoip.source to prune: geofeed (default) or all (also LACNIC rows with a non-empty source_url missing from the catalog)",
						Value: geofeeds.PruneSourceGeofeed,
					},
				},
				Action: runGeoIPPrune,
			},
			{
				Name:   "lacnic",
				Usage:  "Existing LACNIC CSV into geoip (source=LACNIC_DB_CSV). May overlap RFC 9632 prefixes; both rows kept. In opr run this is the periodic [geoip.lacnic] job.",
				Action: runGeoIPLacnic,
			},
			{
				Name:  "ipmap",
				Usage: "RIPE IPmap dump into geoip (source=RIPE_IPMAP). May overlap GEOFEED/LACNIC prefixes; both rows kept. In opr run this is the periodic [geoip.ipmap] job.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Re-download even when the ETag is unchanged (needed after a metadata wipe)",
					},
					&cli.StringFlag{
						Name:  "url",
						Usage: "IPmap dump URL (default https://ftp.ripe.net/ripe/ipmap/geolocations-latest)",
						Value: geoip.IPMAPDumpURL,
					},
				},
				Action: runGeoIPIPMAP,
			},
			{
				Name:  "anycast",
				Usage: "bgptools anycatch v4/v6 prefix CSVs into anycast_prefix. Lookup prefers a covering anycast prefix over IPmap city. In opr run this is the periodic [geoip.anycast] job.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Re-download even when the ETag is unchanged (needed after a metadata wipe)",
					},
				},
				Action: runGeoIPAnycast,
			},
			geoIPStatusCommand(),
		},
	}
}

func runGeoIPCrawlGeofeeds(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.geoip.crawl-geofeeds")

	dsn := c.String("dsn")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	workers := c.Int("worker-count")
	if workers < 1 {
		return fmt.Errorf("worker-count must be >= 1")
	}

	cr := &geofeeds.Crawler{
		Store: st,
		HTTPClient: &http.Client{
			Timeout: geofeeds.DefaultHTTPTimeout,
		},
		Logger:  logger,
		Workers: workers,
		Refresh: c.Duration("refresh-older-than"),
		Force:   c.Bool("force"),
		Once:    c.Bool("once"),
	}
	return cr.Run(c.Context)
}

func runGeoIPPrune(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.geoip.prune")

	dsn := c.String("dsn")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	dry := c.Bool("dry-run")
	n, err := geofeeds.Prune(c.Context, st, c.String("source"), dry)
	if err != nil {
		return err
	}
	logger.Info("geoip prune",
		zap.Int64("rows", n),
		zap.Bool("dry_run", dry),
		zap.String("source", c.String("source")),
	)
	return nil
}

func runGeoIPLacnic(c *cli.Context) error {
	gi, err := geoip.NewGeoIpAggregator(c)
	if err != nil {
		return err
	}
	defer gi.Close()

	start := time.Now()
	gi.Logger.Info("started to fetch ip geolocation from lacnic")
	err = gi.FetchIpGeolocationFromLacnic(c.Context)
	if err != nil {
		gi.Logger.Error("error while fetching ip geolocation from lacnic", zap.Error(err))
		return err
	}
	gi.Logger.Info("finished to fetch ip geolocation from lacnic", zap.String("duration", time.Since(start).String()))
	return nil
}

func runGeoIPIPMAP(c *cli.Context) error {
	gi, err := geoip.NewGeoIpAggregator(c)
	if err != nil {
		return err
	}
	defer gi.Close()

	start := time.Now()
	gi.Logger.Info("started to fetch ip geolocation from ripe ipmap")
	err = gi.FetchIPMAP(c.Context, c.Bool("force"), c.String("url"))
	if errors.Is(err, geoip.ErrIPMAPEmpty) {
		gi.Logger.Warn("ripe ipmap dump had no valid prefixes; previous rows kept", zap.Error(err))
		return nil
	}
	if err != nil {
		gi.Logger.Error("error while fetching ip geolocation from ripe ipmap", zap.Error(err))
		return err
	}
	gi.Logger.Info("finished to fetch ip geolocation from ripe ipmap", zap.String("duration", time.Since(start).String()))
	return nil
}

func runGeoIPAnycast(c *cli.Context) error {
	gi, err := geoip.NewGeoIpAggregator(c)
	if err != nil {
		return err
	}
	defer gi.Close()

	start := time.Now()
	gi.Logger.Info("started to fetch anycast prefixes")
	err = gi.FetchAnycast(c.Context, c.Bool("force"))
	if err != nil {
		gi.Logger.Error("error while fetching anycast prefixes", zap.Error(err))
		return err
	}
	gi.Logger.Info("finished to fetch anycast prefixes", zap.String("duration", time.Since(start).String()))
	return nil
}
