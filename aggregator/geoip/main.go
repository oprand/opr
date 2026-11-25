package geoip

import (
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"
	"net/http"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

type GeoIpAggregator struct {
	HTTPClient *http.Client
	Logger     *zap.Logger
	Store      *postgres.Store
	ipmap      ipmapStore   // optional FetchIPMAP test seam; nil uses Store
	anycast    anycastStore // optional FetchAnycast test seam; nil uses Store
}

// New builds an aggregator on an existing logger and store. The caller
// owns the store; Close closes it.
func New(logger *zap.Logger, store *postgres.Store) *GeoIpAggregator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GeoIpAggregator{
		Store:      store,
		HTTPClient: &http.Client{Timeout: 30 * time.Minute},
		Logger:     logger,
	}
}

// NewGeoIpAggregator is the one-shot constructor: logger and store from
// the CLI flags, migrations applied.
func NewGeoIpAggregator(c *cli.Context) (*GeoIpAggregator, error) {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return nil, err
	}
	logger = logger.Named("opr.geoip")

	netStore, err := postgres.New(logger.Named("store"), c.String("postgres-db"))
	if err != nil {
		return nil, err
	}
	err = postgres.RunMigrations(logger.Named("store"), c.String("postgres-db"))
	if err != nil {
		return nil, err
	}

	return New(logger, netStore), nil
}

func (geo *GeoIpAggregator) Close() {
	geo.Store.DB.Close()
}
