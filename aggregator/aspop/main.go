package aspop

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const AsPop = "aspop"

type AsPopAggregator struct {
	Name       string
	Logger     *zap.Logger
	Store      *postgres.Store
	httpClient *http.Client
	// Status metadata
	StatusMetadata struct {
		IsRunning         bool          `json:"is_running"`
		IsHealthy         *bool         `json:"is_healthy"`
		IsSavedToDatabase bool          `json:"is_saved_to_database"`
		StartTime         time.Time     `json:"start_time"`
		LastFetchTime     time.Time     `json:"last_fetch_time"`
		TotalASNFetched   int           `json:"total_fetched"`
		JobDuration       time.Duration `json:"job_duration"`
		NextFetchTime     time.Time     `json:"next_fetch_time"`
	}
	// Crawler interval
	CrawlInterval time.Duration
}

// DefaultCrawlInterval is how often the daemon re-fetches aspop.
const DefaultCrawlInterval = 6 * time.Hour

// New builds an aggregator on an existing logger and store. The caller
// owns the store; Close closes it.
func New(logger *zap.Logger, store *postgres.Store) *AsPopAggregator {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AsPopAggregator{
		Name:          AsPop,
		Store:         store,
		Logger:        logger,
		httpClient:    http.DefaultClient,
		CrawlInterval: DefaultCrawlInterval,
	}
}

// NewAsPopAggregator is the one-shot constructor: logger and store from
// the CLI flags, migrations applied.
func NewAsPopAggregator(c *cli.Context) (*AsPopAggregator, error) {

	logger, err := oplog.NewFromCli(c)
	if err != nil {
		panic(err)
	}
	logger = logger.Named("opr.aspop")

	DSN := c.String("dsn")
	pgStore, err := postgres.New(logger.Named("opr.aspop.store"), DSN)
	if err != nil {
		return nil, err
	}

	// Check the database is at last schema version, upgrade if necessary
	err = postgres.RunMigrations(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return nil, err
	}

	return New(logger, pgStore), nil
}

// GetStatus is used to check if the aggregator is running
// Used only when running as a daemon
func (aspopaggr *AsPopAggregator) GetStatus(w http.ResponseWriter, r *http.Request) {
	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Check if the last fetch time is too old
	if aspopaggr.StatusMetadata.LastFetchTime.IsZero() {
		aspopaggr.StatusMetadata.IsHealthy = nil
	} else if aspopaggr.StatusMetadata.LastFetchTime.After(time.Now().Add(-12 * time.Hour)) {
		isHealthy := true
		aspopaggr.StatusMetadata.IsHealthy = &isHealthy
	} else {
		isHealthy := false
		aspopaggr.StatusMetadata.IsHealthy = &isHealthy
	}
	aspopaggr.StatusMetadata.StartTime = aspopaggr.StatusMetadata.StartTime.UTC()
	json.NewEncoder(w).Encode(aspopaggr.StatusMetadata)

}

func (aspopaggr *AsPopAggregator) Close() {
	aspopaggr.Store.Close()
	aspopaggr.Logger.Info("closed aspop aggregator")
}

func (aspopaggr *AsPopAggregator) FetchAsnPopulation(ctx context.Context) error {

	startTime := time.Now()

	// Update status metadata
	aspopaggr.StatusMetadata.IsRunning = true
	aspopaggr.StatusMetadata.StartTime = startTime
	aspopaggr.StatusMetadata.LastFetchTime = time.Time{}
	aspopaggr.StatusMetadata.JobDuration = 0
	aspopaggr.StatusMetadata.IsSavedToDatabase = false
	defer func() {
		aspopaggr.StatusMetadata.IsRunning = false
		aspopaggr.StatusMetadata.JobDuration = time.Since(aspopaggr.StatusMetadata.StartTime)
	}()

	URL := "https://stats.labs.apnic.net/cgi-bin/aspop?w=120&f=c"

	aspopaggr.Logger.Info("fetching aspop file", zap.String("url", URL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return fmt.Errorf("error while fetching ip ip-asn file, skipping this one: %w", err)
	}
	resp, err := aspopaggr.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error while fetching ip ip-asn file, skipping this one: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("response body was nit for ip-asn file, skipping this one")
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("error while downloading file, status was %s, size: %d, skipping this file",
			resp.Status,
			resp.ContentLength,
		)
	} else {
		aspopaggr.Logger.Info("received file without error",
			zap.String("status_code", resp.Status),
			zap.Int64("size", resp.ContentLength),
		)
	}

	csvReader := csv.NewReader(resp.Body)
	csvReader.FieldsPerRecord = 8

	startParsingTime := time.Now()
	var allAsPopInfo []*postgres.AsPopInfo

	for {

		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if errors.Is(err, unix.ECONNRESET) {
			return fmt.Errorf("connection closed while reading: %w", err)
		} else if errors.Is(err, context.Canceled) {
			return fmt.Errorf("connection closed while reading: %w", err)
		} else if strings.HasPrefix(rec[0], "#") {
			aspopaggr.Logger.Debug("skipping comment line", zap.String("rec", strings.Join(rec, ",")))
			continue
		} else if err != nil {
			aspopaggr.Logger.Warn("error while reading a new csv line, skipping row", zap.Error(err), zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		if len(rec) < 8 {
			aspopaggr.Logger.Warn("not enough column in row, skipping row", zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		var asn int
		if strings.HasPrefix(rec[1], "AS") {
			asn, err = strconv.Atoi(rec[1][2:])
			if err != nil {
				aspopaggr.Logger.Warn("cannot convert asn to int, skipping row", zap.Error(err), zap.String("rec", strings.Join(rec, ",")))
				continue
			}
		}

		var userCount int
		userCount, err = strconv.Atoi(rec[4])
		if err != nil {
			aspopaggr.Logger.Warn("cannot convert user count to int, skipping row", zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		var percCountry float64
		percCountry, err = strconv.ParseFloat(rec[5], 64)
		if err != nil {
			aspopaggr.Logger.Warn("cannot convert country percent to float, skipping row", zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		var percInternet float64
		percInternet, err = strconv.ParseFloat(rec[6], 64)
		if err != nil {
			aspopaggr.Logger.Warn("cannot convert internet percent to float, skipping row", zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		var sampleCount int
		sampleCount, err = strconv.Atoi(rec[7])
		if err != nil {
			aspopaggr.Logger.Warn("cannot convert user count to int, skipping row", zap.String("rec", strings.Join(rec, ",")))
			continue
		}

		allAsPopInfo = append(allAsPopInfo, &postgres.AsPopInfo{
			Asn:          uint32(asn),
			CountryCode:  rec[3],
			UserCount:    uint64(userCount),
			PercCountry:  percCountry,
			PercInternet: percInternet,
			SampleCount:  uint64(sampleCount),
		})

		// Stop if more than 65K, max database inserts allowed at once
		if len(allAsPopInfo) > 65_000 {
			aspopaggr.Logger.Error("more items that what database allow in one insert, exiting")
			break
		}

	}

	aspopaggr.Logger.Info(fmt.Sprintf("fetched and parsed aspop data data in %s", time.Since(startParsingTime).String()))

	// Save all aspop info, deleting all data first, in a single transaction

	tx, err := aspopaggr.Store.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Delete all previous data, before inserting new data.
	_, err = tx.Exec(ctx, "TRUNCATE TABLE ONLY aspop RESTART IDENTITY")
	if err != nil {
		return err
	}

	// Save all in db, in TX, delete all, insert all
	// Save any remaining prefixes to database
	aspopaggr.Logger.Info("starting to save all aspop in database, using copy from", zap.Int("length", len(allAsPopInfo)))
	_, err = tx.CopyFrom(
		ctx,
		pgx.Identifier{"aspop"},
		[]string{"asn", "country_code", "user_count", "perc_country", "perc_internet", "sample_count"},
		pgx.CopyFromSlice(len(allAsPopInfo), func(i int) ([]any, error) {
			return []any{
				allAsPopInfo[i].Asn, allAsPopInfo[i].CountryCode,
				allAsPopInfo[i].UserCount, allAsPopInfo[i].PercCountry,
				allAsPopInfo[i].PercInternet, allAsPopInfo[i].SampleCount,
			}, nil
		}),
	)
	if err != nil {
		aspopaggr.Logger.Error("failed to copy new aspop info", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		aspopaggr.Logger.Error("failed to commit the transaction", zap.Error(err))
		return err
	}

	aspopaggr.Logger.Info(fmt.Sprintf("fetched and saved new aspop data data in %s", time.Since(startTime).String()))
	// Update status metadata
	aspopaggr.StatusMetadata.LastFetchTime = time.Now()
	aspopaggr.StatusMetadata.TotalASNFetched = len(allAsPopInfo)
	aspopaggr.StatusMetadata.IsSavedToDatabase = true

	return nil

}
