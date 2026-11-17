package geonames

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/internal/opnet"
	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/store/postgres"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

const Name = "geonames"

// DefaultCrawlInterval is how often the daemon re-fetches dumps. Status
// --stale-after defaults to 2× this window so a stable dump does not flap
// STALE between crawls.
const DefaultCrawlInterval = 24 * time.Hour

type GeoNames struct {
	HTTPClient     http.Client
	Logger         *zap.Logger
	Store          *postgres.Store
	CrawlInterval  time.Duration
	Name           string
	StatusMetadata struct {
		IsRunning     bool          `json:"is_running"`
		IsHealthy     *bool         `json:"is_healthy"`
		StartTime     time.Time     `json:"start_time"`
		LastFetchTime time.Time     `json:"last_fetch_time"`
		JobDuration   time.Duration `json:"job_duration"`
		NextFetchTime time.Time     `json:"next_fetch_time"`
		DumpsChanged  []string      `json:"dumps_changed"`
		LookupRebuilt bool          `json:"lookup_rebuilt"`
	}
}

// New builds an aggregator on an existing logger and store. The caller
// owns the store; Close closes it.
func New(logger *zap.Logger, store *postgres.Store) *GeoNames {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GeoNames{
		Store:         store,
		HTTPClient:    http.Client{Timeout: 30 * time.Minute},
		Logger:        logger,
		Name:          Name,
		CrawlInterval: DefaultCrawlInterval,
	}
}

// NewGeoNames is the one-shot constructor: logger and store from the CLI
// flags, migrations applied.
func NewGeoNames(c *cli.Context) (*GeoNames, error) {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return nil, err
	}
	logger = logger.Named("opr.geonames")

	st, err := postgres.New(logger, c.String("dsn"))
	if err != nil {
		return nil, err
	}
	err = postgres.RunMigrations(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return nil, err
	}

	return New(logger, st), nil
}

func (gn *GeoNames) Close() {
	gn.Store.Close()
	gn.Logger.Info("closed geonames aggregator")
}

// RunOnce is Run with a background context (one-shot `opr geonames`).
func (gn *GeoNames) RunOnce() error {
	return gn.Run(context.Background())
}

// Run fetches every GeoNames dump (skipping unchanged ETags), COPY-swaps
// new tables, and rebuilds geonames_lookup when at least one dump actually
// changed. ctx cancels the HTTP requests and the SQL in flight.
func (gn *GeoNames) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	startTime := time.Now()
	gn.StatusMetadata.IsRunning = true
	gn.StatusMetadata.StartTime = startTime
	gn.StatusMetadata.LastFetchTime = time.Time{}
	gn.StatusMetadata.JobDuration = 0
	gn.StatusMetadata.DumpsChanged = nil
	gn.StatusMetadata.LookupRebuilt = false
	defer func() {
		gn.StatusMetadata.IsRunning = false
		gn.StatusMetadata.JobDuration = time.Since(startTime)
	}()

	var dumpsChanged []string

	type feed struct {
		name string
		run  func() (bool, error)
	}
	feeds := []feed{
		{"countryInfo", func() (bool, error) { return gn.processCountryInfo(ctx) }},
		{"cities500", func() (bool, error) { return gn.processCities500(ctx) }},
		{"postal", func() (bool, error) { return gn.processPostal(ctx) }},
		{"admin1", func() (bool, error) { return gn.processAdmin1(ctx) }},
		{"admin2", func() (bool, error) { return gn.processAdmin2(ctx) }},
		{"timeZones", func() (bool, error) { return gn.processTimezones(ctx) }},
		{"alternateNames", func() (bool, error) { return gn.processAltNames(ctx) }},
	}

	var errs []error
	for _, f := range feeds {
		changed, err := f.run()
		if err != nil {
			gn.Logger.Error("geonames feed failed", zap.String("feed", f.name), zap.Error(err))
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
			continue
		}
		if changed {
			dumpsChanged = append(dumpsChanged, f.name)
		}
	}
	gn.StatusMetadata.DumpsChanged = dumpsChanged

	if err := gn.Store.SyncCountryCodeRemap(ctx); err != nil {
		gn.Logger.Error("failed to sync country_code_remap", zap.Error(err))
		errs = append(errs, err)
	}

	if len(dumpsChanged) == 0 {
		gn.Logger.Info("all geonames dumps unchanged, skipping lookup rebuild")
		gn.StatusMetadata.LastFetchTime = time.Now()
		if len(errs) > 0 {
			return errs[0]
		}
		return nil
	}

	if err := gn.Store.RebuildGeoNamesLookup(ctx); err != nil {
		gn.Logger.Error("failed to rebuild geonames_lookup", zap.Error(err))
		errs = append(errs, err)
	} else {
		gn.StatusMetadata.LookupRebuilt = true
	}

	gn.StatusMetadata.LastFetchTime = time.Now()
	gn.Logger.Info("geonames ingest finished",
		zap.Strings("changed", dumpsChanged),
		zap.Bool("lookup_rebuilt", gn.StatusMetadata.LookupRebuilt),
		zap.Duration("duration", time.Since(startTime)))

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (gn *GeoNames) ifChanged(ctx context.Context, url string, load func() error) (bool, error) {
	newMetadata, changed := opnet.HasFileChanged(gn.Store, &gn.HTTPClient, url)
	if !changed {
		gn.Logger.Info("geonames dump unchanged", zap.String("url", url))
		// !changed is only returned after a successful HEAD whose ETag
		// matched. Do not invent a row if HEAD never produced metadata.
		if newMetadata == nil {
			return false, nil
		}
		if err := gn.Store.TouchRemoteFileMetadata(ctx, url); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := load(); err != nil {
		return false, err
	}
	gn.Store.SaveResponseMetadata(newMetadata)
	return true, nil
}

func (gn *GeoNames) processCountryInfo(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesCountryInfoURL, func() error {
		startTime := time.Now()
		resp, err := gn.HTTPClient.Get(postgres.GeoNamesCountryInfoURL)
		if err != nil {
			return fmt.Errorf("download country info: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download country info: status %d", resp.StatusCode)
		}
		parsed, err := ReadCountryInfo(resp.Body)
		if err != nil {
			return err
		}
		items := make([]*postgres.CountryInfoItem, 0, len(parsed))
		for i := range parsed {
			p := parsed[i]
			items = append(items, &postgres.CountryInfoItem{
				ISO: p.ISO, ISO3: p.ISO3, ISONumeric: p.ISONumeric, FIPS: p.FIPS,
				Country: p.Country, Capital: p.Capital, Area: p.Area, Population: p.Population,
				Continent: p.Continent, TLD: p.TLD, CurrencyCode: p.CurrencyCode, CurrencyName: p.CurrencyName,
				Phone: p.Phone, PostalCodeFormat: p.PostalCodeFormat, PostalCodeRegex: p.PostalCodeRegex,
				Languages: p.Languages, GeonameID: p.GeonameID, Neighbours: p.Neighbours, EquivalentFIPS: p.EquivalentFIPS,
			})
		}
		if err := gn.Store.SaveCountryInfo(items); err != nil {
			return err
		}
		gn.Logger.Info("processed country info",
			zap.Int("rows", len(items)),
			zap.Duration("duration", time.Since(startTime)))
		return nil
	})
}

func (gn *GeoNames) processCities500(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesCities500URL, func() error {
		startTime := time.Now()
		body, cleanup, err := gn.openZipEntry(postgres.GeoNamesCities500URL, "cities500.txt")
		if err != nil {
			return err
		}
		defer cleanup()
		parsed, err := ReadCities500(body)
		if err != nil {
			return err
		}
		rows := make([][]any, 0, len(parsed))
		for _, c := range parsed {
			var alts any
			if len(c.AltNames) > 0 {
				alts = c.AltNames
			}
			rows = append(rows, []any{
				c.GeonameID, c.Name, oputils.NilIfEmpty(c.ASCIIName), c.Latitude, c.Longitude,
				oputils.NilIfEmpty(c.FeatureClass), oputils.NilIfEmpty(c.FeatureCode), c.CountryCode, oputils.NilIfEmpty(c.CC2),
				oputils.NilIfEmpty(c.Admin1Code), oputils.NilIfEmpty(c.Admin2Code), oputils.NilIfEmpty(c.Admin3Code), oputils.NilIfEmpty(c.Admin4Code),
				c.Population, c.Elevation, c.DEM, oputils.NilIfEmpty(c.Timezone), c.Modified,
				alts,
			})
		}
		n, err := gn.Store.ReplaceGeoNamesCities(ctx, rows)
		if err != nil {
			return err
		}
		gn.Logger.Info("processed cities500",
			zap.Int64("rows", n),
			zap.Duration("duration", time.Since(startTime)))
		return nil
	})
}

func (gn *GeoNames) processPostal(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesPostalURL, func() error {
		startTime := time.Now()
		body, cleanup, err := gn.openZipEntry(postgres.GeoNamesPostalURL, "allCountries.txt")
		if err != nil {
			return err
		}
		defer cleanup()
		src := &tsvCopySource{
			r: newTSVReader(body),
			parse: func(record []string) ([]any, bool) {
				p, ok := ParsePostalRecord(record)
				if !ok {
					return nil, false
				}
				return []any{
					p.CountryCode, p.PostalCode, p.PlaceName,
					oputils.NilIfEmpty(p.AdminName1), oputils.NilIfEmpty(p.AdminCode1),
					oputils.NilIfEmpty(p.AdminName2), oputils.NilIfEmpty(p.AdminCode2),
					oputils.NilIfEmpty(p.AdminName3), oputils.NilIfEmpty(p.AdminCode3),
					p.Latitude, p.Longitude, p.Accuracy,
				}, true
			},
		}
		n, err := gn.Store.ReplaceGeoNamesPostal(ctx, src)
		if err != nil {
			return err
		}
		gn.Logger.Info("processed postal dump",
			zap.Int64("rows", n),
			zap.Duration("duration", time.Since(startTime)))
		return nil
	})
}

func (gn *GeoNames) processAdmin1(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesAdmin1URL, func() error {
		resp, err := gn.getOK(postgres.GeoNamesAdmin1URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		parsed, err := ReadAdmin1(resp.Body)
		if err != nil {
			return err
		}
		rows := make([][]any, 0, len(parsed))
		for _, a := range parsed {
			rows = append(rows, []any{
				a.Code, a.CountryCode, a.Admin1Code, a.Name, oputils.NilIfEmpty(a.ASCIIName), a.GeonameID,
			})
		}
		n, err := gn.Store.ReplaceGeoNamesAdmin1(ctx, rows)
		if err != nil {
			return err
		}
		gn.Logger.Info("processed admin1 codes", zap.Int64("rows", n))
		return nil
	})
}

func (gn *GeoNames) processAdmin2(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesAdmin2URL, func() error {
		resp, err := gn.getOK(postgres.GeoNamesAdmin2URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		parsed, err := ReadAdmin2(resp.Body)
		if err != nil {
			return err
		}
		rows := make([][]any, 0, len(parsed))
		for _, a := range parsed {
			rows = append(rows, []any{
				a.Code, a.CountryCode, oputils.NilIfEmpty(a.Admin1Code), oputils.NilIfEmpty(a.Admin2Code),
				a.Name, oputils.NilIfEmpty(a.ASCIIName), a.GeonameID,
			})
		}
		n, err := gn.Store.ReplaceGeoNamesAdmin2(ctx, rows)
		if err != nil {
			return err
		}
		gn.Logger.Info("processed admin2 codes", zap.Int64("rows", n))
		return nil
	})
}

func (gn *GeoNames) processTimezones(ctx context.Context) (bool, error) {
	return gn.ifChanged(ctx, postgres.GeoNamesTimeZonesURL, func() error {
		resp, err := gn.getOK(postgres.GeoNamesTimeZonesURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		parsed, err := ReadTimezones(resp.Body)
		if err != nil {
			return err
		}
		rows := make([][]any, 0, len(parsed))
		for _, t := range parsed {
			rows = append(rows, []any{
				t.TimezoneID, oputils.NilIfEmpty(t.CountryCode), t.GMTOffset, t.DSTOffset, t.RawOffset,
			})
		}
		n, err := gn.Store.ReplaceGeoNamesTimezones(ctx, rows)
		if err != nil {
			return err
		}
		gn.Logger.Info("processed timezones", zap.Int64("rows", n))
		return nil
	})
}

func (gn *GeoNames) processAltNames(ctx context.Context) (bool, error) {
	sources := []struct {
		url   string
		inner string
	}{
		{postgres.GeoNamesAltNamesV2URL, "alternateNamesV2.txt"},
		{postgres.GeoNamesAltNamesURL, "alternateNames.txt"},
	}
	var lastErr error
	for i, src := range sources {
		newMetadata, changed := opnet.HasFileChanged(gn.Store, &gn.HTTPClient, src.url)
		if !changed {
			gn.Logger.Info("geonames dump unchanged", zap.String("url", src.url))
			if newMetadata == nil {
				return false, nil
			}
			if err := gn.Store.TouchRemoteFileMetadata(ctx, src.url); err != nil {
				return false, err
			}
			return false, nil
		}
		err := gn.loadAltNames(ctx, src.url, src.inner)
		if err != nil {
			lastErr = err
			gn.Logger.Warn("alternate names source failed",
				zap.String("url", src.url),
				zap.Error(err),
				zap.Bool("has_fallback", i+1 < len(sources)))
			continue
		}
		gn.Store.SaveResponseMetadata(newMetadata)
		return true, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no alternate names dump loaded")
	}
	return false, lastErr
}

func (gn *GeoNames) loadAltNames(ctx context.Context, url, inner string) error {
	startTime := time.Now()
	known, err := gn.Store.GeoNamesAltNameTargetIDs(ctx)
	if err != nil {
		return fmt.Errorf("load known geoname ids: %w", err)
	}
	gn.Logger.Info("filtering alternate names", zap.Int("known_geonameids", len(known)))

	body, cleanup, err := gn.openZipEntry(url, inner)
	if err != nil {
		return err
	}
	defer cleanup()

	src := &tsvCopySource{
		r: newTSVReader(body),
		parse: func(record []string) ([]any, bool) {
			n, ok := ParseAltNameRecord(record)
			if !ok {
				return nil, false
			}
			if !KeepAlternateName(n.GeonameID, n.ISOLanguage, known) {
				return nil, false
			}
			return []any{
				n.AltNameID, n.GeonameID, oputils.NilIfEmpty(n.ISOLanguage), n.AlternateName,
				n.IsPreferred, n.IsShort, n.IsColloquial, n.IsHistoric,
			}, true
		},
	}
	n, err := gn.Store.ReplaceGeoNamesAltNames(ctx, src)
	if err != nil {
		return err
	}
	gn.Logger.Info("processed alternate names",
		zap.String("url", url),
		zap.Int64("rows", n),
		zap.Duration("duration", time.Since(startTime)))
	return nil
}

func (gn *GeoNames) getOK(url string) (*http.Response, error) {
	resp, err := gn.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}
	return resp, nil
}

func (gn *GeoNames) openZipEntry(url, innerName string) (io.ReadCloser, func(), error) {
	resp, err := gn.HTTPClient.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	tempFile, err := os.CreateTemp("", "geonames-*.zip")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp zip: %w", err)
	}
	if _, err = io.Copy(tempFile, resp.Body); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return nil, nil, fmt.Errorf("write temp zip: %w", err)
	}
	if err = tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return nil, nil, err
	}

	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		os.Remove(tempFile.Name())
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	var file io.ReadCloser
	for _, f := range zipReader.File {
		base := f.Name
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if base == innerName {
			file, err = f.Open()
			if err != nil {
				zipReader.Close()
				os.Remove(tempFile.Name())
				return nil, nil, fmt.Errorf("open %s: %w", innerName, err)
			}
			break
		}
	}
	if file == nil {
		zipReader.Close()
		os.Remove(tempFile.Name())
		return nil, nil, fmt.Errorf("%s not found inside %s", innerName, url)
	}

	cleanup := func() {
		file.Close()
		zipReader.Close()
		os.Remove(tempFile.Name())
	}
	return file, cleanup, nil
}

// tsvCopySource streams parsed TSV rows into pgx.CopyFrom.
type tsvCopySource struct {
	r     *csv.Reader
	parse func([]string) ([]any, bool)
	row   []any
	err   error
}

func (s *tsvCopySource) Next() bool {
	for {
		record, err := s.r.Read()
		if err == io.EOF {
			return false
		}
		if err != nil {
			s.err = err
			return false
		}
		row, ok := s.parse(record)
		if !ok {
			continue
		}
		s.row = row
		return true
	}
}

func (s *tsvCopySource) Values() ([]any, error) { return s.row, nil }

func (s *tsvCopySource) Err() error { return s.err }

var _ pgx.CopyFromSource = (*tsvCopySource)(nil)
