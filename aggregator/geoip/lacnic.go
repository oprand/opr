package geoip

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/opnet"
	"github.com/oprand/opr/store/postgres"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c-robinson/iplib"
	"go.uber.org/zap"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/time/rate"
)

// Fetch and save IP geolocation info from https://ftp.lacnic.net/lacnic/dbase/
func (geo *GeoIpAggregator) FetchIpGeolocationFromLacnic(ctx context.Context) error {

	startTime := time.Now()

	const URL = "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.csv.gz"

	logger := geo.Logger.Named("geoip.lacnic")

	newMetadata, changed := opnet.HasFileChanged(geo.Store, geo.HTTPClient, URL)
	if !changed {
		logger.Info("geoip file not changed", zap.String("url", URL))
		return nil
	}

	logFileCharset(logger, newMetadata)

	var currRetries int
	var expBackOffDurations []time.Duration
	// total cumulative waiting time slighly above 24h
	for _, pwr := range []int{3, 4, 5, 6, 8, 10} {
		amt := time.Duration(2 ^ pwr + 2)
		expBackOffDurations = append(expBackOffDurations, amt*time.Minute)
	}
	maxRetries := len(expBackOffDurations)

	limiter := rate.NewLimiter(rate.Every(1*time.Minute), 1)

	var resp *http.Response

	// Space requests 1 min apart
	err := limiter.Wait(ctx)
	if err != nil {
		logger.Error("error while waiting for rate limiter", zap.Error(err))
		return err
	}

	for {

		currRetries += 1

		if currRetries >= maxRetries {
			logger.Warn("failed up to max retry count for url", zap.String("url", URL))
			return fmt.Errorf("max retries exceeded")
		}

		logger.Info("fetching geoip file", zap.String("url", URL), zap.Int("retry_count", currRetries))

		logger.Info("fetching lacnic geoip file", zap.String("url", URL))
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
		if reqErr != nil {
			return reqErr
		}
		resp, err = geo.HTTPClient.Do(req)

		if err != nil {
			logger.Error("error while fetching ip Geolocation file, skipping this one", zap.Error(err))
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			logger.Error("error while querying url, sleeping 5sec", zap.Error(err))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		} else if resp.StatusCode != 200 {
			logger.Warn("error while downloading file, status not 200, sleeping 5sec",
				zap.String("status_code", resp.Status),
				zap.Int64("size", resp.ContentLength),
			)
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		} else {
			logger.Info("received file without error",
				zap.String("status_code", resp.Status),
				zap.Int64("size", resp.ContentLength),
			)
			break
		}

	}

	// Read CSV from Bzip2 reader that read from HTTP body reader,
	// avoiding unnecessary copies.
	logger.Debug("start readers")

	geoIPItems := make([]*postgres.GeoIPItem, 0, 20_000)
	var totalCountSeen, totalCountSaved int

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		logger.Error("can't initialize gzip reader", zap.Error(err))
		return err
	}
	defer gzipReader.Close()

	csvReader := csv.NewReader(gzipReader)
	csvReader.Comma = '|'
	var errorCount int64

	for {

		if errorCount > 100 {
			logger.Warn("break from CSV read loop due to more than 100 errors not fixed",
				zap.Int64("errorCount", errorCount),
				zap.Int("rowCount", len(geoIPItems)))
			break
		}

		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, csv.ErrFieldCount) {
				// capture this error but do nothing, assume it's the right field cound, we check again below
			} else {
				logger.Debug("error on a line", zap.Error(err), zap.String("row", strings.Join(rec, ", ")))
				errorCount += 1
				continue
			}
		}

		// ignore asn for now
		if rec[2] == "asn" {
			logger.Debug("skipping non-ip row", zap.String("row", strings.Join(rec, ",")))
			continue
		}

		// ignore summary rows
		if rec[len(rec)-1] == "summary" {
			logger.Debug("skipping summary rows, skipping", zap.String("row", strings.Join(rec, ",")))
			continue
		}
		// ignore header
		if len(rec) == 7 {
			logger.Debug("skipping header row, skipping", zap.String("row", strings.Join(rec, ",")))
			continue
		}

		if len(rec) != 10 {
			logger.Warn("wrong number of fields in row (not 10), skipping", zap.Int("count", len(rec)), zap.String("row", strings.Join(rec, ", ")))
			errorCount += 1
			continue
		}

		ipStart := net.ParseIP(rec[3])
		hostCount, err := strconv.ParseInt(rec[4], 10, 64)
		if err != nil {
			logger.Error("error while parsing hostcount on rec[4], skipping", zap.Error(err))
			continue
		}
		ipEnd := iplib.IncrementIPBy(ipStart, uint32(hostCount))

		var ipnet string
		if iplib.DeltaIP(ipStart, ipEnd) == 1 {
			ipnet = fmt.Sprintf("%s/31", ipStart)
		} else {
			subnet, _, err := iplib.NewNetBetween(ipStart, ipEnd)
			if err != nil {
				logger.Error("can't find submask", zap.Error(err))
			}
			ipnet = subnet.String()
		}

		_, inet, err := net.ParseCIDR(ipnet)
		if err != nil {
			logger.Error("error while parsing CIDR, skipping", zap.Error(err))
			continue
		}

		// Parse city
		city, _ := charmap.ISO8859_1.NewDecoder().String(rec[8])
		if strings.ToLower(city) == "unknown" || strings.ToLower(city) == "no data" {
			city = ""
		}

		metaAddedAt := time.Now()
		source := LACNIC_DB_CSV
		countryCode := rec[1]
		var country string

		if countryCode != "" {
			countryCode = strings.ToUpper(countryCode)
			countryFound, ok := opconst.CountryCode[countryCode]
			if ok {
				country = countryFound
			}
		}

		geoIPItems = append(geoIPItems, &postgres.GeoIPItem{
			Netblock:    inet.String(),
			City:        &city,
			CountryCode: &countryCode,
			Country:     &country,
			MetaAddedAt: &metaAddedAt,
			Source:      &source,
		})

		totalCountSeen += 1

		if len(geoIPItems) > 20_000 {

			err := geo.Store.SaveGeoIPItem(geoIPItems)
			if err != nil {
				logger.Error("failed to save batch of 1000 geoip rows", zap.Error(err))
			} else {
				totalCountSaved += len(geoIPItems)
				geoIPItems = make([]*postgres.GeoIPItem, 0, 20_000)
			}
		}

	}

	if len(geoIPItems) > 0 {

		err := geo.Store.SaveGeoIPItem(geoIPItems)
		if err != nil {
			logger.Error("failed to save last batch of geoip rows", zap.Error(err))
		} else {
			totalCountSaved += len(geoIPItems)
		}

	}

	elapsed := time.Since(startTime)

	msg := fmt.Sprintf("seen %d rows in response, saved %d rows in database", totalCountSeen, totalCountSaved)
	logger.Info(msg)
	msg = fmt.Sprintf("fetched and saved geoip data in %s", elapsed.String())
	logger.Info(msg)

	// Save response metadata, so that next time we can first check if
	// file changed without downloading/straining the serve.
	// Do it now that we know we did save the new data successfully
	geo.Store.SaveResponseMetadata(newMetadata)

	return nil

}

// logFileCharset logs HasFileChanged metadata without dereferencing a nil
// charset. LACNIC CSV HEAD is application/x-gzip with no charset; HEAD failure
// returns (nil, true). Both must download anyway. City rows already decode as
// ISO-8859-1 regardless of the header.
func logFileCharset(logger *zap.Logger, meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		logger.Warn("unable to get new metadata for lacnic geoip file, downloading anyway")
		return
	}
	logger.Debug("file charset", zap.Stringp("charset", meta.Charset))
}
