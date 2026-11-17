package geoip

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

// Anycast dump URLs are remote_files_metadata keys. Single source of truth is
// postgres.AnycastV4DumpURL / postgres.AnycastV6DumpURL (status board + ingest).
const (
	AnycastV4DumpURL = postgres.AnycastV4DumpURL
	AnycastV6DumpURL = postgres.AnycastV6DumpURL
)

// AnycastDumpURLs is the ingest order for FetchAnycast.
var AnycastDumpURLs = postgres.AnycastDumpURLs

// AnycastMaxBytes caps the HTTP body. Today's dumps are ~4k lines; 4MiB is
// generous headroom. Exceeding the cap is fatal (ErrAnycastTooLarge), not a
// silent truncate that would look like a successful partial dump.
const AnycastMaxBytes = 4 << 20

// AnycastReplaceFloor is the minimum new/existing row-count ratio required
// before ReplaceAnycastBySourceURL. A truncated dump that still yields some
// rows must not wipe a previous ingest. Empty parse is ErrAnycastEmpty and
// skips replace before this check.
const AnycastReplaceFloor = 0.50

// ErrAnycastEmpty is returned when the dump parses but contains no valid
// prefixes. Callers must not ReplaceAnycastBySourceURL (a previous ingest is
// kept). The CLI treats this as a distinct, non-catastrophic outcome.
var ErrAnycastEmpty = errors.New("anycast: no valid prefixes in dump")

// ErrAnycastReplaceFloor is returned when a non-empty parse is below
// AnycastReplaceFloor of the existing row count for that source_url.
// Callers must not ReplaceAnycastBySourceURL.
var ErrAnycastReplaceFloor = errors.New("anycast: new row count below replace floor")

// ErrAnycastTooLarge is returned when the CSV exceeds AnycastMaxBytes.
var ErrAnycastTooLarge = errors.New("anycast: dump exceeds size cap")

// anycastStore is the test seam for FetchAnycast (see memAnycastStore in tests).
type anycastStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	ReplaceAnycastBySourceURL(ctx context.Context, sourceURL string, items []*postgres.AnycastPrefix) error
	CountAnycastBySourceURL(ctx context.Context, sourceURL string) (int64, error)
}

var _ anycastStore = (*postgres.Store)(nil)

func (geo *GeoIpAggregator) anycastDB() anycastStore {
	if geo.anycast != nil {
		return geo.anycast
	}
	return geo.Store
}

func (geo *GeoIpAggregator) anycastHTTP() *http.Client {
	if geo.HTTPClient != nil {
		return geo.HTTPClient
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (geo *GeoIpAggregator) anycastLog() *zap.Logger {
	if geo.Logger != nil {
		return geo.Logger.Named("geoip.anycast")
	}
	return zap.NewNop()
}

// FetchAnycast downloads the bgptools anycatch v4 and v6 prefix CSVs into
// anycast_prefix. Per URL, anycastFileChanged (ETag) skips an unchanged dump
// unless force is set. A successful parse replaces every prior row for that
// URL so stale prefixes drop.
func (geo *GeoIpAggregator) FetchAnycast(ctx context.Context, force bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return geo.fetchAnycastURLs(ctx, force, AnycastDumpURLs)
}

func (geo *GeoIpAggregator) fetchAnycastURLs(ctx context.Context, force bool, urls []string) error {
	var errs []error
	for _, url := range urls {
		err := geo.fetchAnycastURL(ctx, force, url)
		if errors.Is(err, ErrAnycastEmpty) {
			geo.anycastLog().Warn("anycast dump had no valid prefixes; previous rows kept",
				zap.String("url", url),
				zap.Error(err),
			)
			continue
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (geo *GeoIpAggregator) fetchAnycastURL(ctx context.Context, force bool, dumpURL string) error {
	startTime := time.Now()
	logger := geo.anycastLog()
	st := geo.anycastDB()
	client := geo.anycastHTTP()

	var newMetadata *postgres.ResponseMetadataItem
	if !force {
		var changed bool
		newMetadata, changed = anycastFileChanged(ctx, st, client, dumpURL)
		if !changed {
			logger.Info("geoip file not changed", zap.String("url", dumpURL))
			return nil
		}
		if newMetadata == nil {
			logger.Warn("unable to get new metadata for anycast dump, downloading anyway")
		}
	}

	logger.Info("fetching geoip file", zap.String("url", dumpURL))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dumpURL, nil)
	if err != nil {
		return fmt.Errorf("anycast: fetch %s: %w", dumpURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("anycast: fetch %s: %w", dumpURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("anycast: fetch %s: status %s", dumpURL, resp.Status)
	}
	if newMetadata == nil {
		newMetadata = ipmapMetadataFromHeader(dumpURL, resp.Header)
	}

	items, err := parseAnycastBody(resp.Body, dumpURL)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		// Do not wipe a previous successful ingest.
		return fmt.Errorf("%w: %s", ErrAnycastEmpty, dumpURL)
	}

	existing, err := st.CountAnycastBySourceURL(ctx, dumpURL)
	if err != nil {
		return fmt.Errorf("anycast: count: %w", err)
	}
	if existing > 0 && float64(len(items)) < AnycastReplaceFloor*float64(existing) {
		return fmt.Errorf("%w: %d new vs %d existing (floor %.0f%%) url %s",
			ErrAnycastReplaceFloor, len(items), existing, AnycastReplaceFloor*100, dumpURL)
	}

	if err := st.ReplaceAnycastBySourceURL(ctx, dumpURL, items); err != nil {
		return fmt.Errorf("anycast: replace: %w", err)
	}

	st.SaveResponseMetadata(newMetadata)

	logger.Info("fetched and saved anycast data",
		zap.Int("rows", len(items)),
		zap.String("url", dumpURL),
		zap.String("duration", time.Since(startTime).String()),
	)
	return nil
}

// anycastFileChanged is the only ETag path, in tests and in production: st is
// anycastDB(), so a nil test seam simply means the live Store. Unlike
// opnet.HasFileChanged it carries ctx into the HEAD request.
func anycastFileChanged(ctx context.Context, st anycastStore, client *http.Client, url string) (*postgres.ResponseMetadataItem, bool) {
	prev := st.GetResponseMetadata(url)
	if prev == nil || prev.Url == "" {
		now := time.Now()
		return &postgres.ResponseMetadataItem{
			Url:         url,
			MetaAddedAt: &now,
		}, true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, true
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil, true
	}
	defer resp.Body.Close()

	newMetadata := ipmapMetadataFromHeader(url, resp.Header)
	if prev.Etag != nil && newMetadata.Etag != nil && *prev.Etag == *newMetadata.Etag {
		return newMetadata, false
	}
	return newMetadata, true
}

func parseAnycastBody(r io.Reader, sourceURL string) ([]*postgres.AnycastPrefix, error) {
	r = newCapReader(r, AnycastMaxBytes, fmt.Errorf("%w: > %d bytes", ErrAnycastTooLarge, AnycastMaxBytes))
	return ParseAnycast(r, sourceURL)
}

// ParseAnycast reads a bgptools anycatch CSV: no header, prefix,example_host
// (e.g. 1.1.1.0/24,1.1.1.0). Invalid CIDRs and CIDRs with host bits set are
// skipped (do not widen), same as IPmap. An invalid example_host is stored as
// NULL; the prefix is kept.
func ParseAnycast(r io.Reader, sourceURL string) ([]*postgres.AnycastPrefix, error) {
	csvReader := csv.NewReader(r)
	csvReader.FieldsPerRecord = -1
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true
	csvReader.ReuseRecord = true

	now := time.Now()
	out := make([]*postgres.AnycastPrefix, 0, 64)

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("anycast: csv: %w", err)
		}
		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		netblock, ok := parseAnycastNetblock(raw)
		if !ok {
			continue
		}

		var host *string
		if len(record) > 1 {
			if h := parseAnycastHost(record[1]); h != "" {
				host = &h
			}
		}

		meta := now
		out = append(out, &postgres.AnycastPrefix{
			Netblock:    netblock,
			ExampleHost: host,
			SourceURL:   sourceURL,
			MetaAddedAt: &meta,
		})
	}
	return out, nil
}

func parseAnycastHost(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func parseAnycastNetblock(raw string) (string, bool) {
	ip, inet, err := net.ParseCIDR(raw)
	if err != nil || inet == nil {
		return "", false
	}
	if !ip.Equal(inet.IP) {
		// Host bits set (e.g. 192.0.2.5/24). Do not widen to the network.
		return "", false
	}
	return inet.String(), true
}
