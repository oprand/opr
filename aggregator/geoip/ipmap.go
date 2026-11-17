package geoip

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/store/postgres"

	"github.com/dsnet/compress/bzip2"
	"go.uber.org/zap"
)

// IPMAPDumpURL is the daily RIPE IPmap full dump on ftp.ripe.net.
// The file is bzip2 despite having no .bz2 suffix (see README.txt in that
// directory). Historical dated files are geolocations_YYYY-MM-DD.csv.bz2.
//
// Uniqueness is (netblock, source_url); the dump URL is the ingest key so a
// re-ingest replaces that source's rows via ReplaceGeoIPBySourceURL.
// Single source of truth is postgres.IPMAPDumpURL (status board + ingest).
const IPMAPDumpURL = postgres.IPMAPDumpURL

// IPMAPMaxCompressedBytes / IPMAPMaxUncompressedBytes cap the HTTP body and
// the decompressed CSV. Exceeding either is fatal (ErrIPMAPTooLarge), not a
// silent truncate that would look like a successful partial dump. Today's
// dump is ~3.4MB compressed / ~49MB uncompressed / ~410k rows; 64MiB / 512MiB
// is generous headroom.
const (
	IPMAPMaxCompressedBytes   = 64 << 20
	IPMAPMaxUncompressedBytes = 512 << 20
)

// IPMAPReplaceFloor is the minimum new/existing row-count ratio required
// before ReplaceGeoIPBySourceURL. A truncated dump that still yields some
// rows must not wipe a previous ingest. Empty parse is ErrIPMAPEmpty and
// skips replace before this check.
const IPMAPReplaceFloor = 0.50

// ipmapRecordFields is the official IPmap dump column count (no header in
// geolocations-latest). Off-shape rows are skipped; if they exceed
// ipmapMaxOffShapeFraction of non-comment data rows the parse fails so a
// shifted schema is not ingested silently.
const ipmapRecordFields = 10

// ipmapMaxOffShapeFraction fails ParseIPMAP when more than this share of
// non-comment, non-header rows have a field count other than ipmapRecordFields.
const ipmapMaxOffShapeFraction = 0.10

// ErrIPMAPUnparseable is returned when the body is HTML or not an IPmap CSV.
// Callers must not ReplaceGeoIPBySourceURL.
var ErrIPMAPUnparseable = errors.New("ipmap: unparseable body")

// ErrIPMAPEmpty is returned when the dump parses but contains no valid
// prefixes. Callers must not ReplaceGeoIPBySourceURL (a previous ingest is
// kept). The CLI treats this as a distinct, non-catastrophic outcome.
var ErrIPMAPEmpty = errors.New("ipmap: no valid prefixes in dump")

// ErrIPMAPReplaceFloor is returned when a non-empty parse is below
// IPMAPReplaceFloor of the existing row count for that source_url.
// Callers must not ReplaceGeoIPBySourceURL.
var ErrIPMAPReplaceFloor = errors.New("ipmap: new row count below replace floor")

// ErrIPMAPTooLarge is returned when the compressed or decompressed dump
// exceeds IPMAPMaxCompressedBytes / IPMAPMaxUncompressedBytes.
var ErrIPMAPTooLarge = errors.New("ipmap: dump exceeds size cap")

var ipmapHTMLPrefixes = []string{
	"<!doctype html",
	"<html",
	"<head",
	"<body",
	"<meta",
}

// ipmapStore is the test seam for FetchIPMAP (see memIPMAPStore in tests).
type ipmapStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*postgres.GeoIPItem) error
	CountGeoIPBySourceURL(ctx context.Context, sourceURL string) (int64, error)
}

var _ ipmapStore = (*postgres.Store)(nil)

func (geo *GeoIpAggregator) ipmapDB() ipmapStore {
	if geo.ipmap != nil {
		return geo.ipmap
	}
	return geo.Store
}

func (geo *GeoIpAggregator) ipmapHTTP() *http.Client {
	if geo.HTTPClient != nil {
		return geo.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Minute}
}

func (geo *GeoIpAggregator) ipmapLog() *zap.Logger {
	if geo.Logger != nil {
		return geo.Logger.Named("geoip.ipmap")
	}
	return zap.NewNop()
}

// FetchIPMAP downloads the RIPE IPmap full dump into geoip with
// source=RIPE_IPMAP. HasFileChanged (ETag) skips an unchanged dump unless
// force is set. dumpURL defaults to IPMAPDumpURL. A successful parse replaces
// every prior row for that URL so stale prefixes drop.
func (geo *GeoIpAggregator) FetchIPMAP(ctx context.Context, force bool, dumpURL string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if dumpURL == "" {
		dumpURL = IPMAPDumpURL
	}

	startTime := time.Now()
	logger := geo.ipmapLog()
	st := geo.ipmapDB()
	client := geo.ipmapHTTP()

	var newMetadata *postgres.ResponseMetadataItem
	if !force {
		var changed bool
		newMetadata, changed = ipmapFileChanged(ctx, st, client, dumpURL)
		if !changed {
			logger.Info("geoip file not changed", zap.String("url", dumpURL))
			return nil
		}
		if newMetadata == nil {
			logger.Warn("unable to get new metadata for ipmap dump, downloading anyway")
		}
	}

	logger.Info("fetching geoip file", zap.String("url", dumpURL))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dumpURL, nil)
	if err != nil {
		return fmt.Errorf("ipmap: fetch %s: %w", dumpURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ipmap: fetch %s: %w", dumpURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ipmap: fetch %s: status %s", dumpURL, resp.Status)
	}
	if newMetadata == nil {
		newMetadata = ipmapMetadataFromHeader(dumpURL, resp.Header)
	}

	items, err := parseIPMAPBody(resp.Body, dumpURL)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		// The dump has been flaky; do not wipe a previous successful ingest.
		return ErrIPMAPEmpty
	}

	existing, err := st.CountGeoIPBySourceURL(ctx, dumpURL)
	if err != nil {
		return fmt.Errorf("ipmap: count geoip: %w", err)
	}
	if existing > 0 && float64(len(items)) < IPMAPReplaceFloor*float64(existing) {
		return fmt.Errorf("%w: %d new vs %d existing (floor %.0f%%)",
			ErrIPMAPReplaceFloor, len(items), existing, IPMAPReplaceFloor*100)
	}

	if err := st.ReplaceGeoIPBySourceURL(ctx, dumpURL, items); err != nil {
		return fmt.Errorf("ipmap: replace geoip: %w", err)
	}

	st.SaveResponseMetadata(newMetadata)

	logger.Info("fetched and saved ipmap data",
		zap.Int("rows", len(items)),
		zap.String("duration", time.Since(startTime).String()),
	)
	return nil
}

func ipmapFileChanged(ctx context.Context, st ipmapStore, client *http.Client, url string) (*postgres.ResponseMetadataItem, bool) {
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

func ipmapMetadataFromHeader(url string, h http.Header) *postgres.ResponseMetadataItem {
	etag := h.Get("Etag")
	contentType := h.Get("Content-Type")
	contentLength, _ := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	lastModified, _ := time.Parse(http.TimeFormat, h.Get("Last-Modified"))
	now := time.Now()
	return &postgres.ResponseMetadataItem{
		Etag:          &etag,
		Url:           url,
		ContentType:   &contentType,
		ContentLength: &contentLength,
		LastModified:  &lastModified,
		MetaAddedAt:   &now,
	}
}

func parseIPMAPBody(r io.Reader, sourceURL string) ([]*postgres.GeoIPItem, error) {
	r = newCapReader(r, IPMAPMaxCompressedBytes, fmt.Errorf("%w: compressed > %d bytes", ErrIPMAPTooLarge, IPMAPMaxCompressedBytes))
	dec, err := openIPMAPReader(r)
	if err != nil {
		return nil, err
	}
	closer, hasCloser := dec.(io.Closer)

	dec = newCapReader(dec, IPMAPMaxUncompressedBytes, fmt.Errorf("%w: uncompressed > %d bytes", ErrIPMAPTooLarge, IPMAPMaxUncompressedBytes))
	br := bufio.NewReader(dec)
	peek, err := br.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		if hasCloser {
			_ = closer.Close()
		}
		return nil, err
	}
	if ipmapLooksLikeHTML(string(peek)) {
		if hasCloser {
			_ = closer.Close()
		}
		return nil, ErrIPMAPUnparseable
	}
	items, err := ParseIPMAP(br, sourceURL)
	var closeErr error
	if hasCloser {
		closeErr = closer.Close()
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return items, nil
}

func openIPMAPReader(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(3)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	switch {
	case len(magic) >= 3 && string(magic[:3]) == "BZh":
		return bzip2.NewReader(br, &bzip2.ReaderConfig{})
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(br)
	default:
		return br, nil
	}
}

func ipmapLooksLikeHTML(s string) bool {
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	t = strings.ToLower(t)
	for _, p := range ipmapHTMLPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// capReader returns Err (over) if more than limit bytes are read. Hitting
// the cap exactly is allowed; one extra byte is a fatal overflow, not EOF.
type capReader struct {
	r          io.Reader
	remain     int64
	over       error
	overflowed bool
}

func newCapReader(r io.Reader, limit int64, over error) *capReader {
	return &capReader{r: r, remain: limit, over: over}
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.overflowed {
		return 0, c.over
	}
	if c.remain <= 0 {
		var buf [1]byte
		n, err := c.r.Read(buf[:])
		if n > 0 {
			c.overflowed = true
			return 0, c.over
		}
		if err == nil {
			return 0, io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.r.Read(p)
	c.remain -= int64(n)
	return n, err
}

// ParseIPMAP reads a RIPE IPmap dump CSV.
//
// Record shape (no header in geolocations-latest; a header row is skipped):
//
//	prefix, geolocation_id, city_name, state_name, country_name,
//	country_code_alpha2, country_code_alpha3, latitude, longitude, score
//
// Official docs list the first column as "ip"; the dump publishes host
// prefixes (typically /32). Invalid CIDRs and CIDRs with host bits set are
// skipped. A bare IP is stored as /32 or /128. Non-finite or out-of-range
// coordinates skip the row. Rows with != 10 fields are skipped; too many
// off-shape rows fail the parse (ipmapMaxOffShapeFraction).
// source=RIPE_IPMAP, source_url is the dump URL.
func ParseIPMAP(r io.Reader, sourceURL string) ([]*postgres.GeoIPItem, error) {
	csvReader := csv.NewReader(r)
	csvReader.FieldsPerRecord = -1
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true
	csvReader.ReuseRecord = true

	source := RIPE_IPMAP
	url := sourceURL
	now := time.Now()
	out := make([]*postgres.GeoIPItem, 0, 64)
	var nData, nOffShape int

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ipmap: csv: %w", err)
		}
		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if ipmapHeaderRow(record) {
			continue
		}

		nData++
		if len(record) != ipmapRecordFields {
			nOffShape++
			continue
		}

		netblock, ok := parseIPMAPNetblock(raw)
		if !ok {
			continue
		}

		field := func(i int) string {
			return strings.TrimSpace(record[i])
		}

		lat, ok := parseCoord(field(7), -90, 90)
		if !ok {
			continue
		}
		lon, ok := parseCoord(field(8), -180, 180)
		if !ok {
			continue
		}

		countryCode := strings.ToUpper(field(5))
		meta := now
		item := &postgres.GeoIPItem{
			Netblock:    netblock,
			LocationID:  oputils.NilIfEmpty(field(1)),
			City:        oputils.NilIfEmpty(field(2)),
			Region:      oputils.NilIfEmpty(field(3)),
			Country:     oputils.NilIfEmpty(field(4)),
			CountryCode: oputils.NilIfEmpty(countryCode),
			Latitude:    lat,
			Longitude:   lon,
			Score:       parseFloatPtr(field(9)),
			Source:      &source,
			SourceURL:   &url,
			MetaAddedAt: &meta,
		}
		out = append(out, item)
	}
	if nData > 0 && float64(nOffShape) > ipmapMaxOffShapeFraction*float64(nData) {
		return nil, fmt.Errorf("%w: %d/%d rows have != %d fields", ErrIPMAPUnparseable, nOffShape, nData, ipmapRecordFields)
	}
	return out, nil
}

func ipmapHeaderRow(record []string) bool {
	first := strings.ToLower(strings.TrimSpace(record[0]))
	switch first {
	case "ip", "prefix", "netblock", "cidr":
		return true
	}
	if len(record) > 1 && strings.EqualFold(strings.TrimSpace(record[1]), "geolocation_id") {
		return true
	}
	return false
}

func parseIPMAPNetblock(raw string) (string, bool) {
	if ip, inet, err := net.ParseCIDR(raw); err == nil && inet != nil {
		if !ip.Equal(inet.IP) {
			// Host bits set (e.g. 192.0.2.5/24). Do not widen to the network.
			return "", false
		}
		return inet.String(), true
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", false
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	_, inet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
	if err != nil || inet == nil {
		return "", false
	}
	return inet.String(), true
}

func parseCoord(s string, min, max float64) (*float64, bool) {
	if s == "" {
		return nil, true
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !isFinite(v) || v < min || v > max {
		return nil, false
	}
	return &v, true
}

func parseFloatPtr(s string) *float64 {
	if s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !isFinite(v) {
		return nil
	}
	return &v
}

func isFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
