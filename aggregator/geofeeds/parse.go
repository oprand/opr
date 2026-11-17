package geofeeds

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/store/postgres"

	"golang.org/x/text/encoding/charmap"
)

const SourceGEOFEED = "GEOFEED"

// ErrUnparseable is returned when the body is HTML or not a geofeed CSV.
// Callers must not ReplaceGeoIPBySourceURL.
var ErrUnparseable = errors.New("geofeed: unparseable body")

var htmlPrefixes = []string{
	"<!doctype html",
	"<html",
	"<head",
	"<body",
	"<meta",
}

func looksLikeHTML(s string) bool {
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	t = strings.ToLower(t)
	for _, p := range htmlPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func contentTypeLooksLikeHTML(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	return ct == "text/html" || ct == "application/xhtml+xml"
}

func charsetFromContentType(ct string) string {
	parts := strings.Split(ct, ";")
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "charset=") {
			cs := strings.TrimSpace(p[len("charset="):])
			cs = strings.Trim(cs, `"'`)
			return cs
		}
	}
	return ""
}

// ParseRFC8805 reads an RFC 8805 / RFC 9632 self-published geofeed CSV.
// Comments (#) and empty lines are skipped. Short rows are valid; FieldsPerRecord
// is not fixed at 5. Invalid CIDRs are skipped. source=GEOFEED.
func ParseRFC8805(r io.Reader, sourceURL, charset string) ([]*postgres.GeoIPItem, error) {
	br := bufio.NewReader(r)
	if bom, err := br.Peek(3); err == nil && bytes.Equal(bom, []byte{0xEF, 0xBB, 0xBF}) {
		_, _ = br.Discard(3)
	}

	csvReader := csv.NewReader(br)
	csvReader.FieldsPerRecord = -1
	csvReader.LazyQuotes = true
	csvReader.TrimLeadingSpace = true
	csvReader.ReuseRecord = true

	source := SourceGEOFEED
	url := sourceURL
	now := time.Now()
	out := make([]*postgres.GeoIPItem, 0, 64)
	latin1 := strings.EqualFold(charset, "ISO-8859-1") || strings.EqualFold(charset, "latin1")

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A single malformed line is not a failed parse; keep reading.
			continue
		}
		if len(record) == 0 {
			continue
		}
		netblock := strings.TrimSpace(record[0])
		if netblock == "" || strings.HasPrefix(netblock, "#") {
			continue
		}
		_, inet, err := net.ParseCIDR(netblock)
		if err != nil || inet == nil {
			continue
		}

		field := func(i int) string {
			if i >= len(record) {
				return ""
			}
			s := strings.TrimSpace(record[i])
			if latin1 {
				if dec, decErr := charmap.ISO8859_1.NewDecoder().String(s); decErr == nil {
					s = dec
				}
			}
			return s
		}

		country := field(1)
		region := field(2)
		city := field(3)
		zip := field(4)
		meta := now
		item := &postgres.GeoIPItem{
			Netblock:    inet.String(),
			CountryCode: oputils.NilIfEmpty(country),
			RegionCode:  oputils.NilIfEmpty(region),
			City:        oputils.NilIfEmpty(city),
			ZipCode:     oputils.NilIfEmpty(zip),
			Source:      &source,
			SourceURL:   &url,
			MetaAddedAt: &meta,
		}
		out = append(out, item)
	}
	return out, nil
}

func parseGeofeedBody(body io.Reader, sourceURL, contentType string) ([]*postgres.GeoIPItem, error) {
	if contentTypeLooksLikeHTML(contentType) {
		return nil, ErrUnparseable
	}
	buf := make([]byte, 512)
	n, err := io.ReadFull(body, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	peek := buf[:n]
	if looksLikeHTML(string(peek)) {
		return nil, ErrUnparseable
	}
	return ParseRFC8805(io.MultiReader(bytes.NewReader(peek), body), sourceURL, charsetFromContentType(contentType))
}
