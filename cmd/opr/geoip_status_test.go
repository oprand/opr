package main

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/store/postgres"
)

func TestGeoIPStaleAfterMatchesFeedRefresh(t *testing.T) {
	t.Parallel()
	if postgres.DefaultGeoIPStaleAfter != geofeeds.DefaultRefreshOlderThan {
		t.Fatalf("DefaultGeoIPStaleAfter = %s, DefaultRefreshOlderThan = %s", postgres.DefaultGeoIPStaleAfter, geofeeds.DefaultRefreshOlderThan)
	}
}

func sampleGeoIPStatusSnapshot(now time.Time) postgres.GeoIPStatusSnapshot {
	lastFetch := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	lastChecked := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	lastWhois := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	lacnicSeen := time.Date(2026, 8, 1, 4, 0, 0, 0, time.UTC)
	lacnicAdded := time.Date(2026, 8, 1, 4, 10, 0, 0, time.UTC)

	return postgres.GeoIPStatusSnapshot{
		GeneratedAt:      now,
		StaleAfter:       (168 * time.Hour).String(),
		RefreshOlderThan: (168 * time.Hour).String(),
		Catalog: postgres.GeofeedCatalogStatus{
			URLs:            1204,
			Fetched:         1192,
			NeverFetched:    12,
			Due:             40,
			Quarantined:     3,
			Invalid:         5,
			LastFetchedAt:   &lastFetch,
			LastCheckedAt:   &lastChecked,
			LastSeenInWhois: &lastWhois,
			Never:           false,
			Stale:           true,
		},
		GeoIP: []postgres.GeoIPSourceCount{
			{Source: postgres.GeoIPStatusSourceGEOFEED, Rows: 0, DistinctURLs: 0, Missing: true},
			{Source: postgres.GeoIPStatusSourceLACNIC, Rows: 12000, DistinctURLs: 0, NewestAddedAt: &lacnicAdded},
			{Source: postgres.GeoIPStatusSourceIPMAP},
		},
		Lacnic: postgres.LacnicCSVStatus{
			URL:           postgres.LacnicCSVURL,
			LastSeen:      &lacnicSeen,
			Rows:          12000,
			NewestAddedAt: &lacnicAdded,
			Stale:         true,
		},
		IPMap: postgres.IPMAPDumpStatus{
			URL:   postgres.IPMAPDumpURL,
			Never: true,
		},
		AnycastV4: postgres.AnycastDumpStatus{
			URL:   postgres.AnycastV4DumpURL,
			Never: true,
		},
		AnycastV6: postgres.AnycastDumpStatus{
			URL:   postgres.AnycastV6DumpURL,
			Never: true,
		},
	}
}

const geoipStatusBoardGolden = `GEOIP   2026-09-08 14:18 UTC

CATALOG
urls        1204   fetched 1192   never 12
due         40   quarantine 3   invalid 5
last fetch  2026-09-01 12:00   checked 2026-09-08 08:00   whois 2026-09-08 06:00
            STALE   DUE   QUARANTINE

GEOIP
                rows  urls  newest
GEOFEED            0     0  NEVER             MISSING
LACNIC_DB_CSV  12000     0  2026-08-01 04:10
RIPE_IPMAP         0     0  NEVER

LACNIC      2026-08-01 04:00   12000 rows
            STALE

IPMAP       NEVER           

ANYCAST V4  NEVER           

ANYCAST V6  NEVER           
`

func TestFormatGeoIPStatusGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoIPStatus(sampleGeoIPStatusSnapshot(now), false)
	if got != geoipStatusBoardGolden {
		t.Fatalf("human board mismatch\nGOT:\n%s\nWANT:\n%s", got, geoipStatusBoardGolden)
	}
}

func TestFormatGeoIPStatusNoANSIWhenColorOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoIPStatus(sampleGeoIPStatusSnapshot(now), false)
	if strings.Contains(got, "\033[") {
		t.Fatal("color-off output must not contain ANSI")
	}
}

func TestFormatGeoIPStatusFlags(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoIPStatus(sampleGeoIPStatusSnapshot(now), false)
	for _, word := range []string{"STALE", "DUE", "QUARANTINE", "MISSING", "NEVER"} {
		if !strings.Contains(got, word) {
			t.Fatalf("missing %q in board:\n%s", word, got)
		}
	}
	if strings.Contains(got, "\u2500") || strings.Contains(got, "+--") {
		t.Fatal("board must not draw box art")
	}
}

func TestFormatGeoIPStatusNumbersRightAligned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoIPStatus(sampleGeoIPStatusSnapshot(now), false)
	var header, geofeed, lacnic string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "rows") && strings.Contains(line, "urls") && strings.Contains(line, "newest") {
			header = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "GEOFEED") {
			geofeed = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "LACNIC_DB_CSV") {
			lacnic = line
		}
	}
	if header == "" || geofeed == "" || lacnic == "" {
		t.Fatalf("geoip table lines missing\n%s", got)
	}
	rowsAt := strings.Index(header, "rows")
	urlsAt := strings.Index(header, "urls")
	if rowsAt < 0 || urlsAt < 0 {
		t.Fatalf("headers: %q", header)
	}
	if lacnic[rowsAt+len("rows")-1] != '0' {
		t.Fatalf("12000 not right-aligned under rows\n%s\n%s", header, lacnic)
	}
	if geofeed[urlsAt+len("urls")-1] != '0' {
		t.Fatalf("GEOFEED urls not right-aligned\n%s\n%s", header, geofeed)
	}
}

func TestFormatEmptyCatalogNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	s := sampleGeoIPStatusSnapshot(now)
	s.Catalog = postgres.GeofeedCatalogStatus{Never: true}
	s.GeoIP = []postgres.GeoIPSourceCount{
		{Source: postgres.GeoIPStatusSourceGEOFEED},
		{Source: postgres.GeoIPStatusSourceLACNIC},
		{Source: postgres.GeoIPStatusSourceIPMAP},
	}
	s.Lacnic = postgres.LacnicCSVStatus{URL: postgres.LacnicCSVURL, Never: true}
	s.IPMap = postgres.IPMAPDumpStatus{URL: postgres.IPMAPDumpURL, Never: true}
	s.AnycastV4 = postgres.AnycastDumpStatus{URL: postgres.AnycastV4DumpURL, Never: true}
	s.AnycastV6 = postgres.AnycastDumpStatus{URL: postgres.AnycastV6DumpURL, Never: true}
	got := formatGeoIPStatus(s, false)
	if !strings.Contains(got, "NEVER") {
		t.Fatalf("empty catalog/LACNIC:\n%s", got)
	}
	if strings.Contains(got, "STALE") {
		t.Fatal("empty catalog must not also flag STALE")
	}
	if strings.Contains(got, "MISSING") {
		t.Fatal("empty catalog with 0 GEOFEED rows is not MISSING")
	}
	if catalogFlags := catalogFlagsLine(got); catalogFlags != "NEVER" {
		t.Fatalf("catalog flags = %q, want NEVER\n%s", catalogFlags, got)
	}
	if !strings.Contains(got, "LACNIC      NEVER") {
		t.Fatalf("LACNIC NEVER line missing:\n%s", got)
	}
	if !strings.Contains(got, "IPMAP       NEVER") {
		t.Fatalf("IPMAP NEVER line missing:\n%s", got)
	}
	if !strings.Contains(got, "ANYCAST V4  NEVER") {
		t.Fatalf("ANYCAST V4 NEVER line missing:\n%s", got)
	}
	if !strings.Contains(got, "ANYCAST V6  NEVER") {
		t.Fatalf("ANYCAST V6 NEVER line missing:\n%s", got)
	}
}

func TestFormatCatalogOK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	fetched := now.Add(-4 * time.Hour)
	s := sampleGeoIPStatusSnapshot(now)
	s.Catalog = postgres.GeofeedCatalogStatus{
		URLs: 10, Fetched: 10, LastFetchedAt: &fetched, LastCheckedAt: &fetched, LastSeenInWhois: &fetched,
	}
	s.GeoIP = []postgres.GeoIPSourceCount{
		{Source: postgres.GeoIPStatusSourceGEOFEED, Rows: 4, DistinctURLs: 2, NewestAddedAt: &fetched},
		{Source: postgres.GeoIPStatusSourceLACNIC, Rows: 1, NewestAddedAt: &fetched},
		{Source: postgres.GeoIPStatusSourceIPMAP, Rows: 2, DistinctURLs: 1, NewestAddedAt: &fetched},
	}
	s.Lacnic = postgres.LacnicCSVStatus{URL: postgres.LacnicCSVURL, LastSeen: &fetched, Rows: 1, NewestAddedAt: &fetched}
	s.IPMap = postgres.IPMAPDumpStatus{URL: postgres.IPMAPDumpURL, LastSeen: &fetched, Rows: 2, NewestAddedAt: &fetched}
	got := formatGeoIPStatus(s, false)
	if catalogFlags := catalogFlagsLine(got); catalogFlags != "OK" {
		t.Fatalf("catalog flags = %q, want OK\n%s", catalogFlags, got)
	}
	if !strings.Contains(got, "OK") {
		t.Fatalf("missing OK:\n%s", got)
	}
	if strings.Contains(got, "MISSING") || strings.Contains(got, "STALE") || strings.Contains(got, "DUE") {
		t.Fatalf("fresh board should not flag problems:\n%s", got)
	}
}

func TestFormatIPMAPNeverVsStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	s := sampleGeoIPStatusSnapshot(now)
	s.Catalog = postgres.GeofeedCatalogStatus{URLs: 1, Fetched: 1}
	s.Lacnic = postgres.LacnicCSVStatus{URL: postgres.LacnicCSVURL, Never: true}

	s.IPMap = postgres.IPMAPDumpStatus{URL: postgres.IPMAPDumpURL, Never: true}
	got := formatGeoIPStatus(s, false)
	if !strings.Contains(got, "IPMAP       NEVER") {
		t.Fatalf("IPMAP NEVER:\n%s", got)
	}

	seen := now.Add(-169 * time.Hour)
	s.IPMap = postgres.IPMAPDumpStatus{URL: postgres.IPMAPDumpURL, LastSeen: &seen, Rows: 410000, Stale: true}
	got = formatGeoIPStatus(s, false)
	if !strings.Contains(got, "IPMAP       2026-09-01 13:18") {
		t.Fatalf("IPMAP last seen missing:\n%s", got)
	}
	if !strings.Contains(got, "410000 rows") {
		t.Fatalf("IPMAP rows missing:\n%s", got)
	}
	ipmapStale := false
	lines := strings.Split(got, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimRight(line, " "), "IPMAP") && i+1 < len(lines) && strings.Contains(lines[i+1], "STALE") {
			ipmapStale = true
		}
	}
	if !ipmapStale {
		t.Fatalf("IPMAP STALE flag missing:\n%s", got)
	}
}

func TestFormatAnycastNeverVsStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	s := sampleGeoIPStatusSnapshot(now)
	s.Catalog = postgres.GeofeedCatalogStatus{URLs: 1, Fetched: 1}
	s.Lacnic = postgres.LacnicCSVStatus{URL: postgres.LacnicCSVURL, Never: true}
	s.IPMap = postgres.IPMAPDumpStatus{URL: postgres.IPMAPDumpURL, Never: true}

	s.AnycastV4 = postgres.AnycastDumpStatus{URL: postgres.AnycastV4DumpURL, Never: true}
	s.AnycastV6 = postgres.AnycastDumpStatus{URL: postgres.AnycastV6DumpURL, Never: true}
	got := formatGeoIPStatus(s, false)
	if !strings.Contains(got, "ANYCAST V4  NEVER") || !strings.Contains(got, "ANYCAST V6  NEVER") {
		t.Fatalf("ANYCAST NEVER:\n%s", got)
	}

	seen := now.Add(-169 * time.Hour)
	s.AnycastV4 = postgres.AnycastDumpStatus{URL: postgres.AnycastV4DumpURL, LastSeen: &seen, Rows: 3500, Stale: true}
	s.AnycastV6 = postgres.AnycastDumpStatus{URL: postgres.AnycastV6DumpURL, LastSeen: &seen, Rows: 1200, Stale: true}
	got = formatGeoIPStatus(s, false)
	if !strings.Contains(got, "ANYCAST V4  2026-09-01 13:18") {
		t.Fatalf("ANYCAST V4 last seen missing:\n%s", got)
	}
	if !strings.Contains(got, "3500 rows") || !strings.Contains(got, "1200 rows") {
		t.Fatalf("ANYCAST rows missing:\n%s", got)
	}
	v4Stale, v6Stale := false, false
	lines := strings.Split(got, "\n")
	for i, line := range lines {
		trim := strings.TrimRight(line, " ")
		if strings.HasPrefix(trim, "ANYCAST V4") && i+1 < len(lines) && strings.Contains(lines[i+1], "STALE") {
			v4Stale = true
		}
		if strings.HasPrefix(trim, "ANYCAST V6") && i+1 < len(lines) && strings.Contains(lines[i+1], "STALE") {
			v6Stale = true
		}
	}
	if !v4Stale || !v6Stale {
		t.Fatalf("ANYCAST STALE flags missing:\n%s", got)
	}
}

func catalogFlagsLine(board string) string {
	in := false
	for _, line := range strings.Split(board, "\n") {
		if line == "CATALOG" {
			in = true
			continue
		}
		if !in {
			continue
		}
		if line == "" {
			return ""
		}
		if strings.HasPrefix(line, "urls") || strings.HasPrefix(line, "due") || strings.HasPrefix(line, "last fetch") {
			continue
		}
		return strings.TrimSpace(line)
	}
	return ""
}
