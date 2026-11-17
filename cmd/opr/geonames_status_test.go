package main

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/geonames"
	"github.com/oprand/opr/store/postgres"
)

func TestGeoNamesStaleAfterMatchesCrawlInterval(t *testing.T) {
	t.Parallel()
	if postgres.DefaultGeoNamesStaleAfter != 2*geonames.DefaultCrawlInterval {
		t.Fatalf("DefaultGeoNamesStaleAfter = %s, want 2× DefaultCrawlInterval (%s)", postgres.DefaultGeoNamesStaleAfter, geonames.DefaultCrawlInterval)
	}
}

func sampleGeoNamesStatusSnapshot(now time.Time) postgres.GeoNamesStatusSnapshot {
	citiesSeen := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	countrySeen := time.Date(2026, 8, 1, 4, 0, 0, 0, time.UTC)
	postalSeen := time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)

	return postgres.GeoNamesStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  (48 * time.Hour).String(),
		Tables: []postgres.GeoNamesTableCount{
			{Table: postgres.GeoNamesStatusTableCity, Rows: 198432},
			{Table: postgres.GeoNamesStatusTablePostal, Rows: 1400123},
			{Table: postgres.GeoNamesStatusTableAdmin1, Rows: 0, Missing: true},
			{Table: postgres.GeoNamesStatusTableAdmin2, Rows: 47900},
			{Table: postgres.GeoNamesStatusTableTimezone, Rows: 425},
			{Table: postgres.GeoNamesStatusTableAltName, Rows: 890000},
			{Table: postgres.GeoNamesStatusTableLookup, Rows: 2500001},
			{Table: postgres.GeoNamesStatusTableCountryInfo, Rows: 252},
		},
		MatchKind: []postgres.GeoNamesMatchKindCount{
			{Kind: postgres.GeoNamesMatchKindZip, Rows: 800001},
			{Kind: postgres.GeoNamesMatchKindCity, Rows: 198432},
			{Kind: postgres.GeoNamesMatchKindAlias, Rows: 400000},
			{Kind: postgres.GeoNamesMatchKindAdmin, Rows: 0},
			{Kind: postgres.GeoNamesMatchKindCapital, Rows: 252},
		},
		Dumps: []postgres.GeoNamesDumpClock{
			{
				URL:         "https://download.geonames.org/export/dump/cities500.zip",
				LastSeen:    &citiesSeen,
				MetaAddedAt: &citiesSeen,
				ETagPresent: true,
			},
			{
				URL:         "https://download.geonames.org/export/dump/countryInfo.txt",
				LastSeen:    &countrySeen,
				MetaAddedAt: &countrySeen,
				ETagPresent: true,
				Stale:       true,
			},
			{
				URL:         "https://download.geonames.org/export/zip/allCountries.zip",
				LastSeen:    &postalSeen,
				MetaAddedAt: &postalSeen,
			},
		},
		RemapRows:     8,
		LegalFlagRows: 265,
	}
}

const geonamesStatusBoardGolden = `GEONAMES   2026-09-08 14:18 UTC

TABLES
                      rows
geonames_city       198432
geonames_postal    1400123
geonames_admin1          0  MISSING
geonames_admin2      47900
geonames_timezone      425
geonames_altname    890000
geonames_lookup    2500001
country_info           252
remap                    8
legal_flags            265

MATCH KIND
              rows
zip         800001
city        198432
alias       400000
admin            0
capital        252

DUMPS
                  last seen         etag
cities500.zip     2026-09-08 12:00  yes
countryInfo.txt   2026-08-01 04:00  yes   STALE
allCountries.zip  2026-09-08 11:00  no
`

func TestFormatGeoNamesStatusGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoNamesStatus(sampleGeoNamesStatusSnapshot(now), false)
	if got != geonamesStatusBoardGolden {
		t.Fatalf("human board mismatch\nGOT:\n%s\nWANT:\n%s", got, geonamesStatusBoardGolden)
	}
}

func TestFormatGeoNamesStatusNoANSIWhenColorOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoNamesStatus(sampleGeoNamesStatusSnapshot(now), false)
	if strings.Contains(got, "\033[") {
		t.Fatal("color-off output must not contain ANSI")
	}
}

func TestFormatGeoNamesStatusFlags(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoNamesStatus(sampleGeoNamesStatusSnapshot(now), false)
	for _, word := range []string{"STALE", "MISSING"} {
		if !strings.Contains(got, word) {
			t.Fatalf("missing %q in board:\n%s", word, got)
		}
	}
	if strings.Contains(got, "\u2500") || strings.Contains(got, "+--") {
		t.Fatal("board must not draw box art")
	}
}

func TestFormatGeoNamesStatusNumbersRightAligned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatGeoNamesStatus(sampleGeoNamesStatusSnapshot(now), false)
	var header, postal, city string
	inTables := false
	for _, line := range strings.Split(got, "\n") {
		if line == "TABLES" {
			inTables = true
			continue
		}
		if !inTables {
			continue
		}
		if line == "" || line == "MATCH KIND" {
			break
		}
		if strings.Contains(line, "rows") && !strings.Contains(line, "geonames") {
			header = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "geonames_postal") {
			postal = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "geonames_city") {
			city = line
		}
	}
	if header == "" || postal == "" || city == "" {
		t.Fatalf("table lines missing\n%s", got)
	}
	rowsAt := strings.Index(header, "rows")
	if rowsAt < 0 {
		t.Fatalf("headers: %q", header)
	}
	end := rowsAt + len("rows") - 1
	if end >= len(postal) || postal[end] != '3' {
		t.Fatalf("1400123 not right-aligned under rows\n%s\n%s", header, postal)
	}
	if end >= len(city) || city[end] != '2' {
		t.Fatalf("198432 not right-aligned under rows\n%s\n%s", header, city)
	}
}

func TestFormatEmptyGeoNamesNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	s := postgres.GeoNamesStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  (48 * time.Hour).String(),
		Tables: []postgres.GeoNamesTableCount{
			{Table: postgres.GeoNamesStatusTableCity, Missing: true},
			{Table: postgres.GeoNamesStatusTablePostal, Missing: true},
			{Table: postgres.GeoNamesStatusTableAdmin1, Missing: true},
			{Table: postgres.GeoNamesStatusTableAdmin2, Missing: true},
			{Table: postgres.GeoNamesStatusTableTimezone, Missing: true},
			{Table: postgres.GeoNamesStatusTableAltName, Missing: true},
			{Table: postgres.GeoNamesStatusTableLookup, Missing: true},
			{Table: postgres.GeoNamesStatusTableCountryInfo, Missing: true},
		},
		MatchKind: []postgres.GeoNamesMatchKindCount{
			{Kind: postgres.GeoNamesMatchKindZip},
			{Kind: postgres.GeoNamesMatchKindCity},
			{Kind: postgres.GeoNamesMatchKindAlias},
			{Kind: postgres.GeoNamesMatchKindAdmin},
			{Kind: postgres.GeoNamesMatchKindCapital},
		},
		Dumps: []postgres.GeoNamesDumpClock{
			{URL: postgres.GeoNamesCountryInfoURL, Never: true, Stale: true},
			{URL: postgres.GeoNamesCities500URL, Never: true},
		},
	}
	got := formatGeoNamesStatus(s, false)
	if !strings.Contains(got, "NEVER") {
		t.Fatalf("empty dumps:\n%s", got)
	}
	if !strings.Contains(got, "MISSING") {
		t.Fatalf("empty tables must flag MISSING:\n%s", got)
	}
	if !strings.Contains(got, "geonames_admin2") || !strings.Contains(got, "geonames_timezone") || !strings.Contains(got, "geonames_altname") {
		t.Fatalf("TABLES must list admin2/timezone/altname:\n%s", got)
	}
	if strings.Contains(got, "STALE") {
		t.Fatal("empty dumps must not also flag STALE")
	}
	if !strings.Contains(got, "NEVER") || !strings.Contains(got, "DUMPS") {
		t.Fatalf("DUMPS NEVER missing:\n%s", got)
	}
}

func TestFormatGeoNamesOK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	fresh := now.Add(-4 * time.Hour)
	s := sampleGeoNamesStatusSnapshot(now)
	s.Tables = []postgres.GeoNamesTableCount{
		{Table: postgres.GeoNamesStatusTableCity, Rows: 4},
		{Table: postgres.GeoNamesStatusTablePostal, Rows: 4},
		{Table: postgres.GeoNamesStatusTableAdmin1, Rows: 4},
		{Table: postgres.GeoNamesStatusTableAdmin2, Rows: 4},
		{Table: postgres.GeoNamesStatusTableTimezone, Rows: 4},
		{Table: postgres.GeoNamesStatusTableAltName, Rows: 4},
		{Table: postgres.GeoNamesStatusTableLookup, Rows: 4},
		{Table: postgres.GeoNamesStatusTableCountryInfo, Rows: 4},
	}
	s.RemapRows = 3
	s.MatchKind = []postgres.GeoNamesMatchKindCount{
		{Kind: postgres.GeoNamesMatchKindZip, Rows: 1},
		{Kind: postgres.GeoNamesMatchKindCity, Rows: 1},
		{Kind: postgres.GeoNamesMatchKindAlias, Rows: 1},
		{Kind: postgres.GeoNamesMatchKindAdmin, Rows: 1},
		{Kind: postgres.GeoNamesMatchKindCapital, Rows: 1},
	}
	s.Dumps = []postgres.GeoNamesDumpClock{
		{URL: "https://download.geonames.org/export/dump/cities500.zip", LastSeen: &fresh, ETagPresent: true},
	}
	got := formatGeoNamesStatus(s, false)
	if strings.Contains(got, "MISSING") || strings.Contains(got, "STALE") || strings.Contains(got, "NEVER") {
		t.Fatalf("fresh board should not flag problems:\n%s", got)
	}
}

func TestGeoNamesDumpLabel(t *testing.T) {
	t.Parallel()
	got := geoNamesDumpLabel("https://download.geonames.org/export/dump/cities500.zip")
	if got != "cities500.zip" {
		t.Fatalf("got %q", got)
	}
	if geoNamesDumpLabel("") != "" {
		t.Fatal("empty url")
	}
}
