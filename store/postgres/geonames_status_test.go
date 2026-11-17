package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGeoNamesStatusOptionsDefaults(t *testing.T) {
	t.Parallel()
	got := NormalizeGeoNamesStatusOptions(GeoNamesStatusOptions{})
	if got.Now.IsZero() {
		t.Fatal("Now must be filled")
	}
	if got.StaleAfter != DefaultGeoNamesStaleAfter {
		t.Fatalf("StaleAfter = %s, want %s", got.StaleAfter, DefaultGeoNamesStaleAfter)
	}
	if DefaultGeoNamesStaleAfter != 48*time.Hour {
		t.Fatalf("DefaultGeoNamesStaleAfter = %s, want 48h (2× geonames CrawlInterval)", DefaultGeoNamesStaleAfter)
	}
}

func TestNormalizeGeoNamesStatusOptionsKeepsExplicit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := NormalizeGeoNamesStatusOptions(GeoNamesStatusOptions{
		Now:        now,
		StaleAfter: 48 * time.Hour,
	})
	if !got.Now.Equal(now) || got.StaleAfter != 48*time.Hour {
		t.Fatalf("got %+v", got)
	}
}

func TestGeoNamesTableCountSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoNamesTableCountSQL)
	for _, table := range []string{
		"geonames_city",
		"geonames_postal",
		"geonames_admin1",
		"geonames_admin2",
		"geonames_timezone",
		"geonames_altname",
		"geonames_lookup",
		"country_info",
		"country_code_remap",
		"country_legal_flag",
	} {
		if !strings.Contains(sql, "from "+table) {
			t.Fatalf("missing COUNT from %s", table)
		}
	}
	if strings.Contains(sql, "update ") || strings.Contains(sql, "delete ") {
		t.Fatal("status must be read-only")
	}
	if strings.Contains(sql, "geonames ") || strings.Contains(sql, "from geonames\n") {
		t.Fatal("must not count the dropped mixed geonames table")
	}
}

func TestGeoNamesMatchKindSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoNamesMatchKindSQL)
	if !strings.Contains(sql, "from geonames_lookup") {
		t.Fatal("expected FROM geonames_lookup")
	}
	if !strings.Contains(sql, "group by 1") && !strings.Contains(sql, "group by match_kind") {
		t.Fatal("expected GROUP BY match_kind")
	}
	if !strings.Contains(sql, "coalesce(match_kind") {
		t.Fatal("blank match_kind must still count")
	}
	if strings.Contains(sql, "delete ") || strings.Contains(sql, "update ") {
		t.Fatal("status must be read-only")
	}
}

func TestGeoNamesDumpClockSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoNamesDumpClockSQL)
	if !strings.Contains(sql, "from remote_files_metadata") {
		t.Fatal("expected FROM remote_files_metadata")
	}
	if !strings.Contains(sql, "like '%geonames.org%'") {
		t.Fatal("dumps must filter url LIKE percent-geonames.org-percent")
	}
	if !strings.Contains(sql, "etag is not null") {
		t.Fatal("etag present is etag IS NOT NULL")
	}
	if !strings.Contains(sql, "trim(etag)") {
		t.Fatal("empty etag is not present")
	}
	for _, col := range []string{"last_modified", "meta_added_at"} {
		if !strings.Contains(sql, col) {
			t.Fatalf("missing %s", col)
		}
	}
	if strings.Contains(sql, "update ") || strings.Contains(sql, "delete ") {
		t.Fatal("status must be read-only")
	}
	if !strings.Contains(sql, "order by url") {
		t.Fatal("dump clocks must be stable by url")
	}
}

func TestGeoNamesRemoteFileURLLike(t *testing.T) {
	t.Parallel()
	if GeoNamesRemoteFileURLLike != "%geonames.org%" {
		t.Fatalf("GeoNamesRemoteFileURLLike = %q", GeoNamesRemoteFileURLLike)
	}
}

func TestEvaluateGeoNamesDump(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 48 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-49 * time.Hour)
	exact := now.Add(-48 * time.Hour)
	olderMeta := now.Add(-72 * time.Hour)
	url := GeoNamesCities500URL

	cases := []struct {
		name         string
		lastModified *time.Time
		metaAdded    *time.Time
		etag         bool
		wantNever    bool
		wantStale    bool
		wantSeen     *time.Time
	}{
		{name: "no clocks", wantNever: true},
		{name: "prefers meta_added_at when last_modified is fresher", lastModified: &fresh, metaAdded: &olderMeta, etag: true, wantStale: true, wantSeen: &olderMeta},
		{name: "fresh meta wins over old last_modified", lastModified: &old, metaAdded: &fresh, etag: true, wantSeen: &fresh},
		{name: "exactly stale-after", lastModified: &exact, etag: true, wantSeen: &exact},
		{name: "meta_added_at only fresh", metaAdded: &fresh, etag: false, wantSeen: &fresh},
		{name: "meta_added_at only old", metaAdded: &old, wantStale: true, wantSeen: &old},
		{name: "etag without clocks is stale not never", etag: true, wantStale: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EvaluateGeoNamesDump(url, tc.lastModified, tc.metaAdded, tc.etag, staleAfter, now)
			if got.Never != tc.wantNever {
				t.Fatalf("never=%v, want %v (%+v)", got.Never, tc.wantNever, got)
			}
			if got.Stale != tc.wantStale {
				t.Fatalf("stale=%v, want %v (%+v)", got.Stale, tc.wantStale, got)
			}
			if tc.wantNever && got.Stale {
				t.Fatal("NEVER must not also be STALE")
			}
			if tc.wantNever && got.LastSeen != nil {
				t.Fatalf("NEVER must clear last_seen, got %v", got.LastSeen)
			}
			if tc.wantSeen != nil {
				if got.LastSeen == nil || !got.LastSeen.Equal(*tc.wantSeen) {
					t.Fatalf("last_seen = %v, want %v", got.LastSeen, *tc.wantSeen)
				}
			}
			if tc.wantSeen == nil && got.LastSeen != nil {
				t.Fatalf("last_seen = %v, want nil", got.LastSeen)
			}
			if got.URL != url {
				t.Fatalf("url = %q", got.URL)
			}
			if got.ETagPresent != tc.etag {
				t.Fatalf("etag = %v, want %v", got.ETagPresent, tc.etag)
			}
			if got.MetaAddedAt != tc.metaAdded {
				t.Fatalf("meta_added_at = %v, want %v", got.MetaAddedAt, tc.metaAdded)
			}
		})
	}
}

func TestMergeGeoNamesTableCountsAlwaysIncludesAll(t *testing.T) {
	t.Parallel()
	got := MergeGeoNamesTableCounts(
		map[string]int64{
			GeoNamesStatusTableCity:   198432,
			GeoNamesStatusTablePostal: 1400123,
			geoNamesRemapTable:        8,
		},
		geoNamesStatusTables,
	)
	want := []GeoNamesTableCount{
		{Table: GeoNamesStatusTableCity, Rows: 198432},
		{Table: GeoNamesStatusTablePostal, Rows: 1400123},
		{Table: GeoNamesStatusTableAdmin1, Missing: true},
		{Table: GeoNamesStatusTableAdmin2, Missing: true},
		{Table: GeoNamesStatusTableTimezone, Missing: true},
		{Table: GeoNamesStatusTableAltName, Missing: true},
		{Table: GeoNamesStatusTableLookup, Missing: true},
		{Table: GeoNamesStatusTableCountryInfo, Missing: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestGeoNamesDumpURLsPinned(t *testing.T) {
	t.Parallel()
	want := []string{
		"https://download.geonames.org/export/dump/countryInfo.txt",
		"https://download.geonames.org/export/zip/allCountries.zip",
		"https://download.geonames.org/export/dump/cities500.zip",
		"https://download.geonames.org/export/dump/admin1CodesASCII.txt",
		"https://download.geonames.org/export/dump/admin2Codes.txt",
		"https://download.geonames.org/export/dump/timeZones.txt",
		"https://download.geonames.org/export/dump/alternateNamesV2.zip",
		"https://download.geonames.org/export/dump/alternateNames.zip",
	}
	if !reflect.DeepEqual(GeoNamesDumpURLs, want) {
		t.Fatalf("GeoNamesDumpURLs = %#v, want %#v", GeoNamesDumpURLs, want)
	}
	if GeoNamesCountryInfoURL != want[0] || GeoNamesAltNamesURL != want[7] {
		t.Fatal("named dump URL constants must match GeoNamesDumpURLs")
	}
}

func TestMergeGeoNamesDumpClocksFillsMissingAsNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	fresh := now.Add(-4 * time.Hour)
	cities := EvaluateGeoNamesDump(GeoNamesCities500URL, &fresh, &fresh, true, DefaultGeoNamesStaleAfter, now)
	extraURL := "https://download.geonames.org/export/dump/extra.txt"
	extra := EvaluateGeoNamesDump(extraURL, &fresh, &fresh, false, DefaultGeoNamesStaleAfter, now)
	got := MergeGeoNamesDumpClocks([]GeoNamesDumpClock{cities, extra}, GeoNamesDumpURLs, DefaultGeoNamesStaleAfter, now)
	if len(got) != len(GeoNamesDumpURLs)+1 {
		t.Fatalf("len=%d, want %d", len(got), len(GeoNamesDumpURLs)+1)
	}
	for i, url := range GeoNamesDumpURLs {
		if got[i].URL != url {
			t.Fatalf("got[%d].URL = %q, want %q", i, got[i].URL, url)
		}
		if url == GeoNamesCities500URL {
			if got[i].Never || got[i].Stale || got[i].LastSeen == nil {
				t.Fatalf("cities500 should be present: %+v", got[i])
			}
			continue
		}
		if !got[i].Never || got[i].Stale || got[i].LastSeen != nil {
			t.Fatalf("missing %s must be NEVER not STALE: %+v", url, got[i])
		}
	}
	last := got[len(got)-1]
	if last.URL != extraURL || last.Never {
		t.Fatalf("extra last: %+v", last)
	}
}

func TestMergeGeoNamesMatchKindsAlwaysThenExtra(t *testing.T) {
	t.Parallel()
	got := MergeGeoNamesMatchKinds(
		map[string]int64{
			GeoNamesMatchKindZip:  800001,
			GeoNamesMatchKindCity: 198432,
			"other":               3,
		},
		geoNamesMatchKinds,
	)
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6", len(got))
	}
	if got[0].Kind != GeoNamesMatchKindZip || got[0].Rows != 800001 {
		t.Fatalf("zip first: %+v", got[0])
	}
	if got[1].Kind != GeoNamesMatchKindCity || got[1].Rows != 198432 {
		t.Fatalf("city second: %+v", got[1])
	}
	if got[2].Kind != GeoNamesMatchKindAlias || got[2].Rows != 0 {
		t.Fatalf("alias zeros: %+v", got[2])
	}
	if got[3].Kind != GeoNamesMatchKindAdmin || got[4].Kind != GeoNamesMatchKindCapital {
		t.Fatalf("admin/capital order: %+v %+v", got[3], got[4])
	}
	if got[5].Kind != "other" || got[5].Rows != 3 {
		t.Fatalf("extra last: %+v", got[5])
	}
}
