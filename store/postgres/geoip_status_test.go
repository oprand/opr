package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeGeoIPStatusOptionsDefaults(t *testing.T) {
	t.Parallel()
	got := NormalizeGeoIPStatusOptions(GeoIPStatusOptions{})
	if got.Now.IsZero() {
		t.Fatal("Now must be filled")
	}
	if got.StaleAfter != DefaultGeoIPStaleAfter {
		t.Fatalf("StaleAfter = %s, want %s", got.StaleAfter, DefaultGeoIPStaleAfter)
	}
	if got.RefreshOlderThan != DefaultGeoIPStaleAfter {
		t.Fatalf("RefreshOlderThan = %s, want %s (align with geofeeds.DefaultRefreshOlderThan)", got.RefreshOlderThan, DefaultGeoIPStaleAfter)
	}
	if got.LacnicURL != LacnicCSVURL {
		t.Fatalf("LacnicURL = %q", got.LacnicURL)
	}
	if got.IPMAPURL != IPMAPDumpURL {
		t.Fatalf("IPMAPURL = %q", got.IPMAPURL)
	}
	if got.AnycastV4URL != AnycastV4DumpURL {
		t.Fatalf("AnycastV4URL = %q", got.AnycastV4URL)
	}
	if got.AnycastV6URL != AnycastV6DumpURL {
		t.Fatalf("AnycastV6URL = %q", got.AnycastV6URL)
	}
	if DefaultGeoIPStaleAfter != 168*time.Hour {
		t.Fatalf("DefaultGeoIPStaleAfter = %s, want 168h (feed content, not NRO 48h)", DefaultGeoIPStaleAfter)
	}
}

func TestNormalizeGeoIPStatusOptionsKeepsExplicit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := NormalizeGeoIPStatusOptions(GeoIPStatusOptions{
		Now:              now,
		StaleAfter:       48 * time.Hour,
		RefreshOlderThan: 24 * time.Hour,
		LacnicURL:        "https://example/lacnic.csv.gz",
		IPMAPURL:         "https://example/ipmap.csv",
		AnycastV4URL:     "https://example/anycast-v4.csv",
		AnycastV6URL:     "https://example/anycast-v6.csv",
	})
	if !got.Now.Equal(now) || got.StaleAfter != 48*time.Hour || got.RefreshOlderThan != 24*time.Hour {
		t.Fatalf("got %+v", got)
	}
	if got.LacnicURL != "https://example/lacnic.csv.gz" {
		t.Fatalf("LacnicURL = %q", got.LacnicURL)
	}
	if got.IPMAPURL != "https://example/ipmap.csv" {
		t.Fatalf("IPMAPURL = %q", got.IPMAPURL)
	}
	if got.AnycastV4URL != "https://example/anycast-v4.csv" {
		t.Fatalf("AnycastV4URL = %q", got.AnycastV4URL)
	}
	if got.AnycastV6URL != "https://example/anycast-v6.csv" {
		t.Fatalf("AnycastV6URL = %q", got.AnycastV6URL)
	}
}

func TestGeoIPCatalogStatusSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoIPCatalogStatusSQL)
	if strings.Contains(sql, "crawl_target") {
		t.Fatal("catalog status reads geofeeds, not crawl_target")
	}
	if !strings.Contains(sql, "from geofeeds") {
		t.Fatal("expected FROM geofeeds")
	}
	if strings.Contains(sql, "update ") || strings.Contains(sql, "for update") {
		t.Fatal("status must be read-only")
	}
	if !strings.Contains(sql, "last_fetched_at is null") {
		t.Fatal("never fetched is last_fetched_at IS NULL")
	}
	if !strings.Contains(sql, "last_fetched_at is not null") {
		t.Fatal("fetched count is last_fetched_at IS NOT NULL")
	}
	if !strings.Contains(sql, "quarantined_until is null or quarantined_until < $1") {
		t.Fatal("due must skip quarantined URLs")
	}
	if !strings.Contains(sql, "cache_until < $1") {
		t.Fatal("expired cache_until must be due")
	}
	if !strings.Contains(sql, "last_fetched_at < $1 - ($2 * interval '1 second')") {
		t.Fatal("due refresh interval must match ClaimDueGeofeeds ($2 seconds)")
	}
	if !strings.Contains(sql, "quarantined_until is not null and quarantined_until > $1") {
		t.Fatal("quarantine count is quarantined_until > now")
	}
	if !strings.Contains(sql, "is_valid is false") {
		t.Fatal("invalid count is is_valid IS FALSE (NULL is not invalid)")
	}
	for _, col := range []string{"max(last_fetched_at)", "max(last_checked_at)", "max(last_seen_in_whois)"} {
		if !strings.Contains(sql, col) {
			t.Fatalf("missing %s", col)
		}
	}
}

func TestGeoIPCatalogDueAlignsWithClaim(t *testing.T) {
	t.Parallel()
	claim := strings.ToLower(claimDueGeofeedsSQL)
	status := strings.ToLower(geoIPCatalogStatusSQL)
	for _, pred := range []string{
		"last_fetched_at is null",
		"cache_until <",
	} {
		if !strings.Contains(claim, pred) || !strings.Contains(status, pred) {
			t.Fatalf("due predicate %q must appear in both claim and status", pred)
		}
	}
	if !strings.Contains(claim, "interval '1 second'") || !strings.Contains(status, "interval '1 second'") {
		t.Fatal("refresh interval must be seconds in both claim and status")
	}
}

func TestGeoIPSourceCountSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoIPSourceCountSQL)
	if strings.Contains(sql, "geofeeds") {
		t.Fatal("derived-row counts must not join geofeeds (empty LACNIC source_url is not an orphan)")
	}
	if !strings.Contains(sql, "from geoip") {
		t.Fatal("expected FROM geoip")
	}
	if !strings.Contains(sql, "group by source") {
		t.Fatal("expected GROUP BY source")
	}
	if !strings.Contains(sql, "count(distinct nullif(source_url, ''))") {
		t.Fatal("distinct source_url must ignore empty string")
	}
	if !strings.Contains(sql, "max(meta_added_at)") {
		t.Fatal("expected MAX(meta_added_at)")
	}
	if strings.Contains(sql, "delete ") {
		t.Fatal("status must not prune")
	}
}

func TestCatalogIsStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 168 * time.Hour
	fetchedOK := now.Add(-4 * time.Hour)
	fetchedOld := now.Add(-169 * time.Hour)
	fetchedExact := now.Add(-168 * time.Hour)
	seenFresh := now.Add(-2 * time.Hour)
	seenAhead := fetchedOK.Add(169 * time.Hour)

	cases := []struct {
		name     string
		urls     int64
		lastSeen *time.Time
		fetched  *time.Time
		want     bool
	}{
		{name: "empty catalog", urls: 0, lastSeen: &seenFresh, fetched: &fetchedOld, want: false},
		{name: "fresh fetch", urls: 10, lastSeen: &seenFresh, fetched: &fetchedOK, want: false},
		{name: "exactly stale-after", urls: 10, fetched: &fetchedExact, want: false},
		{name: "fetch older than stale-after", urls: 10, fetched: &fetchedOld, want: true},
		{name: "whois newer than fetch by stale-after", urls: 10, lastSeen: &seenAhead, fetched: &fetchedOK, want: true},
		{name: "whois slightly newer than fetch", urls: 10, lastSeen: &seenFresh, fetched: &fetchedOK, want: false},
		{name: "never fetched not stale", urls: 10, lastSeen: &seenFresh, fetched: nil, want: false},
		{name: "nil clocks", urls: 10, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CatalogIsStale(tc.urls, tc.lastSeen, tc.fetched, staleAfter, now)
			if got != tc.want {
				t.Fatalf("CatalogIsStale = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGeoIPGEOFEEDMissing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rows, fetched int64
		want          bool
	}{
		{rows: 0, fetched: 5, want: true},
		{rows: 0, fetched: 0, want: false},
		{rows: 10, fetched: 5, want: false},
		{rows: 0, fetched: 1, want: true},
	}
	for _, tc := range cases {
		if got := GeoIPGEOFEEDMissing(tc.rows, tc.fetched); got != tc.want {
			t.Fatalf("rows=%d fetched=%d: got %v, want %v", tc.rows, tc.fetched, got, tc.want)
		}
	}
}

func TestEvaluateLacnicCSV(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 168 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-169 * time.Hour)
	exact := now.Add(-168 * time.Hour)
	rowAdded := now.Add(-2 * time.Hour)

	cases := []struct {
		name      string
		hasMeta   bool
		meta      RemoteFileTime
		rows      int64
		newest    *time.Time
		wantNever bool
		wantStale bool
		wantSeen  *time.Time
	}{
		{name: "no metadata no rows", wantNever: true},
		{name: "fresh metadata", hasMeta: true, meta: RemoteFileTime{MetaAddedAt: &fresh}, rows: 12, newest: &rowAdded, wantSeen: &fresh},
		{name: "old metadata", hasMeta: true, meta: RemoteFileTime{LastModified: &old}, rows: 12, newest: &rowAdded, wantStale: true, wantSeen: &old},
		{name: "exactly stale-after", hasMeta: true, meta: RemoteFileTime{MetaAddedAt: &exact}, rows: 1, wantSeen: &exact},
		{name: "rows without metadata uses row clock", rows: 12, newest: &rowAdded, wantSeen: &rowAdded},
		{name: "rows without metadata old", rows: 12, newest: &old, wantStale: true, wantSeen: &old},
		{name: "metadata prefers last_modified", hasMeta: true, meta: RemoteFileTime{LastModified: &fresh, MetaAddedAt: &old}, rows: 1, newest: &rowAdded, wantSeen: &fresh},
		{name: "metadata no times no rows is stale", hasMeta: true, wantStale: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EvaluateLacnicCSV(LacnicCSVURL, tc.hasMeta, tc.meta, tc.rows, tc.newest, staleAfter, now)
			if got.Never != tc.wantNever || got.Stale != tc.wantStale {
				t.Fatalf("never=%v stale=%v, want never=%v stale=%v (%+v)", got.Never, got.Stale, tc.wantNever, tc.wantStale, got)
			}
			if tc.wantNever && got.LastSeen != nil {
				t.Fatalf("NEVER must clear last_seen, got %v", got.LastSeen)
			}
			if tc.wantSeen != nil {
				if got.LastSeen == nil || !got.LastSeen.Equal(*tc.wantSeen) {
					t.Fatalf("last_seen = %v, want %v", got.LastSeen, *tc.wantSeen)
				}
			}
			if got.URL != LacnicCSVURL {
				t.Fatalf("url = %q", got.URL)
			}
			if got.Rows != tc.rows {
				t.Fatalf("rows = %d, want %d", got.Rows, tc.rows)
			}
		})
	}
}

func TestMergeGeoIPSourceCountsAlwaysIncludesBoth(t *testing.T) {
	t.Parallel()
	got := MergeGeoIPSourceCounts(
		map[string]GeoIPSourceCount{
			GeoIPStatusSourceGEOFEED: {Source: GeoIPStatusSourceGEOFEED, Rows: 89000, DistinctURLs: 400},
		},
		geoIPStatusSources,
	)
	want := []GeoIPSourceCount{
		{Source: GeoIPStatusSourceGEOFEED, Rows: 89000, DistinctURLs: 400},
		{Source: GeoIPStatusSourceLACNIC},
		{Source: GeoIPStatusSourceIPMAP},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMergeGeoIPSourceCountsExtraAlphaAfterAlways(t *testing.T) {
	t.Parallel()
	got := MergeGeoIPSourceCounts(
		map[string]GeoIPSourceCount{
			GeoIPStatusSourceIPMAP:  {Rows: 3},
			GeoIPStatusSourceLACNIC: {Rows: 12, DistinctURLs: 0},
			"OTHER_SRC":             {Rows: 1},
		},
		geoIPStatusSources,
	)
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4", len(got))
	}
	if got[0].Source != GeoIPStatusSourceGEOFEED || got[0].Rows != 0 {
		t.Fatalf("GEOFEED zeros first: %+v", got[0])
	}
	if got[1].Source != GeoIPStatusSourceLACNIC || got[1].Rows != 12 {
		t.Fatalf("LACNIC second: %+v", got[1])
	}
	if got[2].Source != GeoIPStatusSourceIPMAP || got[2].Rows != 3 {
		t.Fatalf("IPMAP third: %+v", got[2])
	}
	if got[3].Source != "OTHER_SRC" || got[3].Rows != 1 {
		t.Fatalf("extra last: %+v", got[3])
	}
}

func TestEvaluateIPMAPDump(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 168 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-169 * time.Hour)

	never := EvaluateIPMAPDump(IPMAPDumpURL, false, RemoteFileTime{}, 0, nil, staleAfter, now)
	if !never.Never || never.Stale {
		t.Fatalf("no metadata no rows: %+v, want NEVER", never)
	}
	if never.URL != IPMAPDumpURL {
		t.Fatalf("url = %q", never.URL)
	}

	stale := EvaluateIPMAPDump(IPMAPDumpURL, true, RemoteFileTime{MetaAddedAt: &old}, 410000, &old, staleAfter, now)
	if stale.Never || !stale.Stale {
		t.Fatalf("old metadata: %+v, want STALE", stale)
	}

	ok := EvaluateIPMAPDump(IPMAPDumpURL, true, RemoteFileTime{MetaAddedAt: &fresh}, 410000, &fresh, staleAfter, now)
	if ok.Never || ok.Stale {
		t.Fatalf("fresh metadata: %+v, want OK", ok)
	}
}

func TestIPMAPDumpURLNotAGeofeed(t *testing.T) {
	t.Parallel()
	if IPMAPDumpURL != "https://ftp.ripe.net/ripe/ipmap/geolocations-latest" {
		t.Fatalf("IPMAPDumpURL = %q", IPMAPDumpURL)
	}
	if !strings.HasPrefix(IPMAPDumpURL, "https://ftp.ripe.net/") {
		t.Fatal("IPmap dump is the ftp.ripe.net file, not a geofeeds catalog URL")
	}
}

func TestEvaluateAnycastDump(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 168 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-169 * time.Hour)

	never := EvaluateAnycastDump(AnycastV4DumpURL, false, RemoteFileTime{}, 0, nil, staleAfter, now)
	if !never.Never || never.Stale {
		t.Fatalf("no metadata no rows: %+v, want NEVER", never)
	}
	if never.URL != AnycastV4DumpURL {
		t.Fatalf("url = %q", never.URL)
	}

	stale := EvaluateAnycastDump(AnycastV6DumpURL, true, RemoteFileTime{MetaAddedAt: &old}, 4000, &old, staleAfter, now)
	if stale.Never || !stale.Stale {
		t.Fatalf("old metadata: %+v, want STALE", stale)
	}

	ok := EvaluateAnycastDump(AnycastV4DumpURL, true, RemoteFileTime{MetaAddedAt: &fresh}, 4000, &fresh, staleAfter, now)
	if ok.Never || ok.Stale {
		t.Fatalf("fresh metadata: %+v, want OK", ok)
	}
}

func TestAnycastDumpURLsNotAGeofeed(t *testing.T) {
	t.Parallel()
	if AnycastV4DumpURL != "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.csv" {
		t.Fatalf("AnycastV4DumpURL = %q", AnycastV4DumpURL)
	}
	if AnycastV6DumpURL != "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.csv" {
		t.Fatalf("AnycastV6DumpURL = %q", AnycastV6DumpURL)
	}
	if len(AnycastDumpURLs) != 2 {
		t.Fatalf("AnycastDumpURLs len=%d", len(AnycastDumpURLs))
	}
}

func TestLacnicCSVURLNotAGeofeed(t *testing.T) {
	t.Parallel()
	if LacnicCSVURL != "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.csv.gz" {
		t.Fatalf("LacnicCSVURL = %q", LacnicCSVURL)
	}
	if !strings.HasPrefix(LacnicCSVURL, "https://ftp.lacnic.net/") {
		t.Fatal("LACNIC CSV is the ftp.lacnic.net dump, not a geofeeds catalog URL")
	}
}
