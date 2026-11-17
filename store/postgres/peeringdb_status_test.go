package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizePeeringDBStatusOptionsDefaults(t *testing.T) {
	t.Parallel()
	got := NormalizePeeringDBStatusOptions(PeeringDBStatusOptions{})
	if got.Now.IsZero() {
		t.Fatal("Now must be filled")
	}
	if got.StaleAfter != DefaultPeeringDBStaleAfter {
		t.Fatalf("StaleAfter = %s, want %s", got.StaleAfter, DefaultPeeringDBStaleAfter)
	}
	if DefaultPeeringDBStaleAfter != 48*time.Hour {
		t.Fatalf("DefaultPeeringDBStaleAfter = %s, want 48h (2× peeringdb CrawlInterval)", DefaultPeeringDBStaleAfter)
	}
}

func TestNormalizePeeringDBStatusOptionsKeepsExplicit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := NormalizePeeringDBStatusOptions(PeeringDBStatusOptions{
		Now:        now,
		StaleAfter: 48 * time.Hour,
	})
	if !got.Now.Equal(now) || got.StaleAfter != 48*time.Hour {
		t.Fatalf("got %+v", got)
	}
}

func TestPeeringDBTableCountSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(peeringDBTableCountSQL)
	for _, table := range []string{
		"peeringdb_organization",
		"peeringdb_facility",
		"peeringdb_network",
		"peeringdb_ix",
		"peeringdb_ix_facility",
		"peeringdb_ixlan",
		"peeringdb_ixlan_prefix",
		"peeringdb_network_contact",
		"peeringdb_network_facility",
		"peeringdb_network_ixlan",
	} {
		if !strings.Contains(sql, "from "+table) {
			t.Fatalf("missing COUNT from %s", table)
		}
	}
	if strings.Contains(sql, "from ix_expanded") {
		t.Fatal("tables are base peeringdb_* only, not ix_expanded")
	}
	if strings.Contains(sql, "update ") || strings.Contains(sql, "delete ") {
		t.Fatal("status must be read-only")
	}
}

func TestPeeringDBSyncClockSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(peeringDBSyncClockSQL)
	if !strings.Contains(sql, "max(updated)") {
		t.Fatal("sync clock is MAX(updated)")
	}
	for _, table := range []string{
		PeeringDBTableOrganization,
		PeeringDBTableFacility,
		PeeringDBTableNetwork,
		PeeringDBTableIX,
		PeeringDBTableIXFacility,
		PeeringDBTableIXLAN,
		PeeringDBTableIXLANPrefix,
		PeeringDBTableNetworkContact,
		PeeringDBTableNetworkFacility,
		PeeringDBTableNetworkIXLAN,
	} {
		if !strings.Contains(sql, "from "+table) {
			t.Fatalf("sync missing %s", table)
		}
	}
	if strings.Contains(sql, "from ix_expanded") {
		t.Fatal("sync is base tables only, not ix_expanded")
	}
	if strings.Contains(sql, "update ") || strings.Contains(sql, "delete ") {
		t.Fatal("status must be read-only")
	}
}

func TestPeeringDBDumpClockSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(peeringDBDumpClockSQL)
	if !strings.Contains(sql, "from remote_files_metadata") {
		t.Fatal("expected FROM remote_files_metadata")
	}
	if !strings.Contains(sql, "like '%public.peeringdb.com%'") {
		t.Fatal("dumps must filter url LIKE percent-public.peeringdb.com-percent")
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

func TestPeeringDBRemoteFileURLLike(t *testing.T) {
	t.Parallel()
	if PeeringDBRemoteFileURLLike != "%public.peeringdb.com%" {
		t.Fatalf("PeeringDBRemoteFileURLLike = %q", PeeringDBRemoteFileURLLike)
	}
}

func TestPeeringDBDumpURLsPinned(t *testing.T) {
	t.Parallel()
	want := []string{
		"https://public.peeringdb.com/org-0.json",
		"https://public.peeringdb.com/fac-0.json",
		"https://public.peeringdb.com/net-0.json",
		"https://public.peeringdb.com/ix-0.json",
		"https://public.peeringdb.com/ixfac-0.json",
		"https://public.peeringdb.com/ixlan-0.json",
		"https://public.peeringdb.com/ixpfx-0.json",
		"https://public.peeringdb.com/poc-0.json",
		"https://public.peeringdb.com/netfac-0.json",
		"https://public.peeringdb.com/netixlan-0.json",
	}
	if !reflect.DeepEqual(PeeringDBDumpURLs, want) {
		t.Fatalf("PeeringDBDumpURLs = %#v, want %#v", PeeringDBDumpURLs, want)
	}
	if PeeringDBOrgDumpURL != want[0] || PeeringDBNetIXLANDumpURL != want[9] {
		t.Fatal("named dump URL constants must match PeeringDBDumpURLs")
	}
	if PeeringDBDumpURL("org") != PeeringDBOrgDumpURL || PeeringDBDumpURL("poc") != PeeringDBPOCDumpURL {
		t.Fatal("PeeringDBDumpURL must match pinned constants")
	}
	if len(PeeringDBDumps) != 10 {
		t.Fatalf("PeeringDBDumps len=%d, want 10", len(PeeringDBDumps))
	}
	for i, d := range PeeringDBDumps {
		if d.URL != want[i] || d.Tag == "" || d.Table == "" {
			t.Fatalf("dump[%d] = %+v", i, d)
		}
	}
}

func TestEvaluatePeeringDBDump(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 48 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-49 * time.Hour)
	exact := now.Add(-48 * time.Hour)
	olderMeta := now.Add(-72 * time.Hour)
	url := PeeringDBOrgDumpURL

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
			got := EvaluatePeeringDBDump(url, tc.lastModified, tc.metaAdded, tc.etag, staleAfter, now)
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

func TestEvaluatePeeringDBSync(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	staleAfter := 48 * time.Hour
	fresh := now.Add(-4 * time.Hour)
	old := now.Add(-49 * time.Hour)

	never := EvaluatePeeringDBSync(nil, staleAfter, now)
	if !never.Never || never.Stale || never.LastUpdated != nil {
		t.Fatalf("nil clock must be NEVER not STALE: %+v", never)
	}
	zero := time.Time{}
	zeroed := EvaluatePeeringDBSync(&zero, staleAfter, now)
	if !zeroed.Never || zeroed.Stale {
		t.Fatalf("zero clock must be NEVER: %+v", zeroed)
	}
	ok := EvaluatePeeringDBSync(&fresh, staleAfter, now)
	if ok.Never || ok.Stale || ok.LastUpdated == nil {
		t.Fatalf("fresh: %+v", ok)
	}
	stale := EvaluatePeeringDBSync(&old, staleAfter, now)
	if stale.Never || !stale.Stale {
		t.Fatalf("old: %+v", stale)
	}
}

func TestMergePeeringDBTableCountsAlwaysIncludesAll(t *testing.T) {
	t.Parallel()
	got := MergePeeringDBTableCounts(
		map[string]int64{
			PeeringDBTableOrganization: 12345,
			PeeringDBTableNetwork:      28000,
		},
		peeringDBStatusTables,
	)
	if len(got) != 10 {
		t.Fatalf("len=%d, want 10", len(got))
	}
	if got[0].Table != PeeringDBTableOrganization || got[0].Rows != 12345 || got[0].Missing {
		t.Fatalf("org: %+v", got[0])
	}
	if got[2].Table != PeeringDBTableNetwork || got[2].Rows != 28000 {
		t.Fatalf("net: %+v", got[2])
	}
	if !got[1].Missing || got[1].Table != PeeringDBTableFacility {
		t.Fatalf("fac missing: %+v", got[1])
	}
	last := got[len(got)-1]
	if last.Table != PeeringDBTableNetworkIXLAN || !last.Missing {
		t.Fatalf("network_ixlan last missing: %+v", last)
	}
}

func TestMergePeeringDBDumpClocksFillsMissingAsNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	fresh := now.Add(-4 * time.Hour)
	org := EvaluatePeeringDBDump(PeeringDBOrgDumpURL, &fresh, &fresh, true, DefaultPeeringDBStaleAfter, now)
	extraURL := "https://public.peeringdb.com/campus-0.json"
	extra := EvaluatePeeringDBDump(extraURL, &fresh, &fresh, false, DefaultPeeringDBStaleAfter, now)
	got := MergePeeringDBDumpClocks([]PeeringDBDumpClock{org, extra}, PeeringDBDumpURLs, DefaultPeeringDBStaleAfter, now)
	if len(got) != len(PeeringDBDumpURLs)+1 {
		t.Fatalf("len=%d, want %d", len(got), len(PeeringDBDumpURLs)+1)
	}
	for i, url := range PeeringDBDumpURLs {
		if got[i].URL != url {
			t.Fatalf("got[%d].URL = %q, want %q", i, got[i].URL, url)
		}
		if url == PeeringDBOrgDumpURL {
			if got[i].Never || got[i].Stale || got[i].LastSeen == nil {
				t.Fatalf("org should be present: %+v", got[i])
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
