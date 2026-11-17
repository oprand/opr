package postgres

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

func TestCrawlPriority(t *testing.T) {
	t.Parallel()
	// Shared by autnum (SQL CASE) and ipnet (Go NRO path + RIB SQL CASE).
	cases := []struct {
		name     string
		registry string
		country  string
		want     int16
	}{
		{name: "LACNIC BR", registry: opconst.LACNIC, country: "BR", want: CrawlPriorityLacnicBR},
		{name: "LACNIC br lowercase", registry: opconst.LACNIC, country: "br", want: CrawlPriorityLacnicBR},
		{name: "LACNIC BR padded", registry: opconst.LACNIC, country: " BR ", want: CrawlPriorityLacnicBR},
		{name: "LACNIC AR", registry: opconst.LACNIC, country: "AR", want: CrawlPriorityDefault},
		{name: "LACNIC MX", registry: opconst.LACNIC, country: "MX", want: CrawlPriorityDefault},
		{name: "LACNIC CL", registry: opconst.LACNIC, country: "CL", want: CrawlPriorityDefault},
		{name: "LACNIC empty country", registry: opconst.LACNIC, country: "", want: CrawlPriorityDefault},
		{name: "ARIN BR", registry: opconst.ARIN, country: "BR", want: CrawlPriorityDefault},
		{name: "ARIN br lowercase", registry: opconst.ARIN, country: "br", want: CrawlPriorityDefault},
		{name: "RIPE BR", registry: opconst.RIPE, country: "BR", want: CrawlPriorityDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := crawlPriority(tc.registry, tc.country); got != tc.want {
				t.Fatalf("crawlPriority(%q, %q) = %d, want %d", tc.registry, tc.country, got, tc.want)
			}
		})
	}
}

func TestCrawlPrioritySQLOnlySpecialCasesBR(t *testing.T) {
	t.Parallel()
	sql := crawlPrioritySQL("registry", "country_code")
	if !strings.Contains(sql, "'BR'") {
		t.Fatalf("expected BR country literal in %s", sql)
	}
	for _, cc := range []string{"'AR'", "'MX'", "'CL'", "'US'"} {
		if strings.Contains(sql, cc) {
			t.Fatalf("must not special-case %s: %s", cc, sql)
		}
	}
	if !strings.Contains(sql, opconst.LACNIC) {
		t.Fatalf("expected LACNIC registry in %s", sql)
	}
}

func TestSeedSQLUsesCrawlPriority(t *testing.T) {
	t.Parallel()
	want := crawlPrioritySQL("registry", "country_code")
	if !strings.Contains(seedAutnumSQL, want) {
		t.Fatal("autnum seed must set priority from the NRO row country")
	}
	if !strings.Contains(seedIpnetFromCIDRsSQL, want) {
		t.Fatal("rib ipnet seed must set priority from the covering NRO country")
	}
}

func TestMarkAutnumRangeSiblingsDoneNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.MarkAutnumRangeSiblingsDone(context.Background(), nil, opconst.ARIN); err != nil {
		t.Fatalf("nil asns: %v", err)
	}
	if err := st.MarkAutnumRangeSiblingsDone(context.Background(), []uint32{0, 0}, opconst.ARIN); err != nil {
		t.Fatalf("asn 0: %v", err)
	}
	if err := st.MarkAutnumRangeSiblingsDone(context.Background(), []uint32{838}, ""); err != nil {
		t.Fatalf("empty registry: %v", err)
	}
}

func TestCoverageRegistriesMapsNIROntoParent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		src  string
		want []string
	}{
		{opconst.JPNIC, []string{opconst.JPNIC, opconst.APNIC}},
		{opconst.KRNIC, []string{opconst.KRNIC, opconst.APNIC}},
		{opconst.TWNIC, []string{opconst.TWNIC, opconst.APNIC}},
		{opconst.APNIC, []string{opconst.APNIC}},
		{opconst.RIPE, []string{opconst.RIPE}},
		{opconst.AFRINIC, []string{opconst.AFRINIC}},
		{opconst.ARIN, []string{opconst.ARIN}},
		{opconst.LACNIC, []string{opconst.LACNIC}},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			t.Parallel()
			got := CoverageRegistries(tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("CoverageRegistries(%s) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}

func TestNIRParentDoesNotIncludeARIN(t *testing.T) {
	t.Parallel()
	if _, ok := NIRParent[opconst.ARIN]; ok {
		t.Fatal("ARIN must not have a parent coverage mapping")
	}
	if _, ok := NIRParent[opconst.LACNIC]; ok {
		t.Fatal("LACNIC must not have a parent coverage mapping")
	}
	if NIRParent[opconst.JPNIC] != opconst.APNIC {
		t.Fatalf("JPNIC parent = %q, want APNIC", NIRParent[opconst.JPNIC])
	}
}

func TestCrawlKindGeofeed(t *testing.T) {
	t.Parallel()
	if CrawlKindGeofeed != "geofeed" {
		t.Fatalf("CrawlKindGeofeed = %q, want geofeed", CrawlKindGeofeed)
	}
}

func TestSaveGeofeedsSQLIsUpsert(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(saveGeofeedsSQL)
	if strings.Contains(sql, "truncate") {
		t.Fatal("SaveGeofeeds must not TRUNCATE")
	}
	if !strings.Contains(sql, "insert into geofeeds") {
		t.Fatal("expected INSERT INTO geofeeds")
	}
	if !strings.Contains(sql, "last_seen_in_whois") {
		t.Fatal("expected last_seen_in_whois")
	}
	if !strings.Contains(sql, "on conflict (url) do update") {
		t.Fatal("expected ON CONFLICT (url) DO UPDATE")
	}
}

func TestSeedGeofeedTargetsSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(seedGeofeedTargetsSQL)
	if !strings.Contains(sql, "insert into crawl_target") {
		t.Fatal("expected INSERT INTO crawl_target")
	}
	if !strings.Contains(sql, "'geofeed'") {
		t.Fatal("expected kind geofeed")
	}
	if !strings.Contains(sql, "on conflict (kind, key, registry) do nothing") {
		t.Fatal("expected ON CONFLICT (kind, key, registry) DO NOTHING")
	}
	if !strings.Contains(seedGeofeedTargetsSQL, ", ''") && !strings.Contains(seedGeofeedTargetsSQL, `''`) {
		t.Fatal("expected empty registry literal")
	}
}

func TestSaveGeofeedsEmptyNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.SaveGeofeeds(context.Background(), nil); err != nil {
		t.Fatalf("nil urls: %v", err)
	}
	if err := st.SaveGeofeeds(context.Background(), []string{"", ""}); err != nil {
		t.Fatalf("empty urls: %v", err)
	}
}

func TestPruneStaleGeofeedsSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(pruneStaleGeofeedsSQL)
	if strings.Contains(sql, "truncate") {
		t.Fatal("prune must not TRUNCATE")
	}
	if !strings.Contains(sql, "delete from geofeeds") {
		t.Fatal("expected DELETE FROM geofeeds")
	}
	if !strings.Contains(sql, "last_seen_in_whois is null") {
		t.Fatal("expected NULL last_seen_in_whois")
	}
	if !strings.Contains(sql, "last_seen_in_whois < $1") {
		t.Fatal("expected last_seen_in_whois < $1")
	}
}

func TestMarkStaleGeofeedTargetsGoneSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(markStaleGeofeedTargetsGoneSQL)
	if strings.Contains(sql, "delete from crawl_target") {
		t.Fatal("stale geofeed jobs must be marked gone, not deleted")
	}
	if !strings.Contains(sql, "update crawl_target") {
		t.Fatal("expected UPDATE crawl_target")
	}
	if !strings.Contains(sql, "'geofeed'") {
		t.Fatal("expected kind geofeed")
	}
	if !strings.Contains(sql, "state = '"+strings.ToLower(CrawlStateGone)+"'") && !strings.Contains(sql, "state = '"+CrawlStateGone+"'") {
		t.Fatal("expected state gone")
	}
	if !strings.Contains(sql, "not (key = any($1::text[]))") {
		t.Fatal("expected key NOT IN this run's url slice")
	}
}

func TestPruneStaleGeofeedsEmptyNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	deleted, gone, err := st.PruneStaleGeofeeds(context.Background(), time.Time{}, nil)
	if err != nil || deleted != 0 || gone != 0 {
		t.Fatalf("nil urls: deleted=%d gone=%d err=%v", deleted, gone, err)
	}
	deleted, gone, err = st.PruneStaleGeofeeds(context.Background(), time.Time{}, []string{"", ""})
	if err != nil || deleted != 0 || gone != 0 {
		t.Fatalf("empty urls: deleted=%d gone=%d err=%v", deleted, gone, err)
	}
}

func TestSeedGeofeedTargetsEmptyNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.SeedGeofeedTargets(context.Background(), nil); err != nil {
		t.Fatalf("nil urls: %v", err)
	}
	if err := st.SeedGeofeedTargets(context.Background(), []string{"", ""}); err != nil {
		t.Fatalf("empty urls: %v", err)
	}
}

func TestEnqueueIpnetParentHandleSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(enqueueIpnetParentHandleSQL)
	if !strings.Contains(sql, "insert into crawl_target") {
		t.Fatal("expected INSERT INTO crawl_target")
	}
	if !strings.Contains(sql, "on conflict (kind, key, registry) do nothing") {
		t.Fatal("expected ON CONFLICT DO NOTHING")
	}
	if strings.Contains(sql, "do update") {
		t.Fatal("must not flip in_progress siblings")
	}
	if !strings.Contains(enqueueIpnetParentHandleSQL, CrawlStatePending) {
		t.Fatal("expected pending-only insert")
	}
}

func TestEnqueueIpnetDownCIDRSQL(t *testing.T) {
	t.Parallel()
	// Same INSERT as parent-handle: pending ipnet, ON CONFLICT DO NOTHING.
	sql := strings.ToLower(enqueueIpnetParentHandleSQL)
	if !strings.Contains(sql, "insert into crawl_target") {
		t.Fatal("expected INSERT INTO crawl_target")
	}
	if !strings.Contains(sql, "on conflict (kind, key, registry) do nothing") {
		t.Fatal("expected ON CONFLICT DO NOTHING")
	}
	if strings.Contains(sql, "do update") {
		t.Fatal("must not flip in_progress siblings")
	}
}

func TestEnqueueIpnetDownCIDRNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.EnqueueIpnetDownCIDR(context.Background(), opconst.ARIN, ""); err != nil {
		t.Fatalf("empty key: %v", err)
	}
	if err := st.EnqueueIpnetDownCIDR(context.Background(), "", "192.0.2.0/25"); err != nil {
		t.Fatalf("empty registry: %v", err)
	}
}

func TestEnqueueIpnetParentHandleNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.EnqueueIpnetParentHandle(context.Background(), opconst.ARIN, "", 0); err != nil {
		t.Fatalf("empty handle: %v", err)
	}
	if err := st.EnqueueIpnetParentHandle(context.Background(), "", "NET-FOO", 0); err != nil {
		t.Fatalf("empty registry: %v", err)
	}
	if err := st.EnqueueIpnetParentHandle(context.Background(), opconst.ARIN, "NET-FOO", 6); err != nil {
		t.Fatalf("depth 6: %v", err)
	}
	if err := st.EnqueueIpnetParentHandle(context.Background(), opconst.ARIN, "NET-FOO", -1); err != nil {
		t.Fatalf("depth -1: %v", err)
	}
}

func TestIpnetParentHandleKey(t *testing.T) {
	t.Parallel()
	if got := IpnetParentHandleKey("NET-192-0-2-0-0", 0); got != "handle:d0:NET-192-0-2-0-0" {
		t.Fatalf("got %q", got)
	}
	if got := IpnetParentHandleKey(" PARENT ", 5); got != "handle:d5:PARENT" {
		t.Fatalf("got %q", got)
	}
	if CrawlPriorityParentHandle != 1 {
		t.Fatalf("parent priority = %d, want 1", CrawlPriorityParentHandle)
	}
	if IpnetParentHandleMaxDepth != 5 {
		t.Fatalf("max depth = %d, want 5", IpnetParentHandleMaxDepth)
	}
}

func TestUniqueCIDRs(t *testing.T) {
	t.Parallel()
	if got := uniqueCIDRs(nil); got != nil {
		t.Fatalf("nil input: got %#v, want nil", got)
	}
	if got := uniqueCIDRs([]string{}); got != nil {
		t.Fatalf("empty input: got %#v, want nil", got)
	}
	if got := uniqueCIDRs([]string{"", ""}); len(got) != 0 {
		t.Fatalf("empty keys: got %#v, want empty", got)
	}

	got := uniqueCIDRs([]string{"192.0.2.0/24", "", "192.0.2.0/24", "2001:db8::/32", "192.0.2.0/24"})
	want := []string{"192.0.2.0/24", "2001:db8::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
