package postgres

import (
	"strings"
	"testing"

	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"
)

func TestWhoisUpsertIncludesFreshnessColumns(t *testing.T) {
	t.Parallel()
	want := []string{
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	}
	specs := []whoisUpsertSpec{
		whoisAutNumUpsert,
		whoisOrgUpsert,
		whoisRoleUpsert,
		whoisInetNumUpsert,
		whoisInet6NumUpsert,
		whoisRouteUpsert,
		whoisRoute6Upsert,
		whoisAsSetUpsert,
		whoisAsBlockUpsert,
		whoisIrtUpsert,
	}
	for _, spec := range specs {
		sql := spec.insertSQL()
		for _, col := range want {
			if !containsColumn(spec.columns, col) {
				t.Errorf("%s missing COPY column %s", spec.live, col)
			}
			if !strings.Contains(sql, "EXCLUDED."+col) {
				t.Errorf("%s ON CONFLICT missing COALESCE for %s", spec.live, col)
			}
		}
	}

	dummyInet := whoisInetNumCopyRow(&whoisdb.WhoisInetNum{})
	if len(dummyInet) != len(whoisInetNumUpsert.columns) {
		t.Errorf("inetnum copy row len %d != columns %d", len(dummyInet), len(whoisInetNumUpsert.columns))
	}
	dummyInet6 := whoisInet6NumCopyRow(&whoisdb.WhoisInet6Num{})
	if len(dummyInet6) != len(whoisInet6NumUpsert.columns) {
		t.Errorf("inet6num copy row len %d != columns %d", len(dummyInet6), len(whoisInet6NumUpsert.columns))
	}
	dummyRoute := whoisRouteCopyRow(&whoisdb.WhoisRoute{})
	if len(dummyRoute) != len(whoisRouteUpsert.columns) {
		t.Errorf("route copy row len %d != columns %d", len(dummyRoute), len(whoisRouteUpsert.columns))
	}
	dummyRoute6 := whoisRoute6CopyRow(&whoisdb.WhoisRoute6{})
	if len(dummyRoute6) != len(whoisRoute6Upsert.columns) {
		t.Errorf("route6 copy row len %d != columns %d", len(dummyRoute6), len(whoisRoute6Upsert.columns))
	}
	dummyAsSet := whoisAsSetCopyRow(&whoisdb.WhoisAsSet{})
	if len(dummyAsSet) != len(whoisAsSetUpsert.columns) {
		t.Errorf("as-set copy row len %d != columns %d", len(dummyAsSet), len(whoisAsSetUpsert.columns))
	}
	dummyAsBlock := whoisAsBlockCopyRow(&whoisdb.WhoisAsBlock{})
	if len(dummyAsBlock) != len(whoisAsBlockUpsert.columns) {
		t.Errorf("as-block copy row len %d != columns %d", len(dummyAsBlock), len(whoisAsBlockUpsert.columns))
	}
	dummyIrt := whoisIrtCopyRow(&whoisdb.WhoisIrt{})
	if len(dummyIrt) != len(whoisIrtUpsert.columns) {
		t.Errorf("irt copy row len %d != columns %d", len(dummyIrt), len(whoisIrtUpsert.columns))
	}
}

func TestWhoisAutNumSparseUpsertDoesNotClobberSource(t *testing.T) {
	t.Parallel()
	sql := whoisAutNumUpsert.insertSQL()
	// Empty string is what asnames persists (source is NOT NULL). Without
	// NULLIF, COALESCE(EXCLUDED.source, existing) would wipe a dump RIR source.
	if !strings.Contains(sql, "source = COALESCE(NULLIF(EXCLUDED.source, ''), whoisdb_autnum.source)") {
		t.Fatalf("autnum ON CONFLICT must treat empty source as unset:\n%s", sql)
	}
	for _, col := range []string{"as_name", "country_code", "fetch_method"} {
		want := col + " = COALESCE(EXCLUDED." + col + ","
		if !strings.Contains(sql, want) {
			t.Errorf("autnum ON CONFLICT missing COALESCE for %s", col)
		}
	}

	sparse := whoisAutNumCopyRow(&whoisdb.WhoisAutNum{
		AutNum: 10000,
		ASName: "NCM - Nagasaki Cable Media Inc.",
	})
	if len(sparse) != len(whoisAutNumUpsert.columns) {
		t.Fatalf("sparse copy row len %d != columns %d", len(sparse), len(whoisAutNumUpsert.columns))
	}
	sourceIdx := -1
	asNameIdx := -1
	fetchIdx := -1
	for i, col := range whoisAutNumUpsert.columns {
		switch col {
		case "source":
			sourceIdx = i
		case "as_name":
			asNameIdx = i
		case "fetch_method":
			fetchIdx = i
		}
	}
	if sourceIdx < 0 || asNameIdx < 0 || fetchIdx < 0 {
		t.Fatal("missing source/as_name/fetch_method columns")
	}
	if s, ok := sparse[sourceIdx].(*string); !ok || s != nil {
		t.Fatalf("nil-Source copy must pass nil *string (COALESCE keeps dump source); got %T %v", sparse[sourceIdx], sparse[sourceIdx])
	}
	if sparse[asNameIdx] != "NCM - Nagasaki Cable Media Inc." {
		t.Fatalf("as_name=%v", sparse[asNameIdx])
	}
	if s, ok := sparse[fetchIdx].(*string); !ok || s != nil {
		t.Fatalf("unset fetch_method should copy as nil *string so COALESCE keeps dump value, got %T %v", sparse[fetchIdx], sparse[fetchIdx])
	}
}

func TestWhoisAsSetAsBlockIrtUpsertMatchesRoleCoalesce(t *testing.T) {
	t.Parallel()
	for _, spec := range []whoisUpsertSpec{whoisAsSetUpsert, whoisAsBlockUpsert, whoisIrtUpsert} {
		sql := spec.insertSQL()
		if strings.Contains(sql, "UNNEST") || strings.Contains(sql, "||") {
			t.Errorf("%s must COALESCE arrays like role, not concat: %s", spec.live, sql)
		}
		if !strings.Contains(sql, "meta_added_at = NOW()") {
			t.Errorf("%s missing meta_added_at bump", spec.live)
		}
	}
	if !strings.Contains(whoisAsSetUpsert.insertSQL(), "ON CONFLICT (as_set, source)") {
		t.Fatal("as-set unique key")
	}
	if !strings.Contains(whoisAsBlockUpsert.insertSQL(), "ON CONFLICT (asn_start, asn_end, source)") {
		t.Fatal("as-block unique key")
	}
	if !strings.Contains(whoisIrtUpsert.insertSQL(), "ON CONFLICT (irt, source)") {
		t.Fatal("irt unique key")
	}
}

func TestDedupWhoisAsSetAsBlockIrtLastWins(t *testing.T) {
	t.Parallel()
	apnic := "APNIC"
	ripe := "RIPE"
	first := []string{"AS1"}
	second := []string{"AS1", "AS-FOO"}

	asSets := dedupWhoisAsSet([]*whoisdb.WhoisAsSet{
		{AsSet: "AS-CLOUDFLARE", Source: &apnic, Members: &first},
		{AsSet: "AS-CLOUDFLARE", Source: &apnic, Members: &second},
		{AsSet: "AS-CLOUDFLARE", Source: &ripe, Members: &first},
		{AsSet: "", Source: &apnic},
		{AsSet: "AS-NIL", Source: nil},
		nil,
	})
	if len(asSets) != 2 {
		t.Fatalf("as-set dedup len=%d, want 2", len(asSets))
	}
	if asSets[0].Members == nil || len(*asSets[0].Members) != 2 {
		t.Fatalf("last-wins members=%v", asSets[0].Members)
	}
	if asSets[1].Source == nil || *asSets[1].Source != ripe {
		t.Fatalf("second key source=%v", asSets[1].Source)
	}

	blocks := dedupWhoisAsBlock([]*whoisdb.WhoisAsBlock{
		{AsnStart: 37945, AsnEnd: 37950, Source: &apnic, AsBlock: "first"},
		{AsnStart: 37945, AsnEnd: 37950, Source: &apnic, AsBlock: "last"},
		{AsnStart: 0, AsnEnd: 10, Source: &apnic},
		{AsnStart: 20, AsnEnd: 10, Source: &apnic},
		{AsnStart: 1, AsnEnd: 2, Source: nil},
		nil,
	})
	if len(blocks) != 1 || blocks[0].AsBlock != "last" {
		t.Fatalf("as-block dedup=%+v", blocks)
	}

	irts := dedupWhoisIrt([]*whoisdb.WhoisIrt{
		{Irt: "IRT-APNICRANDNET-AU", Source: &apnic},
		{Irt: "IRT-APNICRANDNET-AU", Source: &apnic, Auth: &[]string{"PGP"}},
		{Irt: "", Source: &apnic},
		{Irt: "IRT-NIL", Source: nil},
		nil,
	})
	if len(irts) != 1 || irts[0].Auth == nil || (*irts[0].Auth)[0] != "PGP" {
		t.Fatalf("irt dedup=%+v", irts)
	}
}

func TestDedupWhoisAutNumDropsNilSourceKeepsEmpty(t *testing.T) {
	t.Parallel()
	empty := ""
	apnic := "APNIC"
	got := dedupWhoisAutNum([]*whoisdb.WhoisAutNum{
		{AutNum: 1, ASName: "nil source", Source: nil},
		{AutNum: 2, ASName: "asnames", Source: &empty},
		{AutNum: 3, ASName: "dump", Source: &apnic},
		nil,
		{AutNum: 0, ASName: "zero", Source: &empty},
	})
	if len(got) != 2 {
		t.Fatalf("got %d, want 2 (empty-source asnames + dump)", len(got))
	}
	if got[0].AutNum != 2 || got[0].Source == nil || *got[0].Source != "" {
		t.Fatalf("asnames row: %+v", got[0])
	}
	if got[1].AutNum != 3 || got[1].Source == nil || *got[1].Source != "APNIC" {
		t.Fatalf("dump row: %+v", got[1])
	}
}

func containsColumn(cols []string, want string) bool {
	for _, c := range cols {
		if c == want {
			return true
		}
	}
	return false
}
