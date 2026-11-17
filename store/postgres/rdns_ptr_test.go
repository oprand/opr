package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestListRDNSLeavesSQLIsDeepestCuts(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(listRDNSLeavesSQL)
	if !strings.Contains(sql, "source <> 'iana'") {
		t.Fatal("leaves must exclude IANA parent cuts")
	}
	if !strings.Contains(sql, "c.prefix << d.prefix") {
		t.Fatal("leaf query must use more-specific prefix << parent")
	}
	if !strings.Contains(sql, "prefix::text") {
		t.Fatal("prefix::text so pgx binary scan fills a string")
	}
	if !strings.Contains(sql, "d.prefix <<=") {
		t.Fatal("zone scope must include child leaves via prefix <<=")
	}
	if !strings.Contains(sql, "c.prefix &&") {
		t.Fatal("anti-join must be scoped with c.prefix && so --zone/--prefix hit GiST")
	}
	if !strings.Contains(sql, "d.prefix &&") {
		t.Fatal("outer filter must use d.prefix && scope")
	}
	if !strings.Contains(sql, "not ($2::text = '' and $3::text = '')") {
		t.Fatal("leaf SQL must refuse unscoped prefix+zone so the anti-join cannot run over the whole table")
	}
}

func TestListRDNSLeavesUnscopedRefused(t *testing.T) {
	t.Parallel()
	var st *Store
	_, err := st.ListRDNSLeaves(context.Background(), RDNSLeafQuery{})
	if err == nil {
		t.Fatal("unscoped ListRDNSLeaves must error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unscoped") {
		t.Fatalf("err=%v", err)
	}
}

func TestRDNSPTRUpsertConflictsOnIP(t *testing.T) {
	t.Parallel()
	oc := strings.ToLower(rdnsPTRUpsert.onConflict)
	if !strings.Contains(oc, "on conflict (ip)") {
		t.Fatal("unique key is (ip)")
	}
	if !strings.Contains(oc, "masklen(excluded.source_prefix) > masklen(rdns_ptr.source_prefix)") {
		t.Fatal("upsert must prefer the more-specific source_prefix")
	}
	if !strings.Contains(oc, "excluded.ptr is not null") {
		t.Fatal("same-specificity PTR name must replace empty")
	}
}

func TestShouldReplaceRDNSPTR(t *testing.T) {
	t.Parallel()
	name := "host.example"
	child := RDNSPTR{IP: "192.0.2.1", PTR: &name, Rcode: "NOERROR", SourcePrefix: "192.0.2.0/27"}
	parentEmpty := RDNSPTR{IP: "192.0.2.1", Rcode: "NODATA", SourcePrefix: "192.0.2.0/24"}
	if ShouldReplaceRDNSPTR(child, parentEmpty) {
		t.Fatal("parent NODATA must not replace child PTR")
	}
	if !ShouldReplaceRDNSPTR(parentEmpty, child) {
		t.Fatal("child PTR must replace parent NODATA")
	}
	sameEmpty := RDNSPTR{IP: "192.0.2.1", Rcode: "NXDOMAIN", SourcePrefix: "192.0.2.0/27"}
	if ShouldReplaceRDNSPTR(child, sameEmpty) {
		t.Fatal("same-length empty must not replace a PTR name")
	}
	if !ShouldReplaceRDNSPTR(sameEmpty, child) {
		t.Fatal("same-length PTR name must replace empty")
	}
}

func TestUpsertRDNSPTREmptyNoOp(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.UpsertRDNSPTR(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertRDNSPTRPostgresRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRTestStore(t)
	if !rdnsPTRHasSourcePrefix(t, st) {
		t.Skip("rdns_ptr.source_prefix missing (run migration 0081)")
	}
	ctx := context.Background()
	ip := "192.0.2.77"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr WHERE ip = $1`, ip)
	})
	nx := "NXDOMAIN"
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP:        ip,
		QueriedNS: "ns.example.net",
		FetchedAt: time.Now().UTC(),
		Rcode:     nx,
	}}); err != nil {
		t.Fatal(err)
	}
	var ptr *string
	var rcode string
	if err := st.DB.QueryRow(ctx, `SELECT ptr, rcode FROM rdns_ptr WHERE ip = $1::inet`, ip).Scan(&ptr, &rcode); err != nil {
		t.Fatal(err)
	}
	if ptr != nil || rcode != nx {
		t.Fatalf("ptr=%v rcode=%s", ptr, rcode)
	}
}

func TestUpsertRDNSPTRChildSurvivesParentNODATA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRTestStore(t)
	if !rdnsPTRHasSourcePrefix(t, st) {
		t.Skip("rdns_ptr.source_prefix missing (run migration 0081)")
	}
	ctx := context.Background()
	ip := "192.0.2.78"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr WHERE ip = $1`, ip)
	})
	name := "child.example"
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP: ip, PTR: &name, QueriedNS: "ns.child", FetchedAt: time.Now().UTC(),
		Rcode: "NOERROR", SourcePrefix: "192.0.2.64/27",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP: ip, PTR: nil, QueriedNS: "ns.parent", FetchedAt: time.Now().UTC(),
		Rcode: "NODATA", SourcePrefix: "192.0.2.0/24",
	}}); err != nil {
		t.Fatal(err)
	}
	var ptr *string
	var rcode, src string
	if err := st.DB.QueryRow(ctx, `SELECT ptr, rcode, source_prefix::text FROM rdns_ptr WHERE ip = $1::inet`, ip).Scan(&ptr, &rcode, &src); err != nil {
		t.Fatal(err)
	}
	if ptr == nil || *ptr != name || rcode != "NOERROR" {
		t.Fatalf("parent NODATA overwrote child: ptr=%v rcode=%s src=%s", ptr, rcode, src)
	}
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP: ip, PTR: &name, QueriedNS: "ns.child", FetchedAt: time.Now().UTC(),
		Rcode: "NOERROR", SourcePrefix: "192.0.2.64/27",
	}}); err != nil {
		t.Fatal(err)
	}
	// reverse order: parent first, then child
	ip2 := "192.0.2.79"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr WHERE ip = $1`, ip2)
	})
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP: ip2, PTR: nil, QueriedNS: "ns.parent", FetchedAt: time.Now().UTC(),
		Rcode: "NODATA", SourcePrefix: "192.0.2.0/24",
	}}); err != nil {
		t.Fatal(err)
	}
	childName := "more-specific.example"
	if err := st.UpsertRDNSPTR(ctx, []RDNSPTR{{
		IP: ip2, PTR: &childName, QueriedNS: "ns.child", FetchedAt: time.Now().UTC(),
		Rcode: "NOERROR", SourcePrefix: "192.0.2.64/27",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, `SELECT ptr, rcode FROM rdns_ptr WHERE ip = $1::inet`, ip2).Scan(&ptr, &rcode); err != nil {
		t.Fatal(err)
	}
	if ptr == nil || *ptr != childName {
		t.Fatalf("child PTR did not replace parent NODATA: ptr=%v rcode=%s", ptr, rcode)
	}
}

func rdnsPTRHasSourcePrefix(t *testing.T, st *Store) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var n int
	if err := st.DB.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'rdns_ptr' AND column_name = 'source_prefix'`).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func rdnsPTRTestStore(t *testing.T) *Store {
	t.Helper()
	st := rdnsTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	var n int
	if err := st.DB.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'rdns_ptr'`).Scan(&n); err != nil || n == 0 {
		t.Skip("rdns_ptr table missing (run migration 0079)")
	}
	return st
}
