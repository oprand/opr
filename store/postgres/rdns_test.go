package postgres

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func TestReplaceRDNSBySourceURLSQLScopedToURL(t *testing.T) {
	t.Parallel()
	stale := strings.ToLower(replaceRDNSDeleteStaleSQL)
	if !strings.Contains(stale, "delete from rdns_delegation") {
		t.Fatal("expected DELETE FROM rdns_delegation")
	}
	if !strings.Contains(stale, "source_url = $1") {
		t.Fatal("replace must filter source_url = $1 so other RIRs / files are kept")
	}
	if !strings.Contains(stale, "rdns_delegation_stg") {
		t.Fatal("stale delete must use the COPY temp set")
	}
	if strings.Contains(stale, "truncate") {
		t.Fatal("must not TRUNCATE the whole table")
	}
}

func TestReplaceRDNSBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.ReplaceRDNSBySourceURL(context.Background(), "", nil); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestReplaceRDNSBySourceURLEmptyRowsError(t *testing.T) {
	t.Parallel()
	var st *Store
	err := st.ReplaceRDNSBySourceURL(context.Background(), "https://ftp.ripe.net/pub/zones/193.in-addr.arpa-RIPE", nil)
	if err == nil {
		t.Fatal("empty rows must error instead of wiping last good rows")
	}
	if !strings.Contains(err.Error(), "must not wipe") {
		t.Fatalf("err=%v", err)
	}
}

func TestListRDNSSourceURLsSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(listRDNSSourceURLsSQL)
	if !strings.Contains(sql, "select distinct source_url") {
		t.Fatal("expected DISTINCT source_url")
	}
	if !strings.Contains(sql, "from rdns_delegation") {
		t.Fatal("expected FROM rdns_delegation")
	}
	if !strings.Contains(sql, "source = $1") {
		t.Fatal("list must filter source = $1")
	}
}

func TestListRDNSSourceURLsEmptySourceError(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.ListRDNSSourceURLs(context.Background(), ""); err == nil {
		t.Fatal("empty source must error")
	}
}

func TestRDNSStatusSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(rdnsStatusBySourceSQL)
	if !strings.Contains(sql, "from rdns_delegation") {
		t.Fatal("expected FROM rdns_delegation")
	}
	if !strings.Contains(sql, "group by source") {
		t.Fatal("expected GROUP BY source")
	}
	if !strings.Contains(sql, "source <> 'iana'") {
		t.Fatal("SOURCES counts must exclude IANA parent rows")
	}
}

func TestCountRDNSBySourceURLSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(countRDNSBySourceURLSQL)
	if !strings.Contains(sql, "select count(*) from rdns_delegation") {
		t.Fatal("expected SELECT COUNT(*) FROM rdns_delegation")
	}
	if !strings.Contains(sql, "source_url = $1") {
		t.Fatal("count must filter source_url = $1")
	}
}

func TestCountRDNSBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.CountRDNSBySourceURL(context.Background(), ""); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestRDNSUpsertConflictsOnZoneSource(t *testing.T) {
	t.Parallel()
	oc := strings.ToLower(rdnsUpsert.onConflict)
	if !strings.Contains(oc, "on conflict (zone, source)") {
		t.Fatal("upsert must conflict on (zone, source) so ERX /8s can exist per RIR")
	}
}

func TestRDNSIANACoverageSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(rdnsIANACutsSQL)
	if !strings.Contains(sql, "source = 'iana'") {
		t.Fatal("IANA coverage must read source=IANA rows")
	}
	if !strings.Contains(sql, "prefix::text") {
		t.Fatal("IANA cuts must cast prefix::text so pgx binary scan can fill a string")
	}
	if !strings.Contains(sql, "delegated_rir") {
		t.Fatal("IANA cuts must select delegated_rir")
	}
	fetched := strings.ToLower(rdnsFetchedZonesSQL)
	if !strings.Contains(fetched, "source <> 'iana'") {
		t.Fatal("fetched checklist must exclude IANA rows")
	}
}

func TestRDNSWhoisEnrichSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(rdnsWhoisEnrichSQL)
	for _, col := range []string{"org", "admin_c", "tech_c", "mnt_by"} {
		if !strings.Contains(sql, col) {
			t.Fatalf("whois enrich count missing %s", col)
		}
	}
}

func TestRDNSPTRStatusSQL(t *testing.T) {
	t.Parallel()
	tot := strings.ToLower(rdnsPTRStatusTotalsSQL)
	if !strings.Contains(tot, "from rdns_ptr") {
		t.Fatal("PTR totals must read rdns_ptr")
	}
	if !strings.Contains(tot, "ptr is not null") {
		t.Fatal("with-ptr count must be ptr IS NOT NULL")
	}
	if !strings.Contains(tot, "max(fetched_at)") {
		t.Fatal("PTR clock must be MAX(fetched_at)")
	}
	if strings.Contains(tot, "rdns_delegation") {
		t.Fatal("PTR status must not recompute leaves from rdns_delegation")
	}
	rc := strings.ToLower(rdnsPTRStatusRcodeSQL)
	if !strings.Contains(rc, "from rdns_ptr") {
		t.Fatal("rcode counts must read rdns_ptr")
	}
	if !strings.Contains(rc, "group by") {
		t.Fatal("rcode counts must GROUP BY rcode")
	}
	if strings.Contains(rc, "rdns_delegation") {
		t.Fatal("rcode counts must not join rdns_delegation")
	}
}

func TestEvaluateRDNSPTRStatusNeverNotStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	empty := EvaluateRDNSPTRStatus(0, 0, nil, nil, DefaultRDNSStaleAfter, now)
	if !empty.Never {
		t.Fatal("empty rdns_ptr is NEVER")
	}
	if empty.Stale {
		t.Fatal("NEVER must not also be STALE")
	}
	if empty.Rows != 0 || empty.WithPTR != 0 || empty.Empty != 0 {
		t.Fatalf("empty counts: %+v", empty)
	}
	want := []string{"NOERROR", "NXDOMAIN", "NODATA", "SERVFAIL", "REFUSED", "TIMEOUT", "ERROR", "other"}
	if len(empty.Rcodes) != len(want) {
		t.Fatalf("pinned rcodes: %+v", empty.Rcodes)
	}
	for i, name := range want {
		if empty.Rcodes[i].Rcode != name || empty.Rcodes[i].Rows != 0 {
			t.Fatalf("rcode[%d]=%+v want %s 0", i, empty.Rcodes[i], name)
		}
	}

	old := now.Add(-DefaultRDNSStaleAfter - time.Hour)
	stale := EvaluateRDNSPTRStatus(12, 4, &old, map[string]int64{"NOERROR": 4, "NXDOMAIN": 8}, DefaultRDNSStaleAfter, now)
	if stale.Never || !stale.Stale {
		t.Fatalf("stale ptr: %+v", stale)
	}
	if stale.Empty != 8 {
		t.Fatalf("empty=%d want 8", stale.Empty)
	}
	if stale.Rcodes[0].Rows != 4 || stale.Rcodes[1].Rows != 8 {
		t.Fatalf("rcode rows: %+v", stale.Rcodes)
	}
}

func TestRDNSStatusJSONIncludesPTR(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	snap := RDNSStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  DefaultRDNSStaleAfter.String(),
		PTR:         EvaluateRDNSPTRStatus(0, 0, nil, nil, DefaultRDNSStaleAfter, now),
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"ptr"`, `"with_ptr"`, `"rcodes"`, `"last_fetched_at"`, `"never"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("json missing %s: %s", want, s)
		}
	}
}

func TestRDNSUpsertKeepsZoneFileNS(t *testing.T) {
	t.Parallel()
	oc := strings.ToLower(rdnsUpsert.onConflict)
	if !strings.Contains(oc, "when excluded.fetch_method in ('zone_file', 'iana_zone') then excluded.nservers") {
		t.Fatal("zone-file / IANA ingest must overwrite nservers")
	}
	if !strings.Contains(oc, "when cardinality(rdns_delegation.nservers) > 0 then rdns_delegation.nservers") {
		t.Fatal("WHOIS nserver must not replace existing zone-file NS")
	}
	if !strings.Contains(oc, "coalesce(nullif(excluded.org, ''), rdns_delegation.org)") {
		t.Fatal("WHOIS org must enrich without wiping on empty zone ingest")
	}
}

func TestRIRFromNameserver(t *testing.T) {
	t.Parallel()
	if got := RIRFromNameserver("arin.authdns.ripe.net"); got != "ARIN" {
		t.Fatalf("got %s, want ARIN", got)
	}
	if got := RIRFromNameserver("ns.afrinic.net."); got != "AFRINIC" {
		t.Fatalf("got %s", got)
	}
	if got := RIRFromNameserver("a.in-addr-servers.arpa"); got != "" {
		t.Fatalf("apex IANA NS must not map to a RIR: %s", got)
	}
}

func TestEvaluateRDNSDumpNeverNotStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	d := EvaluateRDNSDump(IANAInAddrURL, nil, nil, false, DefaultRDNSStaleAfter, now)
	if !d.Never {
		t.Fatal("missing metadata is NEVER")
	}
	if d.Stale {
		t.Fatal("NEVER must not also be STALE")
	}
	old := now.Add(-DefaultRDNSStaleAfter - time.Hour)
	stale := EvaluateRDNSDump(IANAInAddrURL, &old, &old, true, DefaultRDNSStaleAfter, now)
	if stale.Never || !stale.Stale {
		t.Fatalf("stale dump: %+v", stale)
	}
}

func TestRDNSDumpURLs(t *testing.T) {
	t.Parallel()
	if IANAInAddrURL != "https://www.internic.net/zones/in-addr.arpa.zone" {
		t.Fatalf("IANAInAddrURL=%s", IANAInAddrURL)
	}
	if IANAIP6URL != "https://www.internic.net/zones/ip6.arpa" {
		t.Fatalf("IANAIP6URL=%s", IANAIP6URL)
	}
	if DefaultRDNSStaleAfter != 168*time.Hour {
		t.Fatalf("DefaultRDNSStaleAfter=%s", DefaultRDNSStaleAfter)
	}
}

func TestReplaceRDNSBySourceURLLeavesOtherSourceURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsTestStore(t)
	ctx := context.Background()
	ripeURL := "https://example.test/rdns/" + t.Name() + "/193.in-addr.arpa-RIPE"
	apnicURL := "https://example.test/rdns/" + t.Name() + "/1.in-addr.arpa-APNIC"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(),
			`DELETE FROM rdns_delegation WHERE source_url LIKE $1`,
			"https://example.test/rdns/"+t.Name()+"/%")
	})

	ripeRow := testRDNSRow("1.2.0.192.in-addr.arpa.", "192.0.2.1/32", "RIPE", ripeURL)
	apnicRow := testRDNSRow("2.2.0.192.in-addr.arpa.", "192.0.2.2/32", "APNIC", apnicURL)
	if err := st.ReplaceRDNSBySourceURL(ctx, ripeURL, []RDNSDelegation{ripeRow}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceRDNSBySourceURL(ctx, apnicURL, []RDNSDelegation{apnicRow}); err != nil {
		t.Fatal(err)
	}

	ripe2 := testRDNSRow("3.2.0.192.in-addr.arpa.", "192.0.2.3/32", "RIPE", ripeURL)
	if err := st.ReplaceRDNSBySourceURL(ctx, ripeURL, []RDNSDelegation{ripe2}); err != nil {
		t.Fatal(err)
	}

	var ripeN, apnicN int64
	if err := st.DB.QueryRow(ctx, `SELECT count(*) FROM rdns_delegation WHERE source_url = $1`, ripeURL).Scan(&ripeN); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, `SELECT count(*) FROM rdns_delegation WHERE source_url = $1`, apnicURL).Scan(&apnicN); err != nil {
		t.Fatal(err)
	}
	if ripeN != 1 {
		t.Fatalf("ripe rows=%d, want 1 after replace", ripeN)
	}
	if apnicN != 1 {
		t.Fatalf("apnic rows=%d, want 1 (untouched)", apnicN)
	}

	var apnicZone string
	if err := st.DB.QueryRow(ctx,
		`SELECT zone FROM rdns_delegation WHERE source_url = $1`, apnicURL).Scan(&apnicZone); err != nil {
		t.Fatal(err)
	}
	if apnicZone != apnicRow.Zone {
		t.Fatalf("apnic zone=%s, want %s", apnicZone, apnicRow.Zone)
	}

	var ripeZone string
	if err := st.DB.QueryRow(ctx,
		`SELECT zone FROM rdns_delegation WHERE source_url = $1`, ripeURL).Scan(&ripeZone); err != nil {
		t.Fatal(err)
	}
	if ripeZone != ripe2.Zone {
		t.Fatalf("ripe zone=%s, want replaced %s", ripeZone, ripe2.Zone)
	}
}

func TestUpsertRDNSDelegationsKeepsZoneNS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsTestStore(t)
	ctx := context.Background()
	zoneURL := "https://example.test/rdns/" + t.Name() + "/193.in-addr.arpa-RIPE"
	whoisURL := "https://example.test/rdns/" + t.Name() + "/ripe.db.domain.gz"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(),
			`DELETE FROM rdns_delegation WHERE source_url LIKE $1`,
			"https://example.test/rdns/"+t.Name()+"/%")
	})

	zoneRow := testRDNSRow("0.0.193.in-addr.arpa.", "193.0.0.0/24", "RIPE", zoneURL)
	zoneRow.Nservers = []string{"ns.ripe.net"}
	if err := st.ReplaceRDNSBySourceURL(ctx, zoneURL, []RDNSDelegation{zoneRow}); err != nil {
		t.Fatal(err)
	}

	method := FetchMethodWhoisDomain
	whois := testRDNSRow("0.0.193.in-addr.arpa.", "193.0.0.0/24", "RIPE", whoisURL)
	whois.Nservers = []string{"whois-only.example.net"}
	whois.Org = "ORG-RIEN1-RIPE"
	whois.AdminC = []string{"CREW-RIPE"}
	whois.FetchMethod = &method
	whois.IsPartial = true
	if err := st.UpsertRDNSDelegations(ctx, []RDNSDelegation{whois}); err != nil {
		t.Fatal(err)
	}

	var ns []string
	var org *string
	if err := st.DB.QueryRow(ctx,
		`SELECT nservers, org FROM rdns_delegation WHERE source_url = $1`, zoneURL,
	).Scan(&ns, &org); err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || ns[0] != "ns.ripe.net" {
		t.Fatalf("zone NS must win: %v", ns)
	}
	if org == nil || *org != "ORG-RIEN1-RIPE" {
		t.Fatalf("org=%v", org)
	}
}

func testRDNSRow(zone, prefix, source, url string) RDNSDelegation {
	now := time.Now().UTC()
	m := FetchMethodZoneFile
	return RDNSDelegation{
		Zone:               zone,
		Prefix:             prefix,
		Nservers:           []string{"ns.example.net"},
		Source:             source,
		SourceURL:          url,
		MetaAddedAt:        &now,
		LastFetchedAt:      &now,
		FetchMethod:        &m,
		LastSeenInSourceAt: &now,
	}
}

func rdnsTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("OPR_TEST_DSN")
	if dsn == "" {
		dsn = "postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres ping: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'rdns_delegation'`).Scan(&n); err != nil || n == 0 {
		t.Skip("rdns_delegation table missing (run migrations)")
	}
	var orgCol int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'rdns_delegation' AND column_name = 'org'`).Scan(&orgCol); err != nil || orgCol == 0 {
		t.Skip("rdns_delegation.org missing (run migration 0078)")
	}
	return &Store{DB: pool, logger: zap.NewNop()}
}
