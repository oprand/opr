package whoisdb

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"

	mapset "github.com/deckarep/golang-set/v2"
	"go.uber.org/zap"
)

func TestParseWhoisDBStampsBulkDumpTypes(t *testing.T) {
	records := parseFixture(t, "testdata/contacts-and-route.txt", []opconst.RecordType{
		opconst.RecordTypeOrg,
		opconst.RecordTypeRole,
		opconst.RecordTypeRoute,
	})

	var sawOrg, sawRole, sawPerson, sawRoute bool
	for _, rec := range records {
		stampBulkDumpRecord(t, rec)
		switch rec.GetRecordType() {
		case opconst.RecordTypeOrg:
			org, ok := rec.(*whoisdb_store.WhoisOrganization)
			if !ok {
				t.Fatalf("org type assertion failed: %T", rec)
			}
			assertBulkDump(t, org.FetchMethod, org.LastFetchedAt)
			if org.Organization != "ORG-TEST1-AFRINIC" {
				t.Fatalf("org=%q", org.Organization)
			}
			sawOrg = true
		case opconst.RecordTypeRole:
			role, ok := rec.(*whoisdb_store.WhoisRole)
			if !ok {
				t.Fatalf("role type assertion failed: %T", rec)
			}
			assertBulkDump(t, role.FetchMethod, role.LastFetchedAt)
			switch role.NicHdl {
			case "TR1-AFRINIC":
				sawRole = true
			case "TP1-AFRINIC":
				if role.RdapKind == nil || *role.RdapKind != "individual" {
					t.Fatalf("person dumped as role must set rdap_kind=individual, got %v", role.RdapKind)
				}
				if role.Role == nil || *role.Role != "Test Person" {
					t.Fatalf("person name stored on role: got %v", role.Role)
				}
				sawPerson = true
			default:
				t.Fatalf("unexpected nic-hdl %q", role.NicHdl)
			}
		case opconst.RecordTypeRoute:
			route, ok := rec.(*whoisdb_store.WhoisRoute)
			if !ok {
				t.Fatalf("route type assertion failed: %T", rec)
			}
			assertBulkDump(t, route.FetchMethod, route.LastFetchedAt)
			if route.Route != "196.192.103.0/24" {
				t.Fatalf("route=%q", route.Route)
			}
			sawRoute = true
		default:
			t.Fatalf("unexpected record type %q", rec.GetRecordType())
		}
	}
	if !sawOrg || !sawRole || !sawPerson || !sawRoute {
		t.Fatalf("missing parsed types: org=%v role=%v person=%v route=%v", sawOrg, sawRole, sawPerson, sawRoute)
	}
}

func parseFixture(t *testing.T, path string, accepted []opconst.RecordType, opts ...ParseOption) []whoisdb_store.WhoisRecord {
	t.Helper()
	recs, _ := parseFixtureSource(t, path, accepted, &whoisDBSource{url: path, isAuthoritative: true, source: opconst.AFRINIC}, opts...)
	return recs
}

func parseFixtureSource(t *testing.T, path string, accepted []opconst.RecordType, src *whoisDBSource, opts ...ParseOption) ([]whoisdb_store.WhoisRecord, *WhoisDBAggregator) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	recordChan := make(chan whoisdb_store.WhoisRecord, 32)
	wdb := &WhoisDBAggregator{
		Logger:          zap.NewNop(),
		RecordChan:      recordChan,
		ForceSaveSignal: make(chan struct{}, 2),
		Geofeeds:        mapset.NewSet[string](),
		StatusMetadata: WhoisDBStatusMetadata{
			URLs: make(map[string]*WhoisDBURLStatus),
		},
	}
	if src.url == "" {
		src.url = path
	}
	wdb.StatusMetadata.URLs[statusKey(src.url, accepted)] = &WhoisDBURLStatus{}

	wdb.ParseWhoisDBFile(context.Background(), bufio.NewScanner(f), accepted, src, opts...)
	close(recordChan)

	var out []whoisdb_store.WhoisRecord
	for rec := range recordChan {
		out = append(out, rec)
	}
	return out, wdb
}

func stampBulkDumpRecord(t *testing.T, rec whoisdb_store.WhoisRecord) {
	t.Helper()
	switch v := rec.(type) {
	case *whoisdb_store.WhoisAutNum:
		stampBulkDump(v)
	case *whoisdb_store.WhoisInetNum:
		stampBulkDump(v)
	case *whoisdb_store.WhoisInet6Num:
		stampBulkDump(v)
	case *whoisdb_store.WhoisOrganization:
		stampBulkDump(v)
	case *whoisdb_store.WhoisRole:
		stampBulkDump(v)
	case *whoisdb_store.WhoisRoute:
		stampBulkDump(v)
	case *whoisdb_store.WhoisRoute6:
		stampBulkDump(v)
	case *whoisdb_store.WhoisAsSet:
		stampBulkDump(v)
	case *whoisdb_store.WhoisAsBlock:
		stampBulkDump(v)
	case *whoisdb_store.WhoisIrt:
		stampBulkDump(v)
	default:
		t.Fatalf("cannot stamp %T", rec)
	}
}

func assertBulkDump(t *testing.T, method *string, fetched interface{}) {
	t.Helper()
	if method == nil || *method != whoisdb_store.FetchMethodBulkDump {
		t.Fatalf("fetch_method=%v, want %q", method, whoisdb_store.FetchMethodBulkDump)
	}
	if fetched == nil {
		t.Fatal("last_fetched_at must be set")
	}
}

func TestParseWhoisDBGeofeedAuthoritativeInetnumOnly(t *testing.T) {
	accepted := []opconst.RecordType{
		opconst.RecordTypeInetNum,
		opconst.RecordTypeInet6Num,
		opconst.RecordTypeAutNum,
	}
	src := &whoisDBSource{url: "testdata/geofeed.txt", isAuthoritative: true, source: opconst.RIPE}
	records, wdb := parseFixtureSource(t, "testdata/geofeed.txt", accepted, src)

	wantURLs := []string{
		"https://ripe.example/official.csv",
		"https://ripe.example/remarks.csv",
		"https://apnic.example/v6.csv",
		"https://afrinic.example/feed.csv",
		"https://arin.example/feed.csv",
		"https://wrap.example/feed.csv",
		"http://example.com/Feed.csv",
	}
	for _, u := range wantURLs {
		if !wdb.Geofeeds.Contains(u) {
			t.Errorf("Geofeeds missing %q; have %v", u, wdb.Geofeeds.ToSlice())
		}
	}
	if wdb.Geofeeds.Contains("https://autnum.example/should-not-collect.csv") {
		t.Error("aut-num geofeed must not be collected")
	}

	got := map[string]string{}
	var sawAutnum bool
	for _, rec := range records {
		switch v := rec.(type) {
		case *whoisdb_store.WhoisInetNum:
			if v.Netname == nil {
				t.Fatalf("inetnum missing netname: %+v", v)
			}
			got[*v.Netname] = derefString(v.Geofeed)
		case *whoisdb_store.WhoisInet6Num:
			if v.Netname == nil {
				t.Fatalf("inet6num missing netname: %+v", v)
			}
			got[*v.Netname] = derefString(v.Geofeed)
		case *whoisdb_store.WhoisAutNum:
			sawAutnum = true
		default:
			t.Fatalf("unexpected type %T", rec)
		}
	}
	if !sawAutnum {
		t.Fatal("expected aut-num in fixture")
	}
	wantFields := map[string]string{
		"RIPE-GEOFEED":    "https://ripe.example/official.csv",
		"APNIC-GEOFEED":   "https://apnic.example/v6.csv",
		"AFRINIC-GEOFEED": "https://afrinic.example/feed.csv",
		"ARIN-GEOFEED":    "https://arin.example/feed.csv",
		"WRAP-GEOFEED":    "https://wrap.example/feed.csv",
		"CASE-GEOFEED":    "http://example.com/Feed.csv",
	}
	for name, url := range wantFields {
		if got[name] != url {
			t.Errorf("%s.Geofeed = %q, want %q", name, got[name], url)
		}
	}
}

func TestParseWhoisDBGeofeedSkipsNonAuthoritative(t *testing.T) {
	accepted := []opconst.RecordType{
		opconst.RecordTypeInetNum,
		opconst.RecordTypeInet6Num,
		opconst.RecordTypeAutNum,
	}
	src := &whoisDBSource{url: "testdata/geofeed.txt", isAuthoritative: false, source: "RADB"}
	records, wdb := parseFixtureSource(t, "testdata/geofeed.txt", accepted, src)
	if wdb.Geofeeds.Cardinality() != 0 {
		t.Fatalf("non-authoritative Geofeeds = %v, want empty", wdb.Geofeeds.ToSlice())
	}
	for _, rec := range records {
		switch v := rec.(type) {
		case *whoisdb_store.WhoisInetNum:
			if v.Geofeed != nil {
				t.Errorf("inetnum %v Geofeed=%q, want unset", v.Netname, *v.Geofeed)
			}
		case *whoisdb_store.WhoisInet6Num:
			if v.Geofeed != nil {
				t.Errorf("inet6num %v Geofeed=%q, want unset", v.Netname, *v.Geofeed)
			}
		}
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestParseWhoisDBAsSetAsBlockIrt(t *testing.T) {
	records := parseFixture(t, "testdata/as-set-as-block-irt.txt", []opconst.RecordType{
		opconst.RecordTypeAsSet,
		opconst.RecordTypeAsBlock,
		opconst.RecordTypeIrt,
	})

	got := map[opconst.RecordType]int{}
	var asSet *whoisdb_store.WhoisAsSet
	var asBlock *whoisdb_store.WhoisAsBlock
	var irt *whoisdb_store.WhoisIrt
	for _, rec := range records {
		stampBulkDumpRecord(t, rec)
		got[rec.GetRecordType()]++
		switch v := rec.(type) {
		case *whoisdb_store.WhoisAsSet:
			if v.AsSet == "AS-CLOUDFLARE" {
				asSet = v
				assertBulkDump(t, v.FetchMethod, v.LastFetchedAt)
			}
		case *whoisdb_store.WhoisAsBlock:
			asBlock = v
			assertBulkDump(t, v.FetchMethod, v.LastFetchedAt)
		case *whoisdb_store.WhoisIrt:
			irt = v
			assertBulkDump(t, v.FetchMethod, v.LastFetchedAt)
		default:
			t.Fatalf("unexpected type %T", rec)
		}
	}
	if got[opconst.RecordTypeAsSet] != 2 {
		t.Fatalf("as-set count=%d, want 2", got[opconst.RecordTypeAsSet])
	}
	if got[opconst.RecordTypeAsBlock] != 1 || got[opconst.RecordTypeIrt] != 1 {
		t.Fatalf("counts=%v", got)
	}

	if asSet == nil {
		t.Fatal("missing AS-CLOUDFLARE")
	}
	if asSet.Members == nil || len(*asSet.Members) != 2 || (*asSet.Members)[0] != "AS13335" || (*asSet.Members)[1] != "AS-FOO" {
		t.Fatalf("members=%v", asSet.Members)
	}
	if asSet.MbrsByRef == nil || (*asSet.MbrsByRef)[0] != "MAINT-CLOUDFLARE" {
		t.Fatalf("mbrs-by-ref=%v", asSet.MbrsByRef)
	}

	if asBlock == nil {
		t.Fatal("missing as-block")
	}
	if asBlock.AsBlock != "AS37945 - AS37950" || asBlock.AsnStart != 37945 || asBlock.AsnEnd != 37950 {
		t.Fatalf("as-block=%q range=%d-%d", asBlock.AsBlock, asBlock.AsnStart, asBlock.AsnEnd)
	}

	if irt == nil {
		t.Fatal("missing irt")
	}
	if irt.Irt != "IRT-APNICRANDNET-AU" {
		t.Fatalf("irt=%q", irt.Irt)
	}
	if irt.AbuseMailbox == nil || (*irt.AbuseMailbox)[0] != "abuse@example.net" {
		t.Fatalf("abuse-mailbox=%v", irt.AbuseMailbox)
	}
	if irt.Auth == nil || (*irt.Auth)[0] != "PGPKEY-23F0C2B5" {
		t.Fatalf("auth=%v", irt.Auth)
	}
}

func TestParseWhoisDBAFRINICMixedIgnoresUnknownAndRouteOnPass1(t *testing.T) {
	records := parseFixture(t, "testdata/as-set-as-block-irt.txt", registrationRecordTypes)

	got := map[opconst.RecordType]int{}
	var sawAfrinicSet bool
	for _, rec := range records {
		got[rec.GetRecordType()]++
		switch rec.GetRecordType() {
		case opconst.RecordTypeRoute, opconst.RecordTypeRoute6:
			t.Fatalf("pass 1 must not save %s", rec.GetRecordType())
		case opconst.RecordTypeAsSet:
			asSet := rec.(*whoisdb_store.WhoisAsSet)
			if asSet.AsSet == "AS-AFRINIC-TEST" {
				sawAfrinicSet = true
			}
		}
	}
	if !sawAfrinicSet {
		t.Fatal("AFRINIC mixed dump must save as-set when present")
	}
	if got[opconst.RecordTypeAsSet] != 2 || got[opconst.RecordTypeAsBlock] != 1 || got[opconst.RecordTypeIrt] != 1 {
		t.Fatalf("pass-1 counts=%v, want as-set=2 as-block=1 irt=1 (mntner ignored, route dropped)", got)
	}
	if _, ok := got[opconst.RecordTypeRoute]; ok {
		t.Fatal("mntner/route must not appear in pass-1 output")
	}
}

func TestParseWhoisDBFileCancelledContextReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("inetnum: 192.0.2.0 - 192.0.2.255\nnetname: TEST\nsource: AFRINIC\n\n")
	}
	src := &whoisDBSource{url: "mem", isAuthoritative: true, source: opconst.AFRINIC}
	accepted := []opconst.RecordType{opconst.RecordTypeInetNum}
	st := &WhoisDBURLStatus{}
	wdb := &WhoisDBAggregator{
		Logger:          zap.NewNop(),
		RecordChan:      make(chan whoisdb_store.WhoisRecord),
		ForceSaveSignal: make(chan struct{}),
		StatusMetadata: WhoisDBStatusMetadata{
			URLs: map[string]*WhoisDBURLStatus{},
		},
	}
	wdb.StatusMetadata.URLs[statusKey(src.url, accepted)] = st

	done := make(chan struct{})
	go func() {
		wdb.ParseWhoisDBFile(ctx, bufio.NewScanner(strings.NewReader(b.String())), accepted, src)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled parse did not return")
	}
	if st.LineCount != 0 {
		t.Fatalf("line count=%d, parse should stop before the first line", st.LineCount)
	}
}

func TestParseWhoisDBFileCancelUnblocksSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body := strings.Repeat("inetnum: 192.0.2.0 - 192.0.2.255\nnetname: TEST\nsource: AFRINIC\n\n", 5)
	src := &whoisDBSource{url: "mem", isAuthoritative: true, source: opconst.AFRINIC}
	accepted := []opconst.RecordType{opconst.RecordTypeInetNum}
	wdb := &WhoisDBAggregator{
		Logger:          zap.NewNop(),
		RecordChan:      make(chan whoisdb_store.WhoisRecord),
		ForceSaveSignal: make(chan struct{}),
		StatusMetadata: WhoisDBStatusMetadata{
			URLs: map[string]*WhoisDBURLStatus{
				statusKey(src.url, accepted): {},
			},
		},
	}

	done := make(chan struct{})
	go func() {
		wdb.ParseWhoisDBFile(ctx, bufio.NewScanner(strings.NewReader(body)), accepted, src)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("parse blocked on a full channel after cancel")
	}
}
