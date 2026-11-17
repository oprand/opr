package whoisdb

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"
)

func TestRegistrationDumpFilesMatchesPass1(t *testing.T) {
	t.Parallel()
	files := RegistrationDumpFiles()
	if len(files) != len(registrationSources) {
		t.Fatalf("len=%d, want %d", len(files), len(registrationSources))
	}
	bySrc := map[string]int{}
	for i, f := range files {
		src := registrationSources[i]
		if f.URL != src.url || f.Source != src.source {
			t.Fatalf("file[%d]=%+v, want url=%s source=%s", i, f, src.url, src.source)
		}
		if f.Coverage != IsBulkDumpCoverage(src.source) {
			t.Fatalf("%s Coverage=%v", f.Source, f.Coverage)
		}
		bySrc[f.Source]++
	}
	if bySrc[opconst.RIPE] != 9 || bySrc[opconst.APNIC] != 9 {
		t.Fatalf("split-dump counts: %+v", bySrc)
	}
	if bySrc[opconst.AFRINIC] != 1 || bySrc[opconst.ARIN] != 1 || bySrc[opconst.LACNIC] != 1 {
		t.Fatalf("single-file counts: %+v", bySrc)
	}
	for _, f := range files {
		if (f.Source == opconst.ARIN || f.Source == opconst.LACNIC) && f.Coverage {
			t.Fatalf("%s dump is saved but not coverage", f.Source)
		}
	}
}

func TestRegistrationDumpFilesMissingUntilNextBulk(t *testing.T) {
	t.Parallel()
	files := RegistrationDumpFiles()
	seen := time.Date(2026, 9, 3, 4, 1, 0, 0, time.UTC)
	times := map[string]postgres.RemoteFileTime{}
	for _, f := range files {
		if isAsSetAsBlockIrtSplitURL(f.URL) {
			continue
		}
		times[f.URL] = postgres.RemoteFileTime{MetaAddedAt: &seen}
	}

	got := postgres.GroupBulkSources(files, times)
	bySrc := map[string]postgres.BulkSourceStatus{}
	for _, s := range got {
		bySrc[s.Source] = s
	}
	for _, src := range []string{opconst.RIPE, opconst.APNIC} {
		st := bySrc[src]
		if st.Files != 9 || st.Present != 6 || st.Never || !st.Missing {
			t.Fatalf("%s = %+v, want MISSING 6/9 until the next bulk fetches as-set/as-block/irt", src, st)
		}
	}
	afr := bySrc[opconst.AFRINIC]
	if afr.Files != 1 || afr.Present != 1 || afr.Missing || afr.Never {
		t.Fatalf("AFRINIC mixed dump is unchanged: %+v", afr)
	}

	after := postgres.GroupBulkSources(files, allDumpTimes(files, seen))
	for _, s := range after {
		if s.Source == opconst.RIPE || s.Source == opconst.APNIC {
			if s.Files != 9 || s.Present != 9 || s.Missing || s.Never {
				t.Fatalf("%s after ingest = %+v, want 9/9 OK", s.Source, s)
			}
		}
	}
}

func isAsSetAsBlockIrtSplitURL(url string) bool {
	return strings.Contains(url, ".as-set.") || strings.Contains(url, ".as-block.") || strings.Contains(url, ".irt.")
}

func allDumpTimes(files []postgres.BulkFileRef, seen time.Time) map[string]postgres.RemoteFileTime {
	times := make(map[string]postgres.RemoteFileTime, len(files))
	for _, f := range files {
		times[f.URL] = postgres.RemoteFileTime{MetaAddedAt: &seen}
	}
	return times
}

func TestBulkDumpCoverageExcludesIncompleteDumps(t *testing.T) {
	t.Parallel()
	want := []string{opconst.RIPE, opconst.APNIC, opconst.AFRINIC, opconst.JPNIC, opconst.KRNIC, opconst.TWNIC}
	got := BulkDumpCoverageRegistries()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
		if !IsBulkDumpCoverage(want[i]) {
			t.Fatalf("expected %s to be coverage", want[i])
		}
	}
	if IsBulkDumpCoverage(opconst.ARIN) {
		t.Fatal("ARIN dump is incomplete; must not be coverage")
	}
	if IsBulkDumpCoverage(opconst.LACNIC) {
		t.Fatal("LACNIC dump is incomplete; must not be coverage")
	}
	got[0] = "MUTATED"
	if BulkDumpCoverageRegistries()[0] != opconst.RIPE {
		t.Fatal("BulkDumpCoverageRegistries must return a copy")
	}
}

func TestAppendCoveredIpnetCIDRSkipsARINAndNil(t *testing.T) {
	t.Parallel()
	ripe := opconst.RIPE
	arin := opconst.ARIN
	byRegistry := make(map[string][]string)

	appendCoveredIpnetCIDR(byRegistry, &ripe, "192.0.2.0/24")
	appendCoveredIpnetCIDR(byRegistry, &ripe, "192.0.2.0/24")
	appendCoveredIpnetCIDR(byRegistry, &arin, "198.51.100.0/24")
	appendCoveredIpnetCIDR(byRegistry, nil, "203.0.113.0/24")
	appendCoveredIpnetCIDR(byRegistry, &ripe, "")

	if _, ok := byRegistry[opconst.ARIN]; ok {
		t.Fatalf("ARIN must not be marked: %v", byRegistry)
	}
	got := byRegistry[opconst.RIPE]
	if len(got) != 2 || got[0] != "192.0.2.0/24" || got[1] != "192.0.2.0/24" {
		t.Fatalf("RIPE cidrs = %v, want two 192.0.2.0/24 (dedup is store-side)", got)
	}
}

func TestInetnumCoverageCanonicalCIDRFromFixture(t *testing.T) {
	v4 := parseFixture(t, "testdata/inetnum-one.txt", []opconst.RecordType{opconst.RecordTypeInetNum})
	if len(v4) != 1 {
		t.Fatalf("parsed %d inetnum records, want 1", len(v4))
	}
	inet, ok := v4[0].(*whoisdb_store.WhoisInetNum)
	if !ok {
		t.Fatalf("type %T", v4[0])
	}
	if inet.Netblock == nil {
		t.Fatal("netblock is nil")
	}
	if got := inet.Netblock.String(); got != "196.32.192.0/24" {
		t.Fatalf("canonical v4 cidr=%q, want 196.32.192.0/24", got)
	}
	if inet.Source == nil || *inet.Source != opconst.AFRINIC {
		t.Fatalf("source=%v, want AFRINIC", inet.Source)
	}

	byV4 := make(map[string][]string)
	appendCoveredIpnetCIDR(byV4, inet.Source, inet.Netblock.String())
	if got := byV4[opconst.AFRINIC]; len(got) != 1 || got[0] != "196.32.192.0/24" {
		t.Fatalf("coverage v4 = %v", byV4)
	}

	v6 := parseFixture(t, "testdata/inet6num-one.txt", []opconst.RecordType{opconst.RecordTypeInet6Num})
	if len(v6) != 1 {
		t.Fatalf("parsed %d inet6num records, want 1", len(v6))
	}
	inet6, ok := v6[0].(*whoisdb_store.WhoisInet6Num)
	if !ok {
		t.Fatalf("type %T", v6[0])
	}
	if inet6.Netblock == nil {
		t.Fatal("netblock is nil")
	}
	if got := inet6.Netblock.String(); got != "2001:4300::/32" {
		t.Fatalf("canonical v6 cidr=%q, want 2001:4300::/32", got)
	}

	byV6 := make(map[string][]string)
	appendCoveredIpnetCIDR(byV6, inet6.Source, inet6.Netblock.String())
	if got := byV6[opconst.AFRINIC]; len(got) != 1 || got[0] != "2001:4300::/32" {
		t.Fatalf("coverage v6 = %v", byV6)
	}
}

func TestAppendCoveredAutnumMarksNIRAndParent(t *testing.T) {
	t.Parallel()
	jpnic := opconst.JPNIC
	krnic := opconst.KRNIC
	twnic := opconst.TWNIC
	ripe := opconst.RIPE
	arin := opconst.ARIN
	apnic := opconst.APNIC
	byRegistry := make(map[string][]uint32)

	appendCoveredAutnum(byRegistry, &jpnic, 2516)
	appendCoveredAutnum(byRegistry, &krnic, 4766)
	appendCoveredAutnum(byRegistry, &twnic, 3462)
	appendCoveredAutnum(byRegistry, &ripe, 3333)
	appendCoveredAutnum(byRegistry, &apnic, 4608)
	appendCoveredAutnum(byRegistry, &arin, 393225)
	appendCoveredAutnum(byRegistry, nil, 1)
	appendCoveredAutnum(byRegistry, &jpnic, 0)

	if _, ok := byRegistry[opconst.ARIN]; ok {
		t.Fatalf("ARIN must not be marked: %v", byRegistry)
	}
	if got := byRegistry[opconst.JPNIC]; len(got) != 1 || got[0] != 2516 {
		t.Fatalf("JPNIC = %v, want [2516]", got)
	}
	if got := byRegistry[opconst.KRNIC]; len(got) != 1 || got[0] != 4766 {
		t.Fatalf("KRNIC = %v, want [4766]", got)
	}
	if got := byRegistry[opconst.TWNIC]; len(got) != 1 || got[0] != 3462 {
		t.Fatalf("TWNIC = %v, want [3462]", got)
	}
	gotAPNIC := byRegistry[opconst.APNIC]
	wantAPNIC := map[uint32]bool{2516: true, 4766: true, 3462: true, 4608: true}
	if len(gotAPNIC) != 4 {
		t.Fatalf("APNIC coverage = %v, want 3 NIR ASNs plus native 4608", gotAPNIC)
	}
	for _, asn := range gotAPNIC {
		if !wantAPNIC[asn] {
			t.Fatalf("unexpected APNIC ASN %d in %v", asn, gotAPNIC)
		}
	}
	if got := byRegistry[opconst.RIPE]; len(got) != 1 || got[0] != 3333 {
		t.Fatalf("RIPE = %v, want [3333]", got)
	}
}

func TestAppendCoveredAutnumDoesNotRewriteSource(t *testing.T) {
	t.Parallel()
	jpnic := opconst.JPNIC
	a := &whoisdb_store.WhoisAutNum{AutNum: 2516, Source: &jpnic}
	byRegistry := make(map[string][]uint32)
	appendCoveredAutnum(byRegistry, a.Source, a.AutNum)
	if a.Source == nil || *a.Source != opconst.JPNIC {
		t.Fatalf("WhoisAutNum.Source mutated: %v, want JPNIC", a.Source)
	}
	if _, ok := byRegistry[opconst.JPNIC]; !ok {
		t.Fatal("expected JPNIC coverage")
	}
	if _, ok := byRegistry[opconst.APNIC]; !ok {
		t.Fatal("expected APNIC parent coverage")
	}
}

func TestAppendCoveredIpnetCIDRMarksNIRAndParent(t *testing.T) {
	t.Parallel()
	jpnic := opconst.JPNIC
	arin := opconst.ARIN
	byRegistry := make(map[string][]string)

	appendCoveredIpnetCIDR(byRegistry, &jpnic, "203.0.113.0/24")
	appendCoveredIpnetCIDR(byRegistry, &arin, "198.51.100.0/24")

	if _, ok := byRegistry[opconst.ARIN]; ok {
		t.Fatalf("ARIN must not be marked: %v", byRegistry)
	}
	if got := byRegistry[opconst.JPNIC]; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("JPNIC = %v, want [203.0.113.0/24]", got)
	}
	if got := byRegistry[opconst.APNIC]; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("APNIC parent = %v, want [203.0.113.0/24]", got)
	}
}

func TestMarkIpnetCoveredByBulkInetnumSkipsARIN(t *testing.T) {
	t.Parallel()
	ripe := opconst.RIPE
	arin := opconst.ARIN
	_, ripeNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, arinNet, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}

	items := []*whoisdb_store.WhoisInetNum{
		{Source: &ripe, Netblock: ripeNet},
		{Source: &arin, Netblock: arinNet},
		{Source: &ripe, Netblock: nil},
		nil,
	}
	byRegistry := make(map[string][]string)
	for _, n := range items {
		if n == nil || n.Netblock == nil {
			continue
		}
		appendCoveredIpnetCIDR(byRegistry, n.Source, n.Netblock.String())
	}
	if _, ok := byRegistry[opconst.ARIN]; ok {
		t.Fatalf("ARIN must not be marked: %v", byRegistry)
	}
	if got := byRegistry[opconst.RIPE]; len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("RIPE = %v, want [192.0.2.0/24]", got)
	}
}
