package postgres

import (
	"reflect"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

func TestNROIsStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	staleAfter := 48 * time.Hour
	ingestedOK := now.Add(-4 * time.Hour)
	ingestedOld := now.Add(-49 * time.Hour)
	ingestedExact := now.Add(-48 * time.Hour)

	cases := []struct {
		name     string
		rows     int64
		ingested *time.Time
		want     bool
	}{
		{name: "empty", rows: 0, ingested: &ingestedOK, want: true},
		{name: "nil ingested", rows: 10, ingested: nil, want: true},
		{name: "zero ingested", rows: 10, ingested: &time.Time{}, want: true},
		{name: "fresh", rows: 769149, ingested: &ingestedOK, want: false},
		{name: "exactly stale-after", rows: 10, ingested: &ingestedExact, want: false},
		{name: "older than stale-after", rows: 10, ingested: &ingestedOld, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NROIsStale(tc.rows, tc.ingested, staleAfter, now)
			if got != tc.want {
				t.Fatalf("NROIsStale = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPickFileTimePrefersLastModified(t *testing.T) {
	t.Parallel()
	mod := time.Date(2026, 9, 3, 6, 12, 0, 0, time.UTC)
	added := time.Date(2026, 9, 3, 7, 0, 0, 0, time.UTC)
	if got := PickFileTime(RemoteFileTime{LastModified: &mod, MetaAddedAt: &added}); got == nil || !got.Equal(mod) {
		t.Fatalf("got %v, want last_modified", got)
	}
	if got := PickFileTime(RemoteFileTime{MetaAddedAt: &added}); got == nil || !got.Equal(added) {
		t.Fatalf("got %v, want meta_added_at", got)
	}
	if got := PickFileTime(RemoteFileTime{}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestGroupBulkSourcesMissingAndNever(t *testing.T) {
	t.Parallel()
	ripeA := "https://ftp.ripe.net/a"
	ripeB := "https://ftp.ripe.net/b"
	afrinic := "https://ftp.afrinic.net/db"
	arin := "https://ftp.arin.net/db"
	seen := time.Date(2026, 9, 3, 6, 12, 0, 0, time.UTC)
	older := time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC)

	files := []BulkFileRef{
		{URL: ripeA, Source: opconst.RIPE, Coverage: true},
		{URL: ripeB, Source: opconst.RIPE, Coverage: true},
		{URL: afrinic, Source: opconst.AFRINIC, Coverage: true},
		{URL: arin, Source: opconst.ARIN, Coverage: false},
	}
	times := map[string]RemoteFileTime{
		ripeA: {LastModified: &seen},
		ripeB: {MetaAddedAt: &older},
		// afrinic missing
		arin: {MetaAddedAt: &seen},
	}

	got := GroupBulkSources(files, times)
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 sources", len(got))
	}

	ripe := got[0]
	if ripe.Source != opconst.RIPE || ripe.Files != 2 || ripe.Present != 2 || ripe.Never || ripe.Missing || !ripe.Coverage {
		t.Fatalf("RIPE = %+v", ripe)
	}
	if ripe.LastSeen == nil || !ripe.LastSeen.Equal(seen) {
		t.Fatalf("RIPE last_seen = %v, want newer file", ripe.LastSeen)
	}

	afr := got[1]
	if afr.Source != opconst.AFRINIC || afr.Files != 1 || afr.Present != 0 || !afr.Never || !afr.Missing {
		t.Fatalf("AFRINIC = %+v, want NEVER+MISSING 0/1", afr)
	}
	if afr.LastSeen != nil {
		t.Fatalf("AFRINIC last_seen = %v, want nil", afr.LastSeen)
	}

	ar := got[2]
	if ar.Source != opconst.ARIN || ar.Coverage || ar.Never || ar.Missing || ar.Present != 1 {
		t.Fatalf("ARIN = %+v", ar)
	}
}

func TestGroupBulkSourcesPartialMissing(t *testing.T) {
	t.Parallel()
	files := []BulkFileRef{
		{URL: "u1", Source: opconst.APNIC, Coverage: true},
		{URL: "u2", Source: opconst.APNIC, Coverage: true},
	}
	seen := time.Date(2026, 9, 3, 4, 1, 0, 0, time.UTC)
	got := GroupBulkSources(files, map[string]RemoteFileTime{"u1": {MetaAddedAt: &seen}})
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Present != 1 || got[0].Files != 2 || got[0].Never || !got[0].Missing {
		t.Fatalf("partial = %+v, want MISSING 1/2", got[0])
	}
}

func TestGroupBulkSourcesNewSplitFilesMissingUntilBulk(t *testing.T) {
	t.Parallel()
	// APNIC/RIPE pass 1 grew 6→9 (as-set, as-block, irt split dumps). Until the
	// next bulk, remote_files_metadata still has the old six URLs.
	seen := time.Date(2026, 9, 3, 4, 1, 0, 0, time.UTC)
	old := []string{"aut-num", "inetnum", "inet6num", "organisation", "role", "person"}
	added := []string{"as-set", "as-block", "irt"}
	files := make([]BulkFileRef, 0, 9)
	times := map[string]RemoteFileTime{}
	for _, name := range old {
		u := "https://ftp.apnic.net/" + name
		files = append(files, BulkFileRef{URL: u, Source: opconst.APNIC, Coverage: true})
		times[u] = RemoteFileTime{MetaAddedAt: &seen}
	}
	for _, name := range added {
		files = append(files, BulkFileRef{URL: "https://ftp.apnic.net/" + name, Source: opconst.APNIC, Coverage: true})
	}
	got := GroupBulkSources(files, times)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Present != 6 || got[0].Files != 9 || got[0].Never || !got[0].Missing {
		t.Fatalf("until next bulk = %+v, want MISSING 6/9", got[0])
	}
	if got[0].LastSeen == nil || !got[0].LastSeen.Equal(seen) {
		t.Fatalf("last_seen = %v, want the old files' timestamp", got[0].LastSeen)
	}

	allPresent := map[string]RemoteFileTime{}
	for _, f := range files {
		allPresent[f.URL] = RemoteFileTime{MetaAddedAt: &seen}
	}
	ok := GroupBulkSources(files, allPresent)
	if ok[0].Present != 9 || ok[0].Files != 9 || ok[0].Missing || ok[0].Never {
		t.Fatalf("after ingest = %+v, want 9/9 OK", ok[0])
	}
}

func TestPivotQueueAlignmentShape(t *testing.T) {
	t.Parallel()
	rows := []QueueCount{
		{Kind: CrawlKindAutnum, Registry: opconst.ARIN, State: CrawlStatePending, Count: 12041},
		{Kind: CrawlKindAutnum, Registry: opconst.ARIN, State: CrawlStateInProgress, Count: 2},
		{Kind: CrawlKindAutnum, Registry: opconst.ARIN, State: CrawlStateDone, Count: 21000},
		{Kind: CrawlKindAutnum, Registry: opconst.ARIN, State: CrawlStateFailed, Count: 12},
		{Kind: CrawlKindAutnum, Registry: opconst.ARIN, State: CrawlStateGone, Count: 80},
		{Kind: CrawlKindIpnet, Registry: opconst.LACNIC, State: CrawlStatePending, Count: 5},
	}
	always := []string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}
	got := PivotQueue(rows, []string{CrawlKindAutnum, CrawlKindIpnet}, always)
	if len(got) != 2 {
		t.Fatalf("kinds=%d, want 2", len(got))
	}
	if got[0].Kind != CrawlKindAutnum || got[1].Kind != CrawlKindIpnet {
		t.Fatalf("kind order = %s %s", got[0].Kind, got[1].Kind)
	}

	arin := findQueueReg(got[0].Registries, opconst.ARIN)
	if arin != (QueueRegistryRow{Registry: opconst.ARIN, Pending: 12041, InProgress: 2, Done: 21000, Failed: 12, Gone: 80}) {
		t.Fatalf("ARIN autnum = %+v", arin)
	}
	ripe := findQueueReg(got[0].Registries, opconst.RIPE)
	if ripe != (QueueRegistryRow{Registry: opconst.RIPE}) {
		t.Fatalf("RIPE zeros = %+v", ripe)
	}
	if len(got[0].Registries) != 5 {
		t.Fatalf("autnum regs=%d, want 5", len(got[0].Registries))
	}

	lacnic := findQueueReg(got[1].Registries, opconst.LACNIC)
	if lacnic.Pending != 5 {
		t.Fatalf("LACNIC ipnet = %+v", lacnic)
	}
	arinIP := findQueueReg(got[1].Registries, opconst.ARIN)
	if arinIP != (QueueRegistryRow{Registry: opconst.ARIN}) {
		t.Fatalf("ARIN ipnet zeros = %+v", arinIP)
	}
}

func TestMergeWhoisDBCountsShowsZeros(t *testing.T) {
	t.Parallel()
	got := MergeWhoisDBCounts(
		map[string]WhoisDBSourceCount{
			opconst.RIPE: {Source: opconst.RIPE, Autnum: 35000, Inetnum: 120000, Inet6num: 45000, AsSet: 800, AsBlock: 12, Irt: 40},
		},
		[]string{opconst.RIPE, opconst.AFRINIC},
	)
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Source != opconst.AFRINIC || got[0].Autnum != 0 || got[0].AsSet != 0 || got[0].AsBlock != 0 || got[0].Irt != 0 {
		t.Fatalf("AFRINIC should be first with zeros: %+v", got[0])
	}
	if got[1].Source != opconst.RIPE || got[1].Autnum != 35000 || got[1].AsSet != 800 || got[1].AsBlock != 12 || got[1].Irt != 40 {
		t.Fatalf("RIPE = %+v", got[1])
	}
}

func TestMergeAutnumCoverage(t *testing.T) {
	t.Parallel()
	got := MergeAutnumCoverage(
		map[string]int64{opconst.ARIN: 18400},
		map[string]int64{opconst.ARIN: 18400, opconst.RIPE: 1},
		map[string]int64{opconst.ARIN: 12000, "": 99},
		[]string{opconst.ARIN, opconst.LACNIC},
	)
	want := []AutnumCoverage{
		{Registry: opconst.ARIN, NRO: 18400, Target: 18400, WhoisDB: 12000},
		{Registry: opconst.LACNIC},
		{Registry: opconst.RIPE, Target: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestMergeIpnetCoverage(t *testing.T) {
	t.Parallel()
	got := MergeIpnetCoverage(
		map[string]int64{opconst.ARIN: 89000},
		[]WhoisDBSourceCount{
			{Source: opconst.ARIN, Inetnum: 1200, Inet6num: 400},
		},
		[]string{opconst.ARIN, opconst.LACNIC},
	)
	if got[0] != (IpnetCoverage{Registry: opconst.ARIN, Target: 89000, Inetnum: 1200, Inet6num: 400}) {
		t.Fatalf("ARIN = %+v", got[0])
	}
	if got[1] != (IpnetCoverage{Registry: opconst.LACNIC}) {
		t.Fatalf("LACNIC zeros = %+v", got[1])
	}
}

func TestRibSeedWatermarkURL(t *testing.T) {
	t.Parallel()
	if RibSeedWatermarkURL != "registry-crawl:rib-seed" {
		t.Fatalf("RibSeedWatermarkURL = %q", RibSeedWatermarkURL)
	}
}

func findQueueReg(rows []QueueRegistryRow, registry string) QueueRegistryRow {
	for _, r := range rows {
		if r.Registry == registry {
			return r
		}
	}
	return QueueRegistryRow{}
}
