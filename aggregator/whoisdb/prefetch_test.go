package whoisdb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

func TestPass2StaysRouteOnly(t *testing.T) {
	t.Parallel()
	// Widening pass 2 lets a third-party IRR aut-num overwrite the
	// authoritative RIR row, since whoisdb_autnum is UNIQUE(aut_num).
	want := []opconst.RecordType{opconst.RecordTypeRoute, opconst.RecordTypeRoute6}
	if !slices.Equal(routeRecordTypes, want) {
		t.Fatalf("routeRecordTypes = %v, want %v", routeRecordTypes, want)
	}
	for _, src := range routeSources {
		if strings.Contains(src.url, "as-set") || strings.Contains(src.url, "as-block") || strings.Contains(src.url, ".irt.") {
			t.Fatalf("pass 2 must not fetch as-set/as-block/irt split dumps: %s", src.url)
		}
	}
	if slices.Contains(routeRecordTypes, opconst.RecordTypeAsSet) ||
		slices.Contains(routeRecordTypes, opconst.RecordTypeAsBlock) ||
		slices.Contains(routeRecordTypes, opconst.RecordTypeIrt) {
		t.Fatal("pass 2 must not accept as-set/as-block/irt")
	}
}

func TestPass1AcceptsAsSetAsBlockIrt(t *testing.T) {
	t.Parallel()
	want := []opconst.RecordType{
		opconst.RecordTypeAutNum,
		opconst.RecordTypeInet6Num,
		opconst.RecordTypeInetNum,
		opconst.RecordTypeOrg,
		opconst.RecordTypeRole,
		opconst.RecordTypeAsSet,
		opconst.RecordTypeAsBlock,
		opconst.RecordTypeIrt,
	}
	if !slices.Equal(registrationRecordTypes, want) {
		t.Fatalf("registrationRecordTypes = %v, want %v", registrationRecordTypes, want)
	}
}

func TestPass1SplitURLsForAsSetAsBlockIrt(t *testing.T) {
	t.Parallel()
	want := []struct{ url, source string }{
		{"https://ftp.apnic.net/apnic/whois/apnic.db.as-set.gz", opconst.APNIC},
		{"https://ftp.apnic.net/apnic/whois/apnic.db.as-block.gz", opconst.APNIC},
		{"https://ftp.apnic.net/apnic/whois/apnic.db.irt.gz", opconst.APNIC},
		{"https://ftp.ripe.net/ripe/dbase/split/ripe.db.as-set.gz", opconst.RIPE},
		{"https://ftp.ripe.net/ripe/dbase/split/ripe.db.as-block.gz", opconst.RIPE},
		{"https://ftp.ripe.net/ripe/dbase/split/ripe.db.irt.gz", opconst.RIPE},
	}
	for _, tc := range want {
		idx := slices.IndexFunc(registrationSources, func(s whoisDBSource) bool { return s.url == tc.url })
		if idx < 0 {
			t.Fatalf("pass 1 missing %s", tc.url)
		}
		src := registrationSources[idx]
		if src.source != tc.source || !src.isAuthoritative {
			t.Fatalf("%s source=%q authoritative=%v, want %s/true", tc.url, src.source, src.isAuthoritative, tc.source)
		}
	}
	for _, src := range registrationSources {
		if strings.Contains(src.url, "nonauth") || strings.Contains(strings.ToLower(src.url), "radb") {
			t.Fatalf("pass 1 must not fetch RADB/nonauth: %s", src.url)
		}
	}
}

func TestPass2IncludesARINAndAFRINICMixedDumps(t *testing.T) {
	t.Parallel()
	const (
		arinURL    = "https://ftp.arin.net/pub/rr/arin.db.gz"
		afrinicURL = "https://ftp.afrinic.net/dbase/afrinic.db.gz"
	)
	for _, tc := range []struct{ url, source string }{
		{arinURL, opconst.ARIN},
		{afrinicURL, opconst.AFRINIC},
	} {
		inPass1 := slices.ContainsFunc(registrationSources, func(s whoisDBSource) bool {
			return s.url == tc.url
		})
		if !inPass1 {
			t.Fatalf("%s must stay in pass 1 for its registration objects", tc.url)
		}
		idx := slices.IndexFunc(routeSources, func(s whoisDBSource) bool { return s.url == tc.url })
		if idx < 0 {
			t.Fatalf("%s missing from pass 2; its route objects would never be stored", tc.url)
		}
		if routeSources[idx].source != tc.source {
			t.Fatalf("%s pass 2 source = %q, want %q", tc.url, routeSources[idx].source, tc.source)
		}
	}
}

func TestStatusKeySeparatesPasses(t *testing.T) {
	t.Parallel()
	const u = "https://ftp.arin.net/pub/rr/arin.db.gz"
	k1 := statusKey(u, registrationRecordTypes)
	k2 := statusKey(u, routeRecordTypes)
	if k1 == k2 {
		t.Fatalf("both passes share status key %q; the pass 2 entry would erase the pass 1 result", k1)
	}
	if k1 != statusKey(u, registrationRecordTypes) {
		t.Fatal("statusKey must be stable for the same inputs")
	}
}

func TestRunPassRegistersOneStatusEntryPerJob(t *testing.T) {
	t.Parallel()
	wdb := &WhoisDBAggregator{
		Logger:         zap.NewNop(),
		StatusMetadata: WhoisDBStatusMetadata{URLs: make(map[string]*WhoisDBURLStatus)},
	}
	const u = "https://ftp.arin.net/pub/rr/arin.db.gz"
	wdb.registerStatus(prefetchJob{
		src:      whoisDBSource{url: u, source: opconst.ARIN},
		accepted: registrationRecordTypes,
	})
	wdb.registerStatus(prefetchJob{
		src:      whoisDBSource{url: u, source: opconst.ARIN},
		accepted: routeRecordTypes,
	})
	if got := len(wdb.StatusMetadata.URLs); got != 2 {
		t.Fatalf("status entries = %d, want 2 (one per pass for the same URL)", got)
	}
	routeStatus := wdb.StatusMetadata.URLs[statusKey(u, routeRecordTypes)]
	if routeStatus == nil {
		t.Fatal("pass 2 status entry missing")
	}
	if got := routeStatus.RecordTypes; !slices.Equal(got, []string{"route", "route6"}) {
		t.Fatalf("record_types = %v", got)
	}
	if routeStatus.URL != u {
		t.Fatalf("URL field must stay the plain url, got %q", routeStatus.URL)
	}
}

func TestForceRefetchDuplicates(t *testing.T) {
	t.Parallel()
	const (
		arinURL   = "https://ftp.arin.net/pub/rr/arin.db.gz"
		routeOnly = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz"
	)
	pass1 := newPass([]whoisDBSource{{url: arinURL}}, registrationRecordTypes)
	pass2 := newPass([]whoisDBSource{{url: arinURL}, {url: routeOnly}}, routeRecordTypes)
	forceRefetchDuplicates(pass1, pass2)

	if !pass2[0].forceDownload {
		t.Fatal("a URL both passes read must be forced, or pass 2 skips it against pass 1's own ETag")
	}
	if pass2[1].forceDownload {
		t.Fatal("a URL that appears only in pass 2 must never be forced")
	}
}

func TestRealPassListsForceBothMixedDumps(t *testing.T) {
	t.Parallel()
	pass1 := newPass(registrationSources, registrationRecordTypes)
	pass2 := newPass(routeSources, routeRecordTypes)
	forceRefetchDuplicates(pass1, pass2)

	forced := make(map[string]bool, len(pass2))
	for _, j := range pass2 {
		forced[j.src.url] = j.forceDownload
	}
	for _, u := range []string{
		"https://ftp.arin.net/pub/rr/arin.db.gz",
		"https://ftp.afrinic.net/dbase/afrinic.db.gz",
	} {
		if !forced[u] {
			t.Fatalf("%s appears in both passes and must be forced in pass 2", u)
		}
	}
	// LACNIC ships two different files, so neither is a duplicate.
	if forced["https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz"] {
		t.Fatal("the LACNIC IRR file is a distinct URL and must not be forced")
	}
}

func TestPrefetchPipelineOrdersConsumptionAndBoundsConcurrency(t *testing.T) {
	t.Parallel()
	const (
		n     = 12
		depth = 3
	)

	var (
		mu       sync.Mutex
		consumed []int
		inFlight atomic.Int32
		maxSeen  atomic.Int32
		fetched  atomic.Int32
	)

	prefetchPipeline(context.Background(), n, depth,
		func(ctx context.Context, i int) *prefetchResult {
			cur := inFlight.Add(1)
			for {
				old := maxSeen.Load()
				if cur <= old || maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			// Reverse the sleep order so completion order is not list order:
			// the consumer must still see 0..n-1.
			time.Sleep(time.Duration(n-i) * time.Millisecond)
			inFlight.Add(-1)
			fetched.Add(1)
			return &prefetchResult{job: prefetchJob{src: whoisDBSource{url: fmt.Sprint(i)}}}
		},
		func(res *prefetchResult) {
			mu.Lock()
			defer mu.Unlock()
			var idx int
			fmt.Sscan(res.job.src.url, &idx)
			consumed = append(consumed, idx)
		},
	)

	if len(consumed) != n {
		t.Fatalf("consumed %d results, want %d", len(consumed), n)
	}
	for i, got := range consumed {
		if got != i {
			t.Fatalf("consumed out of order at %d: %v", i, consumed)
		}
	}
	if got := int(fetched.Load()); got != n {
		t.Fatalf("fetched %d, want %d", got, n)
	}
	if got := int(maxSeen.Load()); got > depth {
		t.Fatalf("max concurrent fetches = %d, want <= %d", got, depth)
	}
	if got := int(maxSeen.Load()); got < 2 {
		t.Fatalf("max concurrent fetches = %d, prefetch is not overlapping at all", got)
	}
}

func TestPrefetchPipelineDeletesEveryTempFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const n = 5

	paths := make([]string, n)
	var maxOnDisk atomic.Int32

	prefetchPipeline(context.Background(), n, 2,
		func(ctx context.Context, i int) *prefetchResult {
			f, err := os.CreateTemp(dir, "prefetch-*")
			if err != nil {
				t.Error(err)
				return &prefetchResult{}
			}
			f.WriteString("x")
			f.Close()
			paths[i] = f.Name()
			if entries, err := os.ReadDir(dir); err == nil {
				if cur := int32(len(entries)); cur > maxOnDisk.Load() {
					maxOnDisk.Store(cur)
				}
			}
			return &prefetchResult{path: f.Name()}
		},
		func(res *prefetchResult) {
			if _, err := os.Stat(res.path); err != nil {
				t.Errorf("temp file must exist while being parsed: %v", err)
			}
		},
	)

	for i, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp file %d (%s) leaked: %v", i, p, err)
		}
	}
	if got := maxOnDisk.Load(); got > 2 {
		t.Fatalf("temp files on disk peaked at %d, want <= prefetch depth 2", got)
	}
}

func TestPrefetchPipelineCleansUpAfterCancel(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var consumeCalls atomic.Int32
	prefetchPipeline(ctx, 4, 2,
		func(ctx context.Context, i int) *prefetchResult {
			f, err := os.CreateTemp(dir, "cancelled-*")
			if err != nil {
				t.Error(err)
				return &prefetchResult{}
			}
			f.Close()
			return &prefetchResult{path: f.Name()}
		},
		func(res *prefetchResult) { consumeCalls.Add(1) },
	)

	if got := consumeCalls.Load(); got != 0 {
		t.Fatalf("consume ran %d times on a cancelled context, want 0", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d temp files left behind after cancellation", len(entries))
	}
}

func TestDownloadToTempFileStreamsAndCleansUpOnError(t *testing.T) {
	t.Parallel()
	const body = "compressed-bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	wdb := &WhoisDBAggregator{Logger: zap.NewNop(), HTTPClient: srv.Client()}

	status := &WhoisDBURLStatus{}
	path, err := wdb.downloadToTempFile(context.Background(), srv.URL+"/ok", status)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("temp file contents = %q, want %q", got, body)
	}

	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wdb.downloadToTempFile(context.Background(), srv.URL+"/missing", status); err == nil {
		t.Fatal("expected an error on 404")
	}
	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatal("a failed download must not leave a temp file behind")
	}

	if _, err := wdb.downloadToTempFile(context.Background(), "gopher://example.test/x", status); err == nil {
		t.Fatal("expected an error on an unsupported scheme")
	}
}

func TestPrefetchResultCleanupIsIdempotent(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "cleanup-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	res := &prefetchResult{path: f.Name()}
	res.cleanup()
	res.cleanup()
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
	(&prefetchResult{}).cleanup()
	var nilRes *prefetchResult
	nilRes.cleanup()
}

func TestEtagOfHandlesMissingEtag(t *testing.T) {
	t.Parallel()
	if got := etagOf(nil); got != "" {
		t.Fatalf("etagOf(nil) = %q", got)
	}
	if got := etagOf(&postgres.ResponseMetadataItem{Url: "u"}); got != "" {
		t.Fatalf("etagOf(no etag) = %q", got)
	}
	tag := `"abc"`
	if got := etagOf(&postgres.ResponseMetadataItem{Etag: &tag}); got != tag {
		t.Fatalf("etagOf = %q, want %q", got, tag)
	}
}

func TestResolveCharsetPrefersSourceThenHeader(t *testing.T) {
	t.Parallel()
	latin := "ISO-8859-1"
	utf := "UTF-8"
	junk := "windows-1252"

	tests := []struct {
		name string
		src  whoisDBSource
		meta *postgres.ResponseMetadataItem
		want string
	}{
		{"source override wins", whoisDBSource{charset: CharsetISO8859}, &postgres.ResponseMetadataItem{Charset: &utf}, CharsetISO8859},
		{"header latin1", whoisDBSource{}, &postgres.ResponseMetadataItem{Charset: &latin}, CharsetISO8859},
		{"header utf8", whoisDBSource{}, &postgres.ResponseMetadataItem{Charset: &utf}, CharsetUTF8},
		{"unrecognised header falls back to auto", whoisDBSource{}, &postgres.ResponseMetadataItem{Charset: &junk}, CharsetAuto},
		{"no metadata at all", whoisDBSource{}, nil, CharsetAuto},
	}
	for _, tc := range tests {
		if got := resolveCharset(tc.src, tc.meta); got != tc.want {
			t.Fatalf("%s: resolveCharset = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDecodeLine(t *testing.T) {
	t.Parallel()
	utf8Line := "descr:          Café Réseau"
	latin1Line := "descr:          Caf\xe9 R\xe9seau"

	if got := decodeLine(utf8Line, CharsetAuto); got != utf8Line {
		t.Fatalf("auto mangled a valid UTF-8 line: %q", got)
	}
	if got := decodeLine(latin1Line, CharsetAuto); got != utf8Line {
		t.Fatalf("auto did not decode a latin-1 line: %q, want %q", got, utf8Line)
	}
	if got := decodeLine(latin1Line, CharsetISO8859); got != utf8Line {
		t.Fatalf("explicit iso-8859-1: %q, want %q", got, utf8Line)
	}
	if got := decodeLine(latin1Line, CharsetUTF8); got != latin1Line {
		t.Fatalf("explicit utf-8 must pass bytes through unchanged: %q", got)
	}
	// The bug this replaced: an always-ISO-8859-1 decode double-encodes an
	// already-UTF-8 line.
	if got := decodeLine(utf8Line, CharsetISO8859); got == utf8Line {
		t.Fatal("expected mojibake when forcing latin-1 on a UTF-8 line; the test premise is wrong")
	}
	if !utf8.ValidString(decodeLine(latin1Line, CharsetAuto)) {
		t.Fatal("auto must always produce valid UTF-8")
	}
}

func TestParseDecodesBothEncodingsUnderAuto(t *testing.T) {
	t.Parallel()
	const wantDescr = "Café Réseau Sàrl"

	for _, path := range []string{"testdata/inetnum-latin1.txt", "testdata/inetnum-utf8.txt"} {
		got := firstDescr(t, path)
		if got != wantDescr {
			t.Fatalf("%s: descr = %q, want %q", path, got, wantDescr)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("%s: descr is not valid UTF-8; Postgres would reject the insert", path)
		}
	}

	// Forcing latin-1 on the UTF-8 file is what the old aggregator-wide flag
	// did to every file after the first one.
	if got := firstDescr(t, "testdata/inetnum-utf8.txt", WithCharset(CharsetISO8859)); got == wantDescr {
		t.Fatal("expected mojibake; the fixture is not actually UTF-8")
	}
}

func firstDescr(t *testing.T, path string, opts ...ParseOption) string {
	t.Helper()
	records := parseFixture(t, path, []opconst.RecordType{opconst.RecordTypeInetNum}, opts...)
	if len(records) != 1 {
		t.Fatalf("%s: parsed %d records, want 1", path, len(records))
	}
	inet, ok := records[0].(*whoisdb_store.WhoisInetNum)
	if !ok {
		t.Fatalf("%s: type %T", path, records[0])
	}
	if inet.Descr == nil || len(*inet.Descr) == 0 {
		t.Fatalf("%s: no descr parsed", path)
	}
	return (*inet.Descr)[0]
}

func TestOpenFTPAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wdb := &WhoisDBAggregator{}
	_, _, err := wdb.openFTP(ctx, "ftp://192.0.2.1/db.gz")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
}

func TestOpenFTPCancelDuringDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	wdb := &WhoisDBAggregator{}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := wdb.openSource(ctx, "ftp://"+ln.Addr().String()+"/file.gz", &WhoisDBURLStatus{})
		errCh <- err
	}()

	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("ftp dial did not connect")
	}
	defer conn.Close()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ftp dial did not return on cancel")
	}
}
