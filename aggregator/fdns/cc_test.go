package fdns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestParseCrawlID(t *testing.T) {
	t.Parallel()
	y, w, ok := ParseCrawlID("CC-MAIN-2025-18")
	if !ok || y != 2025 || w != 18 {
		t.Fatalf("got year=%d week=%d ok=%v", y, w, ok)
	}
	if _, _, ok := ParseCrawlID("CC-MAIN-2026-8"); ok {
		t.Fatal("unpadded week must fail")
	}
	if _, _, ok := ParseCrawlID("CC-MAIN-2025"); ok {
		t.Fatal("short id must fail")
	}
	id, err := NormalizeCrawlID("  cc-main-2025-18  ")
	if err != nil || id != "CC-MAIN-2025-18" {
		t.Fatalf("normalize: %q %v", id, err)
	}
}

func TestCrawlIDAtLeast(t *testing.T) {
	t.Parallel()
	if !CrawlIDAtLeast("CC-MAIN-2025-18", "CC-MAIN-2025-13") {
		t.Fatal("later crawl must be >= earlier")
	}
	if CrawlIDAtLeast("CC-MAIN-2025-08", "CC-MAIN-2025-18") {
		t.Fatal("earlier crawl must not be >= later")
	}
}

func TestFilterHostIndexPaths(t *testing.T) {
	t.Parallel()
	crawl := "CC-MAIN-2025-18"
	got := FilterHostIndexPaths([]string{
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00000.parquet",
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00001.parquet",
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-13/CC-MAIN-2025-13.part-00000.parquet",
		"s3://commoncrawl/projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00002.parquet",
		"https://data.commoncrawl.org/projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00000.parquet",
		"cc-index/table/cc-main/warc/crawl=CC-MAIN-2025-18/subset=warc/part-0.parquet",
		"",
		"# comment",
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/../escape.parquet",
	}, crawl)
	if len(got) != 3 {
		t.Fatalf("got=%v, want 3 parts for this crawl", got)
	}
	for _, p := range got {
		if !strings.Contains(p, "crawl=CC-MAIN-2025-18/") {
			t.Fatalf("wrong crawl kept: %s", p)
		}
		if !strings.Contains(p, "host-index-testing") {
			t.Fatalf("non-host-index path kept: %s", p)
		}
	}
}

func TestLatestCrawlFromPaths(t *testing.T) {
	t.Parallel()
	id, err := LatestCrawlFromPaths([]string{
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-13/x.parquet",
		"projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/y.parquet",
		"projects/host-index-testing/v2/crawl=CC-MAIN-2024-51/z.parquet",
	})
	if err != nil || id != "CC-MAIN-2025-18" {
		t.Fatalf("got %q %v", id, err)
	}
	if _, err := LatestCrawlFromPaths(nil); err == nil {
		t.Fatal("empty paths must error")
	}
}

func TestDiscoverPicksLatestHostIndexCrawl(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	man, err := in.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if man.ID != "CC-MAIN-2025-18" {
		t.Fatalf("crawl=%s, want 2025-18 (latest in fixture)", man.ID)
	}
	if len(man.Paths) != 2 {
		t.Fatalf("paths=%d, want 2", len(man.Paths))
	}
	got := srv.mem.meta[postgres.FDNSCCCrawlMetadataURL]
	if got == nil || got.Charset == nil || *got.Charset != "CC-MAIN-2025-18" {
		t.Fatalf("crawl id not persisted: %+v", got)
	}
	if srv.pathsGets.Load() == 0 {
		t.Fatal("expected Host Index paths GET")
	}
}

func TestDiscoverPinnedSkipsLatest(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-13"
	man, err := in.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if man.ID != "CC-MAIN-2025-13" {
		t.Fatalf("crawl=%s", man.ID)
	}
	if len(man.Paths) != 1 {
		t.Fatalf("paths=%d, want 1", len(man.Paths))
	}
}

func TestDiscoverPinnedMissingCrawl(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2026-39"
	if _, err := in.Discover(context.Background()); err == nil {
		t.Fatal("expected missing crawl error")
	}
}

func TestDownloadHostIndexPartsOnly(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.partGets.Load() != 2 {
		t.Fatalf("parquet GETs=%d, want 2", srv.partGets.Load())
	}
	entries, err := os.ReadDir(filepath.Join(in.ParquetDir, "projects/host-index-testing/v2/crawl=CC-MAIN-2025-18"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("local parts=%d, want 2", len(entries))
	}
	if got := len(srv.ch.insertedPaths()); got != 2 {
		t.Fatalf("clickhouse parts loaded=%d, want 2", got)
	}
	if srv.mem.upsertN != 0 {
		t.Fatal("Host Index ingest must not write Postgres hostnames")
	}
	if srv.mem.upsertIPN != 0 {
		t.Fatal("Host Index ingest must not write fdns_host_ip")
	}
}

func TestDownloadSkipMatchingETag(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := srv.partGets.Load()
	if first != 2 {
		t.Fatalf("first parquet GETs=%d, want 2", first)
	}
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.partGets.Load(); got != first {
		t.Fatalf("second run parquet GETs=%d, want %d (ETag/size skip)", got, first)
	}
}

func TestDownloadForceReGets(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	in.Force = true
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.partGets.Load(); got != 4 {
		t.Fatalf("parquet GETs=%d, want 4 (2 + --force 2)", got)
	}
}

func TestDownloadMissingContentLengthDoesNotSkip(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := srv.partGets.Load()
	if first != 2 {
		t.Fatalf("first parquet GETs=%d, want 2", first)
	}
	// Strip Content-Length from stored metadata while keeping ETag — must re-GET.
	srv.mem.mu.Lock()
	for url, meta := range srv.mem.meta {
		if !strings.Contains(url, ".parquet") || meta == nil {
			continue
		}
		zero := int64(0)
		cp := *meta
		cp.ContentLength = &zero
		srv.mem.meta[url] = &cp
	}
	srv.mem.mu.Unlock()
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.partGets.Load(); got != first+2 {
		t.Fatalf("parquet GETs=%d, want %d (missing/zero Content-Length must not skip)", got, first+2)
	}
}

func TestFileUnchangedRequiresContentLength(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, "part.parquet")
	if err := os.WriteFile(dest, []byte("PARQUET"), 0o644); err != nil {
		t.Fatal(err)
	}
	etag := `"abc"`
	n := int64(len("PARQUET"))
	ok := &postgres.ResponseMetadataItem{Etag: &etag, ContentLength: &n}
	if !fileUnchanged(dest, ok, false) {
		t.Fatal("matching ETag+size must be unchanged")
	}
	zero := int64(0)
	noCL := &postgres.ResponseMetadataItem{Etag: &etag, ContentLength: &zero}
	if fileUnchanged(dest, noCL, false) {
		t.Fatal("zero Content-Length must not skip")
	}
	nilCL := &postgres.ResponseMetadataItem{Etag: &etag}
	if fileUnchanged(dest, nilCL, false) {
		t.Fatal("nil Content-Length must not skip")
	}
}

func TestRequireContentLength(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	if _, err := requireContentLength(h); err == nil {
		t.Fatal("missing Content-Length must error")
	}
	h.Set("Content-Length", "0")
	if _, err := requireContentLength(h); err == nil {
		t.Fatal("zero Content-Length must error")
	}
	h.Set("Content-Length", "42")
	n, err := requireContentLength(h)
	if err != nil || n != 42 {
		t.Fatalf("got %d %v", n, err)
	}
}

func TestKeepParquetFalseDeletesAfterNonEmptyLoad(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	in.KeepParquet = false
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(in.ParquetDir, "projects/host-index-testing/v2/crawl=CC-MAIN-2025-18")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".parquet") {
			t.Fatalf("keep-parquet=false should delete parquet after non-empty load; found %s", e.Name())
		}
	}
}

func TestKeepParquetFalseKeepsParquetWhenLoadFinishesEmpty(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	in.KeepParquet = false
	srv.ch.rowsPerPart = 0

	if err := in.Ingest(context.Background()); err == nil {
		t.Fatal("an empty load must not report success")
	}
	root := filepath.Join(in.ParquetDir, "projects/host-index-testing/v2/crawl=CC-MAIN-2025-18")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var parquet int
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".parquet") {
			parquet++
		}
	}
	if parquet != 2 {
		t.Fatalf("keep-parquet=false must not delete after an aborted load; parquet=%d, want 2", parquet)
	}
}

func TestDownloadRejectsResponseWithoutContentLength(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, "part.parquet")
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"ETag": {`"x"`}},
			Body:       io.NopCloser(strings.NewReader("PARQUET")),
			Request:    req,
		}, nil
	})
	in := NewCCIngestor(zap.NewNop(), newMemFDNSStore(), &http.Client{Transport: rt})
	in.ParquetDir = dir
	_, _, err := in.downloadOne(context.Background(), ccFileJob{
		URL:  "http://example.test/part.parquet",
		Dest: dest,
		Rel:  "part.parquet",
	})
	if err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("err=%v, want Content-Length error", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("failed download must not leave dest")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSkipDownloadRequiresVerifiedFiles(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	in.SkipDownload = true
	if err := in.Ingest(context.Background()); err == nil {
		t.Fatal("skip-download with empty dir must fail")
	}
	in.SkipDownload = false
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	gets := srv.partGets.Load()
	in.SkipDownload = true
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.partGets.Load() != gets {
		t.Fatalf("skip-download issued parquet GETs")
	}
}

func TestDownloadConcurrencyResume(t *testing.T) {
	t.Parallel()
	srv := newCCTestServer(t)
	srv.extraParts = 6
	in := srv.ingestor(t)
	in.Crawl = "CC-MAIN-2025-18"
	in.Concurrency = 4
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := int64(2 + 6)
	if srv.partGets.Load() != want {
		t.Fatalf("first parquet GETs=%d, want %d", srv.partGets.Load(), want)
	}
	var removed string
	root := filepath.Join(in.ParquetDir, "projects/host-index-testing/v2/crawl=CC-MAIN-2025-18")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), "part-x") {
			removed = filepath.Join(root, e.Name())
			break
		}
	}
	if removed == "" {
		t.Fatal("expected extra part-x* file")
	}
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.partGets.Load() != want+1 {
		t.Fatalf("resume parquet GETs=%d, want %d (one missing file)", srv.partGets.Load(), want+1)
	}
	if _, err := os.Stat(removed); err != nil {
		t.Fatalf("resumed file missing: %v", err)
	}
}

func TestForceAndSkipDownloadConflict(t *testing.T) {
	t.Parallel()
	in := NewCCIngestor(zap.NewNop(), newMemFDNSStore(), http.DefaultClient)
	in.Force = true
	in.SkipDownload = true
	in.ParquetDir = t.TempDir()
	if err := in.Ingest(context.Background()); err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestHostIndexPathsManifestURL(t *testing.T) {
	t.Parallel()
	got := HostIndexPathsManifestURL("https://data.commoncrawl.org/")
	if got != DefaultHostIndexPathsURL {
		t.Fatalf("got %s", got)
	}
	custom := HostIndexPathsManifestURL("http://127.0.0.1:9")
	if custom != "http://127.0.0.1:9/projects/host-index-testing/v2.paths.gz" {
		t.Fatalf("got %s", custom)
	}
}

func TestDefaultParquetDirNonEmpty(t *testing.T) {
	t.Parallel()
	dir := DefaultParquetDir()
	if dir == "" || !strings.Contains(dir, "cc-host-index") {
		t.Fatalf("DefaultParquetDir=%q", dir)
	}
}

func TestEtaField(t *testing.T) {
	t.Parallel()
	f := etaField(10*time.Second, 2, 4) // half done → ~10s remaining
	if f.Key != "eta" || f.String != "10s" {
		t.Fatalf("eta=%q", f.String)
	}
	z := etaField(0, 0, 10)
	if z.String != "0s" {
		t.Fatalf("unknown eta=%q", z.String)
	}
}

type ccTestServer struct {
	srv        *httptest.Server
	mem        *memFDNSStore
	ch         *fakeCCClickHouse
	pathsGets  atomic.Int64
	partGets   atomic.Int64
	extraParts int
	mu         sync.Mutex
	partBody   []byte
}

func newCCTestServer(t *testing.T) *ccTestServer {
	t.Helper()
	st := &ccTestServer{
		partBody: []byte("PARQUET-HOST-INDEX"),
	}

	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v2.paths.gz") || strings.HasSuffix(r.URL.Path, "/host-index-testing/v2.paths.gz"):
			st.pathsGets.Add(1)
			var b strings.Builder
			b.WriteString("projects/host-index-testing/v2/crawl=CC-MAIN-2025-13/CC-MAIN-2025-13.part-00000.parquet\n")
			b.WriteString("projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00000.parquet\n")
			b.WriteString("projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-00001.parquet\n")
			st.mu.Lock()
			extra := st.extraParts
			st.mu.Unlock()
			for i := 0; i < extra; i++ {
				b.WriteString("projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/CC-MAIN-2025-18.part-x" + strconv.Itoa(i) + ".parquet\n")
			}
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("ETag", `"paths-v1"`)
			_, _ = w.Write(gzipBytes(t, b.String()))
		case strings.Contains(r.URL.Path, "host-index-testing/v2/") && strings.HasSuffix(r.URL.Path, ".parquet"):
			st.partGets.Add(1)
			body := st.partBody
			etag := `"hi-0"`
			if strings.Contains(r.URL.Path, "part-00001") {
				etag = `"hi-1"`
			} else if strings.Contains(r.URL.Path, "part-x") {
				etag = `"hi-x"`
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(st.srv.Close)
	st.mem = newMemFDNSStore()
	return st
}

func (st *ccTestServer) ingestor(t *testing.T) *CCIngestor {
	t.Helper()
	st.ch = newFakeCCClickHouse()
	in := NewCCIngestor(zap.NewNop(), st.mem, st.srv.Client())
	in.CH = st.ch
	in.HostIndexPathsURL = st.srv.URL + "/projects/host-index-testing/v2.paths.gz"
	in.DataBaseURL = st.srv.URL
	in.ParquetDir = t.TempDir()
	in.Concurrency = 4
	return in
}

func gzipBytes(t *testing.T, body string) []byte {
	t.Helper()
	return gzipCSV(t, body)
}
