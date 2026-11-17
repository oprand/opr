package fdns

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestIngest304SkipsUpsert(t *testing.T) {
	t.Parallel()
	st, gets := newFDNSTestServer(t)
	etag := `"v1"`
	st.mem.meta[st.trancoURL] = &postgres.ResponseMetadataItem{Url: st.trancoURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []List{{
		Name: SourceTranco, URL: st.trancoURL, Format: FormatRankedCSV, Compression: CompressZip,
	}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1 (If-None-Match)", gets())
	}
	if st.mem.upsertN != 0 {
		t.Fatalf("upsertN=%d, want 0", st.mem.upsertN)
	}
	if st.mem.saveMetaN != 0 {
		t.Fatalf("saveMetaN=%d, want 0 on 304", st.mem.saveMetaN)
	}
	if st.mem.touchN != 1 {
		t.Fatalf("touchN=%d, want 1", st.mem.touchN)
	}
	if got := st.ifNoneMatch(); got != `"v1"` {
		t.Fatalf("If-None-Match=%q", got)
	}
}

func TestIngestForceIgnoresETag(t *testing.T) {
	t.Parallel()
	st, gets := newFDNSTestServer(t)
	etag := `"v1"`
	st.mem.meta[st.trancoURL] = &postgres.ResponseMetadataItem{Url: st.trancoURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []List{{
		Name: SourceTranco, URL: st.trancoURL, Format: FormatRankedCSV, Compression: CompressZip,
	}})
	in.Force = true
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1", gets())
	}
	if got := st.ifNoneMatch(); got != "" {
		t.Fatalf("--force sent If-None-Match=%q", got)
	}
	if st.mem.upsertN != 1 {
		t.Fatalf("upsertN=%d, want 1", st.mem.upsertN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1", st.mem.saveMetaN)
	}
}

func TestIngestSuccessUpsertThenMetadata(t *testing.T) {
	t.Parallel()
	st, _ := newFDNSTestServer(t)
	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []List{
		{Name: SourceTranco, URL: st.trancoURL, Format: FormatRankedCSV, Compression: CompressZip},
		{Name: SourceUmbrella, URL: st.umbrellaURL, Format: FormatRankedCSV, Compression: CompressZip},
		{Name: SourceCrux, URL: st.cruxURL, Format: FormatCrUXCSV, Compression: CompressGzip},
	})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.mem.upsertN != 3 {
		t.Fatalf("upsertN=%d, want 3", st.mem.upsertN)
	}
	if st.mem.saveMetaN != 3 {
		t.Fatalf("saveMetaN=%d, want 3 (upsert then metadata)", st.mem.saveMetaN)
	}
	tranco := namesIn(st.mem.upserted[SourceTranco])
	if !tranco["google.com"] || !tranco["facebook.com"] {
		t.Fatalf("tranco=%v", tranco)
	}
	umb := namesIn(st.mem.upserted[SourceUmbrella])
	if !umb["www.google.com"] {
		t.Fatalf("umbrella=%v", umb)
	}
	crux := namesIn(st.mem.upserted[SourceCrux])
	if !crux["www.youtube.com"] {
		t.Fatalf("crux=%v", crux)
	}
}

func TestIngestEmptyParseSkipsUpsertAndMetadata(t *testing.T) {
	t.Parallel()
	mem := newMemFDNSStore()
	body := zipCSV(t, "top-1m.csv", "# only comments\n")
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		w.Header().Set("ETag", `"empty"`)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []List{{
		Name: SourceTranco, URL: srv.URL, Format: FormatRankedCSV, Compression: CompressZip,
	}})
	err := in.Ingest(context.Background())
	if !errors.Is(err, ErrEmptyList) {
		t.Fatalf("err=%v, want ErrEmptyList", err)
	}
	if mem.upsertN != 0 || mem.saveMetaN != 0 {
		t.Fatalf("upsertN=%d saveMetaN=%d, want 0", mem.upsertN, mem.saveMetaN)
	}
	if gets.Load() < 1 {
		t.Fatal("empty dump still requires a GET")
	}
}

func TestIngestUnparseableDoesNotUpsert(t *testing.T) {
	t.Parallel()
	mem := newMemFDNSStore()
	body := zipCSV(t, "top-1m.csv", "<!DOCTYPE html><html><body>nope</body></html>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []List{{
		Name: SourceTranco, URL: srv.URL, Format: FormatRankedCSV, Compression: CompressZip,
	}})
	err := in.Ingest(context.Background())
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("err=%v, want ErrUnparseable", err)
	}
	if mem.upsertN != 0 || mem.saveMetaN != 0 {
		t.Fatalf("upsertN=%d saveMetaN=%d, want 0", mem.upsertN, mem.saveMetaN)
	}
}

func TestIngestOneFailureKeepsOtherLists(t *testing.T) {
	t.Parallel()
	st, _ := newFDNSTestServer(t)
	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []List{
		{Name: SourceTranco, URL: st.trancoURL, Format: FormatRankedCSV, Compression: CompressZip},
		{Name: SourceUmbrella, URL: st.srv.URL + "/missing.zip", Format: FormatRankedCSV, Compression: CompressZip},
	})
	err := in.Ingest(context.Background())
	if err == nil {
		t.Fatal("missing list must error")
	}
	if st.mem.upsertN != 1 {
		t.Fatalf("upsertN=%d, want 1 (tranco kept)", st.mem.upsertN)
	}
}

type fdnsTestServer struct {
	srv         *httptest.Server
	mem         *memFDNSStore
	trancoURL   string
	umbrellaURL string
	cruxURL     string
	lastINM     string
	mu          sync.Mutex
}

func newFDNSTestServer(t *testing.T) (*fdnsTestServer, func() int) {
	t.Helper()
	st := &fdnsTestServer{mem: newMemFDNSStore()}
	var gets atomic.Int32
	tranco := zipCSV(t, "top-1m.csv", "1,google.com\n2,facebook.com\n")
	umbrella := zipCSV(t, "top-1m.csv", "1,www.google.com\n2,cdn.example.net\n")
	crux := gzipCSV(t, "origin,rank\nhttps://www.youtube.com/,1000\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm := r.Header.Get("If-None-Match")
		st.mu.Lock()
		st.lastINM = inm
		st.mu.Unlock()
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		w.Header().Set("ETag", `"v1"`)
		if inm == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		switch r.URL.Path {
		case "/tranco.zip":
			w.Write(tranco)
		case "/umbrella.zip":
			w.Write(umbrella)
		case "/crux.csv.gz":
			w.Write(crux)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	st.srv = srv
	st.trancoURL = srv.URL + "/tranco.zip"
	st.umbrellaURL = srv.URL + "/umbrella.zip"
	st.cruxURL = srv.URL + "/crux.csv.gz"
	return st, func() int { return int(gets.Load()) }
}

func (st *fdnsTestServer) ifNoneMatch() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.lastINM
}

func zipCSV(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipCSV(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.WriteString(gz, body); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func namesIn(rows []postgres.HostName) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Name] = true
	}
	return out
}

type memFDNSStore struct {
	mu          sync.Mutex
	meta        map[string]*postgres.ResponseMetadataItem
	upserted    map[string][]postgres.HostName
	upsertedIPs []postgres.HostIP
	upsertN     int
	upsertIPN   int
	saveMetaN   int
	touchN      int
}

func newMemFDNSStore() *memFDNSStore {
	return &memFDNSStore{
		meta:     make(map[string]*postgres.ResponseMetadataItem),
		upserted: make(map[string][]postgres.HostName),
	}
}

func (m *memFDNSStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memFDNSStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memFDNSStore) TouchRemoteFileMetadata(ctx context.Context, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touchN++
	return nil
}

func (m *memFDNSStore) UpsertHostNames(ctx context.Context, rows []postgres.HostName) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertN++
	cp := append([]postgres.HostName(nil), rows...)
	if len(rows) > 0 && len(rows[0].Source) > 0 {
		m.upserted[rows[0].Source[0]] = cp
	}
	return nil
}

func (m *memFDNSStore) UpsertHostIPs(ctx context.Context, rows []postgres.HostIP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertIPN++
	m.upsertedIPs = append(m.upsertedIPs, append([]postgres.HostIP(nil), rows...)...)
	return nil
}
