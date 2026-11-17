package peeringdb

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oprand/opr/store/postgres"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

const orgDumpOne = `{"data":[{"id":1,"status":"ok","created":"2024-01-02T03:04:05Z","updated":"2024-01-02T03:04:05Z","name":"Org","address1":"1 Main","country":"US"}]}`

func TestIngestDumpEmptySkipsReplaceAndMetadata(t *testing.T) {
	t.Parallel()
	st, gets := newDumpTestServer(t, `{"data":[]}`)
	s := newDumpTestClient(st.srv.Client(), st.mem)

	changed, err := s.ingestDump(context.Background(), st.dump)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("empty dump must not report changed")
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 0 {
		t.Fatalf("saveMetaN=%d, want 0", st.mem.saveMetaN)
	}
	if gets() < 1 {
		t.Fatal("empty dump still requires a GET")
	}
}

func TestIngestDumpUnchangedETagShortCircuits(t *testing.T) {
	t.Parallel()
	st, gets := newDumpTestServer(t, orgDumpOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	s := newDumpTestClient(st.srv.Client(), st.mem)

	changed, err := s.ingestDump(context.Background(), st.dump)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged ETag must not report changed")
	}
	if gets() != 0 {
		t.Fatalf("GET count=%d, want 0 (ETag short-circuit)", gets())
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
	if st.mem.touchN != 1 {
		t.Fatalf("touchN=%d, want 1 (unchanged HEAD still watermarks)", st.mem.touchN)
	}
}

func TestIngestDumpForceIgnoresETag(t *testing.T) {
	t.Parallel()
	st, gets := newDumpTestServer(t, orgDumpOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	s := newDumpTestClient(st.srv.Client(), st.mem)
	s.Force = true

	changed, err := s.ingestDump(context.Background(), st.dump)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("--force must report changed")
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1 (--force)", gets())
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1", st.mem.saveMetaN)
	}
	got := st.mem.meta[st.srv.URL]
	if got == nil || got.Etag == nil || *got.Etag != `"v1"` {
		t.Fatalf("saved etag=%v, want GET ETag", got)
	}
}

func TestIngestDumpForceEmptySkipsMetadata(t *testing.T) {
	t.Parallel()
	st, gets := newDumpTestServer(t, `{"data":[]}`)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	s := newDumpTestClient(st.srv.Client(), st.mem)
	s.Force = true

	changed, err := s.ingestDump(context.Background(), st.dump)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("empty dump must not report changed")
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1 (--force still GETs)", gets())
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 0 {
		t.Fatalf("saveMetaN=%d, want 0 (failed ingest must not write metadata)", st.mem.saveMetaN)
	}
}

func TestIngestDumpSuccessReplaceThenMetadata(t *testing.T) {
	t.Parallel()
	st, _ := newDumpTestServer(t, orgDumpOne)
	s := newDumpTestClient(st.srv.Client(), st.mem)

	changed, err := s.ingestDump(context.Background(), st.dump)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first ingest must report changed")
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1 (replace then metadata)", st.mem.saveMetaN)
	}
	got := st.mem.replaced[st.dump.Table]
	if len(got) != 1 {
		t.Fatalf("replaced rows=%d, want 1", len(got))
	}
}

func TestDumpDBFallsBackToLiveStore(t *testing.T) {
	t.Parallel()
	mem := newMemDumpStore()
	if got := (&PeeringDBSynchronizationClient{dump: mem}).dumpDB(); got != dumpStore(mem) {
		t.Fatalf("seam store = %#v, want the injected memDumpStore", got)
	}
	live := &postgres.Store{}
	got, ok := (&PeeringDBSynchronizationClient{Store: live}).dumpDB().(*postgres.Store)
	if !ok || got != live {
		t.Fatalf("nil seam must resolve to the live Store, got %#v", got)
	}
}

type dumpTestServer struct {
	srv  *httptest.Server
	mem  *memDumpStore
	dump postgres.PeeringDBDumpRef
}

func newDumpTestServer(t *testing.T, body string) (*dumpTestServer, func() int) {
	t.Helper()
	mem := newMemDumpStore()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			gets.Add(1)
			io.WriteString(w, body)
		}
	}))
	t.Cleanup(srv.Close)
	return &dumpTestServer{
		srv: srv,
		mem: mem,
		dump: postgres.PeeringDBDumpRef{
			Tag:   postgres.PeeringDBDumpTagOrg,
			Table: postgres.PeeringDBTableOrganization,
			URL:   srv.URL,
		},
	}, func() int { return int(gets.Load()) }
}

func newDumpTestClient(client *http.Client, mem *memDumpStore) *PeeringDBSynchronizationClient {
	return &PeeringDBSynchronizationClient{
		HTTP:   client,
		Logger: zap.NewNop(),
		dump:   mem,
	}
}

type memDumpStore struct {
	mu        sync.Mutex
	meta      map[string]*postgres.ResponseMetadataItem
	replaced  map[string][][]any
	replaceN  int
	saveMetaN int
	touchN    int
}

func newMemDumpStore() *memDumpStore {
	return &memDumpStore{
		meta:     make(map[string]*postgres.ResponseMetadataItem),
		replaced: make(map[string][][]any),
	}
}

func (m *memDumpStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memDumpStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memDumpStore) TouchRemoteFileMetadata(ctx context.Context, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touchN++
	return nil
}

func (m *memDumpStore) ReplacePeeringDBTable(ctx context.Context, table string, src pgx.CopyFromSource) (int64, error) {
	var n int64
	var rows [][]any
	for src.Next() {
		vals, err := src.Values()
		if err != nil {
			return 0, err
		}
		rows = append(rows, vals)
		n++
	}
	if err := src.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, postgres.ErrPeeringDBEmptyDump
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	m.replaced[table] = rows
	return n, nil
}

var _ dumpStore = (*memDumpStore)(nil)
