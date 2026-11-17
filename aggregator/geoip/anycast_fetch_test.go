package geoip

import (
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

const anycastCSVOne = "192.0.2.0/24,192.0.2.1\n"

func TestFetchAnycastEmptyParseSkipsReplaceAndMetadata(t *testing.T) {
	t.Parallel()
	st, gets := newAnycastTestServer(t, "# only comments\n")
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	err := geo.fetchAnycastURL(context.Background(), false, st.srv.URL)
	if !errors.Is(err, ErrAnycastEmpty) {
		t.Fatalf("err=%v, want ErrAnycastEmpty", err)
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

func TestFetchAnycastUnchangedETagShortCircuits(t *testing.T) {
	t.Parallel()
	st, gets := newAnycastTestServer(t, anycastCSVOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	if err := geo.fetchAnycastURL(context.Background(), false, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if gets() != 0 {
		t.Fatalf("GET count=%d, want 0 (ETag short-circuit)", gets())
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

func TestFetchAnycastForceIgnoresETag(t *testing.T) {
	t.Parallel()
	st, gets := newAnycastTestServer(t, anycastCSVOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	if err := geo.fetchAnycastURL(context.Background(), true, st.srv.URL); err != nil {
		t.Fatal(err)
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
}

func TestFetchAnycastSuccessReplaceThenMetadata(t *testing.T) {
	t.Parallel()
	st, _ := newAnycastTestServer(t, anycastCSVOne)
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	if err := geo.fetchAnycastURL(context.Background(), false, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1 (replace then metadata)", st.mem.saveMetaN)
	}
	got := st.mem.replaced[st.srv.URL]
	if len(got) != 1 || got[0].Netblock != "192.0.2.0/24" {
		t.Fatalf("replaced=%+v", got)
	}
}

func TestFetchAnycastFloorGuardDoesNotReplace(t *testing.T) {
	t.Parallel()
	st, _ := newAnycastTestServer(t, anycastCSVOne)
	st.mem.existing[st.srv.URL] = 100
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	err := geo.fetchAnycastURL(context.Background(), false, st.srv.URL)
	if !errors.Is(err, ErrAnycastReplaceFloor) {
		t.Fatalf("err=%v, want ErrAnycastReplaceFloor", err)
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

// fetchAnycastURL has no production/test fork any more: the ETag check always
// runs anycastFileChanged against anycastDB(), so the short-circuit and
// --force tests above cover the code production runs. anycastDB() picking the
// live Store when the seam is nil is the only remaining difference.
func TestAnycastDBFallsBackToLiveStore(t *testing.T) {
	t.Parallel()
	mem := newMemAnycastStore()
	if got := (&GeoIpAggregator{anycast: mem}).anycastDB(); got != anycastStore(mem) {
		t.Fatalf("seam store = %#v, want the injected memAnycastStore", got)
	}
	live := &postgres.Store{}
	got, ok := (&GeoIpAggregator{Store: live}).anycastDB().(*postgres.Store)
	if !ok || got != live {
		t.Fatalf("nil seam must resolve to the live Store, got %#v", got)
	}
}

// opnet.HasFileChanged used httpClient.Head, which ignores ctx. A canceled
// context must fail the fetch instead of silently completing a HEAD and
// short-circuiting on a matching ETag.
func TestFetchAnycastHeadHonorsContext(t *testing.T) {
	t.Parallel()
	st, gets := newAnycastTestServer(t, anycastCSVOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	geo := newAnycastTestAgg(st.srv.Client(), st.mem)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := geo.fetchAnycastURL(ctx, false, st.srv.URL); err == nil {
		t.Fatal("canceled context must fail the fetch, not fall back to a context-less HEAD")
	}
	if gets() != 0 {
		t.Fatalf("GET count=%d, want 0", gets())
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

func TestFetchAnycastWalksBothURLs(t *testing.T) {
	t.Parallel()
	v4, _ := newAnycastTestServer(t, "1.1.1.0/24,1.1.1.0\n")
	v6, _ := newAnycastTestServer(t, "2001:db8::/32,2001:db8::1\n")
	mem := newMemAnycastStore()
	geo := newAnycastTestAgg(v4.srv.Client(), mem)
	geo.HTTPClient = v4.srv.Client()

	err := geo.fetchAnycastURLs(context.Background(), false, []string{v4.srv.URL, v6.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if mem.replaceN != 2 {
		t.Fatalf("replaceN=%d, want 2", mem.replaceN)
	}
	if _, ok := mem.replaced[v4.srv.URL]; !ok {
		t.Fatal("v4 url must be replaced")
	}
	if _, ok := mem.replaced[v6.srv.URL]; !ok {
		t.Fatal("v6 url must be replaced")
	}
}

type anycastTestServer struct {
	srv *httptest.Server
	mem *memAnycastStore
}

func newAnycastTestServer(t *testing.T, body string) (*anycastTestServer, func() int) {
	t.Helper()
	mem := newMemAnycastStore()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			gets.Add(1)
			io.WriteString(w, body)
		}
	}))
	t.Cleanup(srv.Close)
	return &anycastTestServer{srv: srv, mem: mem}, func() int { return int(gets.Load()) }
}

func newAnycastTestAgg(client *http.Client, mem *memAnycastStore) *GeoIpAggregator {
	return &GeoIpAggregator{
		HTTPClient: client,
		Logger:     zap.NewNop(),
		anycast:    mem,
	}
}

type memAnycastStore struct {
	mu        sync.Mutex
	meta      map[string]*postgres.ResponseMetadataItem
	replaced  map[string][]*postgres.AnycastPrefix
	existing  map[string]int64
	replaceN  int
	saveMetaN int
}

func newMemAnycastStore() *memAnycastStore {
	return &memAnycastStore{
		meta:     make(map[string]*postgres.ResponseMetadataItem),
		replaced: make(map[string][]*postgres.AnycastPrefix),
		existing: make(map[string]int64),
	}
}

func (m *memAnycastStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memAnycastStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memAnycastStore) ReplaceAnycastBySourceURL(ctx context.Context, sourceURL string, items []*postgres.AnycastPrefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	m.replaced[sourceURL] = append([]*postgres.AnycastPrefix(nil), items...)
	return nil
}

func (m *memAnycastStore) CountAnycastBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.existing[sourceURL], nil
}
