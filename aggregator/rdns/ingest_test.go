package rdns

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestIngestUnchangedETagShortCircuits(t *testing.T) {
	t.Parallel()
	st, gets := newRDNSTestServer(t)
	etag := `"v1"`
	st.mem.meta[st.fileURL] = &postgres.ResponseMetadataItem{Url: st.fileURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1 (live listing GET, per-file ETag skip)", gets())
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
}

func TestIngestLiveListingRetriesFailedFile(t *testing.T) {
	t.Parallel()
	st, gets := newRDNSTestServer(t)
	etag := `"v1"`
	st.mem.meta[st.listURL] = &postgres.ResponseMetadataItem{Url: st.listURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets() < 2 {
		t.Fatalf("GET count=%d, want listing+file (listing ETag must not hide live files)", gets())
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
}

func TestIngestForceIgnoresETag(t *testing.T) {
	t.Parallel()
	st, gets := newRDNSTestServer(t)
	etag := `"v1"`
	st.mem.meta[st.listURL] = &postgres.ResponseMetadataItem{Url: st.listURL, Etag: &etag}
	st.mem.meta[st.fileURL] = &postgres.ResponseMetadataItem{Url: st.fileURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	in.Force = true
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets() < 2 {
		t.Fatalf("GET count=%d, want listing+file", gets())
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
}

func TestIngestSuccessReplaceThenMetadata(t *testing.T) {
	t.Parallel()
	st, _ := newRDNSTestServer(t)
	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	got := st.mem.replaced[st.fileURL]
	if len(got) == 0 {
		t.Fatal("expected rows")
	}
	if got[0].Source != opconst.RIPE {
		t.Fatalf("source=%s", got[0].Source)
	}
	if st.mem.saveMetaN < 2 {
		t.Fatalf("saveMetaN=%d, want listing+file", st.mem.saveMetaN)
	}
}

func TestIngestEmptyParseDoesNotReplace(t *testing.T) {
	t.Parallel()
	st, _ := newRDNSTestServer(t)
	st.zoneBody = `$ORIGIN 193.in-addr.arpa.
@ IN SOA ns.ripe.net. dns.ripe.net. 1 2 3 4 5
`
	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatalf("SOA-only ingest must not fail: %v", err)
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
}

func TestIngestFailedRIRKeepsOther(t *testing.T) {
	t.Parallel()
	good, _ := newRDNSTestServer(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)

	in := NewIngestor(zap.NewNop(), good.mem, &http.Client{Timeout: time.Minute}, []Source{
		{Name: opconst.APNIC, ListURL: bad.URL + "/"},
		{Name: opconst.RIPE, ListURL: good.listURL},
	})
	err := in.Ingest(context.Background())
	if err == nil {
		t.Fatal("expected joined error from APNIC")
	}
	if !strings.Contains(err.Error(), opconst.APNIC) {
		t.Fatalf("err=%v", err)
	}
	if good.mem.replaceN != 1 {
		t.Fatalf("RIPE replaceN=%d, want 1 (failed RIR must not wipe the other)", good.mem.replaceN)
	}
	if _, ok := good.mem.replaced[good.fileURL]; !ok {
		t.Fatal("RIPE rows missing")
	}
}

func TestIngestHEADErrorFallsThroughToGET(t *testing.T) {
	t.Parallel()
	zone, err := os.ReadFile(filepath.Join("testdata", "193.in-addr.arpa-RIPE"))
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemRDNSStore()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.URL.Path == "/" || r.URL.Path == "" {
			if r.Method == http.MethodGet {
				gets.Add(1)
				io.WriteString(w, `<html><a href="193.in-addr.arpa-RIPE">193.in-addr.arpa-RIPE</a></html>`)
			}
			return
		}
		if r.Method == http.MethodHead {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			gets.Add(1)
			w.Write(zone)
		}
	}))
	t.Cleanup(srv.Close)
	fileURL := srv.URL + "/193.in-addr.arpa-RIPE"
	etag := `"v1"`
	mem.meta[fileURL] = &postgres.ResponseMetadataItem{Url: fileURL, Etag: &etag}

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []Source{{Name: opconst.RIPE, ListURL: srv.URL + "/"}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets.Load() < 2 {
		t.Fatalf("GET count=%d, want listing+file after non-2xx HEAD", gets.Load())
	}
	if mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", mem.replaceN)
	}
}

func TestIngestReplaceFloorDoesNotReplace(t *testing.T) {
	t.Parallel()
	st, _ := newRDNSTestServer(t)
	st.mem.existing[st.fileURL] = 100
	in := NewIngestor(zap.NewNop(), st.mem, st.srv.Client(), []Source{{Name: opconst.RIPE, ListURL: st.listURL}})
	err := in.Ingest(context.Background())
	if !errors.Is(err, ErrRDNSReplaceFloor) {
		t.Fatalf("err=%v, want ErrRDNSReplaceFloor", err)
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
}

func TestIngestEmptyListingIsError(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "listing_empty_hrefs.html"))
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemRDNSStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []Source{{Name: opconst.RIPE, ListURL: srv.URL + "/"}})
	err = in.Ingest(context.Background())
	if !errors.Is(err, ErrEmptyListing) {
		t.Fatalf("err=%v, want ErrEmptyListing", err)
	}
	if mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", mem.replaceN)
	}
}

func TestIngestSkipsChecksumGets(t *testing.T) {
	t.Parallel()
	var md5Gets atomic.Int32
	zone, err := os.ReadFile(filepath.Join("testdata", "193.in-addr.arpa-RIPE"))
	if err != nil {
		t.Fatal(err)
	}
	listing, err := os.ReadFile(filepath.Join("testdata", "listing.html"))
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemRDNSStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch {
		case strings.HasSuffix(r.URL.Path, ".md5") || strings.HasSuffix(r.URL.Path, ".asc"):
			if r.Method == http.MethodGet {
				md5Gets.Add(1)
			}
			io.WriteString(w, "deadbeef")
		case r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/"):
			if r.Method == http.MethodGet {
				w.Write(listing)
			}
		default:
			if r.Method == http.MethodGet {
				w.Write(zone)
			}
		}
	}))
	t.Cleanup(srv.Close)

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []Source{{Name: opconst.RIPE, ListURL: srv.URL + "/"}})
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if md5Gets.Load() != 0 {
		t.Fatalf("checksum GETs=%d, want 0", md5Gets.Load())
	}
}

type rdnsTestServer struct {
	srv      *httptest.Server
	mem      *memRDNSStore
	listURL  string
	fileURL  string
	zoneBody string
}

func newRDNSTestServer(t *testing.T) (*rdnsTestServer, func() int) {
	t.Helper()
	zone, err := os.ReadFile(filepath.Join("testdata", "193.in-addr.arpa-RIPE"))
	if err != nil {
		t.Fatal(err)
	}
	st := &rdnsTestServer{mem: newMemRDNSStore(), zoneBody: string(zone)}
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch {
		case r.URL.Path == "/" || r.URL.Path == "":
			if r.Method == http.MethodGet {
				gets.Add(1)
				io.WriteString(w, `<html><a href="193.in-addr.arpa-RIPE">193.in-addr.arpa-RIPE</a></html>`)
			}
		case strings.HasSuffix(r.URL.Path, "193.in-addr.arpa-RIPE"):
			if r.Method == http.MethodGet {
				gets.Add(1)
				io.WriteString(w, st.zoneBody)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	st.srv = srv
	st.listURL = srv.URL + "/"
	st.fileURL = srv.URL + "/193.in-addr.arpa-RIPE"
	return st, func() int { return int(gets.Load()) }
}

type memRDNSStore struct {
	mu        sync.Mutex
	meta      map[string]*postgres.ResponseMetadataItem
	replaced  map[string][]postgres.RDNSDelegation
	existing  map[string]int64
	replaceN  int
	saveMetaN int
}

func newMemRDNSStore() *memRDNSStore {
	return &memRDNSStore{
		meta:     make(map[string]*postgres.ResponseMetadataItem),
		replaced: make(map[string][]postgres.RDNSDelegation),
		existing: make(map[string]int64),
	}
}

func (m *memRDNSStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memRDNSStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memRDNSStore) ReplaceRDNSBySourceURL(ctx context.Context, sourceURL string, rows []postgres.RDNSDelegation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	cp := append([]postgres.RDNSDelegation(nil), rows...)
	m.replaced[sourceURL] = cp
	return nil
}

func (m *memRDNSStore) CountRDNSBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.existing[sourceURL], nil
}

func (m *memRDNSStore) UpsertRDNSDelegations(ctx context.Context, rows []postgres.RDNSDelegation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	for _, row := range rows {
		updated := false
		for url, list := range m.replaced {
			for i := range list {
				if list[i].Zone != row.Zone || list[i].Source != row.Source {
					continue
				}
				if len(list[i].Nservers) == 0 {
					list[i].Nservers = row.Nservers
				}
				if row.Org != "" {
					list[i].Org = row.Org
				}
				if len(row.AdminC) > 0 {
					list[i].AdminC = row.AdminC
				}
				if len(row.TechC) > 0 {
					list[i].TechC = row.TechC
				}
				if len(row.MntBy) > 0 {
					list[i].MntBy = row.MntBy
				}
				m.replaced[url] = list
				updated = true
			}
		}
		if !updated {
			key := row.SourceURL
			if key == "" {
				key = row.Source
			}
			m.replaced[key] = append(m.replaced[key], row)
		}
	}
	return nil
}
