package geofeeds

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"
)

type memCrawlStore struct {
	mu       sync.Mutex
	due      []postgres.GeofeedRow
	stamps   []postgres.GeofeedStamp
	replaced map[string][]*postgres.GeoIPItem
	claims   int
	replaceN int
}

func newMemCrawlStore(due ...postgres.GeofeedRow) *memCrawlStore {
	return &memCrawlStore{
		due:      due,
		replaced: make(map[string][]*postgres.GeoIPItem),
	}
}

func (m *memCrawlStore) ClaimDueGeofeeds(ctx context.Context, batch int, refreshOlderThan, lease time.Duration) ([]postgres.GeofeedRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claims++
	if m.claims > 1 {
		return nil, nil
	}
	if batch < len(m.due) {
		return m.due[:batch], nil
	}
	return append([]postgres.GeofeedRow(nil), m.due...), nil
}

func (m *memCrawlStore) StampGeofeed(ctx context.Context, stamp postgres.GeofeedStamp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stamps = append(m.stamps, stamp)
	return nil
}

func (m *memCrawlStore) ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*postgres.GeoIPItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	cp := append([]*postgres.GeoIPItem(nil), items...)
	m.replaced[sourceURL] = cp
	return nil
}

func (m *memCrawlStore) stampsCopy() []postgres.GeofeedStamp {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]postgres.GeofeedStamp(nil), m.stamps...)
}

func TestCrawl200ReplaceAndStamp(t *testing.T) {
	t.Parallel()
	var gotIMS, gotINM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		gotIMS = r.Header.Get("If-Modified-Since")
		w.Header().Set("ETag", `"v2"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2020 00:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Content-Type", "text/csv")
		io.WriteString(w, "192.0.2.0/24,US\n203.0.113.0/24,DE\n")
	}))
	t.Cleanup(srv.Close)

	etag := `"v1"`
	lm := "Tue, 01 Jan 2019 00:00:00 GMT"
	other := "https://other.example/feed.csv"
	st := newMemCrawlStore(postgres.GeofeedRow{
		URL:          srv.URL,
		ETag:         &etag,
		LastModified: &lm,
	})
	st.replaced[other] = []*postgres.GeoIPItem{{Netblock: "198.51.100.0/24"}}

	c := &Crawler{
		Store:      st,
		HTTPClient: srv.Client(),
		Workers:    1,
		Once:       true,
		Timeout:    5 * time.Second,
		now:        func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotINM != `"v1"` {
		t.Fatalf("If-None-Match = %q, want stored etag", gotINM)
	}
	if gotIMS != lm {
		t.Fatalf("If-Modified-Since = %q, want stored last-modified", gotIMS)
	}
	got := st.replaced[srv.URL]
	if len(got) != 2 {
		t.Fatalf("replaced %d rows, want 2", len(got))
	}
	if _, ok := st.replaced[other]; !ok {
		t.Fatal("replace must not drop another source_url's in-memory rows")
	}
	stamps := st.stampsCopy()
	if len(stamps) != 1 {
		t.Fatalf("stamps = %d, want 1", len(stamps))
	}
	s := stamps[0]
	if s.LastHTTPStatus == nil || *s.LastHTTPStatus != 200 {
		t.Fatalf("status = %v, want 200", s.LastHTTPStatus)
	}
	if s.LastFetchedAt == nil {
		t.Fatal("200 must set last_fetched_at")
	}
	if !s.ClearQuarantine {
		t.Fatal("200 must clear quarantine")
	}
	if s.ItemCount == nil || *s.ItemCount != 2 {
		t.Fatalf("item_count = %v, want 2", s.ItemCount)
	}
	if s.ETag == nil || *s.ETag != `"v2"` {
		t.Fatalf("etag = %v, want v2", s.ETag)
	}
}

func TestCrawl304DoesNotReplace(t *testing.T) {
	t.Parallel()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") != `"same"` {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(srv.Close)

	etag := `"same"`
	st := newMemCrawlStore(postgres.GeofeedRow{URL: srv.URL, ETag: &etag})
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 1, Once: true, Timeout: 5 * time.Second}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.replaceN != 0 {
		t.Fatalf("replace called %d times, want 0", st.replaceN)
	}
	stamps := st.stampsCopy()
	if len(stamps) != 1 || stamps[0].LastHTTPStatus == nil || *stamps[0].LastHTTPStatus != 304 {
		t.Fatalf("stamps = %+v, want 304", stamps)
	}
	if stamps[0].LastFetchedAt != nil {
		t.Fatal("304 must not set last_fetched_at")
	}
	if stamps[0].ClearQuarantine {
		t.Fatal("304 must not clear quarantine via success path")
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (one GET, no HEAD)", hits)
	}
}

func TestCrawl404QuarantinesDoesNotDelete(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	st := newMemCrawlStore(postgres.GeofeedRow{URL: srv.URL})
	fixed := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	c := &Crawler{
		Store:      st,
		HTTPClient: srv.Client(),
		Workers:    1,
		Once:       true,
		Timeout:    5 * time.Second,
		Quarantine: 24 * time.Hour,
		now:        func() time.Time { return fixed },
	}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.replaceN != 0 {
		t.Fatal("404 must not replace/delete geoip")
	}
	stamps := st.stampsCopy()
	if len(stamps) != 1 {
		t.Fatalf("stamps = %d", len(stamps))
	}
	s := stamps[0]
	if s.LastHTTPStatus == nil || *s.LastHTTPStatus != 404 {
		t.Fatalf("status = %v", s.LastHTTPStatus)
	}
	if s.QuarantinedUntil == nil || !s.QuarantinedUntil.Equal(fixed.Add(24*time.Hour)) {
		t.Fatalf("quarantine = %v, want +24h", s.QuarantinedUntil)
	}
	if s.IsValid == nil || *s.IsValid {
		t.Fatal("404 is_valid must be false")
	}
}

func TestCrawlHTMLQuarantines(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<!DOCTYPE html><html><body>nope</body></html>")
	}))
	t.Cleanup(srv.Close)

	st := newMemCrawlStore(postgres.GeofeedRow{URL: srv.URL})
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 1, Once: true, Timeout: 5 * time.Second}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.replaceN != 0 {
		t.Fatal("HTML must not replace geoip")
	}
	stamps := st.stampsCopy()
	if len(stamps) != 1 || stamps[0].QuarantinedUntil == nil {
		t.Fatalf("want quarantine stamp, got %+v", stamps)
	}
}

func TestCrawl304Then200ContinueDoesNotKillWorker(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/stale.csv":
			w.WriteHeader(http.StatusNotModified)
		case "/fresh.csv":
			w.Header().Set("Content-Type", "text/csv")
			io.WriteString(w, "192.0.2.0/24,US\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	st := newMemCrawlStore(
		postgres.GeofeedRow{URL: srv.URL + "/stale.csv"},
		postgres.GeofeedRow{URL: srv.URL + "/fresh.csv"},
	)
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 1, Once: true, Timeout: 5 * time.Second}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/stale.csv"] != 1 || hits["/fresh.csv"] != 1 {
		t.Fatalf("hits = %v; 304 must continue to the next URL (not return from the worker)", hits)
	}
	if _, ok := st.replaced[srv.URL+"/fresh.csv"]; !ok {
		t.Fatal("fresh URL must be replaced after a 304 sibling")
	}
	if _, ok := st.replaced[srv.URL+"/stale.csv"]; ok {
		t.Fatal("304 URL must not replace")
	}
}

func TestCrawlForceSkipsValidators(t *testing.T) {
	t.Parallel()
	var inm, ims string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inm = r.Header.Get("If-None-Match")
		ims = r.Header.Get("If-Modified-Since")
		w.Header().Set("Content-Type", "text/csv")
		io.WriteString(w, "192.0.2.0/24,US\n")
	}))
	t.Cleanup(srv.Close)

	etag := `"keep"`
	lm := "Wed, 01 Jan 2020 00:00:00 GMT"
	st := newMemCrawlStore(postgres.GeofeedRow{URL: srv.URL, ETag: &etag, LastModified: &lm})
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 1, Once: true, Force: true, Timeout: 5 * time.Second}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inm != "" || ims != "" {
		t.Fatalf("--force sent validators If-None-Match=%q If-Modified-Since=%q", inm, ims)
	}
}

func TestCrawlTwoSourceURLsIndependent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		switch r.URL.Path {
		case "/a.csv":
			io.WriteString(w, "192.0.2.0/24,US\n")
		case "/b.csv":
			io.WriteString(w, "198.51.100.0/24,BR\n")
		}
	}))
	t.Cleanup(srv.Close)

	urlA := srv.URL + "/a.csv"
	urlB := srv.URL + "/b.csv"
	st := newMemCrawlStore(
		postgres.GeofeedRow{URL: urlA},
		postgres.GeofeedRow{URL: urlB},
	)
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 2, Once: true, Timeout: 5 * time.Second}
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.replaced[urlA]) != 1 || st.replaced[urlA][0].Netblock != "192.0.2.0/24" {
		t.Fatalf("A = %+v", st.replaced[urlA])
	}
	if len(st.replaced[urlB]) != 1 || st.replaced[urlB][0].Netblock != "198.51.100.0/24" {
		t.Fatalf("B = %+v", st.replaced[urlB])
	}
}

func TestCacheUntilFromCacheControl(t *testing.T) {
	t.Parallel()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Run("max-age", func(t *testing.T) {
		got, ok := cacheUntilFromCacheControl("public, max-age=60", now)
		if !ok || got == nil || !got.Equal(now.Add(60*time.Second)) {
			t.Fatalf("got %v ok=%v", got, ok)
		}
	})
	t.Run("s-maxage wins", func(t *testing.T) {
		got, ok := cacheUntilFromCacheControl("max-age=10, s-maxage=30", now)
		if !ok || got == nil || !got.Equal(now.Add(30*time.Second)) {
			t.Fatalf("got %v ok=%v", got, ok)
		}
	})
	t.Run("no-cache", func(t *testing.T) {
		got, ok := cacheUntilFromCacheControl("no-cache", now)
		if !ok || got == nil || !got.Equal(now) {
			t.Fatalf("got %v ok=%v", got, ok)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, ok := cacheUntilFromCacheControl("public", now); ok {
			t.Fatal("expected no cache-until")
		}
	})
}

func TestCrawlSeenSetStopsReclaimLoop(t *testing.T) {
	t.Parallel()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(srv.Close)

	st := &loopStore{due: []postgres.GeofeedRow{{URL: srv.URL}}}
	c := &Crawler{Store: st, HTTPClient: srv.Client(), Workers: 1, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (304 must not infinite-loop ClaimDue)", hits)
	}
}

type loopStore struct {
	due []postgres.GeofeedRow
}

func (l *loopStore) ClaimDueGeofeeds(ctx context.Context, batch int, refreshOlderThan, lease time.Duration) ([]postgres.GeofeedRow, error) {
	return append([]postgres.GeofeedRow(nil), l.due...), nil
}

func (l *loopStore) StampGeofeed(ctx context.Context, stamp postgres.GeofeedStamp) error { return nil }

func (l *loopStore) ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*postgres.GeoIPItem) error {
	return nil
}
