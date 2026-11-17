package registry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

func TestResultForParsedIpnetPersistError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("save failed")
	got := resultForParsedIpnet(func() error { return wantErr })
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("outcome: got %v, want OutcomeRetry", got.Outcome)
	}
	if got.Err != wantErr {
		t.Fatalf("err: got %v, want %v", got.Err, wantErr)
	}
}

func TestResultForParsedIpnetSuccess(t *testing.T) {
	t.Parallel()
	saved := false
	got := resultForParsedIpnet(func() error {
		saved = true
		return nil
	})
	if !saved {
		t.Fatal("persist must be called")
	}
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome: got %v, want OutcomeSuccess", got.Outcome)
	}
}

func TestIpnetHandler429Retry(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Retry-After", "90")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	_, ipn, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, res, ok := h.fetchIpnetWithBases(context.Background(), zap.NewNop(), ipn, srv.URL, "")
	if ok {
		t.Fatal("429 must not persist")
	}
	if res.Outcome != crawl.OutcomeRetry {
		t.Fatalf("outcome = %v, want Retry", res.Outcome)
	}
	if res.StatusCode == nil || *res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %v, want 429", res.StatusCode)
	}
	if res.RetryAfter != 90*time.Second {
		t.Fatalf("RetryAfter = %v, want 90s", res.RetryAfter)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (no inner spin on throttle)", hits)
	}
}

func TestFetchIpnetRegistroBR404FallsBackToLACNIC(t *testing.T) {
	t.Parallel()
	var nicbrHits, lacHits int
	nicbr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nicbrHits++
		if !strings.Contains(r.URL.Path, "/ip/192.0.2.0/24") {
			t.Errorf("nic.br path = %s, want /ip/192.0.2.0/24", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nicbr.Close()
	lac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lacHits++
		if !strings.Contains(r.URL.Path, "/ip/192.0.2.0/24") {
			t.Errorf("lacnic path = %s, want /ip/192.0.2.0/24", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer lac.Close()

	h := testIpnetHandler(t)
	_, ipn, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, res, ok := h.fetchIpnetWithBases(context.Background(), zap.NewNop(), ipn, nicbr.URL, lac.URL)
	if ok {
		t.Fatal("both 404s must not persist")
	}
	if res.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", res.Outcome)
	}
	if nicbrHits != 1 || lacHits != 1 {
		t.Fatalf("hits nicbr=%d lac=%d, want 1 each (404 then parent retry)", nicbrHits, lacHits)
	}
}

func TestFetchIpnetLACNIC404DoesNotFallback(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	_, ipn, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, res, ok := h.fetchIpnetWithBases(context.Background(), zap.NewNop(), ipn, srv.URL, "")
	if ok || res.Outcome != crawl.OutcomeGone {
		t.Fatalf("ok=%v outcome=%v, want Gone", ok, res.Outcome)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (no fallback when already on parent)", hits)
	}
}

func TestIpnetHandlerProcessInvalidAndHandle(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	if got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "not-a-cidr"}); got.Outcome != crawl.OutcomeGone {
		t.Fatalf("invalid: %v", got.Outcome)
	}
	if got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d0:ARIN-NET"}); got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("handle without probe cache: %v, want Retry (probe transport missing)", got.Outcome)
	}
	if got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:junk"}); got.Outcome != crawl.OutcomeGone {
		t.Fatalf("invalid handle: %v, want Gone", got.Outcome)
	}
}

func TestDoRDAPRequestIPNetUsesIntendedServer(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Limiter.OnThrottle(time.Hour)

	_, ipn, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	req := applyRDAPServer(rdap.NewIPNetRequest(ipn), srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, _ := h.aggr.doRDAPRequest(ctx, h.worker, req)
	if time.Since(start) > time.Second {
		t.Fatal("Waited on paused LACNIC limiter; AIMD must follow req.Server host")
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 against intended server", hits)
	}
	httpResp := rdapFirstHTTP(resp)
	if httpResp == nil || httpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %v, want 404 from httptest", httpResp)
	}
}

func testIpnetHandler(t *testing.T) ipnetHandler {
	t.Helper()
	pr, err := NewRingLoadBalancer(nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return ipnetHandler{
		aggr: &RegistryAggregator{Logger: zap.NewNop()},
		worker: &RegistryWorker{
			Name:      opconst.LACNIC,
			ProxyRing: pr,
			Limiter:   newLimiterForRegistry(opconst.LACNIC),
		},
	}
}

func TestPersistMappedGeofeedsBestEffort(t *testing.T) {
	t.Parallel()
	url := "https://example.com/geofeed.csv"
	called := false
	h := stubIpnetHandler()
	h.saveGeofeedsOverride = func(ctx context.Context, urls []string) error {
		called = true
		if len(urls) != 1 || urls[0] != url {
			t.Fatalf("urls = %v, want [%s]", urls, url)
		}
		return errors.New("db down")
	}
	h.persistMappedGeofeeds(context.Background(), zap.NewNop(),
		[]*whoisdb.WhoisInetNum{{Geofeed: &url}}, nil)
	if !called {
		t.Fatal("SaveGeofeeds must be attempted")
	}
}

func TestPersistMappedGeofeedsSkipsEmpty(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.saveGeofeedsOverride = func(ctx context.Context, urls []string) error {
		t.Fatal("must not save empty catalog")
		return nil
	}
	h.persistMappedGeofeeds(context.Background(), zap.NewNop(), nil, nil)
}
