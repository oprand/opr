package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"

	"go.uber.org/zap"
)

func TestRdapBasesForCrawl(t *testing.T) {
	t.Parallel()
	primary, fallback := rdapBasesForCrawl(opconst.LACNIC, "BR")
	if primary != opconst.RegistroBRRDAPEndpoint {
		t.Fatalf("BR primary: got %q, want %q", primary, opconst.RegistroBRRDAPEndpoint)
	}
	if fallback != opconst.RegistryRDAPEndpoints[opconst.LACNIC] {
		t.Fatalf("BR fallback: got %q, want lacnic.net", fallback)
	}

	primary, fallback = rdapBasesForCrawl(opconst.LACNIC, "CL")
	if primary != opconst.RegistryRDAPEndpoints[opconst.LACNIC] || fallback != "" {
		t.Fatalf("CL: primary=%q fallback=%q, want lacnic.net and no fallback", primary, fallback)
	}

	primary, fallback = rdapBasesForCrawl(opconst.LACNIC, "")
	if primary != opconst.RegistryRDAPEndpoints[opconst.LACNIC] || fallback != "" {
		t.Fatalf("empty country: primary=%q fallback=%q", primary, fallback)
	}

	primary, fallback = rdapBasesForCrawl(opconst.ARIN, "BR")
	if primary != opconst.RegistryRDAPEndpoints[opconst.ARIN] || fallback != "" {
		t.Fatalf("ARIN+BR must not switch servers: primary=%q fallback=%q", primary, fallback)
	}
}

func TestIpFromRDAPQueryUsesNetworkAddress(t *testing.T) {
	t.Parallel()
	if got := ipFromRDAPQuery("192.0.2.1/24"); got == nil || got.String() != "192.0.2.0" {
		t.Fatalf("cidr host bits: got %v, want 192.0.2.0", got)
	}
	if got := ipFromRDAPQuery("2001:db8::1/32"); got == nil || got.String() != "2001:db8::" {
		t.Fatalf("v6 cidr: got %v, want 2001:db8::", got)
	}
	if got := ipFromRDAPQuery("192.0.2.9"); got == nil || got.String() != "192.0.2.9" {
		t.Fatalf("bare IP: got %v", got)
	}
}

func TestFetchAutnumRegistroBR404FallsBackToLACNIC(t *testing.T) {
	t.Parallel()
	var nicbrHits, lacHits int
	nicbr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nicbrHits++
		if !strings.Contains(r.URL.Path, "/autnum/268000") {
			t.Errorf("nic.br path = %s, want /autnum/268000", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nicbr.Close()
	lac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lacHits++
		if !strings.Contains(r.URL.Path, "/autnum/268000") {
			t.Errorf("lacnic path = %s, want /autnum/268000", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer lac.Close()

	h := testAutnumHandler(t)
	_, res, ok := h.fetchAutnumWithBases(context.Background(), zap.NewNop(), 268000, nicbr.URL, lac.URL)
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

func TestFetchAutnumLACNIC404DoesNotFallback(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := testAutnumHandler(t)
	_, res, ok := h.fetchAutnumWithBases(context.Background(), zap.NewNop(), 1, srv.URL, "")
	if ok || res.Outcome != crawl.OutcomeGone {
		t.Fatalf("ok=%v outcome=%v, want Gone", ok, res.Outcome)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (no fallback when already on parent)", hits)
	}
}

func TestDoRDAPRequestUsesIntendedServerNotWorkerLimiter(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := testAutnumHandler(t)
	// Pause the LACNIC worker limiter as if lacnic.net had 429'd. BR (and this
	// httptest host) must Wait on a different AdaptiveLimiter.
	h.worker.Limiter.OnThrottle(time.Hour)

	req := applyRDAPServer(rdap.NewAutnumRequest(1), srv.URL)
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
	if req.Server == nil || req.Server.Host != mustURL(t, srv.URL).Host {
		t.Fatalf("doRDAPRequest must not overwrite req.Server with lacnic.net, got %v", req.Server)
	}
}

func testAutnumHandler(t *testing.T) autnumHandler {
	t.Helper()
	pr, err := NewRingLoadBalancer(nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return autnumHandler{
		aggr: &RegistryAggregator{Logger: zap.NewNop()},
		worker: &RegistryWorker{
			Name:      opconst.LACNIC,
			ProxyRing: pr,
			Limiter:   newLimiterForRegistry(opconst.LACNIC),
		},
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
