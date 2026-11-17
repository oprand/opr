package registry

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestShouldDownIpnet(t *testing.T) {
	t.Parallel()
	alloc := decodeIPNetworkFixture(t, "NET-192-0-2-allocation.json")
	if !shouldDownIpnet(alloc) {
		t.Fatal("allocation with rdap-down must down")
	}
	if ipnetRDAPDownHref(alloc) == "" {
		t.Fatal("expected rdap-down href")
	}

	nolink := decodeIPNetworkFixture(t, "NET-192-0-2-allocation-nolink.json")
	if !shouldDownIpnet(nolink) {
		t.Fatal("allocation status without link must still down (constructed URL)")
	}
	if ipnetRDAPDownHref(nolink) != "" {
		t.Fatal("nolink fixture must have no down href")
	}

	leaf := decodeIPNetworkFixture(t, "NET-192-0-2-0-assignment.json")
	if shouldDownIpnet(leaf) {
		t.Fatal("leaf assignment with no down link must not down")
	}
}

func TestIpnetConstructRDAPDownURL(t *testing.T) {
	t.Parallel()
	got := ipnetConstructRDAPDownURL("https://rdap.arin.net/registry/", "192.0.2.0/24")
	want := "https://rdap.arin.net/registry/ips/rirSearch1/rdap-down/192.0.2.0/24"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	got6 := ipnetConstructRDAPDownURL("https://rdap.arin.net/registry", "2001:db8::/32")
	if !strings.Contains(got6, "/ips/rirSearch1/rdap-down/2001:db8::/32") {
		t.Fatalf("ipv6 url = %s", got6)
	}
	if ipnetConstructRDAPDownURL("", "192.0.2.0/24") != "" {
		t.Fatal("empty base must be empty")
	}
}

func TestIpnetDownChildKeySkipsParentCidr0(t *testing.T) {
	t.Parallel()
	parent := decodeIPNetworkFixture(t, "NET-192-0-2-allocation.json")
	parentCIDRs := ipnetParentCIDRSet("192.0.2.0/24", parent)
	if _, ok := parentCIDRs["192.0.2.0/24"]; !ok {
		t.Fatal("parent cidr0 must be in the skip set")
	}

	child := decodeIPNetworkFixture(t, "NET-192-0-2-0-assignment.json")
	// assignment cidr0 is also 192.0.2.0/24 — must not enqueue parent prefix
	if key := ipnetDownChildKey(child, parentCIDRs); key != "handle:d0:NET-192-0-2-0-1" {
		t.Fatalf("parent cidr0 child key = %q, want handle:d0 fallback", key)
	}

	lo := &rdap.IPNetwork{
		Handle:       "NET-192-0-2-0-25",
		StartAddress: "192.0.2.0",
		EndAddress:   "192.0.2.127",
		CIDR0Cidrs:   []rdap.CIDR0Cidr{{V4Prefix: "192.0.2.0", Length: 25}},
	}
	if key := ipnetDownChildKey(lo, parentCIDRs); key != "192.0.2.0/25" {
		t.Fatalf("child key = %q, want 192.0.2.0/25", key)
	}
}

func TestParseRDAPIPSearch(t *testing.T) {
	t.Parallel()
	raw := readRDAPTestdata(t, "NET-192-0-2-allocation-down.json")
	children, next := parseRDAPIPSearch(&rdap.Response{HTTP: []*rdap.HTTPResponse{{Body: raw}}})
	if len(children) != 2 {
		t.Fatalf("children = %d, want 2", len(children))
	}
	if next != "" {
		t.Fatalf("next = %q, want empty", next)
	}

	page1 := readRDAPTestdata(t, "NET-192-0-2-allocation-down-page1.json")
	children, next = parseRDAPIPSearch(&rdap.Response{HTTP: []*rdap.HTTPResponse{{Body: page1}}})
	if len(children) != 1 || children[0].Handle != "NET-192-0-2-0-25" {
		t.Fatalf("page1 children = %+v", children)
	}
	if !strings.Contains(next, "page=2") {
		t.Fatalf("page1 next = %q, want page=2", next)
	}
}

func TestIpnetHandlerAllocationDownEnqueuesChildren(t *testing.T) {
	t.Parallel()
	down := readRDAPTestdata(t, "NET-192-0-2-allocation-down.json")

	var paths []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/rdap+json")
		if strings.Contains(r.URL.Path, "/ips/rirSearch1/rdap-down") {
			_, _ = w.Write(down)
			return
		}
		_, _ = w.Write(rewriteARINHost(readRDAPTestdata(t, "NET-192-0-2-allocation.json"), srv.URL))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.ARIN
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var keys []string
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		if registry != opconst.ARIN {
			t.Errorf("registry = %q", registry)
		}
		keys = append(keys, key)
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "192.0.2.0/24", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if len(keys) != 2 {
		t.Fatalf("enqueue keys = %v, want 2 children", keys)
	}
	if keys[0] != "192.0.2.0/25" || keys[1] != "192.0.2.128/25" {
		t.Fatalf("keys = %v, want 192.0.2.0/25 and 192.0.2.128/25", keys)
	}
	for _, k := range keys {
		if k == "192.0.2.0/24" {
			t.Fatal("must not enqueue parent cidr0")
		}
	}
	var downs int
	for _, p := range paths {
		if strings.Contains(p, "rdap-down") {
			downs++
		}
	}
	if downs != 1 {
		t.Fatalf("down GETs = %d, want 1 (paths %v)", downs, paths)
	}
}

func TestIpnetHandlerLeafAssignmentNoDownGET(t *testing.T) {
	t.Parallel()
	body := readRDAPTestdata(t, "NET-192-0-2-0-assignment.json")
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.ARIN
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var downs int
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		downs++
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "192.0.2.0/24", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if downs != 0 {
		t.Fatalf("down enqueues = %d, want 0", downs)
	}
	for _, p := range paths {
		if strings.Contains(p, "rdap-down") || strings.Contains(p, "/ips/") {
			t.Fatalf("leaf assignment extra GET %s (paths %v)", p, paths)
		}
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %v, want one /ip/ GET", paths)
	}
}

func TestIpnetHandlerDownProbeFalse(t *testing.T) {
	t.Parallel()
	var paths []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(rewriteARINHost(readRDAPTestdata(t, "NET-192-0-2-allocation.json"), srv.URL))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.ARIN
	h.worker.setRIRSearch1(false)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var downs int
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		downs++
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "192.0.2.0/24", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if downs != 0 {
		t.Fatalf("down enqueues = %d, want 0 when probe is false", downs)
	}
	for _, p := range paths {
		if strings.Contains(p, "rdap-down") {
			t.Fatalf("probe false must not GET down, got %s", p)
		}
	}
}

func TestIpnetHandlerDownPaginationFollowsNext(t *testing.T) {
	t.Parallel()
	page2 := readRDAPTestdata(t, "NET-192-0-2-allocation-down-page2.json")

	var downPaths []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		if strings.Contains(r.URL.Path, "/ips/rirSearch1/rdap-down") {
			downPaths = append(downPaths, r.URL.RequestURI())
			if r.URL.Query().Get("page") == "2" {
				_, _ = w.Write(page2)
				return
			}
			_, _ = w.Write(rewriteARINHost(readRDAPTestdata(t, "NET-192-0-2-allocation-down-page1.json"), srv.URL))
			return
		}
		_, _ = w.Write(rewriteARINHost(readRDAPTestdata(t, "NET-192-0-2-allocation.json"), srv.URL))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.ARIN
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var keys []string
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		keys = append(keys, key)
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "192.0.2.0/24", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if len(downPaths) != 2 {
		t.Fatalf("down GETs = %v, want first page then rel=next", downPaths)
	}
	if !strings.Contains(downPaths[1], "page=2") {
		t.Fatalf("second GET = %s, want page=2", downPaths[1])
	}
	if len(keys) != 2 || keys[0] != "192.0.2.0/25" || keys[1] != "192.0.2.128/25" {
		t.Fatalf("keys = %v, want both page children", keys)
	}
}

func TestIpnetHandlerLACNICPersistDoesNotDown(t *testing.T) {
	t.Parallel()
	body := readRDAPTestdata(t, "LACNIC-2804-14d.json")
	// Allocation-shaped LACNIC object plus a down link: ARIN-only must still skip.
	body = bytes.Replace(body,
		[]byte(`"type": "allocated"`),
		[]byte(`"type": "ALLOCATION"`),
		1)
	body = bytes.Replace(body,
		[]byte(`"rel": "self"`),
		[]byte(`"rel": "rdap-down"`),
		1)

	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.LACNIC
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var downs int
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		downs++
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "2804:14d::/32", Registry: opconst.LACNIC})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if downs != 0 {
		t.Fatalf("LACNIC down enqueues = %d, want 0", downs)
	}
	for _, p := range paths {
		if strings.Contains(p, "rdap-down") || strings.Contains(p, "/ips/") {
			t.Fatalf("LACNIC must not GET down, got %s (paths %v)", p, paths)
		}
	}
}

func TestMaybeEnqueueDownDirect(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(true)
	var n int
	h.enqueueDownOverride = func(ctx context.Context, registry, key string) error {
		n++
		return nil
	}
	h.maybeEnqueueDown(context.Background(), zap.NewNop(), opconst.LACNIC,
		"2804:14d::/32", decodeIPNetworkFixture(t, "LACNIC-2804-14d.json"))
	if n != 0 {
		t.Fatalf("LACNIC maybeEnqueueDown enqueues = %d, want 0", n)
	}
}

func readRDAPTestdata(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rdap", file))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rewriteARINHost(body []byte, base string) []byte {
	return bytes.ReplaceAll(body, []byte("https://rdap.arin.net/registry"), []byte(strings.TrimRight(base, "/")))
}
