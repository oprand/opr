package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestConformanceHasRIRSearch1(t *testing.T) {
	t.Parallel()
	if !conformanceHasRIRSearch1([]string{"rdap_level_0", "rirSearch1"}) {
		t.Fatal("rirSearch1 must match")
	}
	if !conformanceHasRIRSearch1([]string{"RIRSEARCH1"}) {
		t.Fatal("match is case-insensitive")
	}
	if conformanceHasRIRSearch1([]string{"rdap_level_0", "cidr0"}) {
		t.Fatal("absent rirSearch1 must be false")
	}
	if conformanceHasRIRSearch1(nil) {
		t.Fatal("empty must be false")
	}
}

func TestProbeRIRSearch1True(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.Contains(r.URL.Path, "/help") {
			t.Errorf("path = %s, want /help", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"rdapConformance":["rdap_level_0","rirSearch1"]}`))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.rdapBaseOverride = srv.URL
	if !h.supportsRIRSearch1(context.Background()) {
		t.Fatal("rirSearch1 conformance must probe true")
	}
	supported, known := h.worker.rirSearch1State()
	if !known || !supported {
		t.Fatalf("cached supported=%v known=%v, want true/true", supported, known)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestProbeRIRSearch1False(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"rdapConformance":["rdap_level_0"]}`))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.rdapBaseOverride = srv.URL
	if h.supportsRIRSearch1(context.Background()) {
		t.Fatal("help without rirSearch1 must probe false")
	}
	supported, known := h.worker.rirSearch1State()
	if !known || supported {
		t.Fatalf("cached supported=%v known=%v, want false/true", supported, known)
	}
}

func TestProbeRIRSearch1CacheHit(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"rdapConformance":["rirSearch1"]}`))
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.rdapBaseOverride = srv.URL
	if !h.supportsRIRSearch1(context.Background()) {
		t.Fatal("first probe")
	}
	if !h.supportsRIRSearch1(context.Background()) {
		t.Fatal("cached probe")
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (cache, no second GET)", hits)
	}
}

func TestRIRSearchProbeUsesParentRDAPBase(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.Name = opconst.LACNIC
	got := h.rirSearchProbeBase()
	want := nro.RDAPBaseURL(opconst.LACNIC)
	if got != want {
		t.Fatalf("LACNIC probe base = %q, want %q", got, want)
	}
	if nro.HostIsRegistroBR(got) {
		t.Fatal("must probe lacnic.net, not registro.br")
	}
	for _, name := range []string{opconst.ARIN, opconst.RIPE, opconst.APNIC, opconst.AFRINIC} {
		h.worker.Name = name
		if h.rirSearchProbeBase() != nro.RDAPBaseURL(name) {
			t.Fatalf("%s probe base = %q, want %q", name, h.rirSearchProbeBase(), nro.RDAPBaseURL(name))
		}
	}
}

func TestParseIpnetHandleKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key    string
		depth  int
		handle string
		ok     bool
	}{
		{key: "handle:d0:NET-192-0-2-0-0", depth: 0, handle: "NET-192-0-2-0-0", ok: true},
		{key: "HANDLE:d1:PARENT", depth: 1, handle: "PARENT", ok: true},
		{key: "handle:d5:H", depth: 5, handle: "H", ok: true},
		{key: "handle:d6:H", depth: 6, handle: "H", ok: true},
		{key: "handle:ARIN-NET", ok: false},
		{key: "handle:d:FOO", ok: false},
		{key: "handle:d0:", ok: false},
		{key: "handle:", ok: false},
		{key: "192.0.2.0/24", ok: false},
	}
	for _, tc := range cases {
		depth, handle, ok := parseIpnetHandleKey(tc.key)
		if ok != tc.ok || depth != tc.depth || handle != tc.handle {
			t.Errorf("%q: got (%d, %q, %v), want (%d, %q, %v)",
				tc.key, depth, handle, ok, tc.depth, tc.handle, tc.ok)
		}
	}
}

func TestNextParentEnqueueDepth(t *testing.T) {
	t.Parallel()
	if d, ok := nextParentEnqueueDepth(99, false); !ok || d != 0 {
		t.Fatalf("CIDR: got %d %v, want d0", d, ok)
	}
	if d, ok := nextParentEnqueueDepth(0, true); !ok || d != 1 {
		t.Fatalf("d0: got %d %v, want d1", d, ok)
	}
	if d, ok := nextParentEnqueueDepth(4, true); !ok || d != 5 {
		t.Fatalf("d4: got %d %v, want d5", d, ok)
	}
	if _, ok := nextParentEnqueueDepth(5, true); ok {
		t.Fatal("d5 must not enqueue d6")
	}
}

func TestShouldEnqueueIpnetParentAssignment(t *testing.T) {
	t.Parallel()
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-0-assignment.json")
	if !shouldEnqueueIpnetParent(resp) {
		t.Fatal("assignment with parentHandle must enqueue")
	}
	if !ipnetLooksLikeAssignmentOrReallocation(resp) {
		t.Fatal("fixture status/type must look like assignment")
	}
	if resp.ParentHandle != "NET-192-0-2-0-0" {
		t.Fatalf("parentHandle = %q", resp.ParentHandle)
	}
}

func TestShouldEnqueueIpnetParentProbeFalseNoInsert(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(false)
	var enqueues int
	h.enqueueOverride = func(ctx context.Context, registry, handle string, depth int) error {
		enqueues++
		return nil
	}
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-0-assignment.json")
	h.maybeEnqueueParent(context.Background(), zap.NewNop(), opconst.ARIN, resp, 0, false)
	if enqueues != 0 {
		t.Fatalf("enqueues = %d, want 0 when probe is false", enqueues)
	}
}

func TestMaybeEnqueueParentCIDRInsertsHandleD0(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(true)
	var gotKey string
	var gotDepth int
	var n int
	h.enqueueOverride = func(ctx context.Context, registry, handle string, depth int) error {
		n++
		gotKey = postgres.IpnetParentHandleKey(handle, depth)
		gotDepth = depth
		if registry != opconst.ARIN {
			t.Errorf("registry = %q", registry)
		}
		return nil
	}
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-0-assignment.json")
	h.maybeEnqueueParent(context.Background(), zap.NewNop(), opconst.ARIN, resp, 0, false)
	if n != 1 {
		t.Fatalf("enqueues = %d, want 1", n)
	}
	if gotDepth != 0 || gotKey != "handle:d0:NET-192-0-2-0-0" {
		t.Fatalf("got key %q depth %d, want handle:d0:NET-192-0-2-0-0", gotKey, gotDepth)
	}
}

func TestShouldEnqueueIpnetParentCidr0DoesNotEnqueueChildren(t *testing.T) {
	t.Parallel()
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-cidr0.json")
	if shouldEnqueueIpnetParent(resp) {
		t.Fatal("cidr0-only object has no parentHandle; must not enqueue")
	}
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(true)
	var enqueues []string
	h.enqueueOverride = func(ctx context.Context, registry, handle string, depth int) error {
		enqueues = append(enqueues, handle)
		return nil
	}
	h.maybeEnqueueParent(context.Background(), zap.NewNop(), opconst.ARIN, resp, 0, false)
	if len(enqueues) != 0 {
		t.Fatalf("cidr0 must not enqueue children, got %v", enqueues)
	}
	prefs := ipnetPrefixesFromRDAP("192.0.2.0/25", resp)
	if len(prefs) != 2 {
		t.Fatalf("cidr0 prefixes = %d, want 2 whois siblings (not crawl_target children)", len(prefs))
	}
}

func TestIpNetworkFromRDAPSearchEnvelope(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "rdap", "NET-192-0-2-0-assignment-search.json"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := rdap.NewDecoder(raw).Decode()
	if err != nil {
		t.Fatal(err)
	}
	resp := &rdap.Response{
		Object: obj,
		HTTP:   []*rdap.HTTPResponse{{Body: raw}},
	}
	n := ipNetworkFromRDAPResponse(resp)
	if n == nil || n.Handle != "NET-192-0-2-0-1" || n.ParentHandle != "NET-192-0-2-0-0" {
		t.Fatalf("search envelope: %+v", n)
	}
}

func TestIpnetHandlerHandleInvalidGone(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(true)
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:ARIN-NET"})
	if got.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", got.Outcome)
	}
}

func TestIpnetHandlerHandleDepthCapGone(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(true)
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d6:NET-TOO-DEEP"})
	if got.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", got.Outcome)
	}
}

func TestIpnetHandlerHandleProbeFalseGone(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	h.worker.setRIRSearch1(false)
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d0:ARIN-NET"})
	if got.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", got.Outcome)
	}
}

func TestIpnetHandlerHandle404Gone(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/ips") || r.URL.Query().Get("handle") != "NET-MISSING" {
			t.Errorf("url = %s", r.URL.String())
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d0:NET-MISSING", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", got.Outcome)
	}
}

func TestIpnetHandlerHandle200Persist(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "rdap", "NET-192-0-2-0-assignment-search.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("handle") != "NET-192-0-2-0-1" {
			t.Errorf("handle = %q", r.URL.Query().Get("handle"))
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.Name = opconst.ARIN
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	var persisted *rdap.IPNetwork
	var queried string
	h.persistOverride = func(ctx context.Context, q, registry string, resp *rdap.IPNetwork) error {
		queried = q
		persisted = resp
		return nil
	}
	var enqueues []string
	h.enqueueOverride = func(ctx context.Context, registry, handle string, depth int) error {
		enqueues = append(enqueues, postgres.IpnetParentHandleKey(handle, depth))
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d0:NET-192-0-2-0-1", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if persisted == nil || persisted.Handle != "NET-192-0-2-0-1" {
		t.Fatalf("persist object = %+v", persisted)
	}
	if queried != "" {
		t.Fatalf("queried CIDR = %q, want empty (mapper uses cidr0)", queried)
	}
	if len(enqueues) != 1 || enqueues[0] != "handle:d1:NET-192-0-2-0-0" {
		t.Fatalf("enqueues = %v, want one handle:d1 parent", enqueues)
	}
}

func TestIpnetHandlerHandleNoEnqueuePast5(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "rdap", "NET-192-0-2-0-assignment.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	h := testIpnetHandler(t)
	h.worker.setRIRSearch1(true)
	h.rdapBaseOverride = srv.URL
	h.persistOverride = func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error {
		return nil
	}
	var enqueues int
	h.enqueueOverride = func(ctx context.Context, registry, handle string, depth int) error {
		enqueues++
		return nil
	}

	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d5:NET-192-0-2-0-1", Registry: opconst.ARIN})
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome = %v err=%v, want Success", got.Outcome, got.Err)
	}
	if enqueues != 0 {
		t.Fatalf("enqueues = %d, want 0 (d5 must not enqueue d6)", enqueues)
	}
}

func TestIpnetHandleSearchRequest(t *testing.T) {
	t.Parallel()
	req := ipnetHandleSearchRequest("https://rdap.arin.net/registry", "NET-192-0-2-0-0")
	if req == nil || req.URL() == nil {
		t.Fatal("nil request")
	}
	u := req.URL().String()
	if !strings.Contains(u, "/ips") || !strings.Contains(u, "handle=NET-192-0-2-0-0") {
		t.Fatalf("url = %s", u)
	}
}
