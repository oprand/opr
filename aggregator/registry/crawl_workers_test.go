package registry

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func TestParseCrawlKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr string
	}{
		{name: "omit", in: "", want: []string{postgres.CrawlKindAutnum, postgres.CrawlKindIpnet}},
		{name: "whitespace", in: "  ", want: []string{postgres.CrawlKindAutnum, postgres.CrawlKindIpnet}},
		{name: "autnum", in: "autnum", want: []string{postgres.CrawlKindAutnum}},
		{name: "autnum-upper", in: "AUTNUM", want: []string{postgres.CrawlKindAutnum}},
		{name: "ipnet", in: " ipnet ", want: []string{postgres.CrawlKindIpnet}},
		{name: "invalid-entity", in: "entity", wantErr: "unknown --kind"},
		{name: "invalid-both", in: "both", wantErr: "unknown --kind"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCrawlKinds(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestHandlerForKindSharesRegistryWorker(t *testing.T) {
	t.Parallel()
	limiter := NewAdaptiveLimiter(rate.Every(10*time.Second), 2, 10, 0.5, 0.5)
	shared := &RegistryWorker{Name: "ARIN", Limiter: limiter}
	aggr := &RegistryAggregator{
		Logger: zap.NewNop(),
		RegistryWorkers: map[string]*RegistryWorker{
			"ARIN": shared,
		},
	}

	autnumH, err := aggr.handlerForKind(postgres.CrawlKindAutnum, shared)
	if err != nil {
		t.Fatal(err)
	}
	ipnetH, err := aggr.handlerForKind(postgres.CrawlKindIpnet, shared)
	if err != nil {
		t.Fatal(err)
	}
	ah, ok := autnumH.(autnumHandler)
	if !ok {
		t.Fatalf("autnum handler type %T", autnumH)
	}
	ih, ok := ipnetH.(ipnetHandler)
	if !ok {
		t.Fatalf("ipnet handler type %T", ipnetH)
	}
	if ah.worker != shared || ih.worker != shared {
		t.Fatal("autnum and ipnet must use the same RegistryWorker pointer")
	}
	if ah.worker.Limiter != ih.worker.Limiter || ah.worker.Limiter != limiter {
		t.Fatal("kinds must share the per-RIR AdaptiveLimiter, not construct a second one")
	}
}

func TestStartCrawlWorkersUnknownKind(t *testing.T) {
	t.Parallel()
	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	err := aggr.StartCrawlWorkers(context.Background(), []string{"entity"}, CrawlConfig{})
	if err == nil || !strings.Contains(err.Error(), "unknown crawl kind") {
		t.Fatalf("err = %v, want unknown crawl kind", err)
	}
}

func TestStartCrawlWorkersEmptyKinds(t *testing.T) {
	t.Parallel()
	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	if err := aggr.StartCrawlWorkers(context.Background(), nil, CrawlConfig{}); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerForKindUnknown(t *testing.T) {
	t.Parallel()
	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	_, err := aggr.handlerForKind("geofeed", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown crawl kind") {
		t.Fatalf("err = %v", err)
	}
}

func TestIpnetHandlerInvalidKeyGone(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "not-a-cidr"})
	if got.Outcome != crawl.OutcomeGone {
		t.Fatalf("outcome = %v, want Gone", got.Outcome)
	}
	if got.Err == nil || !strings.Contains(got.Err.Error(), "invalid ipnet cidr key") {
		t.Fatalf("err = %v", got.Err)
	}
}

func TestIpnetHandlerHandleKeyRetry(t *testing.T) {
	t.Parallel()
	h := stubIpnetHandler()
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "handle:d0:ARIN-NET"})
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("outcome = %v, want Retry (rirSearch1 probe has no transport)", got.Outcome)
	}
	if got.Err == nil || !strings.Contains(got.Err.Error(), "rirSearch1") {
		t.Fatalf("err = %v, want rirSearch1 probe failure", got.Err)
	}
	got = h.Process(context.Background(), &postgres.CrawlTarget{Key: "HANDLE:d1:PARENT"})
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("HANDLE: outcome = %v, want Retry", got.Outcome)
	}
}

func TestIpnetHandlerValidCIDRAttemptsRDAP(t *testing.T) {
	t.Parallel()
	// No ProxyRing: doRDAPRequest returns a transport error. Valid CIDRs must
	// attempt RDAP (not the old 24h stub-no-RDAP path).
	h := stubIpnetHandler()
	got := h.Process(context.Background(), &postgres.CrawlTarget{Key: "192.0.2.0/24"})
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("ipv4 outcome = %v, want Retry after RDAP attempt", got.Outcome)
	}
	got6 := h.Process(context.Background(), &postgres.CrawlTarget{Key: "2001:db8::/32"})
	if got6.Outcome != crawl.OutcomeRetry {
		t.Fatalf("ipv6 outcome = %v, want Retry", got6.Outcome)
	}
	if got.RetryAfter == 24*time.Hour {
		t.Fatal("valid CIDR must not use a 24h stub delay")
	}
	if got.Err == nil || strings.Contains(got.Err.Error(), "not wired") {
		t.Fatalf("err = %v, want a real RDAP/transport error", got.Err)
	}
}

func TestIpnetHandlerNilTarget(t *testing.T) {
	t.Parallel()
	got := stubIpnetHandler().Process(context.Background(), nil)
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("outcome = %v, want Retry", got.Outcome)
	}
}

func stubIpnetHandler() ipnetHandler {
	return ipnetHandler{
		aggr:   &RegistryAggregator{Logger: zap.NewNop()},
		worker: &RegistryWorker{Name: "ARIN"},
	}
}
