package rdns

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestPTRStatsInterval(t *testing.T) {
	t.Parallel()
	if PTRStatsInterval != 5*time.Minute {
		t.Fatalf("PTRStatsInterval=%s, want 5m", PTRStatsInterval)
	}
}

func TestPTRCrawlStatsZapFields(t *testing.T) {
	t.Parallel()
	s := PTRCrawlStats{
		Elapsed:         5 * time.Minute,
		BlocksDone:      12,
		BlocksRemaining: 80,
		QueuePending:    70,
		QueueLeased:     10,
		QueueDone:       12,
		PTRQueries:      1500,
		Upserts:         1472,
		Rcodes:          map[string]int64{RcodeNXDOMAIN: 900, RcodeNOERROR: 600},
		CurrentPrefix:   "192.0.2.0/24",
		CurrentZone:     "2.0.192.in-addr.arpa.",
		CurrentNS:       "ns.example.",
		ApproxQPS:       ApproxPTRQPS(1500, 5*time.Minute),
	}
	if s.ApproxQPS != 5 {
		t.Fatalf("approx_qps=%v, want 5", s.ApproxQPS)
	}
	if ApproxPTRQPS(10, 0) != 0 {
		t.Fatal("zero elapsed must be 0 qps")
	}
	fields := s.ZapFields()
	want := []string{
		"elapsed", "blocks_done", "blocks_remaining",
		"queue_pending", "queue_leased", "queue_done", "queue_failed",
		"ptr_queries", "upserts", "rcodes",
		"current_prefix", "current_zone", "current_ns", "approx_qps",
	}
	got := map[string]zap.Field{}
	for _, f := range fields {
		got[f.Key] = f
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing zap field %s in %+v", k, fields)
		}
	}
	if got["elapsed"].String != "5m0s" {
		t.Fatalf("elapsed=%q, want 5m0s", got["elapsed"].String)
	}
	if got["current_prefix"].String != "192.0.2.0/24" {
		t.Fatalf("current_prefix=%q", got["current_prefix"].String)
	}
}

func TestPTRRunStatsSnapshot(t *testing.T) {
	t.Parallel()
	st := newPTRRunStats()
	st.setCurrent("192.0.2.0/24", "2.0.192.in-addr.arpa.", "ns.example.")
	st.addQuery(RcodeNXDOMAIN, "ns.example.")
	st.addQuery(RcodeNOERROR, "ns2.example.")
	st.addUpserts(2)
	st.addBlockDone()
	snap := st.snapshot()
	if snap.PTRQueries != 2 || snap.Upserts != 2 || snap.BlocksDone != 1 {
		t.Fatalf("%+v", snap)
	}
	if snap.Rcodes[RcodeNXDOMAIN] != 1 || snap.Rcodes[RcodeNOERROR] != 1 {
		t.Fatalf("rcodes=%v", snap.Rcodes)
	}
	if snap.CurrentPrefix != "192.0.2.0/24" || snap.CurrentNS != "ns2.example." {
		t.Fatalf("current %+v", snap)
	}
}
