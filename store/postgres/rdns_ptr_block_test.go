package postgres

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSeedRDNSPTRBlocksSQLIsMasklenQueue(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(seedRDNSPTRBlocksSQL)
	if !strings.Contains(sql, "from rdns_delegation") {
		t.Fatal("seed must read rdns_delegation")
	}
	if !strings.Contains(sql, "masklen(prefix) between 24 and 32") {
		t.Fatal("IPv4 blocks are masklen BETWEEN 24 AND 32")
	}
	if !strings.Contains(sql, "masklen(prefix) >= 120") {
		t.Fatal("IPv6 blocks are masklen >= 120")
	}
	if !strings.Contains(sql, "source <> 'iana'") {
		t.Fatal("seed must exclude IANA")
	}
	if strings.Contains(sql, "prefix <<") {
		t.Fatal("full-crawl seed must not use prefix << anti-join")
	}
	if !strings.Contains(sql, "on conflict (prefix) do update") {
		t.Fatal("re-seed must ON CONFLICT DO UPDATE")
	}
	if !strings.Contains(sql, "rdns_ptr_block.state = 'failed'") {
		t.Fatal("seed must reset failed rows so TIMEOUT/SERVFAIL/ERROR retry")
	}
	if strings.Contains(sql, "on conflict (prefix) do nothing") {
		t.Fatal("DO NOTHING would leave failed blocks stuck")
	}
	if !strings.Contains(sql, "group by b.prefix") {
		t.Fatal("ERX duplicates must merge per prefix")
	}
}

func TestClaimRDNSPTRBlockSQLSkipLocked(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(claimRDNSPTRBlockSQL)
	if !strings.Contains(sql, "for update skip locked") {
		t.Fatal("concurrent claimers must SKIP LOCKED")
	}
	if !strings.Contains(sql, "state = 'pending'") {
		t.Fatal("claim pending blocks")
	}
	if !strings.Contains(sql, "prefix::text") {
		t.Fatal("RETURNING prefix::text so pgx fills a string")
	}
	if !strings.Contains(sql, "locked_at < now() - ($2 * interval '1 second')") {
		t.Fatal("stale leases must be reclaimable")
	}
	if strings.Contains(sql, "md5") || strings.Contains(sql, "order by") {
		t.Fatal("claim must not ORDER BY md5 (sorts the whole queue per block)")
	}
	if !strings.Contains(sql, "source = any($3)") {
		t.Fatal("claim must honor --only-registries via source = ANY($3)")
	}
	if !strings.Contains(strings.ToLower(finishRDNSPTRBlockSQL), "locked_by = $2") {
		t.Fatal("finish must require locked_by")
	}
	if !strings.Contains(strings.ToLower(failRDNSPTRBlockSQL), "locked_by = $2") {
		t.Fatal("fail must require locked_by")
	}
	if !strings.Contains(strings.ToLower(releaseRDNSPTRBlockSQL), "locked_by = $2") {
		t.Fatal("release must require locked_by")
	}
	if !strings.Contains(strings.ToLower(heartbeatRDNSPTRBlockSQL), "locked_at = now()") {
		t.Fatal("heartbeat must renew locked_at")
	}
	if strings.Contains(sql, "rdns_delegation") {
		t.Fatal("claim reads rdns_ptr_block, not rdns_delegation")
	}
}

func TestCountRDNSPTRBlocksSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(countRDNSPTRBlocksSQL)
	if !strings.Contains(sql, "from rdns_ptr_block") {
		t.Fatal("counts must read rdns_ptr_block")
	}
	for _, st := range []string{"pending", "leased", "done", "failed"} {
		if !strings.Contains(sql, "state = '"+st+"'") {
			t.Fatalf("missing %s count", st)
		}
	}
}

func TestClaimRDNSPTRBlockLeaseGuard(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.ClaimRDNSPTRBlock(context.Background(), "t", 0, nil); err == nil {
		t.Fatal("lease <= 0 must error")
	}
}

func TestFinishRDNSPTRBlockEmptyPrefix(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.FinishRDNSPTRBlock(context.Background(), "", "w"); err == nil {
		t.Fatal("empty prefix must error")
	}
}

func TestClaimRDNSPTRBlockPostgresExclusive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRBlockTestStore(t)
	ctx := context.Background()
	a := "192.0.2.0/24"
	b := "198.51.100.0/24"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr_block WHERE prefix IN ($1::inet, $2::inet)`, a, b)
	})
	if _, err := st.DB.Exec(ctx, `
		INSERT INTO rdns_ptr_block (prefix, zone, nservers, source, state)
		VALUES
			($1::inet, '2.0.192.in-addr.arpa.', '{ns.a}', 'RIPE', 'pending'),
			($2::inet, '100.51.198.in-addr.arpa.', '{ns.b}', 'ARIN', 'pending')
		ON CONFLICT (prefix) DO UPDATE SET state = 'pending', locked_at = NULL, done_at = NULL`, a, b); err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			block, err := st.ClaimRDNSPTRBlock(ctx, "test", time.Minute, nil)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			if block == nil {
				t.Error("expected a block")
				return
			}
			got <- block.Prefix
		}()
	}
	wg.Wait()
	close(got)
	seen := map[string]struct{}{}
	for p := range got {
		if _, dup := seen[p]; dup {
			t.Fatalf("two workers claimed %s", p)
		}
		seen[p] = struct{}{}
	}
	if len(seen) != 2 {
		t.Fatalf("claimed %v, want both test prefixes", seen)
	}
}

func TestFinishRDNSPTRBlockWrongWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRBlockTestStore(t)
	ctx := context.Background()
	p := "203.0.113.0/24"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr_block WHERE prefix = $1::inet`, p)
	})
	if _, err := st.DB.Exec(ctx, `
		INSERT INTO rdns_ptr_block (prefix, zone, nservers, source, state)
		VALUES ($1::inet, '0.113.203.in-addr.arpa.', '{ns}', 'TEST-LEASE', 'pending')
		ON CONFLICT (prefix) DO UPDATE SET state = 'pending', locked_at = NULL, locked_by = '', done_at = NULL, source = 'TEST-LEASE'`, p); err != nil {
		t.Fatal(err)
	}
	got, err := st.ClaimRDNSPTRBlock(ctx, "worker-a", time.Minute, []string{"TEST-LEASE"})
	if err != nil || got == nil {
		t.Fatalf("claim: %v %v", got, err)
	}
	err = st.FinishRDNSPTRBlock(ctx, p, "worker-b")
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("wrong worker finish: %v", err)
	}
	var state, lockedBy string
	if err := st.DB.QueryRow(ctx, `SELECT state, locked_by FROM rdns_ptr_block WHERE prefix = $1::inet`, p).Scan(&state, &lockedBy); err != nil {
		t.Fatal(err)
	}
	if state != PTRBlockLeased || lockedBy != "worker-a" {
		t.Fatalf("wrong worker must not Finish: state=%s locked_by=%s", state, lockedBy)
	}
	if err := st.FinishRDNSPTRBlock(ctx, p, "worker-a"); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatRDNSPTRBlockKeepsLease(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRBlockTestStore(t)
	ctx := context.Background()
	p := "203.0.113.8/24"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr_block WHERE prefix = $1::inet`, p)
	})
	if _, err := st.DB.Exec(ctx, `
		INSERT INTO rdns_ptr_block (prefix, zone, nservers, source, state)
		VALUES ($1::inet, '8.113.203.in-addr.arpa.', '{ns}', 'TEST-BEAT', 'pending')
		ON CONFLICT (prefix) DO UPDATE SET state = 'pending', locked_at = NULL, locked_by = '', done_at = NULL, source = 'TEST-BEAT'`, p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimRDNSPTRBlock(ctx, "worker-a", 2*time.Second, []string{"TEST-BEAT"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := st.HeartbeatRDNSPTRBlock(ctx, p, "worker-a"); err != nil {
		t.Fatal(err)
	}
	stolen, err := st.ClaimRDNSPTRBlock(ctx, "worker-b", 2*time.Second, []string{"TEST-BEAT"})
	if err != nil {
		t.Fatal(err)
	}
	if stolen != nil && stolen.Prefix == p {
		t.Fatal("fresh heartbeat must keep the lease from being stolen")
	}
	if _, err := st.DB.Exec(ctx, `UPDATE rdns_ptr_block SET locked_at = now() - interval '1 hour' WHERE prefix = $1::inet`, p); err != nil {
		t.Fatal(err)
	}
	got, err := st.ClaimRDNSPTRBlock(ctx, "worker-b", 2*time.Second, []string{"TEST-BEAT"})
	if err != nil || got == nil {
		t.Fatalf("stale lease must be claimable: %v %v", got, err)
	}
	if got.LockedBy != "worker-b" {
		t.Fatalf("locked_by=%s", got.LockedBy)
	}
}

func TestClaimRDNSPTRBlockOnlyRegistries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rdnsPTRBlockTestStore(t)
	ctx := context.Background()
	ripe := "203.0.113.16/24"
	arin := "203.0.113.32/24"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM rdns_ptr_block WHERE prefix IN ($1::inet, $2::inet)`, ripe, arin)
	})
	if _, err := st.DB.Exec(ctx, `
		INSERT INTO rdns_ptr_block (prefix, zone, nservers, source, state)
		VALUES
			($1::inet, '16.113.203.in-addr.arpa.', '{ns}', 'TEST-RIPE', 'pending'),
			($2::inet, '32.113.203.in-addr.arpa.', '{ns}', 'TEST-ARIN', 'pending')
		ON CONFLICT (prefix) DO UPDATE SET state = 'pending', locked_at = NULL, locked_by = '', done_at = NULL, source = EXCLUDED.source`, ripe, arin); err != nil {
		t.Fatal(err)
	}
	got, err := st.ClaimRDNSPTRBlock(ctx, "w", time.Minute, []string{"TEST-RIPE"})
	if err != nil || got == nil {
		t.Fatalf("claim RIPE: %v %v", got, err)
	}
	if got.Source != "TEST-RIPE" {
		t.Fatalf("claimed %s source=%s, want TEST-RIPE", got.Prefix, got.Source)
	}
}

func TestFinishRDNSPTRBlockEmptyLockedBy(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.FinishRDNSPTRBlock(context.Background(), "192.0.2.0/24", ""); err == nil {
		t.Fatal("empty locked_by must error")
	}
}

func rdnsPTRBlockTestStore(t *testing.T) *Store {
	t.Helper()
	st := rdnsPTRTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	var n int
	if err := st.DB.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'rdns_ptr_block'`).Scan(&n); err != nil || n == 0 {
		t.Skip("rdns_ptr_block table missing (run migration 0080)")
	}
	return st
}
