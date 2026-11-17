package rdns

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type memPTRStore struct {
	mu              sync.Mutex
	leaves          []postgres.RDNSLeaf
	rows            []postgres.RDNSPTR
	lastQuery       postgres.RDNSLeafQuery
	listLeavesCalls int
	blocks          []postgres.RDNSPTRBlock
	lockedAt        map[string]time.Time
}

func (m *memPTRStore) ListRDNSLeaves(ctx context.Context, q postgres.RDNSLeafQuery) ([]postgres.RDNSLeaf, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listLeavesCalls++
	m.lastQuery = q
	out := make([]postgres.RDNSLeaf, 0, len(m.leaves))
	for _, leaf := range m.leaves {
		if len(q.Sources) > 0 {
			ok := false
			for _, s := range q.Sources {
				if strings.EqualFold(s, leaf.Source) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, leaf)
	}
	return out, nil
}

func (m *memPTRStore) UpsertRDNSPTR(ctx context.Context, rows []postgres.RDNSPTR) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byIP := make(map[string]int, len(m.rows))
	for i, r := range m.rows {
		byIP[r.IP] = i
	}
	for _, row := range rows {
		if i, ok := byIP[row.IP]; ok {
			if postgres.ShouldReplaceRDNSPTR(m.rows[i], row) {
				m.rows[i] = row
			}
			continue
		}
		byIP[row.IP] = len(m.rows)
		m.rows = append(m.rows, row)
	}
	return nil
}

func (m *memPTRStore) SeedRDNSPTRBlocks(ctx context.Context, sources []string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	have := make(map[string]int, len(m.blocks))
	for i, b := range m.blocks {
		have[b.Prefix] = i
	}
	var inserted int64
	for _, leaf := range m.leaves {
		if SkipReason(leaf.Prefix) != "" {
			continue
		}
		if len(sources) > 0 {
			ok := false
			for _, s := range sources {
				if strings.EqualFold(s, leaf.Source) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if i, ok := have[leaf.Prefix]; ok {
			if m.blocks[i].State == postgres.PTRBlockFailed {
				m.blocks[i].State = postgres.PTRBlockPending
				delete(m.lockedAt, leaf.Prefix)
			}
			m.blocks[i].Nservers = unionStrings(m.blocks[i].Nservers, leaf.Nservers)
			continue
		}
		m.blocks = append(m.blocks, postgres.RDNSPTRBlock{
			Prefix:   leaf.Prefix,
			Zone:     leaf.Zone,
			Nservers: append([]string(nil), leaf.Nservers...),
			Source:   leaf.Source,
			State:    postgres.PTRBlockPending,
		})
		have[leaf.Prefix] = len(m.blocks) - 1
		inserted++
	}
	return inserted, nil
}

func (m *memPTRStore) ClaimRDNSPTRBlock(ctx context.Context, lockedBy string, lease time.Duration, sources []string) (*postgres.RDNSPTRBlock, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockedAt == nil {
		m.lockedAt = map[string]time.Time{}
	}
	now := time.Now()
	for i := range m.blocks {
		b := &m.blocks[i]
		if len(sources) > 0 {
			ok := false
			for _, s := range sources {
				if strings.EqualFold(s, b.Source) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		due := b.State == postgres.PTRBlockPending
		if b.State == postgres.PTRBlockLeased {
			if t, ok := m.lockedAt[b.Prefix]; ok && lease > 0 && now.Sub(t) > lease {
				due = true
			}
		}
		if !due {
			continue
		}
		b.State = postgres.PTRBlockLeased
		b.LockedBy = lockedBy
		m.lockedAt[b.Prefix] = now
		cp := *b
		return &cp, nil
	}
	return nil, nil
}

func (m *memPTRStore) ownerUpdate(ctx context.Context, prefix, lockedBy, next string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.blocks {
		if m.blocks[i].Prefix != prefix {
			continue
		}
		if m.blocks[i].State != postgres.PTRBlockLeased || m.blocks[i].LockedBy != lockedBy {
			return postgres.ErrPTRBlockLeaseLost
		}
		m.blocks[i].State = next
		if next != postgres.PTRBlockLeased {
			m.blocks[i].LockedBy = ""
			delete(m.lockedAt, prefix)
		}
		return nil
	}
	return postgres.ErrPTRBlockLeaseLost
}

func (m *memPTRStore) FinishRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return m.ownerUpdate(ctx, prefix, lockedBy, postgres.PTRBlockDone)
}

func (m *memPTRStore) FailRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return m.ownerUpdate(ctx, prefix, lockedBy, postgres.PTRBlockFailed)
}

func (m *memPTRStore) ReleaseRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return m.ownerUpdate(ctx, prefix, lockedBy, postgres.PTRBlockPending)
}

func (m *memPTRStore) HeartbeatRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.blocks {
		if m.blocks[i].Prefix != prefix {
			continue
		}
		if m.blocks[i].State != postgres.PTRBlockLeased || m.blocks[i].LockedBy != lockedBy {
			return postgres.ErrPTRBlockLeaseLost
		}
		if m.lockedAt == nil {
			m.lockedAt = map[string]time.Time{}
		}
		m.lockedAt[prefix] = time.Now()
		return nil
	}
	return postgres.ErrPTRBlockLeaseLost
}

func (m *memPTRStore) CountRDNSPTRBlocks(ctx context.Context) (postgres.RDNSPTRBlockCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var c postgres.RDNSPTRBlockCounts
	for _, b := range m.blocks {
		switch b.State {
		case postgres.PTRBlockPending:
			c.Pending++
		case postgres.PTRBlockLeased:
			c.Leased++
		case postgres.PTRBlockDone:
			c.Done++
		case postgres.PTRBlockFailed:
			c.Failed++
		}
	}
	return c, nil
}

func TestCrawlPTRRFC8020SkipsChildren(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "0.0.193.in-addr.arpa.",
		Prefix:   "193.0.0.0/24",
		Nservers: []string{"127.0.0.1:9"},
		Source:   opconst.RIPE,
	}}}
	var names []string
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		names = append(names, strings.ToLower(dns.Fqdn(qname)))
		if strings.EqualFold(dns.Fqdn(qname), "0.0.193.in-addr.arpa.") {
			return dns.RcodeNameError, nil, nil
		}
		t.Fatalf("child PTR must not run after zone NXDOMAIN: %s", qname)
		return dns.RcodeSuccess, nil, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("queries=%v, want only the zone probe", names)
	}
	if len(mem.rows) != 0 {
		t.Fatalf("no address rows after RFC 8020 skip: %+v", mem.rows)
	}
	if mem.blockState("193.0.0.0/24") != postgres.PTRBlockDone {
		t.Fatalf("RFC 8020 NXDOMAIN skip may stay done, got %s", mem.blockState("193.0.0.0/24"))
	}
}

func TestCrawlPTRPersistsNXDOMAIN(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "2.0.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/32",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.Contains(qname, "192.0.2.0") || strings.HasPrefix(strings.ToLower(qname), "2.0.192.in-addr.arpa") {
			if strings.EqualFold(dns.Fqdn(qname), "2.0.192.in-addr.arpa.") {
				return dns.RcodeSuccess, nil, nil // zone exists (NODATA)
			}
			return dns.RcodeNameError, nil, nil
		}
		return dns.RcodeNameError, nil, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mem.rows) != 1 {
		t.Fatalf("rows=%+v", mem.rows)
	}
	if mem.rows[0].Rcode != RcodeNXDOMAIN {
		t.Fatalf("rcode=%s", mem.rows[0].Rcode)
	}
	if mem.rows[0].PTR != nil {
		t.Fatalf("ptr=%v", mem.rows[0].PTR)
	}
	if mem.rows[0].IP != "192.0.2.0" {
		t.Fatalf("ip=%s", mem.rows[0].IP)
	}
}

func TestCrawlPTRLimitStops(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "2.0.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/24",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	var hostQueries int
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.Limit = 3
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.EqualFold(dns.Fqdn(qname), "2.0.192.in-addr.arpa.") {
			return dns.RcodeSuccess, nil, nil
		}
		hostQueries++
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hostQueries != 3 {
		t.Fatalf("hostQueries=%d, want 3", hostQueries)
	}
	if len(mem.rows) != 3 {
		t.Fatalf("rows=%d", len(mem.rows))
	}
	if mem.rows[0].PTR == nil || *mem.rows[0].PTR != "host.example" {
		t.Fatalf("ptr=%v", mem.rows[0].PTR)
	}
	if mem.blockState("192.0.2.0/24") != postgres.PTRBlockLeased {
		t.Fatalf("incomplete --limit walk must stay leased, got %s", mem.blockState("192.0.2.0/24"))
	}
}

func TestCrawlPTRPrefixAndZoneFilter(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{
		{Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24", Nservers: []string{"ns.test."}, Source: opconst.RIPE},
		{Zone: "1.0.1.in-addr.arpa.", Prefix: "1.0.1.0/24", Nservers: []string{"ns.test."}, Source: opconst.APNIC},
	}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.Prefix = "192.0.2.0/24"
	cr.Limit = 1
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.Contains(qname, "1.0.1") {
			t.Fatalf("APNIC leaf must not be queried: %s", qname)
		}
		if strings.EqualFold(dns.Fqdn(qname), "2.0.192.in-addr.arpa.") {
			return dns.RcodeSuccess, nil, nil
		}
		return dns.RcodeSuccess, []string{"a.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}

	mem2 := &memPTRStore{leaves: mem.leaves}
	cr2 := NewPTRCrawler(zap.NewNop(), mem2)
	cr2.Zone = "1.0.1.in-addr.arpa"
	cr2.Limit = 1
	cr2.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.Contains(qname, "192.0.2") || strings.Contains(qname, "2.0.192") {
			t.Fatalf("RIPE leaf must not be queried: %s", qname)
		}
		return dns.RcodeSuccess, []string{"b.example."}, nil
	}
	if err := cr2.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCrawlPTROnlyRegistries(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{
		{Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/32", Nservers: []string{"ns.test."}, Source: opconst.RIPE},
		{Zone: "1.0.1.in-addr.arpa.", Prefix: "1.0.1.1/32", Nservers: []string{"ns.test."}, Source: opconst.APNIC},
	}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.OnlyRegistries = []string{opconst.RIPE}
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.Contains(qname, "1.0.1") {
			t.Fatalf("filtered registry queried: %s", qname)
		}
		return dns.RcodeSuccess, []string{"ripe.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mem.rows) != 1 || mem.rows[0].IP != "192.0.2.0" {
		t.Fatalf("rows=%+v", mem.rows)
	}
}

func TestCrawlPTRRefusesCoarsePrefix(t *testing.T) {
	t.Parallel()
	cr := NewPTRCrawler(zap.NewNop(), &memPTRStore{})
	cr.Prefix = "10.0.0.0/8"
	err := cr.Crawl(context.Background())
	if err == nil {
		t.Fatal("want coarse prefix error")
	}
}

func TestCrawlPTRPassesZoneAndDerivedPrefix(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "0.158.92.in-addr.arpa.",
		Prefix:   "92.158.0.0/24",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.Zone = "0.158.92.in-addr.arpa"
	cr.Limit = 1
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mem.lastQuery.Zone != "0.158.92.in-addr.arpa" {
		t.Fatalf("Zone=%q, want the --zone value on ListRDNSLeaves", mem.lastQuery.Zone)
	}
	wantPrefix, err := ZoneToPrefix("0.158.92.in-addr.arpa")
	if err != nil {
		t.Fatal(err)
	}
	if mem.lastQuery.Prefix != wantPrefix {
		t.Fatalf("Prefix=%q, want derived %q so SQL GiST-scopes the anti-join", mem.lastQuery.Prefix, wantPrefix)
	}
}

func TestLeafQueryDoesNotOverrideUserPrefix(t *testing.T) {
	t.Parallel()
	cr := NewPTRCrawler(zap.NewNop(), &memPTRStore{})
	cr.Zone = "0.158.92.in-addr.arpa"
	cr.Prefix = "92.158.0.0/25"
	q := cr.leafQuery()
	if q.Zone != "0.158.92.in-addr.arpa" {
		t.Fatalf("Zone=%q", q.Zone)
	}
	if q.Prefix != "92.158.0.0/25" {
		t.Fatalf("user --prefix must win: %q", q.Prefix)
	}
}

func TestLeafQueryParentZoneDerivesCoveringPrefix(t *testing.T) {
	t.Parallel()
	cr := NewPTRCrawler(zap.NewNop(), &memPTRStore{})
	cr.Zone = "92.in-addr.arpa"
	q := cr.leafQuery()
	if q.Zone != "92.in-addr.arpa" {
		t.Fatalf("Zone=%q", q.Zone)
	}
	if q.Prefix != "92.0.0.0/8" {
		t.Fatalf("Prefix=%q, want 92.0.0.0/8 so child leaves match via <<=", q.Prefix)
	}
}

func TestCrawlPTRUnscopedDoesNotListLeaves(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "2.0.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/32",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.StatsInterval = time.Hour
	cr.Shuffle = false
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mem.listLeavesCalls != 0 {
		t.Fatalf("unscoped crawl listed leaves %d times; must use the /24 queue", mem.listLeavesCalls)
	}
	if len(mem.rows) != 1 {
		t.Fatalf("rows=%d", len(mem.rows))
	}
	var done int
	for _, b := range mem.blocks {
		if b.State == postgres.PTRBlockDone {
			done++
		}
	}
	if done != 1 {
		t.Fatalf("queue done=%d blocks=%+v", done, mem.blocks)
	}
}

func TestMemClaimPTRBlockExclusive(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{blocks: []postgres.RDNSPTRBlock{
		{Prefix: "192.0.2.0/24", Zone: "a", Nservers: []string{"ns"}, State: postgres.PTRBlockPending},
		{Prefix: "198.51.100.0/24", Zone: "b", Nservers: []string{"ns"}, State: postgres.PTRBlockPending},
	}}
	got := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			b, err := mem.ClaimRDNSPTRBlock(context.Background(), "w", time.Minute, nil)
			if err != nil || b == nil {
				t.Errorf("claim: %v %v", b, err)
				return
			}
			got <- b.Prefix
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
		t.Fatalf("claimed %v", seen)
	}
}

func (m *memPTRStore) blockState(prefix string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.blocks {
		if b.Prefix == prefix {
			return b.State
		}
	}
	return ""
}

func TestCrawlPTRFlushesBeforeFinish(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "0.2.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/27",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.StatsInterval = time.Hour
	cr.Shuffle = false
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mem.rows) != 32 {
		t.Fatalf("RFC 2317 /27 must flush all 32 PTRs before Finish, got %d", len(mem.rows))
	}
	if mem.blockState("192.0.2.0/27") != postgres.PTRBlockDone {
		t.Fatalf("complete /27 must Finish, got %s", mem.blockState("192.0.2.0/27"))
	}
}

func TestCrawlPTRCancelReleasesPending(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "2.0.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/24",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hosts int
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.StatsInterval = time.Hour
	cr.Shuffle = false
	cr.Exchange = func(_ context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.EqualFold(dns.Fqdn(qname), "2.0.192.in-addr.arpa.") {
			return dns.RcodeSuccess, nil, nil
		}
		hosts++
		if hosts >= 1 {
			cancel()
		}
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	err := cr.Crawl(ctx)
	if err == nil {
		t.Fatal("cancelled crawl must return an error")
	}
	if mem.blockState("192.0.2.0/24") != postgres.PTRBlockPending {
		t.Fatalf("cancel must Release with durable ctx, got %s", mem.blockState("192.0.2.0/24"))
	}
	if len(mem.rows) < 1 {
		t.Fatal("durable flush must persist the in-flight batch")
	}
}

func TestCrawlPTRTimeoutBlockIsRetryable(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{{
		Zone:     "2.0.192.in-addr.arpa.",
		Prefix:   "192.0.2.0/32",
		Nservers: []string{"ns.test."},
		Source:   opconst.RIPE,
	}}}
	cr := NewPTRCrawler(zap.NewNop(), mem)
	cr.StatsInterval = time.Hour
	cr.Exchange = func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if strings.EqualFold(dns.Fqdn(qname), "2.0.192.in-addr.arpa.") {
			return dns.RcodeSuccess, nil, nil
		}
		return dns.RcodeServerFailure, nil, nil
	}
	if err := cr.Crawl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mem.blockState("192.0.2.0/32") != postgres.PTRBlockFailed {
		t.Fatalf("all-SERVFAIL walk must be failed, got %s", mem.blockState("192.0.2.0/32"))
	}
	if _, err := mem.SeedRDNSPTRBlocks(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if mem.blockState("192.0.2.0/32") != postgres.PTRBlockPending {
		t.Fatalf("next seed must re-queue failed, got %s", mem.blockState("192.0.2.0/32"))
	}
}

func TestCrawlPTRLimitDoesNotLivelock(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{leaves: []postgres.RDNSLeaf{
		{Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24", Nservers: []string{"ns.test."}, Source: opconst.RIPE},
		{Zone: "100.51.198.in-addr.arpa.", Prefix: "198.51.100.0/24", Nservers: []string{"ns.test."}, Source: opconst.ARIN},
	}}
	exchange := func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, []string{"host.example."}, nil
	}
	run := func() {
		cr := NewPTRCrawler(zap.NewNop(), mem)
		cr.StatsInterval = time.Hour
		cr.Shuffle = false
		cr.Limit = 1
		cr.Exchange = exchange
		if err := cr.Crawl(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	run()
	if mem.blockState("192.0.2.0/24") != postgres.PTRBlockLeased {
		t.Fatalf("first --limit run must leave first block leased, got %s", mem.blockState("192.0.2.0/24"))
	}
	if mem.blockState("198.51.100.0/24") != postgres.PTRBlockPending {
		t.Fatalf("second block must still be pending, got %s", mem.blockState("198.51.100.0/24"))
	}
	run()
	if mem.blockState("198.51.100.0/24") == postgres.PTRBlockPending {
		t.Fatal("--limit livelock: second run claimed the same first /24 again")
	}
}

func TestPTRDNSClientUsesTimeout(t *testing.T) {
	t.Parallel()
	if newPTRDNSClient(50*time.Millisecond).Timeout != 50*time.Millisecond {
		t.Fatal("dns.Client.Timeout must follow --timeout")
	}
	if newPTRDNSClient(0).Timeout != DefaultPTRTimeout {
		t.Fatal("unset timeout must default")
	}
	cr := NewPTRCrawler(zap.NewNop(), &memPTRStore{})
	if cr.Exchange != nil {
		t.Fatal("NewPTRCrawler must leave Exchange nil so Crawl applies --timeout")
	}
	cr.Timeout = 75 * time.Millisecond
	if cr.timeout() != 75*time.Millisecond {
		t.Fatalf("timeout()=%s", cr.timeout())
	}
}

func TestMemFinishWrongWorkerNoOp(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{blocks: []postgres.RDNSPTRBlock{
		{Prefix: "192.0.2.0/24", Source: opconst.RIPE, State: postgres.PTRBlockPending},
	}}
	got, err := mem.ClaimRDNSPTRBlock(context.Background(), "worker-a", time.Minute, nil)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if err := mem.FinishRDNSPTRBlock(context.Background(), got.Prefix, "worker-b"); err == nil {
		t.Fatal("wrong worker must not Finish")
	}
	if mem.blockState("192.0.2.0/24") != postgres.PTRBlockLeased {
		t.Fatalf("state=%s", mem.blockState("192.0.2.0/24"))
	}
	if err := mem.FinishRDNSPTRBlock(context.Background(), got.Prefix, "worker-a"); err != nil {
		t.Fatal(err)
	}
	if mem.blockState("192.0.2.0/24") != postgres.PTRBlockDone {
		t.Fatal("owner Finish must succeed")
	}
}

func TestMemHeartbeatKeepsLease(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{blocks: []postgres.RDNSPTRBlock{
		{Prefix: "192.0.2.0/24", Source: opconst.RIPE, State: postgres.PTRBlockPending},
	}}
	if _, err := mem.ClaimRDNSPTRBlock(context.Background(), "worker-a", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := mem.HeartbeatRDNSPTRBlock(context.Background(), "192.0.2.0/24", "worker-a"); err != nil {
		t.Fatal(err)
	}
	stolen, err := mem.ClaimRDNSPTRBlock(context.Background(), "worker-b", 30*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stolen != nil {
		t.Fatal("heartbeat must keep the lease from being stolen")
	}
	mem.mu.Lock()
	mem.lockedAt["192.0.2.0/24"] = time.Now().Add(-time.Hour)
	mem.mu.Unlock()
	got, err := mem.ClaimRDNSPTRBlock(context.Background(), "worker-b", 30*time.Millisecond, nil)
	if err != nil || got == nil || got.LockedBy != "worker-b" {
		t.Fatalf("stale lease must be claimable: %v %v", got, err)
	}
}

func TestMemClaimOnlyRegistries(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{blocks: []postgres.RDNSPTRBlock{
		{Prefix: "1.0.1.0/24", Source: opconst.APNIC, State: postgres.PTRBlockPending},
		{Prefix: "192.0.2.0/24", Source: opconst.RIPE, State: postgres.PTRBlockPending},
	}}
	got, err := mem.ClaimRDNSPTRBlock(context.Background(), "w", time.Minute, []string{opconst.RIPE})
	if err != nil || got == nil {
		t.Fatalf("%v %v", got, err)
	}
	if got.Source != opconst.RIPE {
		t.Fatalf("claimed %s source=%s", got.Prefix, got.Source)
	}
}

func TestMemUpsertKeepsChildPTR(t *testing.T) {
	t.Parallel()
	mem := &memPTRStore{}
	name := "child.example"
	if err := mem.UpsertRDNSPTR(context.Background(), []postgres.RDNSPTR{{
		IP: "192.0.2.1", PTR: &name, Rcode: RcodeNOERROR, SourcePrefix: "192.0.2.0/27",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := mem.UpsertRDNSPTR(context.Background(), []postgres.RDNSPTR{{
		IP: "192.0.2.1", Rcode: RcodeNODATA, SourcePrefix: "192.0.2.0/24",
	}}); err != nil {
		t.Fatal(err)
	}
	if mem.rows[0].PTR == nil || *mem.rows[0].PTR != name {
		t.Fatalf("parent NODATA overwrote child: %+v", mem.rows[0])
	}
}
