package fdns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type memResolveStore struct {
	mu          sync.Mutex
	due         []string
	queueApprox *int64
	locked      []string
	deleted     []string
	unlocked    []string
	claimed     int
	unlockBy    []string
	ips         []postgres.HostIP
	resolved    map[string]time.Time
}

func newMemResolveStore(names ...string) *memResolveStore {
	return &memResolveStore{
		due:      append([]string(nil), names...),
		resolved: make(map[string]time.Time),
	}
}

func (m *memResolveStore) CountResolveQueue(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.queueApprox != nil {
		return *m.queueApprox, nil
	}
	return int64(len(m.due)), nil
}

func (m *memResolveStore) ClaimDueResolveQueue(ctx context.Context, lockedBy string, batch int, lease time.Duration) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if batch < 1 {
		return nil, nil
	}
	n := batch
	if n > len(m.due) {
		n = len(m.due)
	}
	out := append([]string(nil), m.due[:n]...)
	m.due = append([]string(nil), m.due[n:]...)
	m.locked = append(m.locked, out...)
	m.claimed += len(out)
	return out, nil
}

func (m *memResolveStore) UnlockResolveQueue(ctx context.Context, names []string, lockedBy string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unlocked = append(m.unlocked, names...)
	if lockedBy != "" {
		m.unlockBy = append(m.unlockBy, lockedBy)
	}
	locked := m.locked[:0]
	back := map[string]struct{}{}
	for _, n := range names {
		back[n] = struct{}{}
	}
	for _, n := range m.locked {
		if _, ok := back[n]; ok {
			m.due = append(m.due, n)
			continue
		}
		locked = append(locked, n)
	}
	m.locked = locked
	return nil
}

func (m *memResolveStore) ApplyHostResolve(ctx context.Context, ips []postgres.HostIP, names []string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	byKey := make(map[string]int, len(m.ips))
	for i, row := range m.ips {
		byKey[row.Name+"\x00"+row.IP+"\x00"+row.Source] = i
	}
	for _, row := range ips {
		if row.Source == "" {
			row.Source = postgres.HostIPSourceDNS
		}
		k := row.Name + "\x00" + row.IP + "\x00" + row.Source
		if i, ok := byKey[k]; ok {
			m.ips[i].LastSeen = row.LastSeen
			continue
		}
		byKey[k] = len(m.ips)
		m.ips = append(m.ips, row)
	}
	drop := map[string]struct{}{}
	for _, n := range names {
		m.resolved[n] = at
		m.deleted = append(m.deleted, n)
		drop[n] = struct{}{}
	}
	locked := m.locked[:0]
	for _, n := range m.locked {
		if _, ok := drop[n]; ok {
			continue
		}
		locked = append(locked, n)
	}
	m.locked = locked
	return nil
}

func (m *memResolveStore) snapshot() ([]postgres.HostIP, map[string]time.Time, []string, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ips := append([]postgres.HostIP(nil), m.ips...)
	resolved := make(map[string]time.Time, len(m.resolved))
	for k, v := range m.resolved {
		resolved[k] = v
	}
	return ips, resolved, append([]string(nil), m.unlocked...), append([]string(nil), m.deleted...)
}

func containsName(got []string, want string) bool {
	for _, s := range got {
		if s == want {
			return true
		}
	}
	return false
}

func TestElapsedField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{10 * time.Minute, "10m0s"},
		{time.Hour + 2*time.Minute + 3*time.Second, "1h2m3s"},
		{1500 * time.Millisecond, "2s"},
	}
	for _, tc := range cases {
		f := elapsedField(tc.in)
		if f.Key != "elapsed" || f.String != tc.want {
			t.Errorf("elapsedField(%s)=%q, want %q", tc.in, f.String, tc.want)
		}
	}
}

func TestParseAF(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want4   bool
		want6   bool
		wantErr bool
	}{
		{"", true, true, false},
		{"both", true, true, false},
		{"4", true, false, false},
		{"6", false, true, false},
		{"ipv4", true, false, false},
		{"aaaa", false, true, false},
		{"7", false, false, true},
	}
	for _, tc := range cases {
		got4, got6, err := ParseAF(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseAF(%q) err=nil", tc.in)
			}
			continue
		}
		if err != nil || got4 != tc.want4 || got6 != tc.want6 {
			t.Errorf("ParseAF(%q)=%v,%v,%v want %v,%v,nil", tc.in, got4, got6, err, tc.want4, tc.want6)
		}
	}
}

func TestNormalizeResolverAddr(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeResolverAddr(""); err == nil {
		t.Fatal("empty addr must error (defaults are a slice, not a single empty addr)")
	}
	got, err := NormalizeResolverAddr("127.0.0.1")
	if err != nil || got != "127.0.0.1:53" {
		t.Fatalf("ip=%q %v", got, err)
	}
	got, err = NormalizeResolverAddr("127.0.0.1:5353")
	if err != nil || got != "127.0.0.1:5353" {
		t.Fatalf("hostport=%q %v", got, err)
	}
	got, err = NormalizeResolverAddr("::1")
	if err != nil || got != "[::1]:53" {
		t.Fatalf("v6=%q %v", got, err)
	}
	got, err = NormalizeResolverAddr("dns.google")
	if err != nil || got != "dns.google:53" {
		t.Fatalf("host=%q %v", got, err)
	}
}

func TestDefaultResolverAddrs(t *testing.T) {
	t.Parallel()
	want := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
		"74.82.42.42:53",
	}
	if len(DefaultResolverAddrs) != 5 {
		t.Fatalf("len(DefaultResolverAddrs)=%d, want 5", len(DefaultResolverAddrs))
	}
	for i, addr := range want {
		if DefaultResolverAddrs[i] != addr {
			t.Errorf("DefaultResolverAddrs[%d]=%s, want %s", i, DefaultResolverAddrs[i], addr)
		}
	}
	res := NewResolver(zap.NewNop(), newMemResolveStore())
	if len(res.ResolverAddrs) != 5 {
		t.Fatalf("NewResolver default ResolverAddrs len=%d, want 5", len(res.ResolverAddrs))
	}
}

func TestParseResolverAddrs(t *testing.T) {
	t.Parallel()
	got, err := ParseResolverAddrs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("nil CLI → %d addrs, want 5 defaults", len(got))
	}
	if got[0] != DefaultResolverAddrs[0] {
		t.Fatalf("nil CLI first=%s", got[0])
	}
	got, err = ParseResolverAddrs([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("empty CLI → %d addrs, want 5 defaults", len(got))
	}
	got, err = ParseResolverAddrs([]string{"", "  ", ","})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("whitespace-only CLI → %d addrs, want 5 defaults", len(got))
	}

	got, err = ParseResolverAddrs([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1:53" {
		t.Fatalf("explicit single=%v (must replace defaults, not merge)", got)
	}
	for _, d := range DefaultResolverAddrs {
		if d != "127.0.0.1:53" && got[0] == d {
			t.Fatal("explicit --resolver must not keep a default")
		}
	}

	got, err = ParseResolverAddrs([]string{"1.1.1.1", "8.8.8.8:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Fatalf("repeatable=%v", got)
	}

	got, err = ParseResolverAddrs([]string{"9.9.9.9,208.67.222.222"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "9.9.9.9:53" || got[1] != "208.67.222.222:53" {
		t.Fatalf("comma-separated=%v", got)
	}

	got, err = ParseResolverAddrs([]string{"74.82.42.42", "74.82.42.42:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "74.82.42.42:53" {
		t.Fatalf("dedupe=%v", got)
	}

	if _, err := ParseResolverAddrs([]string{":::bad"}); err == nil {
		t.Fatal("invalid addr must error")
	}
}

func TestTotalQPS(t *testing.T) {
	t.Parallel()
	if got := TotalQPS(500, 5); got != 2500 {
		t.Fatalf("TotalQPS(500, 5)=%v, want 2500", got)
	}
	if got := TotalQPS(250, 2); got != 500 {
		t.Fatalf("TotalQPS(250, 2)=%v, want 500 (per-resolver × N)", got)
	}
	if got := TotalQPS(DefaultResolveQPS, 5); got != float64(DefaultResolveQPS*5) {
		t.Fatalf("TotalQPS(default, 5)=%v, want %v", got, float64(DefaultResolveQPS*5))
	}
	if got := TotalQPS(-1, 3); got != 0 {
		t.Fatalf("TotalQPS(-1, 3)=%v, want 0", got)
	}
}

func TestResolverPoolPlan(t *testing.T) {
	t.Parallel()
	res := NewResolver(zap.NewNop(), newMemResolveStore())
	plan := res.resolverPoolPlan()
	if len(plan.Addrs) != 5 {
		t.Fatalf("default plan addrs=%d, want 5", len(plan.Addrs))
	}
	if plan.PerResolverQPS != DefaultResolveQPS {
		t.Fatalf("per-resolver QPS=%d, want %d", plan.PerResolverQPS, DefaultResolveQPS)
	}
	if plan.PoolQPS != DefaultResolveQPS*5 {
		t.Fatalf("pool QPS=%d, want %d (per-resolver × N)", plan.PoolQPS, DefaultResolveQPS*5)
	}

	res.QPS = 250
	res.ResolverAddrs = []string{"127.0.0.1:53", "1.1.1.1:53"}
	plan = res.resolverPoolPlan()
	if len(plan.Addrs) != 2 || plan.PerResolverQPS != 250 || plan.PoolQPS != 500 {
		t.Fatalf("explicit plan=%+v", plan)
	}

	res.ResolverAddrs = nil
	plan = res.resolverPoolPlan()
	if len(plan.Addrs) != 5 {
		t.Fatalf("empty ResolverAddrs must fall back to 5 defaults, got %d", len(plan.Addrs))
	}
}

func TestResolveAOnly(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("a.example")
	var seenA, seenAAAA atomic.Int32
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		switch qtype {
		case dns.TypeA:
			seenA.Add(1)
			return dns.RcodeSuccess, []string{"192.0.2.1"}, nil
		case dns.TypeAAAA:
			seenAAAA.Add(1)
			return dns.RcodeSuccess, []string{"2001:db8::1"}, nil
		default:
			t.Fatalf("unexpected qtype %d", qtype)
			return 0, nil, nil
		}
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seenA.Load() != 1 || seenAAAA.Load() != 0 {
		t.Fatalf("A=%d AAAA=%d, want A only", seenA.Load(), seenAAAA.Load())
	}
	ips, resolved, unlocked, _ := st.snapshot()
	if len(unlocked) != 0 {
		t.Fatalf("success must not unlock: %v", unlocked)
	}
	if len(ips) != 1 || ips[0].IP != "192.0.2.1" || ips[0].Source != postgres.HostIPSourceDNS {
		t.Fatalf("ips=%+v", ips)
	}
	if ips[0].FirstSeen.IsZero() || ips[0].LastSeen.IsZero() {
		t.Fatalf("FirstSeen/LastSeen must be set for COPY into NOT NULL: %+v", ips[0])
	}
	if _, ok := resolved["a.example"]; !ok {
		t.Fatal("resolved_at not stamped")
	}
}

func TestResolveAAAAOnly(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("aaaa.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "6"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		if qtype != dns.TypeAAAA {
			t.Fatalf("qtype=%d", qtype)
		}
		return dns.RcodeSuccess, []string{"2001:db8::9"}, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, _, _, _ := st.snapshot()
	if len(ips) != 1 || ips[0].IP != "2001:db8::9" {
		t.Fatalf("ips=%+v", ips)
	}
}

func TestResolveBoth(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("both.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "both"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		switch qtype {
		case dns.TypeA:
			return dns.RcodeSuccess, []string{"192.0.2.10"}, nil
		case dns.TypeAAAA:
			return dns.RcodeSuccess, []string{"2001:db8::10"}, nil
		default:
			return dns.RcodeServerFailure, nil, nil
		}
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, resolved, _, _ := st.snapshot()
	got := map[string]bool{}
	for _, row := range ips {
		got[row.IP] = true
		if row.Source != postgres.HostIPSourceDNS {
			t.Fatalf("source=%s", row.Source)
		}
	}
	if !got["192.0.2.10"] || !got["2001:db8::10"] || len(ips) != 2 {
		t.Fatalf("ips=%+v", ips)
	}
	if _, ok := resolved["both.example"]; !ok {
		t.Fatal("resolved_at not stamped")
	}
}

func TestResolveNXDOMAINStampsResolvedAt(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("nx.example", "ok.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "both"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		if name == "nx.example" {
			return dns.RcodeNameError, nil, nil
		}
		if qtype == dns.TypeA {
			return dns.RcodeSuccess, []string{"192.0.2.2"}, nil
		}
		return dns.RcodeSuccess, nil, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, resolved, _, deleted := st.snapshot()
	if _, ok := resolved["nx.example"]; !ok {
		t.Fatal("NXDOMAIN must stamp resolved_at")
	}
	for _, row := range ips {
		if row.Name == "nx.example" {
			t.Fatalf("NXDOMAIN stored an IP: %+v", row)
		}
	}
	if len(ips) != 1 || ips[0].Name != "ok.example" {
		t.Fatalf("ips=%+v", ips)
	}
	if !containsName(deleted, "nx.example") || !containsName(deleted, "ok.example") {
		t.Fatalf("stamped names must leave the queue: %v", deleted)
	}
}

func TestResolveNODATAStampsNoIPs(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("empty.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, nil, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, resolved, _, _ := st.snapshot()
	if len(ips) != 0 {
		t.Fatalf("NODATA stored IPs: %+v", ips)
	}
	if _, ok := resolved["empty.example"]; !ok {
		t.Fatal("NODATA must stamp resolved_at")
	}
}

func TestResolveSERVFAILDoesNotStamp(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("fail.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 1
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		return dns.RcodeServerFailure, nil, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, resolved, unlocked, deleted := st.snapshot()
	if len(ips) != 0 {
		t.Fatalf("ips=%+v", ips)
	}
	if len(resolved) != 0 {
		t.Fatalf("SERVFAIL must not stamp resolved_at: %v", resolved)
	}
	if !containsName(unlocked, "fail.example") {
		t.Fatalf("SERVFAIL must unlock for retry: %v", unlocked)
	}
	if containsName(deleted, "fail.example") {
		t.Fatal("SERVFAIL must not DELETE from the queue")
	}
}

func TestResolveQPSPacesQueries(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("a.example", "b.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.QPS = 5
	res.Workers = 2
	res.ResolverAddrs = []string{"127.0.0.1:53"}
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		return dns.RcodeSuccess, []string{"192.0.2.1"}, nil
	}
	start := time.Now()
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("elapsed=%s, want QPS limiter to pace 2 queries at 5/s", elapsed)
	}
}

func TestResolveClaimsWhenCountDueIsZero(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("stale-lease.example")
	zero := int64(0)
	st.queueApprox = &zero
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 1
	var queried int
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		queried++
		return dns.RcodeSuccess, []string{"192.0.2.1"}, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.claimed != 1 || queried != 1 {
		t.Fatalf("queue_approx=0 must not skip Claim (unanalyzed or stale leases): claimed=%d queried=%d", st.claimed, queried)
	}
}

func TestResolveLimitPassedToStore(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("a.example", "b.example", "c.example")
	res := NewResolver(zap.NewNop(), st)
	res.Limit = 2
	res.AF = "4"
	res.Workers = 1
	var queried []string
	var mu sync.Mutex
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		mu.Lock()
		queried = append(queried, name)
		mu.Unlock()
		return dns.RcodeSuccess, []string{"192.0.2.1"}, nil
	}
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.claimed != 2 {
		t.Fatalf("claimed=%d, want 2 (limit)", st.claimed)
	}
	mu.Lock()
	n := len(queried)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("queried %d names, want 2 (limit)", n)
	}
}

func TestResolveCancel(t *testing.T) {
	t.Parallel()
	st := newMemResolveStore("slow.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 1
	started := make(chan struct{})
	res.Query = func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		close(started)
		<-ctx.Done()
		return 0, nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- res.Resolve(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("query did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("canceled resolve must return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve did not return after cancel")
	}
}

func TestParseDNSMsgCNAMEPlusA(t *testing.T) {
	t.Parallel()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("www.example"), dns.TypeA)
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "cdn.example."},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.8").To4()},
	}
	rcode, ips, err := parseDNSMsg(m, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d err=%v", rcode, err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.8" {
		t.Fatalf("ips=%v (must store A, not CNAME target)", ips)
	}
}

func TestParseDNSMsgCNAMEOnlyIsNODATA(t *testing.T) {
	t.Parallel()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("alias.example"), dns.TypeA)
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "other.example."},
	}
	rcode, ips, err := parseDNSMsg(m, dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d err=%v", rcode, err)
	}
	if len(ips) != 0 {
		t.Fatalf("CNAME-only must not store IPs (recursive resolver follows CNAME): %v", ips)
	}
	if responseKind(rcode, len(ips)) != rcodeNODATA {
		t.Fatalf("kind=%s", responseKind(rcode, len(ips)))
	}
}

func TestFakeDNSServerAAndNXDOMAIN(t *testing.T) {
	t.Parallel()
	addr := startFakeDNS(t, func(q dns.Question) (int, []dns.RR) {
		name := dns.Fqdn(q.Name)
		switch {
		case name == "ok.example." && q.Qtype == dns.TypeA:
			return dns.RcodeSuccess, []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.50").To4()},
			}
		case name == "www.ok.example." && q.Qtype == dns.TypeA:
			return dns.RcodeSuccess, []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "ok.example."},
				&dns.A{Hdr: dns.RR_Header{Name: "ok.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.50").To4()},
			}
		case name == "nx.example.":
			return dns.RcodeNameError, nil
		default:
			return dns.RcodeSuccess, nil
		}
	})
	st := newMemResolveStore("ok.example", "www.ok.example", "nx.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "4"
	res.Workers = 2
	res.Timeout = time.Second
	res.Query = dnsClientQuery(addr, time.Second)
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, resolved, _, _ := st.snapshot()
	got := map[string][]string{}
	for _, row := range ips {
		got[row.Name] = append(got[row.Name], row.IP)
	}
	if len(got["ok.example"]) != 1 || got["ok.example"][0] != "192.0.2.50" {
		t.Fatalf("ok.example ips=%v", got["ok.example"])
	}
	if len(got["www.ok.example"]) != 1 || got["www.ok.example"][0] != "192.0.2.50" {
		t.Fatalf("www CNAME+A ips=%v", got["www.ok.example"])
	}
	if _, ok := got["nx.example"]; ok {
		t.Fatal("NXDOMAIN stored IPs")
	}
	if _, ok := resolved["nx.example"]; !ok {
		t.Fatal("NXDOMAIN must stamp resolved_at")
	}
	if _, ok := resolved["ok.example"]; !ok {
		t.Fatal("A answer must stamp resolved_at")
	}
}

func TestFakeDNSServerAAAA(t *testing.T) {
	t.Parallel()
	addr := startFakeDNS(t, func(q dns.Question) (int, []dns.RR) {
		if q.Qtype != dns.TypeAAAA {
			return dns.RcodeSuccess, nil
		}
		return dns.RcodeSuccess, []dns.RR{
			&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::50")},
		}
	})
	st := newMemResolveStore("v6.example")
	res := NewResolver(zap.NewNop(), st)
	res.AF = "6"
	res.Workers = 1
	res.Query = dnsClientQuery(addr, time.Second)
	if err := res.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ips, _, _, _ := st.snapshot()
	if len(ips) != 1 || ips[0].IP != "2001:db8::50" {
		t.Fatalf("ips=%+v", ips)
	}
}

func dnsClientQuery(addr string, timeout time.Duration) DNSQuery {
	c := &dns.Client{Timeout: timeout, Net: "udp", UDPSize: dns.DefaultMsgSize}
	return func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true
		in, _, err := c.ExchangeContext(ctx, m, addr)
		if err != nil {
			return dns.RcodeServerFailure, nil, err
		}
		return parseDNSMsg(in, qtype)
	}
}

func startFakeDNS(t *testing.T, handle func(q dns.Question) (int, []dns.RR)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn:   pc,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) == 0 {
				_ = w.WriteMsg(m)
				return
			}
			rcode, rr := handle(r.Question[0])
			m.Rcode = rcode
			m.Answer = rr
			_ = w.WriteMsg(m)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- srv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		_ = pc.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	return pc.LocalAddr().String()
}
