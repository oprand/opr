package fdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oprand/opr/internal/opdns"
	"github.com/oprand/opr/store/postgres"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// DefaultResolveQPS is per resolver (not pool-wide). Five default resolvers
	// ⇒ 2500 queries/sec pool cap. Public resolvers will rate-limit a full catalog scan.
	DefaultResolveQPS        = 500
	DefaultResolveTimeout    = 5 * time.Second
	DefaultResolveStaleAfter = 168 * time.Hour
	DefaultResolveWorkers    = 32
	DefaultResolveBatch      = 256
	DefaultResolveLease      = 5 * time.Minute
	DefaultResolveWorkerID   = "fdns-resolve"
	ResolveStatsInterval     = 10 * time.Minute
	resolveDurableTimeout    = 15 * time.Second
)

// DefaultResolverAddrs are the five most common public recursive resolvers.
// A full scan will get rate-limited; pass --resolver 127.0.0.1 for local-only.
var DefaultResolverAddrs = []string{
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"74.82.42.42:53",    // Hurricane Electric
}

const (
	rcodeNOERROR  = "NOERROR"
	rcodeNXDOMAIN = "NXDOMAIN"
	rcodeNODATA   = "NODATA"
	rcodeSERVFAIL = "SERVFAIL"
	rcodeREFUSED  = "REFUSED"
	rcodeTIMEOUT  = "TIMEOUT"
	rcodeERROR    = "ERROR"
)

type resolveStore interface {
	// Resolve claims fdns_resolve_queue (choice B). List ingest and seed-queue
	// enqueue due names; this path does not scan fdns_host_name.
	ClaimDueResolveQueue(ctx context.Context, lockedBy string, batch int, lease time.Duration) ([]string, error)
	// CountResolveQueue is pg_class.reltuples (approximate; ANALYZE lag;
	// locked+unlocked; not the due predicate). 0 can mean empty or unanalyzed.
	CountResolveQueue(ctx context.Context) (int64, error)
	ApplyHostResolve(ctx context.Context, ips []postgres.HostIP, names []string, at time.Time) error
	UnlockResolveQueue(ctx context.Context, names []string, lockedBy string) error
}

var _ resolveStore = (*postgres.Store)(nil)

// DNSQuery is one A or AAAA lookup. Tests inject a stub or a fake DNS server;
// production uses one shared caffix/resolve pool pointed at --resolver(s).
type DNSQuery func(ctx context.Context, name string, qtype uint16) (rcode int, ips []string, err error)

// Resolver scans fdns_host_name for A/AAAA and upserts fdns_host_ip source=dns.
type Resolver struct {
	Store   resolveStore
	Logger  *zap.Logger
	Query   DNSQuery
	QPS     float64 // per resolver
	Timeout time.Duration
	Limit   int
	// StaleAfter is unused by Resolve. Freshness is applied at enqueue
	// (seed-queue / ingest-lists --stale-after). Successful resolve DELETEs
	// the queue row, so a resolved_at window cannot reclaim it. Re-run
	// seed-queue or ingest-lists --force to refresh. CLI keeps the flag
	// so existing scripts do not fail.
	StaleAfter    time.Duration
	AF            string
	ResolverAddrs []string
	Workers       int
	BatchSize     int
	Lease         time.Duration
	WorkerID      string
	StatsInterval time.Duration

	limiter *rate.Limiter
	stats   resolveStats
}

type resolveStats struct {
	start     time.Time
	total     int64
	done      atomic.Int64
	queries   atomic.Int64
	ips       atomic.Int64
	stamped   atomic.Int64
	nxdomain  atomic.Int64
	nodata    atomic.Int64
	retryable atomic.Int64
}

type nameResult struct {
	name    string
	ips     []string
	stamp   bool
	kind    string
	queries int
	err     error
}

// NewResolver builds an A/AAAA scan job. Query is filled from a shared
// resolver pool on Resolve unless tests inject one.
func NewResolver(logger *zap.Logger, st resolveStore) *Resolver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Resolver{
		Store:         st,
		Logger:        logger,
		QPS:           DefaultResolveQPS,
		Timeout:       DefaultResolveTimeout,
		StaleAfter:    DefaultResolveStaleAfter,
		AF:            "both",
		ResolverAddrs: append([]string(nil), DefaultResolverAddrs...),
		Workers:       DefaultResolveWorkers,
		BatchSize:     DefaultResolveBatch,
		Lease:         DefaultResolveLease,
		WorkerID:      DefaultResolveWorkerID,
		StatsInterval: ResolveStatsInterval,
	}
}

// Resolve claims due names from fdns_resolve_queue, queries A/AAAA (per --af),
// upserts fdns_host_ip source=dns, and stamps fdns_host_name.resolved_at.
// NXDOMAIN and NODATA still stamp resolved_at with zero dns IPs and DELETE
// the queue row. SERVFAIL/timeout/REFUSED do not stamp; locked_at is cleared
// so the name is retried.
func (r *Resolver) Resolve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.Store == nil {
		return fmt.Errorf("fdns resolve: store is nil")
	}
	if r.Logger == nil {
		r.Logger = zap.NewNop()
	}

	stopPool := func() {}
	if r.Query == nil {
		pool, addrs, err := r.openPool()
		if err != nil {
			return err
		}
		stopPool = pool.Stop
		r.Query = queryResolvePool(pool)
		perQPS := r.perResolverQPS()
		r.Logger.Info("fdns resolve using resolver(s)",
			zap.Strings("resolvers", addrs),
			zap.Int("resolver_count", len(addrs)),
			zap.Int("connected", pool.Len()),
			zap.Int("qps_per_resolver", perQPS),
			zap.Float64("qps_pool", TotalQPS(float64(perQPS), pool.Len())),
			zap.String("af", r.afLabel()))
	}
	defer stopPool()

	approx, err := r.Store.CountResolveQueue(ctx)
	if err != nil {
		return err
	}
	total := approx
	if r.Limit > 0 && int64(r.Limit) < total {
		total = int64(r.Limit)
	}
	r.Logger.Info("fdns resolve claiming queue (approximate size)",
		zap.Int64("queue_approx", approx),
		zap.Int("limit", r.Limit),
		zap.Int("batch", r.batchSize()),
		zap.Duration("lease", r.lease()),
		zap.String("worker_id", r.workerID()),
		zap.String("af", r.afLabel()))
	// queue_approx is pg_class.reltuples (ANALYZE lag; locked+unlocked;
	// not the due predicate). Do not treat total==0 as done: 0 can mean
	// empty or unanalyzed, and ClaimDue reclaims locked_at older than
	// --lease. Loop until ClaimDue returns empty.

	// --qps is per resolver. Worker-loop limiter must be per × N so it is not
	// pool-wide. caffix AddResolvers applies the same per-resolver cap; SetMaxQPS
	// is set to TotalQPS so the pool-wide ceiling matches.
	r.limiter = rate.NewLimiter(rate.Limit(TotalQPS(r.qps(), len(r.resolverAddrs()))), 1)
	r.stats = resolveStats{start: time.Now(), total: total}
	stopStats := r.startStats(ctx)
	defer stopStats()

	var runErr error
	var retryAll []string
	for {
		if err := ctx.Err(); err != nil {
			if runErr == nil {
				runErr = err
			}
			break
		}
		batch := r.batchSize()
		if r.Limit > 0 {
			remaining := r.Limit - int(r.stats.done.Load())
			if remaining <= 0 {
				break
			}
			if batch > remaining {
				batch = remaining
			}
		}
		names, err := r.Store.ClaimDueResolveQueue(ctx, r.workerID(), batch, r.lease())
		if err != nil {
			if runErr == nil {
				runErr = err
			}
			break
		}
		if len(names) == 0 {
			break
		}
		retry, err := r.resolveClaimed(ctx, names)
		retryAll = append(retryAll, retry...)
		if err != nil {
			if runErr == nil {
				runErr = err
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if err := r.unlockDurable(ctx, retryAll); err != nil && runErr == nil {
		runErr = err
	}
	elapsed := time.Since(r.stats.start)
	r.Logger.Info("fdns resolve finished",
		zap.Int64("names", r.stats.done.Load()),
		zap.Int64("names_total", r.stats.total),
		zap.Int64("dns_queries", r.stats.queries.Load()),
		zap.Int64("ips", r.stats.ips.Load()),
		zap.Int64("stamped", r.stats.stamped.Load()),
		zap.Int64("nxdomain", r.stats.nxdomain.Load()),
		zap.Int64("nodata", r.stats.nodata.Load()),
		elapsedField(elapsed),
		zap.Error(runErr))
	return runErr
}

func (r *Resolver) resolveClaimed(ctx context.Context, names []string) (retry []string, err error) {
	workers := r.workers()
	if workers > len(names) {
		workers = len(names)
	}
	namesCh := make(chan string)
	results := make(chan nameResult, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for name := range namesCh {
				if ctx.Err() != nil {
					return
				}
				results <- r.resolveName(ctx, name)
			}
		}()
	}
	go func() {
		defer close(namesCh)
		for _, name := range names {
			select {
			case <-ctx.Done():
				return
			case namesCh <- name:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	got := make(map[string]nameResult, len(names))
	var runErr error
	for rec := range results {
		r.noteResult(rec)
		got[rec.name] = rec
		if rec.err != nil && runErr == nil && ctx.Err() != nil {
			runErr = ctx.Err()
		}
	}

	now := time.Now().UTC()
	batchIPs := make([]postgres.HostIP, 0, len(names))
	batchNames := make([]string, 0, len(names))
	retry = make([]string, 0, len(names))
	for _, name := range names {
		rec, ok := got[name]
		if !ok || !rec.stamp {
			retry = append(retry, name)
			if !ok {
				r.stats.done.Add(1)
				r.stats.retryable.Add(1)
			}
			continue
		}
		batchNames = append(batchNames, rec.name)
		for _, ip := range rec.ips {
			batchIPs = append(batchIPs, postgres.HostIP{
				Name:      rec.name,
				IP:        ip,
				Source:    postgres.HostIPSourceDNS,
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}
	if len(batchNames) > 0 {
		if err := r.flushDurable(ctx, batchIPs, batchNames, now); err != nil {
			if runErr == nil {
				runErr = err
			}
			retry = append(retry, batchNames...)
		}
	}
	if runErr == nil && ctx.Err() != nil {
		runErr = ctx.Err()
	}
	return retry, runErr
}

func (r *Resolver) resolveName(ctx context.Context, name string) nameResult {
	rec := nameResult{name: name}
	var sawTerminal bool
	var kinds []string
	for _, qt := range r.qtypes() {
		if err := r.waitQPS(ctx); err != nil {
			rec.err = err
			return rec
		}
		rec.queries++
		qctx, cancel := context.WithTimeout(ctx, r.timeout())
		rcode, ips, err := r.Query(qctx, name, qt)
		cancel()
		if err != nil {
			kind := rcodeTIMEOUT
			if ctx.Err() != nil {
				rec.err = ctx.Err()
				return rec
			}
			kinds = append(kinds, kind)
			r.Logger.Debug("fdns resolve query failed",
				zap.String("name", name),
				zap.Uint16("qtype", qt),
				zap.Error(err))
			continue
		}
		ips = filterIPs(ips, qt)
		kind := responseKind(rcode, len(ips))
		kinds = append(kinds, kind)
		if isTerminalKind(kind) {
			sawTerminal = true
			rec.ips = appendUniqIP(rec.ips, ips...)
		}
		if kind == rcodeNXDOMAIN {
			rec.kind = kind
			rec.stamp = true
			return rec
		}
	}
	rec.stamp = sawTerminal
	rec.kind = worstKind(kinds)
	return rec
}

func (r *Resolver) waitQPS(ctx context.Context) error {
	if r.limiter == nil {
		return nil
	}
	return r.limiter.Wait(ctx)
}

func (r *Resolver) flushDurable(parent context.Context, ips []postgres.HostIP, names []string, at time.Time) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), resolveDurableTimeout)
	defer cancel()
	return r.Store.ApplyHostResolve(ctx, ips, names, at)
}

func (r *Resolver) unlockDurable(parent context.Context, names []string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), resolveDurableTimeout)
	defer cancel()
	return r.Store.UnlockResolveQueue(ctx, names, r.workerID())
}

func (r *Resolver) noteResult(rec nameResult) {
	r.stats.done.Add(1)
	r.stats.queries.Add(int64(rec.queries))
	if rec.stamp {
		r.stats.stamped.Add(1)
		r.stats.ips.Add(int64(len(rec.ips)))
		switch rec.kind {
		case rcodeNXDOMAIN:
			r.stats.nxdomain.Add(1)
		case rcodeNODATA:
			r.stats.nodata.Add(1)
		}
	} else {
		r.stats.retryable.Add(1)
	}
}

func elapsedField(d time.Duration) zap.Field {
	return zap.String("elapsed", d.Round(time.Second).String())
}

func (r *Resolver) startStats(ctx context.Context) func() {
	interval := r.StatsInterval
	if interval <= 0 {
		interval = ResolveStatsInterval
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				elapsed := time.Since(r.stats.start)
				q := r.stats.queries.Load()
				var qps float64
				if elapsed > 0 {
					qps = float64(q) / elapsed.Seconds()
				}
				r.Logger.Info("fdns resolve progress",
					zap.Int64("names_done", r.stats.done.Load()),
					zap.Int64("names_total", r.stats.total),
					zap.Int64("dns_queries", q),
					zap.Int64("ips", r.stats.ips.Load()),
					zap.Int64("stamped", r.stats.stamped.Load()),
					zap.Int64("nxdomain", r.stats.nxdomain.Load()),
					zap.Float64("approx_qps", qps),
					elapsedField(elapsed))
			}
		}
	}()
	return func() { close(stop) }
}

func (r *Resolver) openPool() (*resolve.Resolvers, []string, error) {
	plan := r.resolverPoolPlan()
	pool := resolve.NewResolvers()
	pool.SetTimeout(r.timeout())
	// One AddResolvers(qpsPer, addr) per resolver (same pattern as api/ip.go).
	// caffix applies qps to each addr; SetMaxQPS is a separate pool-wide cap.
	for _, addr := range plan.Addrs {
		if err := pool.AddResolvers(plan.PerResolverQPS, addr); err != nil {
			pool.Stop()
			return nil, nil, fmt.Errorf("fdns resolve: add resolver %s: %w", addr, err)
		}
	}
	if pool.Len() == 0 {
		pool.Stop()
		return nil, nil, fmt.Errorf("fdns resolve: could not connect to resolvers %s (pass --resolver 127.0.0.1 for a local recursive resolver)", strings.Join(plan.Addrs, ", "))
	}
	// SetMaxQPS is pool-wide; omit would let per-resolver AddResolvers accumulate.
	// Set to qps × connected so --qps stays per resolver.
	pool.SetMaxQPS(int(TotalQPS(float64(plan.PerResolverQPS), pool.Len())))
	return pool, plan.Addrs, nil
}

// resolverPoolPlan is the AddResolvers / SetMaxQPS mapping (no live DNS).
type resolverPoolPlan struct {
	Addrs          []string
	PerResolverQPS int
	PoolQPS        int
}

func (r *Resolver) resolverPoolPlan() resolverPoolPlan {
	addrs := r.resolverAddrs()
	per := r.perResolverQPS()
	return resolverPoolPlan{
		Addrs:          addrs,
		PerResolverQPS: per,
		PoolQPS:        int(TotalQPS(float64(per), len(addrs))),
	}
}

// TotalQPS is the pool-wide cap: --qps is per resolver, so N resolvers allow per*N.
func TotalQPS(perResolver float64, n int) float64 {
	if perResolver < 0 {
		perResolver = 0
	}
	if n < 0 {
		n = 0
	}
	return perResolver * float64(n)
}

func (r *Resolver) resolverAddrs() []string {
	if len(r.ResolverAddrs) == 0 {
		return append([]string(nil), DefaultResolverAddrs...)
	}
	return r.ResolverAddrs
}

func (r *Resolver) perResolverQPS() int {
	qps := int(r.qps())
	if qps < 1 {
		return DefaultResolveQPS
	}
	return qps
}

func (r *Resolver) qps() float64 {
	if r.QPS <= 0 {
		return DefaultResolveQPS
	}
	return r.QPS
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultResolveTimeout
}

func (r *Resolver) workers() int {
	if r.Workers > 0 {
		return r.Workers
	}
	return DefaultResolveWorkers
}

func (r *Resolver) batchSize() int {
	if r.BatchSize > 0 {
		return r.BatchSize
	}
	return DefaultResolveBatch
}

func (r *Resolver) lease() time.Duration {
	if r.Lease > 0 {
		return r.Lease
	}
	return DefaultResolveLease
}

func (r *Resolver) workerID() string {
	if id := strings.TrimSpace(r.WorkerID); id != "" {
		return id
	}
	return DefaultResolveWorkerID
}

func (r *Resolver) qtypes() []uint16 {
	want4, want6, err := ParseAF(r.AF)
	if err != nil || (!want4 && !want6) {
		want4, want6 = true, true
	}
	var out []uint16
	if want4 {
		out = append(out, dns.TypeA)
	}
	if want6 {
		out = append(out, dns.TypeAAAA)
	}
	return out
}

func (r *Resolver) afLabel() string {
	want4, want6, err := ParseAF(r.AF)
	if err != nil {
		return "both"
	}
	switch {
	case want4 && want6:
		return "both"
	case want4:
		return "4"
	case want6:
		return "6"
	default:
		return "both"
	}
}

// ParseAF accepts --af=4|6|both (also ipv4/ipv6 aliases).
func ParseAF(s string) (want4, want6 bool, err error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "both", "46", "all":
		return true, true, nil
	case "4", "a", "ipv4":
		return true, false, nil
	case "6", "aaaa", "ipv6":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("unknown --af %q (want 4, 6, or both)", s)
	}
}

// NormalizeResolverAddr accepts an IP, host, or host:port. Empty is an error;
// empty slices fall back to DefaultResolverAddrs in ParseResolverAddrs.
func NormalizeResolverAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("fdns resolve: empty resolver address")
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(s, ":") {
		return "", fmt.Errorf("fdns resolve: resolver address %q is not host:port", s)
	}
	return net.JoinHostPort(s, "53"), nil
}

// ParseResolverAddrs normalizes each --resolver value, splits commas, and
// dedups. Empty input (flag omitted) or empty after trim returns a copy of
// DefaultResolverAddrs. Explicit values replace the defaults; they are not merged.
func ParseResolverAddrs(values []string) ([]string, error) {
	var raw []string
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				raw = append(raw, p)
			}
		}
	}
	if len(raw) == 0 {
		return append([]string(nil), DefaultResolverAddrs...), nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, s := range raw {
		addr, err := NormalizeResolverAddr(s)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultResolverAddrs...), nil
	}
	return out, nil
}

func queryResolvePool(pool *resolve.Resolvers) DNSQuery {
	return func(ctx context.Context, name string, qtype uint16) (int, []string, error) {
		resp, err := pool.QueryBlocking(ctx, resolve.QueryMsg(name, qtype))
		if err != nil {
			return dns.RcodeServerFailure, nil, err
		}
		return parseDNSMsg(resp, qtype)
	}
}

func parseDNSMsg(msg *dns.Msg, qtype uint16) (int, []string, error) {
	if msg == nil {
		return dns.RcodeServerFailure, nil, fmt.Errorf("fdns resolve: empty DNS response")
	}
	answers := opdns.AnswersByType(opdns.ExtractAnswers(msg), qtype)
	var ips []string
	for _, a := range answers {
		ip := net.ParseIP(a.Data)
		if ip == nil {
			continue
		}
		ips = append(ips, ip.String())
	}
	return msg.Rcode, filterIPs(ips, qtype), nil
}

func filterIPs(ips []string, qtype uint16) []string {
	out := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if qtype == dns.TypeA && ip.To4() == nil {
			continue
		}
		if qtype == dns.TypeAAAA && (ip.To4() != nil || ip.To16() == nil) {
			continue
		}
		canon := ip.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	return out
}

func appendUniqIP(dst []string, ips ...string) []string {
	seen := make(map[string]struct{}, len(dst)+len(ips))
	for _, s := range dst {
		seen[s] = struct{}{}
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		canon := ip.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		dst = append(dst, canon)
	}
	return dst
}

func responseKind(rcode int, nIPs int) string {
	switch rcode {
	case dns.RcodeSuccess:
		if nIPs == 0 {
			return rcodeNODATA
		}
		return rcodeNOERROR
	case dns.RcodeNameError:
		return rcodeNXDOMAIN
	case dns.RcodeServerFailure:
		return rcodeSERVFAIL
	case dns.RcodeRefused:
		return rcodeREFUSED
	default:
		if s, ok := dns.RcodeToString[rcode]; ok {
			return s
		}
		return rcodeERROR
	}
}

func isTerminalKind(kind string) bool {
	return kind == rcodeNOERROR || kind == rcodeNODATA || kind == rcodeNXDOMAIN
}

func worstKind(kinds []string) string {
	if len(kinds) == 0 {
		return rcodeERROR
	}
	for _, want := range []string{rcodeNXDOMAIN, rcodeNOERROR, rcodeNODATA} {
		for _, k := range kinds {
			if k == want {
				return k
			}
		}
	}
	return kinds[0]
}
