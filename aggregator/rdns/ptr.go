package rdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oprand/opr/store/postgres"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	DefaultPTRQPS     = 5
	DefaultPTRTimeout = 2 * time.Second
	PTRStatsInterval  = 5 * time.Minute
	ptrBatchSize      = 64
)

// Wire / stored rcode labels. NODATA is NOERROR with an empty PTR answer.
const (
	RcodeNOERROR  = "NOERROR"
	RcodeNXDOMAIN = "NXDOMAIN"
	RcodeNODATA   = "NODATA"
	RcodeSERVFAIL = "SERVFAIL"
	RcodeREFUSED  = "REFUSED"
	RcodeTIMEOUT  = "TIMEOUT"
	RcodeERROR    = "ERROR"
)

// ErrCoarsePrefix is returned when --prefix/--zone is too wide without
// --i-mean-it and --max-addresses.
var ErrCoarsePrefix = errors.New("rdns: prefix too coarse to walk")

type ptrStore interface {
	ListRDNSLeaves(ctx context.Context, q postgres.RDNSLeafQuery) ([]postgres.RDNSLeaf, error)
	UpsertRDNSPTR(ctx context.Context, rows []postgres.RDNSPTR) error
	SeedRDNSPTRBlocks(ctx context.Context, sources []string) (int64, error)
	ClaimRDNSPTRBlock(ctx context.Context, lockedBy string, lease time.Duration, sources []string) (*postgres.RDNSPTRBlock, error)
	FinishRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error
	FailRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error
	ReleaseRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error
	HeartbeatRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error
	CountRDNSPTRBlocks(ctx context.Context) (postgres.RDNSPTRBlockCounts, error)
}

// PTRExchange talks to one nameserver. Tests inject a stub.
type PTRExchange func(ctx context.Context, qname, ns string, qtype uint16) (rcode int, ptrs []string, err error)

// PTRCrawler queries PTR at delegated nservers for expandable leaves.
type PTRCrawler struct {
	Store          ptrStore
	Logger         *zap.Logger
	Exchange       PTRExchange
	QPS            float64
	Timeout        time.Duration
	Limit          int // 0 = no cap on address PTR queries
	MaxAddresses   int // 0 = DefaultMaxAddresses per leaf
	IMeanIt        bool
	Prefix         string
	Zone           string
	OnlyRegistries []string
	Truncate       bool // --max-addresses on a coarse --i-mean-it prefix
	BlockLease     time.Duration
	StatsInterval  time.Duration
	LockedBy       string
	Shuffle        bool // shuffle addresses inside a block (default true)

	limiters sync.Map // ns → *rate.Limiter
}

func NewPTRCrawler(logger *zap.Logger, st ptrStore) *PTRCrawler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PTRCrawler{
		Store:         st,
		Logger:        logger,
		QPS:           DefaultPTRQPS,
		Timeout:       DefaultPTRTimeout,
		BlockLease:    postgres.DefaultPTRBlockLease,
		StatsInterval: PTRStatsInterval,
		Shuffle:       true,
	}
}

var _ ptrStore = (*postgres.Store)(nil)

// Crawl walks PTR at delegated NS. Scoped --zone/--prefix uses the GiST leaf
// query. Unscoped runs the /24 block queue (masklen seed + SKIP LOCKED) and
// never calls ListRDNSLeaves. RFC 8020: NXDOMAIN on the zone name skips child PTRs.
func (c *PTRCrawler) Crawl(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Exchange == nil {
		c.Exchange = defaultExchange(c.timeout())
	}
	if err := ValidateUserPrefix(c.Prefix, c.IMeanIt, c.MaxAddresses); err != nil {
		return err
	}
	if c.Zone != "" {
		if p, err := ZoneToPrefix(c.Zone); err == nil {
			if err := ValidateUserPrefix(p, c.IMeanIt, c.MaxAddresses); err != nil && c.Prefix == "" {
				// /8 zone name: still allowed — we walk child leaves, not the /8.
				if SkipReason(p) == SkipTooCoarse {
					c.Logger.Info("rdns crawl-ptr: zone is coarser than a leaf; walking child leaves only",
						zap.String("zone", c.Zone), zap.String("prefix", p))
				}
			}
		}
	}

	run := newPTRCrawlRun(c)
	stopStats := c.startPTRStats(ctx, run.stats)
	defer stopStats()

	var err error
	if c.scoped() {
		err = c.crawlScoped(ctx, run)
	} else {
		err = c.crawlQueue(ctx, run)
	}
	if flushErr := run.flushDurable(ctx); flushErr != nil && err == nil {
		err = flushErr
	}
	c.refreshQueueCounts(ctx, run.stats)
	snap := run.stats.snapshot()
	c.Logger.Info("rdns crawl-ptr finished",
		append(snap.ZapFields(), zap.Bool("limit_hit", run.limitHit), zap.Error(err))...)
	return err
}

func (c *PTRCrawler) scoped() bool {
	return strings.TrimSpace(c.Prefix) != "" || strings.TrimSpace(c.Zone) != ""
}

func (c *PTRCrawler) crawlScoped(ctx context.Context, run *ptrCrawlRun) error {
	q := c.leafQuery()
	c.Logger.Info("rdns crawl-ptr leaf query",
		zap.String("zone", q.Zone),
		zap.String("prefix", q.Prefix),
		zap.Strings("sources", q.Sources))
	leaves, err := c.Store.ListRDNSLeaves(ctx, q)
	if err != nil {
		return err
	}
	// SQL already scopes by zone/prefix; keep the Go filter as a safety net.
	leaves = filterLeavesByZone(leaves, c.Zone)
	walk, skipped := PartitionLeaves(leaves)
	for _, s := range skipped {
		c.Logger.Info("rdns crawl-ptr skip leaf",
			zap.String("prefix", s.Leaf.Prefix),
			zap.String("zone", s.Leaf.Zone),
			zap.String("reason", s.Reason))
	}
	run.stats.setRemaining(int64(len(walk)))

	for _, leaf := range walk {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result, err := run.walkLeaf(ctx, leaf)
		if err != nil {
			return err
		}
		if result.complete {
			run.stats.addBlockDone()
		}
		if run.limitHit {
			break
		}
	}
	return nil
}

func (c *PTRCrawler) crawlQueue(ctx context.Context, run *ptrCrawlRun) error {
	// Queue states:
	//   done    — flush succeeded and the walk is not all TIMEOUT/SERVFAIL/ERROR.
	//             RFC 8020 NXDOMAIN on the zone (empty, skip children) is done.
	//   failed  — complete walk of only TIMEOUT/SERVFAIL/ERROR, or flush failed.
	//             Next Seed resets failed → pending.
	//   leased  — --limit hit mid-block; SKIP LOCKED moves on (do not Release).
	//   pending — cancel/shutdown Release via a durable (non-cancelled) ctx.
	c.Logger.Warn("rdns crawl-ptr: unscoped run uses /24 block queue (masklen 24–32 / IPv6 /120+), not ListRDNSLeaves anti-join")
	n, err := c.Store.SeedRDNSPTRBlocks(ctx, c.OnlyRegistries)
	if err != nil {
		return err
	}
	c.Logger.Info("rdns crawl-ptr queue seeded", zap.Int64("inserted", n))
	// One COUNT after seed for remaining; live ticks use in-process counters.
	// Per-block COUNT(*) over ~2M rows is the hang we just left. Ticker refreshes.
	c.refreshQueueCounts(ctx, run.stats)

	lease := c.BlockLease
	if lease <= 0 {
		lease = postgres.DefaultPTRBlockLease
	}
	lockedBy := c.workerID()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.Limit > 0 && run.queries >= c.Limit {
			run.limitHit = true
			break
		}
		block, err := c.Store.ClaimRDNSPTRBlock(ctx, lockedBy, lease, c.OnlyRegistries)
		if err != nil {
			return err
		}
		if block == nil {
			break
		}
		leaf := postgres.RDNSLeaf{
			Zone:     block.Zone,
			Prefix:   block.Prefix,
			Nservers: block.Nservers,
			Source:   block.Source,
		}
		run.lockedBy = lockedBy
		run.lease = lease
		run.lastBeat = time.Time{}
		result, err := run.walkLeaf(ctx, leaf)
		if err != nil {
			if errors.Is(err, postgres.ErrPTRBlockLeaseLost) {
				c.Logger.Warn("rdns crawl-ptr lost lease", zap.String("prefix", block.Prefix), zap.String("locked_by", lockedBy))
				continue
			}
			if ctx.Err() != nil {
				_ = run.flushDurable(ctx)
				_ = c.queueRelease(ctx, block.Prefix)
				return ctx.Err()
			}
			_ = c.queueFail(ctx, block.Prefix)
			return err
		}
		if !result.complete {
			_ = run.flushDurable(ctx)
			if run.limitHit {
				// Leave leased so SKIP LOCKED claims a different prefix next.
				// Release-to-pending + deterministic claim livelocks --limit.
				break
			}
			_ = c.queueRelease(ctx, block.Prefix)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			break
		}
		if result.retryable {
			if err := c.queueFail(ctx, block.Prefix); err != nil && !errors.Is(err, postgres.ErrPTRBlockLeaseLost) {
				return err
			}
			run.stats.addBlockFailed()
			continue
		}
		if err := c.queueFinish(ctx, block.Prefix); err != nil {
			if errors.Is(err, postgres.ErrPTRBlockLeaseLost) {
				c.Logger.Warn("rdns crawl-ptr lost lease on finish", zap.String("prefix", block.Prefix), zap.String("locked_by", lockedBy))
				continue
			}
			return err
		}
		run.stats.addBlockDone()
		if run.limitHit {
			break
		}
	}
	return nil
}

type ptrCrawlRun struct {
	c        *PTRCrawler
	stats    *ptrRunStats
	batch    []postgres.RDNSPTR
	queries  int
	limitHit bool
	lockedBy string
	lease    time.Duration
	lastBeat time.Time
}

func newPTRCrawlRun(c *PTRCrawler) *ptrCrawlRun {
	return &ptrCrawlRun{
		c:     c,
		stats: newPTRRunStats(),
	}
}

func (r *ptrCrawlRun) flush(ctx context.Context) error {
	if len(r.batch) == 0 {
		return nil
	}
	n := len(r.batch)
	if err := r.c.Store.UpsertRDNSPTR(ctx, r.batch); err != nil {
		return err
	}
	r.stats.addUpserts(int64(n))
	r.batch = r.batch[:0]
	return nil
}

func (r *ptrCrawlRun) maybeHeartbeat(ctx context.Context, prefix string) error {
	if r.lockedBy == "" || r.c.Store == nil {
		return nil
	}
	every := r.lease / 3
	if every <= 0 {
		every = time.Minute
	}
	if !r.lastBeat.IsZero() && time.Since(r.lastBeat) < every {
		return nil
	}
	dctx, cancel := ptrDurableCtx(ctx)
	defer cancel()
	if err := r.c.Store.HeartbeatRDNSPTRBlock(dctx, prefix, r.lockedBy); err != nil {
		return err
	}
	r.lastBeat = time.Now()
	return nil
}

func (r *ptrCrawlRun) flushDurable(ctx context.Context) error {
	dctx, cancel := ptrDurableCtx(ctx)
	defer cancel()
	return r.flush(dctx)
}

func (c *PTRCrawler) workerID() string {
	if s := strings.TrimSpace(c.LockedBy); s != "" {
		return s
	}
	return "crawl-ptr"
}

func (c *PTRCrawler) queueFinish(ctx context.Context, prefix string) error {
	dctx, cancel := ptrDurableCtx(ctx)
	defer cancel()
	return c.Store.FinishRDNSPTRBlock(dctx, prefix, c.workerID())
}

func (c *PTRCrawler) queueFail(ctx context.Context, prefix string) error {
	dctx, cancel := ptrDurableCtx(ctx)
	defer cancel()
	return c.Store.FailRDNSPTRBlock(dctx, prefix, c.workerID())
}

func (c *PTRCrawler) queueRelease(ctx context.Context, prefix string) error {
	dctx, cancel := ptrDurableCtx(ctx)
	defer cancel()
	return c.Store.ReleaseRDNSPTRBlock(dctx, prefix, c.workerID())
}

const ptrDurableTimeout = 15 * time.Second

func ptrDurableCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), ptrDurableTimeout)
}

type walkResult struct {
	complete  bool // walked every address or RFC 8020 skip / skip-reason
	retryable bool // complete walk, every address rcode is TIMEOUT/SERVFAIL/ERROR
}

func ptrRetryableRcode(rcode string) bool {
	switch rcode {
	case RcodeTIMEOUT, RcodeSERVFAIL, RcodeERROR:
		return true
	default:
		return false
	}
}

// walkLeaf PTR-queries one prefix.
//
// complete=true after a full address walk (or RFC 8020 NXDOMAIN skip). The
// tail of the batch is flushed before that return so Finish cannot drop 1–63
// rows. retryable=true when every address outcome was TIMEOUT/SERVFAIL/ERROR
// (next Seed re-queues). RFC 8020 empty-zone NXDOMAIN is complete and not
// retryable (stays done).
func (r *ptrCrawlRun) walkLeaf(ctx context.Context, leaf postgres.RDNSLeaf) (walkResult, error) {
	c := r.c
	walkCIDR, err := IntersectPrefix(leaf.Prefix, c.Prefix)
	if err != nil {
		c.Logger.Info("rdns crawl-ptr leaf does not overlap --prefix",
			zap.String("leaf", leaf.Prefix), zap.String("prefix", c.Prefix))
		return walkResult{complete: true}, nil
	}
	truncate := c.Truncate || (c.IMeanIt && c.MaxAddresses > 0)
	if reason := SkipReason(walkCIDR); reason != "" && !truncate {
		c.Logger.Info("rdns crawl-ptr skip intersected prefix",
			zap.String("prefix", walkCIDR), zap.String("reason", reason))
		return walkResult{complete: true}, nil
	}

	nsList := leaf.Nservers
	if len(nsList) == 0 {
		return walkResult{complete: true}, nil
	}
	r.stats.setCurrent(walkCIDR, leaf.Zone, nsList[0])
	if err := r.maybeHeartbeat(ctx, leaf.Prefix); err != nil {
		return walkResult{}, err
	}

	zoneName := canonicalZone(leaf.Zone)
	if zoneName == "" {
		if z, err := PrefixToZone(walkCIDR); err == nil {
			zoneName = z
		}
	}
	if zoneName != "" {
		rcode, _, nsUsed, qerr := c.query(ctx, zoneName, nsList, dns.TypePTR)
		if nsUsed != "" {
			r.stats.setCurrent(walkCIDR, zoneName, nsUsed)
		}
		if qerr == nil && rcode == RcodeNXDOMAIN {
			c.Logger.Info("rdns crawl-ptr RFC 8020: NXDOMAIN on zone, skipping children",
				zap.String("zone", zoneName), zap.String("prefix", walkCIDR))
			return walkResult{complete: true}, nil
		}
	}

	maxAddr := c.MaxAddresses
	if maxAddr <= 0 {
		maxAddr = DefaultMaxAddresses
	}
	var addrs []net.IP
	if truncate {
		addrs, err = EnumerateAddressesTruncating(walkCIDR, maxAddr)
	} else {
		addrs, err = EnumerateAddresses(walkCIDR, maxAddr)
	}
	if err != nil {
		c.Logger.Warn("rdns crawl-ptr enumerate skipped",
			zap.String("prefix", walkCIDR), zap.Error(err))
		return walkResult{complete: true}, nil
	}
	if c.Shuffle {
		ShuffleAddresses(addrs)
	}

	var addrQueries, retryable int
	for _, ip := range addrs {
		if ctx.Err() != nil {
			return walkResult{}, ctx.Err()
		}
		if c.Limit > 0 && r.queries >= c.Limit {
			r.limitHit = true
			if err := r.flush(ctx); err != nil {
				return walkResult{}, err
			}
			return walkResult{}, nil
		}
		qname, err := dns.ReverseAddr(ip.String())
		if err != nil {
			continue
		}
		rcode, ptrs, nsUsed, qerr := c.query(ctx, qname, nsList, dns.TypePTR)
		if qerr != nil && rcode == "" {
			rcode = RcodeERROR
		}
		r.queries++
		addrQueries++
		if ptrRetryableRcode(rcode) {
			retryable++
		}
		r.stats.addQuery(rcode, nsUsed)
		row := postgres.RDNSPTR{
			IP:           ip.String(),
			QueriedNS:    nsUsed,
			FetchedAt:    time.Now().UTC(),
			Rcode:        rcode,
			SourcePrefix: walkCIDR,
		}
		if len(ptrs) > 0 && rcode == RcodeNOERROR {
			p := strings.TrimSuffix(ptrs[0], ".")
			row.PTR = &p
		}
		r.batch = append(r.batch, row)
		if len(r.batch) >= ptrBatchSize {
			if err := r.flush(ctx); err != nil {
				return walkResult{}, err
			}
			if err := r.maybeHeartbeat(ctx, leaf.Prefix); err != nil {
				return walkResult{}, err
			}
		}
	}
	if err := r.flush(ctx); err != nil {
		return walkResult{}, err
	}
	return walkResult{
		complete:  true,
		retryable: addrQueries > 0 && retryable == addrQueries,
	}, nil
}

// leafQuery builds the Postgres leaf filter. --zone is passed through ($3)
// and, when --prefix is empty, Prefix is derived so GiST ($2) scopes the
// anti-join (0.158.92.in-addr.arpa → covering /24).
func (c *PTRCrawler) leafQuery() postgres.RDNSLeafQuery {
	q := postgres.RDNSLeafQuery{
		Sources: append([]string(nil), c.OnlyRegistries...),
		Prefix:  strings.TrimSpace(c.Prefix),
		Zone:    strings.TrimSpace(c.Zone),
	}
	if q.Prefix == "" && q.Zone != "" {
		if p, err := ZoneToPrefix(q.Zone); err == nil {
			q.Prefix = p
		}
	}
	return q
}

func filterLeavesByZone(leaves []postgres.RDNSLeaf, zone string) []postgres.RDNSLeaf {
	zone = canonicalZone(zone)
	if zone == "" {
		return leaves
	}
	var cover *net.IPNet
	if p, err := ZoneToPrefix(zone); err == nil {
		_, cover, _ = net.ParseCIDR(p)
	}
	out := make([]postgres.RDNSLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		if canonicalZone(leaf.Zone) == zone {
			out = append(out, leaf)
			continue
		}
		if cover == nil {
			continue
		}
		_, lnet, err := net.ParseCIDR(leaf.Prefix)
		if err != nil {
			continue
		}
		if cover.Contains(lnet.IP) || lnet.Contains(cover.IP) {
			out = append(out, leaf)
		}
	}
	return out
}

func (c *PTRCrawler) query(ctx context.Context, qname string, nss []string, qtype uint16) (rcode string, ptrs []string, nsUsed string, err error) {
	var last string
	var lastErr error
	lastNS := ""
	for _, ns := range nss {
		if err := c.waitNS(ctx, ns); err != nil {
			return RcodeERROR, nil, ns, err
		}
		code, answers, qerr := c.Exchange(ctx, qname, ns, qtype)
		lastNS = ns
		if qerr != nil {
			lastErr = qerr
			if isTimeout(qerr) {
				last = RcodeTIMEOUT
				continue
			}
			last = RcodeERROR
			continue
		}
		last = wireRcode(code, answers, qtype)
		if last == RcodeSERVFAIL || last == RcodeTIMEOUT {
			lastErr = nil
			continue
		}
		return last, answers, ns, nil
	}
	if last == "" {
		last = RcodeERROR
	}
	return last, nil, lastNS, lastErr
}

func wireRcode(code int, answers []string, qtype uint16) string {
	switch code {
	case dns.RcodeSuccess:
		if qtype == dns.TypePTR && len(answers) == 0 {
			return RcodeNODATA
		}
		return RcodeNOERROR
	case dns.RcodeNameError:
		return RcodeNXDOMAIN
	case dns.RcodeServerFailure:
		return RcodeSERVFAIL
	case dns.RcodeRefused:
		return RcodeREFUSED
	default:
		if s, ok := dns.RcodeToString[code]; ok {
			return s
		}
		return fmt.Sprintf("RCODE%d", code)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func (c *PTRCrawler) waitNS(ctx context.Context, ns string) error {
	qps := c.QPS
	if qps <= 0 {
		qps = DefaultPTRQPS
	}
	v, _ := c.limiters.LoadOrStore(ns, rate.NewLimiter(rate.Limit(qps), 1))
	return v.(*rate.Limiter).Wait(ctx)
}

func (c *PTRCrawler) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultPTRTimeout
}

func newPTRDNSClient(timeout time.Duration) *dns.Client {
	if timeout <= 0 {
		timeout = DefaultPTRTimeout
	}
	return &dns.Client{Timeout: timeout, Net: "udp"}
}

func defaultExchange(timeout time.Duration) PTRExchange {
	client := newPTRDNSClient(timeout)
	return func(ctx context.Context, qname, ns string, qtype uint16) (int, []string, error) {
		if timeout <= 0 {
			timeout = DefaultPTRTimeout
		}
		qctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		addr, err := nsDialAddr(qctx, ns)
		if err != nil {
			return dns.RcodeServerFailure, nil, err
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qname), qtype)
		m.RecursionDesired = false
		in, _, err := client.ExchangeContext(qctx, m, addr)
		if err != nil {
			return dns.RcodeServerFailure, nil, err
		}
		if in == nil {
			return dns.RcodeServerFailure, nil, fmt.Errorf("rdns: empty DNS response")
		}
		var ptrs []string
		for _, rr := range in.Answer {
			if p, ok := rr.(*dns.PTR); ok {
				ptrs = append(ptrs, p.Ptr)
			}
		}
		return in.Rcode, ptrs, nil
	}
}

func nsDialAddr(ctx context.Context, ns string) (string, error) {
	ns = strings.TrimSpace(ns)
	ns = strings.TrimSuffix(ns, ".")
	if host, port, err := net.SplitHostPort(ns); err == nil {
		if net.ParseIP(host) != nil {
			return net.JoinHostPort(host, port), nil
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("rdns: resolve NS %s: %w", ns, err)
		}
		return net.JoinHostPort(ips[0].IP.String(), port), nil
	}
	if ip := net.ParseIP(ns); ip != nil {
		return net.JoinHostPort(ns, "53"), nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, ns)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("rdns: resolve NS %s: %w", ns, err)
	}
	return net.JoinHostPort(ips[0].IP.String(), "53"), nil
}
