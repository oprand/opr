package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/oprand/opr/pkg/openrdap/rdap"

	"golang.org/x/time/rate"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

// Options are the knobs shared by `registry-crawl worker` and the daemon's
// rdap job.
type Options struct {
	// OnlyRegistries limits RDAP to these RIRs. Empty means all five (the
	// caller then usually narrows with ApplyRDAPWorkerRegistryDefaults).
	OnlyRegistries []string
	// Proxies are HTTP proxy URLs for RDAP requests; empty means direct.
	Proxies []string
}

// NewRegistryAggregator is the one-shot constructor: logger, store and
// options from the CLI flags, migrations applied.
func NewRegistryAggregator(c *cli.Context) (*RegistryAggregator, error) {

	// Create loggger
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return nil, err
	}
	logger = logger.Named("opr.registry")

	// Check the database is at last schema version, upgrade if necessary
	err = postgres.RunMigrations(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return nil, err
	}
	pgStore, err := postgres.New(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return nil, err
	}

	return New(logger, pgStore, Options{
		OnlyRegistries: c.StringSlice("only-registries"),
		Proxies:        c.StringSlice("proxies"),
	})
}

// New builds an aggregator on an existing logger and store. The caller
// owns the store; Close closes it.
func New(logger *zap.Logger, pgStore *postgres.Store, opts Options) (*RegistryAggregator, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// asn/prefix -> registry attribution is served from the NRO delegated_stats
	// snapshot (see aggregator/nro), not the IANA RDAP bootstrap cache.
	resolver := nro.NewResolver(pgStore)

	registriesOfInterest := make([]string, len(opts.OnlyRegistries))
	for i, r := range opts.OnlyRegistries {
		registriesOfInterest[i] = strings.ToUpper(strings.TrimSpace(r))
	}
	if len(registriesOfInterest) == 0 {
		logger.Info("all 5 registries selected")
		registriesOfInterest = []string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}
	} else {
		for _, r := range registriesOfInterest {
			if !slices.Contains([]string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}, r) {
				return nil, fmt.Errorf("unknown registry name: %s. Valid names: %s", r,
					strings.Join([]string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}, ", "))
			}
		}
		logger.Info("fetching data from only registries", zap.Strings("registries", registriesOfInterest))
	}

	// Use a different rate limiter for entity queries, RIPE is known to apply
	// different rate limits for PII data.
	rirWorkers := map[string]*RegistryWorker{
		opconst.AFRINIC: {
			Name: opconst.AFRINIC,
		},
		opconst.APNIC: {
			Name: opconst.APNIC,
		},
		opconst.ARIN: {
			Name: opconst.ARIN,
		},
		opconst.LACNIC: {
			Name: opconst.LACNIC,
		},
		opconst.RIPE: {
			Name: opconst.RIPE,
		},
	}

	// Create independent proxy ring for each RIR.
	// Each RIR has a pool of proxies to use for RDAP requests.
	// Each proxy has a rate limiter to limit the number of requests to send.
	// Blocking a proxy for one registry will not affect other registries.
	for _, rirWorker := range rirWorkers {
		pr, err := NewRingLoadBalancer(opts.Proxies, 20*time.Second)
		if err != nil {
			return nil, err
		}
		rirWorker.ProxyRing = pr
		rirWorker.Limiter = newLimiterForRegistry(rirWorker.Name)
	}

	// One RegistryWorker (limiter + proxy ring) per RIR. Autnum and ipnet
	// goroutines look this up by name; do not construct a second limiter per
	// kind or ARIN QPS doubles.

	na := &RegistryAggregator{
		RegistriesOfInterest: registriesOfInterest,
		Logger:               logger,
		Store:                pgStore,
		RegistryWorkers:      rirWorkers,
		Resolver:             resolver,
		hostLimiters:         make(map[string]*AdaptiveLimiter),
	}

	return na, nil

}

// DefaultRDAPWorkerRegistries is ARIN+LACNIC. RIPE/APNIC/AFRINIC autnums are
// already marked done on crawl_target after a complete bulk whois dump, so
// defaulting to all five would RDAP-hammer servers we already ingested.
// --include-bulk-gaps claims leftover pending rows on the other RIRs;
// --only-registries still wins over this default.
var DefaultRDAPWorkerRegistries = []string{opconst.ARIN, opconst.LACNIC}

// ApplyRDAPWorkerRegistryDefaults is shared by `registry-crawl worker` and
// `opr run`. When --only-registries is empty and --include-bulk-gaps is
// false, claim ARIN+LACNIC only. NewRegistryAggregator already filled all
// five when the slice was empty; this narrows that set. --only-registries
// wins (already applied in NewRegistryAggregator). --include-bulk-gaps
// keeps the all-five set so leftover pending rows on bulk RIRs can be claimed.
func (aggr *RegistryAggregator) ApplyRDAPWorkerRegistryDefaults(onlyRegistries []string, includeBulkGaps bool) {
	if len(onlyRegistries) == 0 && !includeBulkGaps {
		aggr.RegistriesOfInterest = append([]string(nil), DefaultRDAPWorkerRegistries...)
		aggr.Logger.Info("RDAP worker defaulting to ARIN+LACNIC; RIPE/APNIC/AFRINIC autnums are bulk-covered (done on crawl_target). Use --include-bulk-gaps or --only-registries to change",
			zap.Strings("registries", aggr.RegistriesOfInterest),
		)
	}
}

// ParseCrawlKinds maps the --kind flag to crawl_target kinds.
// Empty (omit) means both autnum and ipnet. Values are case-insensitive.
func ParseCrawlKinds(kind string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "":
		return []string{postgres.CrawlKindAutnum, postgres.CrawlKindIpnet}, nil
	case postgres.CrawlKindAutnum:
		return []string{postgres.CrawlKindAutnum}, nil
	case postgres.CrawlKindIpnet:
		return []string{postgres.CrawlKindIpnet}, nil
	default:
		return nil, fmt.Errorf("unknown --kind %q; valid values: autnum, ipnet (omit for both)", kind)
	}
}

// StartCrawlWorkers runs one crawl.Worker goroutine per (kind × registry).
// Autnum and ipnet for the same RIR share that RIR's RegistryWorker (AdaptiveLimiter
// + RingLoadBalancer). Do not construct a second limiter per kind — that would
// double ARIN QPS. kinds is typically ParseCrawlKinds output; empty is a no-op.
func (aggr *RegistryAggregator) StartCrawlWorkers(ctx context.Context, kinds []string, cfg CrawlConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(kinds) == 0 {
		return nil
	}
	for _, kind := range kinds {
		if _, err := aggr.handlerForKind(kind, nil); err != nil {
			return err
		}
	}
	// Batch 1: one in-flight object per kind×RIR worker, matching AdaptiveLimiter's
	// single-token AIMD. batch>1 claims many rows then processes sequentially,
	// holding leases the whole time.
	if cfg.Batch < 1 {
		cfg.Batch = 1
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 2 * time.Minute
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	pid := os.Getpid()

	aggr.Logger.Info("starting rdap crawl workers",
		zap.Strings("kinds", kinds),
		zap.Strings("registries", aggr.RegistriesOfInterest),
		zap.Int("batch", cfg.Batch),
		zap.Duration("lease", cfg.Lease),
		zap.Bool("once", cfg.Once),
	)

	var wg sync.WaitGroup
	errCh := make(chan error, len(kinds)*len(aggr.RegistriesOfInterest))

	for _, kind := range kinds {
		for _, name := range aggr.RegistriesOfInterest {
			rirWorker := aggr.RegistryWorkers[name]
			if rirWorker == nil {
				aggr.Logger.Warn("no registry worker configured, skipping",
					zap.String("registry", name),
					zap.String("kind", kind),
				)
				continue
			}
			handler, err := aggr.handlerForKind(kind, rirWorker)
			if err != nil {
				return err
			}
			wg.Add(1)
			go func(kind string, r *RegistryWorker, h crawl.Handler) {
				defer wg.Done()
				defer oplog.Recover(aggr.Logger, "rdap crawl worker panicked ("+kind+" "+r.Name+")")
				logName := crawlKindLogName(kind)
				lockedBy := fmt.Sprintf("%s-%d-%s-%s", hostname, pid, r.Name, kind)
				w := &crawl.Worker{
					Store:      aggr.Store,
					Logger:     aggr.Logger.Named(r.Name + "." + logName),
					Kind:       kind,
					Handler:    h,
					LockedBy:   lockedBy,
					Batch:      cfg.Batch,
					Lease:      cfg.Lease,
					Registries: []string{r.Name},
				}
				var rps float64
				if r.Limiter != nil {
					rps = r.Limiter.CurrentRate()
				}
				aggr.Logger.Info("starting one rdap crawl worker",
					zap.String("kind", kind),
					zap.String("registry", r.Name),
					zap.String("locked_by", lockedBy),
					zap.Float64("rate_limit_rps", rps),
				)
				var runErr error
				if cfg.Once {
					runErr = runCrawlUntilEmpty(ctx, w)
				} else {
					runErr = w.Run(ctx)
				}
				if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) {
					aggr.Logger.Error("rdap crawl worker stopped with error",
						zap.String("kind", kind),
						zap.String("registry", r.Name),
						zap.Error(runErr),
					)
					errCh <- runErr
				}
			}(kind, rirWorker, handler)
		}
	}

	wg.Wait()
	close(errCh)

	for e := range errCh {
		if e != nil {
			return e
		}
	}
	return nil
}

func crawlKindLogName(kind string) string {
	if kind == postgres.CrawlKindAutnum {
		return "asn"
	}
	return kind
}

func (aggr *RegistryAggregator) handlerForKind(kind string, worker *RegistryWorker) (crawl.Handler, error) {
	switch kind {
	case postgres.CrawlKindAutnum:
		return autnumHandler{aggr: aggr, worker: worker}, nil
	case postgres.CrawlKindIpnet:
		return ipnetHandler{aggr: aggr, worker: worker}, nil
	default:
		return nil, fmt.Errorf("unknown crawl kind %q; valid values: autnum, ipnet", kind)
	}
}

func runCrawlUntilEmpty(ctx context.Context, w *crawl.Worker) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if n == 0 {
				return err
			}
		}
		if n == 0 {
			return nil
		}
	}
}

func (aggr *RegistryAggregator) Close() {

	aggr.Logger.Debug("closing aggregator db")
	aggr.Store.Close()

}

// FindRirRdapUrlFromAsn resolves the administering RIR (and country) for the
// ASN via NRO delegated_stats and returns that resource's RDAP base URL
// (LACNIC+BR → registro.br).
func (aggr *RegistryAggregator) FindRirRdapUrlFromAsn(asn uint32) (*url.URL, error) {

	rirName, err := aggr.Resolver.RegistryForASN(context.Background(), asn)
	if err != nil {
		return nil, err
	}
	country, err := aggr.Resolver.CountryForASN(context.Background(), asn)
	if err != nil {
		country = ""
	}
	base := nro.RDAPBaseURLFor(rirName, country)
	if base == "" {
		return nil, fmt.Errorf("could not find rdap url for asn %d (registry %q)", asn, rirName)
	}
	return url.Parse(base)

}

// FindRirNameFromAsn returns the administering RIR for the ASN from the NRO
// delegated_stats snapshot. Returns an empty string (nil error) if unattributed.
func (aggr *RegistryAggregator) FindRirNameFromAsn(asn uint32) (string, error) {
	return aggr.Resolver.RegistryForASN(context.Background(), asn)
}

// FindRirNameFromRoute returns the administering RIR for the network's address
// from the NRO delegated_stats snapshot. Returns an empty string (nil error) if
// unattributed.
func (aggr *RegistryAggregator) FindRirNameFromRoute(route net.IPNet) (string, error) {
	return aggr.Resolver.RegistryForPrefix(context.Background(), route.IP)
}

// NewRingLoadBalancer initializes a RingLoadBalancer whose entries are
// long-lived transports (RDAP clients). When no proxies are given it still
// returns a single direct-connection entry, so GetNextProxy never returns nil.
func NewRingLoadBalancer(proxyURLs []string, timeout time.Duration) (*RingLoadBalancer, error) {
	var proxies []*Proxy
	if len(proxyURLs) == 0 {
		proxies = append(proxies, newProxy(nil, timeout))
	}
	for _, proxyURL := range proxyURLs {
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		proxies = append(proxies, newProxy(parsedURL, timeout))
	}
	return &RingLoadBalancer{proxies: proxies}, nil
}

// newProxy builds a Proxy with its own persistent Transport and RDAP client.
// A nil url means a direct connection (no proxy). The RDAP client has no
// Bootstrap: every request sets req.Server explicitly (see doRDAPRequest), so
// no IANA bootstrap fallback is needed.
func newProxy(u *url.URL, timeout time.Duration) *Proxy {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if u != nil {
		tr.Proxy = http.ProxyURL(u)
	}
	return &Proxy{
		URL: u,
		RdapClient: &rdap.Client{
			HTTP:      &http.Client{Transport: tr, Timeout: timeout},
			UserAgent: opconst.USER_AGENT,
		},
	}
}

// GetNextProxy returns the next proxy in the ring.
func (lb *RingLoadBalancer) GetNextProxy() *Proxy {
	if len(lb.proxies) == 0 {
		return nil
	}
	lb.mu.Lock()
	defer lb.mu.Unlock()
	proxy := lb.proxies[lb.index]
	lb.index = (lb.index + 1) % len(lb.proxies)
	return proxy
}

func (lb *RingLoadBalancer) GetCurrentProxyIndex() int {
	return lb.index
}

// Size returns the number of transports in the pool (nil-safe).
func (lb *RingLoadBalancer) Size() int {
	if lb == nil {
		return 0
	}
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return len(lb.proxies)
}

// throttlePauseBase is the first synthetic pause when a 429/403 has no
// Retry-After. Consecutive throttles double it (30s, 60s, 120s, …) up to
// throttlePauseCap. LACNIC omits the header; without this, AIMD hits min
// rps and keeps sending every 1/minRate forever (see lacnic.net 429s at 0.1 rps).
const (
	throttlePauseBase     = 30 * time.Second
	throttlePauseCap      = 15 * time.Minute
	throttlePauseMaxShift = 5 // 30s << 5 = 16m, then cap
)

// newLimiterForRegistry is the per-RIR AIMD used as RegistryWorker.Limiter
// (CurrentRate logging fallback). doRDAPRequest Waits on limiterForHost so
// LACNIC's lacnic.net pause does not stall NIC.br.
// ARIN (and the dump-complete RIRs) start at 2 rps, floor 0.1. LACNIC's
// rdap.lacnic.net 429s at that floor and does not send Retry-After; it starts
// slower and floors at 1/min. rdap.registro.br has its own slow profile via
// newLimiterForRegistroBR (same family, separate pointer).
func newLimiterForRegistry(name string) *AdaptiveLimiter {
	if name == opconst.LACNIC {
		return NewAdaptiveLimiter(rate.Every(time.Minute), 0.5, 2, 0.25, 0.5)
	}
	return NewAdaptiveLimiter(rate.Every(10*time.Second), 2, 10, 0.5, 0.5)
}

// newLimiterForRegistroBR is NIC.br's AIMD: same family as lacnic.net
// (floor 1/min, start 0.5, max 2) but a distinct limiter so a lacnic.net
// pause cannot stall registro.br.
func newLimiterForRegistroBR() *AdaptiveLimiter {
	return NewAdaptiveLimiter(rate.Every(time.Minute), 0.5, 2, 0.25, 0.5)
}

const (
	lacnicRDAPHost     = "rdap.lacnic.net"
	registroBRRDAPHost = "rdap.registro.br"
)

// limiterForHost returns the AIMD limiter for an RDAP hostname, creating one
// on first use. Autnum and ipnet for the same host share the pointer. Empty
// host returns nil (caller may fall back to RegistryWorker.Limiter).
func (aggr *RegistryAggregator) limiterForHost(host string) *AdaptiveLimiter {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || aggr == nil {
		return nil
	}
	aggr.hostLimitersMu.Lock()
	defer aggr.hostLimitersMu.Unlock()
	if aggr.hostLimiters == nil {
		aggr.hostLimiters = make(map[string]*AdaptiveLimiter)
	}
	if lim, ok := aggr.hostLimiters[host]; ok {
		return lim
	}
	lim := newLimiterForHost(host)
	aggr.hostLimiters[host] = lim
	return lim
}

// limiterForRDAP is the limiter doRDAPRequest Wait/OnSuccess/OnThrottle use:
// host of the intended server, else the worker fallback.
func (aggr *RegistryAggregator) limiterForRDAP(regWorker *RegistryWorker, server *url.URL) *AdaptiveLimiter {
	if lim := aggr.limiterForHost(rdapHostname(server)); lim != nil {
		return lim
	}
	if regWorker != nil {
		return regWorker.Limiter
	}
	return nil
}

func rdapHostname(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func newLimiterForHost(host string) *AdaptiveLimiter {
	switch strings.ToLower(host) {
	case lacnicRDAPHost:
		return newLimiterForRegistry(opconst.LACNIC)
	case registroBRRDAPHost:
		return newLimiterForRegistroBR()
	default:
		return newLimiterForRegistry("")
	}
}

// NewAdaptiveLimiter creates an AIMD limiter. start/min/max are request rates
// (req/s), addStep is the additive increase applied per success, and backoff is
// the multiplicative decrease factor (e.g. 0.5) applied on throttling.
func NewAdaptiveLimiter(min, start, max, addStep rate.Limit, backoff float64) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		limiter: rate.NewLimiter(start, 1),
		cur:     start,
		min:     min,
		max:     max,
		addStep: addStep,
		backoff: backoff,
	}
}

// Wait blocks until the limiter allows another request, first honoring any
// active pause set from a Retry-After header. This is process-local AIMD;
// job-level backoff is crawl_target.next_retry_at (see crawl.Result.RetryAfter).
func (a *AdaptiveLimiter) Wait(ctx context.Context) error {
	a.mu.Lock()
	pause := time.Until(a.pausedUntil)
	a.mu.Unlock()
	if pause > 0 {
		t := time.NewTimer(pause)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return a.limiter.Wait(ctx)
}

// OnSuccess additively increases the rate toward max and clears the
// consecutive-throttle counter so the next missing Retry-After starts at 30s.
func (a *AdaptiveLimiter) OnSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.consecutiveThrottle = 0
	a.pausedUntil = time.Time{}
	if a.cur = a.cur + a.addStep; a.cur > a.max {
		a.cur = a.max
	}
	a.limiter.SetLimit(a.cur)
}

// OnThrottle multiplicatively decreases the rate toward min and pauses.
// retryAfter is the Retry-After header (0 if missing). A missing header still
// pauses: 30s, then 60s, 120s, … cap 15m on consecutive 429s. Extending an
// already-longer pause is a no-op so a short header cannot cancel a longer
// synthetic backoff.
func (a *AdaptiveLimiter) OnThrottle(retryAfter time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur = rate.Limit(float64(a.cur) * a.backoff); a.cur < a.min {
		a.cur = a.min
	}
	a.limiter.SetLimit(a.cur)
	a.consecutiveThrottle++
	pause := retryAfter
	if pause <= 0 {
		pause = throttlePauseDuration(a.consecutiveThrottle)
	}
	until := time.Now().Add(pause)
	if until.After(a.pausedUntil) {
		a.pausedUntil = until
	}
}

func throttlePauseDuration(consecutive int) time.Duration {
	if consecutive < 1 {
		consecutive = 1
	}
	shift := consecutive - 1
	if shift > throttlePauseMaxShift {
		shift = throttlePauseMaxShift
	}
	d := throttlePauseBase << uint(shift)
	if d > throttlePauseCap {
		return throttlePauseCap
	}
	return d
}

// CurrentRate returns the current request rate (req/s).
func (a *AdaptiveLimiter) CurrentRate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return float64(a.cur)
}

// PauseRemaining is how long Wait will still sleep for an active Retry-After
// pause. Used by autnumHandler so crawl_target.next_retry_at matches the
// limiter pause when the HTTP header was missing but OnThrottle still set one,
// or when Wait already consumed part of the header duration.
func (a *AdaptiveLimiter) PauseRemaining() time.Duration {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d := time.Until(a.pausedUntil)
	if d < 0 {
		return 0
	}
	return d
}
