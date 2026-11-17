package registry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

var _ crawl.Handler = ipnetHandler{}

const ipnetHandlePrefix = "handle:"

// ipnetHandler fetches one CIDR (or handle:dN:H parent) via RDAP for a
// single RegistryWorker's limiter and proxy ring. Autnum and ipnet for
// the same destination host share that host's AdaptiveLimiter
// (doRDAPRequest Waits on it). Do not construct a second limiter here.
type ipnetHandler struct {
	aggr   *RegistryAggregator
	worker *RegistryWorker

	// Test seams. Production stays zero: persist goes to persistIpnet,
	// enqueue to Store.EnqueueIpnetParentHandle / EnqueueIpnetDownCIDR,
	// RDAP base from NRO.
	persistOverride      func(ctx context.Context, queried, registry string, resp *rdap.IPNetwork) error
	enqueueOverride      func(ctx context.Context, registry, handle string, depth int) error
	enqueueDownOverride  func(ctx context.Context, registry, key string) error
	rdapBaseOverride     string
	saveGeofeedsOverride func(ctx context.Context, urls []string) error
}

func (h ipnetHandler) Process(ctx context.Context, t *postgres.CrawlTarget) crawl.Result {
	if t == nil {
		return crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil crawl target")}
	}

	key := strings.TrimSpace(t.Key)
	logger := h.logger().With(
		zap.String("registry", h.workerName()),
		zap.String("key", t.Key),
	)

	if isIpnetHandleKey(key) {
		return h.processHandleKey(ctx, logger, t, key)
	}

	_, ipnet, err := net.ParseCIDR(key)
	if err != nil {
		return crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("invalid ipnet cidr key %q: %w", t.Key, err),
		}
	}

	country := h.countryForIP(ctx, ipnet.IP)
	primary, fallback := rdapBasesForCrawl(h.workerName(), country)
	if h.rdapBaseOverride != "" {
		primary, fallback = h.rdapBaseOverride, ""
	}
	logger = logger.With(
		zap.String("country", country),
		zap.String("rdap_base", primary),
	)

	rdapResp, res, ok := h.fetchIpnetWithBases(ctx, logger, ipnet, primary, fallback)
	if !ok {
		return res
	}
	if rdapResp == nil {
		return crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil rdap response for ipnet %s", key)}
	}

	respData, isIPNet := rdapResp.Object.(*rdap.IPNetwork)
	if !isIPNet || respData == nil {
		logger.Warn("casting to rdap ip network object failed")
		return crawl.Result{
			Outcome:    crawl.OutcomeRetry,
			StatusCode: intPtr(http.StatusOK),
			Err:        fmt.Errorf("rdap object is not ip network"),
		}
	}

	res = resultForParsedIpnet(func() error {
		return h.persistIpnetOrOverride(ctx, logger, key, t.Registry, respData)
	})
	switch res.Outcome {
	case crawl.OutcomeRetry:
		logger.Error("error saving ipnet info", zap.Error(res.Err))
	case crawl.OutcomeSuccess:
		logger.Info("saved ipnet info")
		h.maybeEnqueueParent(ctx, logger, t.Registry, respData, ipnetParentDepthFromCIDR, false)
		h.maybeEnqueueDown(ctx, logger, t.Registry, key, respData)
	}
	return res
}

func (h ipnetHandler) processHandleKey(ctx context.Context, logger *zap.Logger, t *postgres.CrawlTarget, key string) crawl.Result {
	depth, handle, ok := parseIpnetHandleKey(key)
	if !ok {
		return crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("invalid ipnet handle key %q", t.Key),
		}
	}
	if depth > postgres.IpnetParentHandleMaxDepth {
		return crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("ipnet handle depth %d exceeds cap %d", depth, postgres.IpnetParentHandleMaxDepth),
		}
	}

	supported, known := h.worker.rirSearch1State()
	if !known {
		h.probeAndCacheRIRSearch1(ctx)
		supported, known = h.worker.rirSearch1State()
		if !known {
			return crawl.Result{
				Outcome: crawl.OutcomeRetry,
				Err:     fmt.Errorf("rirSearch1 probe failed for %s", h.workerName()),
			}
		}
	}
	if !supported {
		return crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("registry %s has no rirSearch1; cannot resolve ips?handle=", h.workerName()),
		}
	}

	primary, _ := h.handleSearchBase()
	logger = logger.With(
		zap.String("handle", handle),
		zap.Int("parent_depth", depth),
		zap.String("rdap_base", primary),
	)

	rdapResp, res, ok := h.fetchIpnetHandle(ctx, logger, handle, primary)
	if !ok {
		return res
	}
	respData := ipNetworkFromRDAPResponse(rdapResp)
	if respData == nil {
		logger.Warn("rdap handle search did not yield an ip network")
		return crawl.Result{
			Outcome:    crawl.OutcomeRetry,
			StatusCode: intPtr(http.StatusOK),
			Err:        fmt.Errorf("rdap object is not ip network"),
		}
	}

	// Queried CIDR empty: mapper uses cidr0 / start-end. Same persist path
	// as a CIDR job.
	res = resultForParsedIpnet(func() error {
		return h.persistIpnetOrOverride(ctx, logger, "", t.Registry, respData)
	})
	switch res.Outcome {
	case crawl.OutcomeRetry:
		logger.Error("error saving ipnet info", zap.Error(res.Err))
	case crawl.OutcomeSuccess:
		logger.Info("saved ipnet info")
		h.maybeEnqueueParent(ctx, logger, t.Registry, respData, depth, true)
		h.maybeEnqueueDown(ctx, logger, t.Registry, "", respData)
	}
	return res
}

func (h ipnetHandler) handleSearchBase() (primary, fallback string) {
	if h.rdapBaseOverride != "" {
		return h.rdapBaseOverride, ""
	}
	return rdapBasesForCrawl(h.workerName(), "")
}

func (h ipnetHandler) persistIpnetOrOverride(ctx context.Context, logger *zap.Logger, queried, registry string, respData *rdap.IPNetwork) error {
	if h.persistOverride != nil {
		return h.persistOverride(ctx, queried, registry, respData)
	}
	return h.persistIpnet(ctx, logger, queried, registry, respData)
}

func (h ipnetHandler) countryForIP(ctx context.Context, ip net.IP) string {
	if h.aggr == nil || h.aggr.Resolver == nil || ip == nil {
		return ""
	}
	cc, err := h.aggr.Resolver.CountryForIP(ctx, ip)
	if err != nil {
		return ""
	}
	return cc
}

// fetchIpnetWithBases hits primary, then on a NIC.br 404 retries once against
// fallback (lacnic.net). Do not MarkGone on the first registro.br 404.
func (h ipnetHandler) fetchIpnetWithBases(ctx context.Context, logger *zap.Logger, ipnet *net.IPNet, primary, fallback string) (*rdap.Response, crawl.Result, bool) {
	rdapResp, res, ok := h.tryIpnetServer(ctx, logger, ipnet, primary)
	if !ok && isGone404(res) && fallback != "" && fallback != primary {
		logger.Info("rdap 404 at NIR, retrying parent registry",
			zap.String("from", primary),
			zap.String("to", fallback),
		)
		rdapResp, res, ok = h.tryIpnetServer(ctx, logger, ipnet, fallback)
	}
	if !ok && res.Outcome == crawl.OutcomeGone {
		logger.Info("rdap object gone")
	}
	return rdapResp, res, ok
}

func (h ipnetHandler) tryIpnetServer(ctx context.Context, logger *zap.Logger, ipnet *net.IPNet, base string) (*rdap.Response, crawl.Result, bool) {
	req := applyRDAPServer(rdap.NewIPNetRequest(ipnet), base)
	intended, _ := url.Parse(base)
	return h.tryRDAPRequest(ctx, logger, req, intended)
}

func (h ipnetHandler) fetchIpnetHandle(ctx context.Context, logger *zap.Logger, handle, base string) (*rdap.Response, crawl.Result, bool) {
	req := ipnetHandleSearchRequest(base, handle)
	if req == nil {
		return nil, crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("invalid ipnet handle search %q", handle),
		}, false
	}
	intended, _ := url.Parse(base)
	return h.tryRDAPRequest(ctx, logger, req, intended)
}

func (h ipnetHandler) tryRDAPRequest(ctx context.Context, logger *zap.Logger, req *rdap.Request, intended *url.URL) (*rdap.Response, crawl.Result, bool) {
	var rdapResp *rdap.Response
	for attempt := 1; attempt <= maxProxyAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, crawl.Result{Outcome: crawl.OutcomeRetry, Err: err}, false
		}

		var shouldRetry bool
		var err error
		rdapResp, shouldRetry, err = h.aggr.doRDAPRequest(ctx, h.worker, req)

		if ctx.Err() != nil {
			return nil, crawl.Result{Outcome: crawl.OutcomeRetry, Err: ctx.Err()}, false
		}

		httpResp := rdapFirstHTTP(rdapResp)
		status := 0
		if httpResp != nil {
			status = httpResp.StatusCode
			logger = logger.With(
				zap.Int("status_code", status),
				zap.Int("proxy_index", h.worker.ProxyRing.GetCurrentProxyIndex()),
			)
			if httpResp.Request != nil && httpResp.Request.URL != nil {
				logger = logger.With(zap.String("url", httpResp.Request.URL.String()))
			}
		}

		lim := h.aggr.limiterForRDAP(h.worker, intended)
		if lim == nil && h.worker != nil {
			lim = h.worker.Limiter
		}

		if status == http.StatusTooManyRequests || status == http.StatusForbidden {
			retryAfter := retryAfterFromResponse(httpResp)
			if retryAfter == 0 && lim != nil {
				retryAfter = lim.PauseRemaining()
			}
			rate := 0.0
			if lim != nil {
				rate = lim.CurrentRate()
			}
			logger.Warn("rdap throttled, requeueing ipnet",
				zap.Duration("retry_after", retryAfter),
				zap.Float64("rate_limit_rps", rate),
			)
			return nil, crawl.Result{
				Outcome:    crawl.OutcomeRetry,
				StatusCode: intPtr(status),
				RetryAfter: retryAfter,
				Err:        err,
			}, false
		}

		if status == http.StatusNotFound || status == http.StatusGone {
			return nil, crawl.Result{Outcome: crawl.OutcomeGone, StatusCode: intPtr(status)}, false
		}

		if status == http.StatusOK && rdapResp != nil && err == nil {
			return rdapResp, crawl.Result{}, true
		}

		if httpResp != nil && status != http.StatusOK {
			logger.Warn("rdap non-200, requeueing ipnet", zap.Error(err))
			return nil, crawl.Result{
				Outcome:    crawl.OutcomeRetry,
				StatusCode: intPtr(status),
				Err:        err,
			}, false
		}

		if shouldRetry && attempt < maxProxyAttempts {
			logger.Warn("transient rdap error, retrying with next proxy",
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
			continue
		}

		logger.Error("rdap request failed", zap.Error(err), zap.Bool("should_retry", shouldRetry))
		res := crawl.Result{Outcome: crawl.OutcomeRetry, Err: err}
		if status != 0 {
			res.StatusCode = intPtr(status)
		}
		return nil, res, false
	}

	if rdapResp == nil {
		return nil, crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil rdap response for ipnet")}, false
	}
	return rdapResp, crawl.Result{}, true
}

func resultForParsedIpnet(persist func() error) crawl.Result {
	if persist != nil {
		if err := persist(); err != nil {
			return crawl.Result{
				Outcome:    crawl.OutcomeRetry,
				StatusCode: intPtr(http.StatusOK),
				Err:        err,
			}
		}
	}
	return crawl.Result{Outcome: crawl.OutcomeSuccess, StatusCode: intPtr(http.StatusOK)}
}

// persistIpnet maps and saves whoisdb inetnum/inet6num plus nested roles/orgs.
// cidr0 prefixes become extra whois rows (same object). It never Seed/inserts
// crawl_target children.
func (h ipnetHandler) persistIpnet(ctx context.Context, logger *zap.Logger, queried string, registry string, respData *rdap.IPNetwork) error {
	source, err := nro.FindRegistryByURL(FindSelfLink(respData.Links))
	if err != nil {
		logger.Error("error finding rir by url", zap.Error(err), zap.String("handle", respData.Handle), zap.Any("links", respData.Links))
	}
	defaultSource := registry
	if defaultSource == "" {
		defaultSource = h.workerName()
	}

	inet4, inet6, roles, orgs := mapIpnetFromRDAP(h.aggr, queried, respData, source, defaultSource)
	stampIpnetRDAPFetch(inet4, inet6, roles, orgs)
	if len(inet4) == 0 && len(inet6) == 0 {
		return fmt.Errorf("no inetnum rows to save for ipnet %s", queried)
	}

	logger = logger.With(
		zap.Int("inetnum_count", len(inet4)),
		zap.Int("inet6num_count", len(inet6)),
		zap.Int("role_count", len(roles)),
		zap.Int("org_count", len(orgs)),
	)

	saveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	err = h.aggr.Store.SaveWhoisRole(saveCtx, roles)
	cancel()
	if err != nil {
		logger.Error("error saving whois role", zap.Error(err), zap.Any("roles", roles))
	}

	saveCtx, cancel = context.WithTimeout(ctx, 4*time.Second)
	err = h.aggr.Store.SaveWhoisOrganization(saveCtx, orgs)
	cancel()
	if err != nil {
		logger.Error("error saving whois organization", zap.Error(err), zap.Any("orgs", orgs))
	}

	if len(inet4) > 0 {
		saveCtx, cancel = context.WithTimeout(ctx, 4*time.Second)
		err = h.aggr.Store.SaveWhoisInetNum(saveCtx, inet4)
		cancel()
		if err != nil {
			return err
		}
	}
	if len(inet6) > 0 {
		saveCtx, cancel = context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if err := h.aggr.Store.SaveWhoisInet6Num(saveCtx, inet6); err != nil {
			return err
		}
	}
	h.persistMappedGeofeeds(ctx, logger, inet4, inet6)
	return nil
}

// persistMappedGeofeeds upserts canonical geofeed URLs from the mapped whois
// rows into the geofeeds catalog. Best-effort: must not fail the RDAP job.
func (h ipnetHandler) persistMappedGeofeeds(ctx context.Context, logger *zap.Logger, inet4 []*whoisdb.WhoisInetNum, inet6 []*whoisdb.WhoisInet6Num) {
	urls := catalogGeofeedURLs(inet4, inet6)
	if len(urls) == 0 {
		return
	}
	save := h.saveGeofeedsOverride
	if save == nil && h.aggr != nil && h.aggr.Store != nil {
		save = h.aggr.Store.SaveGeofeeds
	}
	if save == nil {
		return
	}
	saveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := save(saveCtx, urls); err != nil {
		logger.Warn("error saving geofeeds catalog from rdap", zap.Error(err), zap.Strings("urls", urls))
	}
}

func isIpnetHandleKey(key string) bool {
	return len(key) >= len(ipnetHandlePrefix) && strings.EqualFold(key[:len(ipnetHandlePrefix)], ipnetHandlePrefix)
}

func (h ipnetHandler) logger() *zap.Logger {
	name := "ipnet"
	if h.worker != nil && h.worker.Name != "" {
		name = h.worker.Name + ".ipnet"
	}
	if h.aggr != nil && h.aggr.Logger != nil {
		return h.aggr.Logger.Named(name)
	}
	return zap.NewNop()
}

func (h ipnetHandler) workerName() string {
	if h.worker == nil {
		return ""
	}
	return h.worker.Name
}
