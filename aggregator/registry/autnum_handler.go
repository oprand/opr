package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/store/postgres"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"github.com/oprand/opr/pkg/openrdap/rdap"

	mapset "github.com/deckarep/golang-set/v2"
	"go.uber.org/zap"
)

// maxProxyAttempts is a small inner retry for transient proxy / nil-response
// errors. Throttle (429/403) is never retried here: one response becomes
// OutcomeRetry so crawl.Worker can release the claim lease.
const maxProxyAttempts = 3

// autnumHandler fetches one ASN via RDAP for a single RegistryWorker's
// limiter and proxy ring. crawl.Worker claims crawl_target rows; this only
// maps HTTP outcomes onto crawl.Result.
//
// Rate limiting is two complementary layers:
//   - AdaptiveLimiter (this process, this RIR): AIMD + pause until Retry-After
//     so we do not hammer the RDAP server.
//   - crawl_target.next_retry_at (the job): SKIP LOCKED workers must not
//     immediately re-claim the same ASN after a 429. Result.RetryAfter is
//     how that timestamp is set — even if this process already slept inside
//     the limiter.
type autnumHandler struct {
	aggr   *RegistryAggregator
	worker *RegistryWorker
}

func (h autnumHandler) Process(ctx context.Context, t *postgres.CrawlTarget) crawl.Result {
	if t == nil {
		return crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil crawl target")}
	}

	asnNum, err := strconv.ParseUint(strings.TrimSpace(t.Key), 10, 32)
	if err != nil {
		return crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("parse asn key %q: %w", t.Key, err)}
	}
	asNumber := uint32(asnNum)

	logger := h.aggr.Logger.Named(h.worker.Name+".asn").With(
		zap.Uint32("asn", asNumber),
		zap.String("registry", h.worker.Name),
		zap.String("key", t.Key),
	)

	country := h.countryForASN(ctx, asNumber)
	primary, fallback := rdapBasesForCrawl(h.worker.Name, country)
	logger = logger.With(
		zap.String("country", country),
		zap.String("rdap_base", primary),
	)

	rdapResp, res, ok := h.fetchAutnumWithBases(ctx, logger, asNumber, primary, fallback)
	if !ok {
		return res
	}
	if rdapResp == nil {
		return crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil rdap response for asn %d", asNumber)}
	}

	respData, isAutnum := rdapResp.Object.(*rdap.Autnum)
	if !isAutnum || respData == nil {
		logger.Warn("casting to rdap autnum object failed")
		return crawl.Result{
			Outcome:    crawl.OutcomeRetry,
			StatusCode: intPtr(http.StatusOK),
			Err:        fmt.Errorf("rdap object is not autnum"),
		}
	}

	res = resultForParsedAutnum(asNumber, respData, func() error {
		return h.persistAutnum(ctx, logger, asNumber, t.Registry, respData)
	})
	switch res.Outcome {
	case crawl.OutcomeRetry:
		logger.Error("error saving asn info", zap.Error(res.Err))
	case crawl.OutcomeSuccess:
		logger.Info("saved asn info", zap.Int("autnum_count", len(autnumsToPersist(asNumber, respData))))
	}
	return res
}

func (h autnumHandler) countryForASN(ctx context.Context, asNumber uint32) string {
	if h.aggr == nil || h.aggr.Resolver == nil {
		return ""
	}
	cc, err := h.aggr.Resolver.CountryForASN(ctx, asNumber)
	if err != nil {
		return ""
	}
	return cc
}

// fetchAutnumWithBases hits primary, then on a NIC.br 404 retries once against
// fallback (lacnic.net). Do not MarkGone on the first registro.br 404.
func (h autnumHandler) fetchAutnumWithBases(ctx context.Context, logger *zap.Logger, asNumber uint32, primary, fallback string) (*rdap.Response, crawl.Result, bool) {
	rdapResp, res, ok := h.tryAutnumServer(ctx, logger, asNumber, primary)
	if !ok && isGone404(res) && fallback != "" && fallback != primary {
		logger.Info("rdap 404 at NIR, retrying parent registry",
			zap.String("from", primary),
			zap.String("to", fallback),
		)
		rdapResp, res, ok = h.tryAutnumServer(ctx, logger, asNumber, fallback)
	}
	if !ok && res.Outcome == crawl.OutcomeGone {
		logger.Info("rdap object gone")
	}
	return rdapResp, res, ok
}

func isGone404(res crawl.Result) bool {
	return res.Outcome == crawl.OutcomeGone && res.StatusCode != nil && *res.StatusCode == http.StatusNotFound
}

func applyRDAPServer(req *rdap.Request, base string) *rdap.Request {
	if req == nil || strings.TrimSpace(base) == "" {
		return req
	}
	u, err := url.Parse(base)
	if err != nil {
		return req
	}
	return req.WithServer(u)
}

func (h autnumHandler) tryAutnumServer(ctx context.Context, logger *zap.Logger, asNumber uint32, base string) (*rdap.Response, crawl.Result, bool) {
	var rdapResp *rdap.Response
	intended, _ := url.Parse(base)
	for attempt := 1; attempt <= maxProxyAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, crawl.Result{Outcome: crawl.OutcomeRetry, Err: err}, false
		}

		req := applyRDAPServer(rdap.NewAutnumRequest(asNumber), base)
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

		// 429/403: limiter already called OnThrottle. Do not spin in this
		// claim — release the lease with OutcomeRetry.
		if status == http.StatusTooManyRequests || status == http.StatusForbidden {
			retryAfter := retryAfterFromResponse(httpResp)
			if retryAfter == 0 && lim != nil {
				retryAfter = lim.PauseRemaining()
			}
			rate := 0.0
			if lim != nil {
				rate = lim.CurrentRate()
			}
			logger.Warn("rdap throttled, requeueing autnum",
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

		// 5xx and other non-OK: queue-level retry, no inner spin.
		if httpResp != nil && status != http.StatusOK {
			logger.Warn("rdap non-200, requeueing autnum", zap.Error(err))
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
		return nil, crawl.Result{Outcome: crawl.OutcomeRetry, Err: fmt.Errorf("nil rdap response for asn %d", asNumber)}, false
	}
	return rdapResp, crawl.Result{}, true
}

// resultForParsedAutnum maps a decoded HTTP-200 RDAP autnum onto a crawl result.
// As-blocks are persisted for every ASN in [start, end] when the queried ASN
// lies in that interval (no width cap, including CNNIC covering blocks).
// UNIQUE(aut_num) is per-ASN, so fan-out does not collide. HTTP 404
// OutcomeGone is decided in tryAutnumServer, not here.
func resultForParsedAutnum(asNumber uint32, respData *rdap.Autnum, persist func() error) crawl.Result {
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

// shouldFanOutAutnumRange is true when this RDAP object is an as-block and the
// queried ASN lies in [start, end]. Any RIR, any width — CNNIC covering
// blocks and APNIC NIR blocks (e.g. AS147191-AS147290) alike. Handle form is
// not used. If queried is outside the range, autnumsToPersist falls back to
// the queried ASN only (no OutcomeGone).
func shouldFanOutAutnumRange(queried uint32, a *rdap.Autnum) bool {
	if !isAutnumRange(a) {
		return false
	}
	start, end := *a.StartAutnum, *a.EndAutnum
	return queried >= start && queried <= end
}

// autnumRangeASNs is every ASN in [start, end]. Caller must have already
// decided this object is safe to expand (shouldFanOutAutnumRange).
func autnumRangeASNs(a *rdap.Autnum) []uint32 {
	if a == nil || a.StartAutnum == nil || a.EndAutnum == nil {
		return nil
	}
	start, end := *a.StartAutnum, *a.EndAutnum
	if end < start {
		return nil
	}
	out := make([]uint32, 0, int(end-start)+1)
	for n := uint64(start); n <= uint64(end); n++ {
		out = append(out, uint32(n))
	}
	return out
}

// autnumsToPersist is the ASN list persist writes. An in-range as-block
// expands to every ASN in [start, end]; everything else is just the queried ASN.
func autnumsToPersist(queried uint32, a *rdap.Autnum) []uint32 {
	if shouldFanOutAutnumRange(queried, a) {
		return autnumRangeASNs(a)
	}
	return []uint32{queried}
}

// isAutnumRange reports an as-block: both start and end are set and end > start.
// A real aut-num has startAutnum == endAutnum. Unset or zero-only pointers are
// not treated as a block (the RDAP library leaves missing fields nil).
func isAutnumRange(a *rdap.Autnum) bool {
	if a == nil || a.StartAutnum == nil || a.EndAutnum == nil {
		return false
	}
	return *a.EndAutnum > *a.StartAutnum
}

// autnumBlockHandle is the as-block label for last_error, from Handle or start-end.
func autnumBlockHandle(a *rdap.Autnum) string {
	if a == nil {
		return ""
	}
	if h := strings.TrimSpace(a.Handle); h != "" {
		return h
	}
	if a.StartAutnum != nil && a.EndAutnum != nil {
		return fmt.Sprintf("AS%d - AS%d", *a.StartAutnum, *a.EndAutnum)
	}
	return ""
}

func (h autnumHandler) persistAutnum(ctx context.Context, logger *zap.Logger, asNumber uint32, registry string, respData *rdap.Autnum) error {
	source, err := nro.FindRegistryByURL(FindSelfLink(respData.Links))
	if err != nil {
		logger.Error("error finding rir by url", zap.Error(err), zap.String("handle", respData.Handle), zap.Any("links", respData.Links))
	}

	asnRows, roles, orgs := mapAutnumRangeFromRDAP(h.aggr, asNumber, respData, source, h.worker.Name)
	if len(asnRows) == 0 {
		return fmt.Errorf("no autnum rows to save for asn %d", asNumber)
	}
	asnInfo := asnRows[0]

	for _, role := range roles {
		logger.Debug("got one role", zap.Any("role", role))
	}
	logger = logger.With(
		zap.Int("autnum_count", len(asnRows)),
		zap.Int("role_count", len(roles)),
		zap.Int("org_count", len(orgs)),
		zap.Stringp("preferred_org", asnInfo.Org),
		zap.Stringp("abuse_c", asnInfo.AbuseC),
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

	saveCtx, cancel = context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := h.aggr.Store.SaveWhoisAutNum(saveCtx, asnRows); err != nil {
		return err
	}
	// crawl.Worker marks the claimed row via MarkSuccess after OutcomeSuccess.
	// Siblings (839–842 when we fetched 838) must be flipped here so they
	// are not re-fetched; UPDATE-only, skip in_progress.
	if len(asnRows) > 1 {
		return h.aggr.Store.MarkAutnumRangeSiblingsDone(saveCtx, autnumsToPersist(asNumber, respData), registry)
	}
	return nil
}

// mapAutnumRangeFromRDAP maps one RDAP object onto one or more WhoisAutNum
// rows. Assignment ranges expand to every ASN in [start, end];
// mapAutnumFromRDAP + StampFetch(rdap) run once per ASN. Roles/orgs are
// produced once (shared handles) and stamped with the first autnum.
func mapAutnumRangeFromRDAP(aggr *RegistryAggregator, queried uint32, respData *rdap.Autnum, source, defaultSource string) ([]*whoisdb.WhoisAutNum, []*whoisdb.WhoisRole, []*whoisdb.WhoisOrganization) {
	asns := autnumsToPersist(queried, respData)
	rows := make([]*whoisdb.WhoisAutNum, 0, len(asns))
	var roles []*whoisdb.WhoisRole
	var orgs []*whoisdb.WhoisOrganization
	for i, n := range asns {
		asnInfo, r, o := mapAutnumFromRDAP(aggr, n, respData, source, defaultSource)
		if i == 0 {
			stampRDAPFetch(asnInfo, r, o)
			roles, orgs = r, o
		} else {
			asnInfo.StampFetch(whoisdb.FetchMethodRDAP)
		}
		rows = append(rows, asnInfo)
	}
	return rows, roles, orgs
}

// mapAutnumFromRDAP turns a decoded RDAP autnum into whoisdb rows. Pure mapping:
// no Postgres, no StampFetch. mapAutnumRangeFromRDAP is map → stamp (once per
// ASN in an assignment range); persistAutnum then SaveWhois*.
//
//	Autnum JSON
//	  ├─ entities[] registrant ──► skip as role, recurse POCs (NestingLevel 1)
//	  │                            └─ RdapEntities2WhoisOrgs → WhoisOrganization
//	  ├─ entities[] other roles ─► WhoisRole (admin/tech/abuse/noc/routing)
//	  └─ name/status/events ────► WhoisAutNum (org, admin_c, abuse_c, …)
//	Then mapAutnumRangeFromRDAP: StampFetch(rdap) per ASN → persist SaveWhois*
//
//	flowchart TD
//	  autnumJSON[Autnum JSON]
//	  autnumJSON --> topEntities[Top-level entities]
//	  topEntities --> registrant[Registrant skipped as role]
//	  topEntities --> topRoles[Non-registrant roles]
//	  registrant --> nestedRoles[Recurse nested POCs]
//	  registrant --> orgs[WhoisOrganization]
//	  nestedRoles --> roles[WhoisRole abuse admin tech]
//	  topRoles --> roles
//	  autnumJSON --> autnumRow[WhoisAutNum]
//	  roles --> stamp[StampFetch rdap]
//	  orgs --> stamp
//	  autnumRow --> stamp
//	  stamp --> save[SaveWhoisRole SaveWhoisOrganization SaveWhoisAutNum]
func mapAutnumFromRDAP(aggr *RegistryAggregator, asNumber uint32, respData *rdap.Autnum, source, defaultSource string) (*whoisdb.WhoisAutNum, []*whoisdb.WhoisRole, []*whoisdb.WhoisOrganization) {
	roles := aggr.RdapEntities2WhoisRoles(&respData.Entities, nil, &source, 0)
	for _, role := range roles {
		if role != nil && role.Source == nil {
			role.Source = &defaultSource
		}
	}

	orgs := aggr.RdapEntities2WhoisOrgs(&respData.Entities, &source, 0)

	var countryCode string
	if len(respData.Country) == 2 {
		countryCode = respData.Country
	} else if len(orgs) > 0 && orgs[0].CountryCode != nil {
		countryCode = *orgs[0].CountryCode
	}
	var country string
	if countryCode != "" {
		country = opconst.CountryCode[countryCode]
	}
	emailsForDomainCandidates := []string{}
	for _, org := range orgs {
		if org != nil && org.Email != nil && len(*org.Email) > 0 {
			emailsForDomainCandidates = append(emailsForDomainCandidates, *org.Email...)
		}
	}
	domain := FindDomainFromEmail(emailsForDomainCandidates...)
	if domain == nil {
		for _, role := range roles {
			if role != nil && role.Email != nil && len(*role.Email) > 0 {
				emailsForDomainCandidates = append(emailsForDomainCandidates, *role.Email...)
			}
		}
		domain = FindDomainFromEmail(emailsForDomainCandidates...)
	}

	adminC, techC, nocC, routingC := mapset.NewSet[string](), mapset.NewSet[string](), mapset.NewSet[string](), mapset.NewSet[string]()
	var abuseC string
	for _, role := range roles {
		if role == nil || role.RdapRoles == nil || role.NestingLevel > 1 {
			continue
		}
		if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ADMIN) {
			adminC.Add(role.NicHdl)
		}
		if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_TECH) {
			techC.Add(role.NicHdl)
		}
		if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_NOC) {
			nocC.Add(role.NicHdl)
		}
		if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ROUTING) {
			routingC.Add(role.NicHdl)
		}
		if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ABUSE) {
			// NestingLevel>1 is already skipped. First remaining abuse wins
			// (ARIN lists the dedicated abuse POC before a combined admin/tech).
			if abuseC == "" {
				abuseC = role.NicHdl
			}
		}
	}
	// Nested-under-registrant POCs are now in `roles` (NestingLevel 1). If a
	// registry still omits them there, fall back to nic-hdls copied onto the org.
	if abuseC == "" {
		for _, org := range orgs {
			if org != nil && org.AbuseC != nil && *org.AbuseC != "" {
				abuseC = *org.AbuseC
				break
			}
		}
	}
	addAllHandles(adminC, orgAdminCs(orgs))
	addAllHandles(techC, orgTechCs(orgs))
	addAllHandles(nocC, orgNocCs(orgs))
	addAllHandles(routingC, orgRoutingCs(orgs))

	var preferredOrg *string
	for _, org := range orgs {
		if org != nil && strings.HasPrefix(org.Organization, "ORG-") && org.NestingLevel == 1 {
			preferredOrg = &org.Organization
			break
		}
	}
	if preferredOrg == nil && len(orgs) > 0 && orgs[0].Organization != "" {
		preferredOrg = &orgs[0].Organization
	}

	lastModified, created := FindEntityDates(respData.Events)
	status := strings.Join(respData.Status, ",")
	metaAddedAt := time.Now()
	asnInfo := &whoisdb.WhoisAutNum{
		AutNum:       asNumber,
		ASName:       respData.Name,
		Org:          preferredOrg,
		Status:       oputils.NilIfEmpty(status),
		AdminC:       oputils.NilIfSliceEmpty(adminC.ToSlice()),
		TechC:        oputils.NilIfSliceEmpty(techC.ToSlice()),
		AbuseC:       oputils.NilIfEmpty(abuseC),
		NocC:         oputils.NilIfSliceEmpty(nocC.ToSlice()),
		RoutingC:     oputils.NilIfSliceEmpty(routingC.ToSlice()),
		Remarks:      RdapRemarks2RemarksStringSlice(respData.Remarks),
		Descr:        RdapRemarks2DescriptionStringSlice(respData.Remarks),
		Created:      created,
		LastModified: lastModified,
		Source:       oputils.NilIfEmpty(source),
		CountryCode:  oputils.NilIfEmpty(countryCode),
		Country:      oputils.NilIfEmpty(country),
		Domain:       domain,
		MetaAddedAt:  &metaAddedAt,
	}
	return asnInfo, roles, orgs
}

// stampRDAPFetch marks the autnum and every related role/org as observed via
// live RDAP. Bulk dump ingest does not call this; upsert COALESCE then keeps
// any previously stored fetch_method.
func stampRDAPFetch(autnum *whoisdb.WhoisAutNum, roles []*whoisdb.WhoisRole, orgs []*whoisdb.WhoisOrganization) {
	autnum.StampFetch(whoisdb.FetchMethodRDAP)
	for _, r := range roles {
		r.StampFetch(whoisdb.FetchMethodRDAP)
	}
	for _, o := range orgs {
		o.StampFetch(whoisdb.FetchMethodRDAP)
	}
}

func addAllHandles(dst mapset.Set[string], src *[]string) {
	if dst == nil || src == nil || dst.Cardinality() > 0 {
		return
	}
	for _, h := range *src {
		if h != "" {
			dst.Add(h)
		}
	}
}

func orgAdminCs(orgs []*whoisdb.WhoisOrganization) *[]string {
	for _, org := range orgs {
		if org != nil && org.AdminC != nil && len(*org.AdminC) > 0 {
			return org.AdminC
		}
	}
	return nil
}

func orgTechCs(orgs []*whoisdb.WhoisOrganization) *[]string {
	for _, org := range orgs {
		if org != nil && org.TechC != nil && len(*org.TechC) > 0 {
			return org.TechC
		}
	}
	return nil
}

func orgNocCs(orgs []*whoisdb.WhoisOrganization) *[]string {
	for _, org := range orgs {
		if org != nil && org.NocC != nil && len(*org.NocC) > 0 {
			return org.NocC
		}
	}
	return nil
}

func orgRoutingCs(orgs []*whoisdb.WhoisOrganization) *[]string {
	for _, org := range orgs {
		if org != nil && org.RoutingC != nil && len(*org.RoutingC) > 0 {
			return org.RoutingC
		}
	}
	return nil
}

func rdapFirstHTTP(resp *rdap.Response) *http.Response {
	if resp == nil || len(resp.HTTP) == 0 || resp.HTTP[0] == nil {
		return nil
	}
	return resp.HTTP[0].Response
}

// retryAfterFromResponse reads Retry-After (delta-seconds or HTTP-date).
// Zero means "no header / unparseable" — crawl.Worker then uses 30s<<failures
// capped at 1h. The limiter may already have paused until this instant; we
// still return it so crawl_target.next_retry_at keeps other workers away.
func retryAfterFromResponse(httpResp *http.Response) time.Duration {
	if httpResp == nil {
		return 0
	}
	return parseRetryAfter(httpResp.Header.Get("Retry-After"))
}

func intPtr(v int) *int {
	return &v
}

// ProcessAutnum runs the RDAP autnum handler for a single ASN (used by rdapcli).
func (aggr *RegistryAggregator) ProcessAutnum(ctx context.Context, worker *RegistryWorker, asNumber uint32) crawl.Result {
	t := &postgres.CrawlTarget{
		Kind:     postgres.CrawlKindAutnum,
		Key:      strconv.FormatUint(uint64(asNumber), 10),
		Registry: worker.Name,
	}
	return autnumHandler{aggr: aggr, worker: worker}.Process(ctx, t)
}
