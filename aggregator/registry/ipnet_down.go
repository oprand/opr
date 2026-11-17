package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

// One paginated RFC 9910 rdap-down after an ARIN persist. Immediate
// children only; do not recurse. Leaf assignments without a down link
// are skipped so empty downs on tens of thousands of /24s stay off.
const (
	rdapDownRel       = "rdap-down"
	rdapNextRel       = "next"
	ipnetDownMaxPages = 32
)

func isARINIpnetRegistry(registry, worker string) bool {
	r := strings.TrimSpace(registry)
	if r != "" {
		return strings.EqualFold(r, opconst.ARIN)
	}
	return strings.EqualFold(strings.TrimSpace(worker), opconst.ARIN)
}

// shouldDownIpnet is true when the object can have children: a
// rel=rdap-down (or RFC 9910 down href) is present, or status/type
// looks like an allocation. Assignment/reallocation without a down
// link is a leaf and must not extra-GET.
func shouldDownIpnet(resp *rdap.IPNetwork) bool {
	if resp == nil {
		return false
	}
	if ipnetRDAPDownHref(resp) != "" {
		return true
	}
	if ipnetLooksLikeAssignmentOrReallocation(resp) {
		return false
	}
	return ipnetLooksLikeAllocation(resp)
}

func ipnetLooksLikeAllocation(resp *rdap.IPNetwork) bool {
	if resp == nil {
		return false
	}
	if typeLooksLikeAllocation(resp.Type) {
		return true
	}
	for _, s := range resp.Status {
		if typeLooksLikeAllocation(s) {
			return true
		}
	}
	return false
}

func typeLooksLikeAllocation(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	if strings.Contains(s, "reallocation") || strings.Contains(s, "reassignment") {
		return false
	}
	return strings.Contains(s, "allocation") || s == "allocated"
}

func rdapLinkHref(links []rdap.Link, rel string) string {
	for _, l := range links {
		if !strings.EqualFold(strings.TrimSpace(l.Rel), rel) {
			continue
		}
		if href := strings.TrimSpace(l.Href); href != "" {
			return href
		}
	}
	return ""
}

func ipnetRDAPDownHref(resp *rdap.IPNetwork) string {
	if resp == nil {
		return ""
	}
	if href := rdapLinkHref(resp.Links, rdapDownRel); href != "" {
		return href
	}
	for _, l := range resp.Links {
		href := strings.TrimSpace(l.Href)
		if href != "" && strings.Contains(strings.ToLower(href), "/ips/rirsearch1/rdap-down") {
			return href
		}
	}
	return ""
}

func ipnetObjectCIDR(queried string, resp *rdap.IPNetwork) string {
	prefs := ipnetPrefixesFromRDAP(queried, resp)
	if len(prefs) == 0 {
		return strings.TrimSpace(queried)
	}
	return prefs[0].String()
}

func ipnetConstructRDAPDownURL(base, cidr string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	n := parseIPNet(cidr)
	if base == "" || n == nil {
		return ""
	}
	ones, bits := n.Mask.Size()
	if ones < 0 || bits == 0 {
		return ""
	}
	return base + "/ips/rirSearch1/rdap-down/" + n.IP.String() + "/" + strconv.Itoa(ones)
}

func ipnetParentCIDRSet(queried string, resp *rdap.IPNetwork) map[string]struct{} {
	set := make(map[string]struct{})
	for _, p := range ipnetPrefixesFromRDAP(queried, resp) {
		set[p.String()] = struct{}{}
	}
	if q := parseIPNet(queried); q != nil {
		set[q.String()] = struct{}{}
	}
	return set
}

// ipnetDownChildKey is the crawl_target key for one down child: the
// first canonical CIDR that is not this object's cidr0, else handle:d0:H.
func ipnetDownChildKey(child *rdap.IPNetwork, parentCIDRs map[string]struct{}) string {
	if child == nil {
		return ""
	}
	for _, p := range ipnetPrefixesFromRDAP("", child) {
		k := p.String()
		if _, skip := parentCIDRs[k]; skip {
			continue
		}
		return k
	}
	handle := strings.TrimSpace(child.Handle)
	if handle == "" {
		return ""
	}
	return postgres.IpnetParentHandleKey(handle, ipnetParentDepthFromCIDR)
}

func ipnetIsFullNetwork(n *rdap.IPNetwork) bool {
	if n == nil {
		return false
	}
	if len(n.CIDR0Cidrs) > 0 {
		return true
	}
	return strings.TrimSpace(n.StartAddress) != ""
}

type rdapIPSearchEnvelope struct {
	Results []json.RawMessage `json:"ipSearchResults"`
	Links   []rdap.Link       `json:"links"`
}

func parseRDAPIPSearch(resp *rdap.Response) (children []*rdap.IPNetwork, next string) {
	body := rdapHTTPBody(resp)
	if len(body) == 0 {
		return nil, ""
	}
	var env rdapIPSearchEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, ""
	}
	for _, raw := range env.Results {
		obj, err := rdap.NewDecoder(raw).Decode()
		if err != nil {
			continue
		}
		n, _ := obj.(*rdap.IPNetwork)
		if n != nil {
			children = append(children, n)
		}
	}
	return children, rdapLinkHref(env.Links, rdapNextRel)
}

func resolveRDAPNext(current, next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		return next
	}
	base, err := url.Parse(strings.TrimSpace(current))
	if err != nil || base == nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func (h ipnetHandler) maybeEnqueueDown(ctx context.Context, logger *zap.Logger, registry, queried string, resp *rdap.IPNetwork) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if !isARINIpnetRegistry(registry, h.workerName()) {
		return
	}
	if !shouldDownIpnet(resp) {
		return
	}
	if !h.supportsRIRSearch1(ctx) {
		return
	}

	downURL := ipnetRDAPDownHref(resp)
	if downURL == "" {
		downURL = ipnetConstructRDAPDownURL(h.rirSearchProbeBase(), ipnetObjectCIDR(queried, resp))
	}
	if downURL == "" {
		return
	}

	enqueueReg := strings.TrimSpace(registry)
	if enqueueReg == "" {
		enqueueReg = opconst.ARIN
	}

	parentCIDRs := ipnetParentCIDRSet(queried, resp)
	seenKeys := map[string]struct{}{}
	pages := 0
	enqueued := 0
	for downURL != "" {
		pages++
		if pages > ipnetDownMaxPages {
			logger.Warn("rdap-down page cap reached",
				zap.Int("pages", pages-1),
				zap.Int("children", enqueued),
			)
			break
		}

		rdapResp, res, ok := h.fetchRDAPDown(ctx, logger, downURL)
		if !ok {
			logger.Warn("rdap-down fetch failed",
				zap.String("url", downURL),
				zap.Error(res.Err),
			)
			return
		}

		pageChildren, next := parseRDAPIPSearch(rdapResp)
		for _, child := range pageChildren {
			key := ipnetDownChildKey(child, parentCIDRs)
			if key == "" {
				continue
			}
			if _, dup := seenKeys[key]; dup {
				continue
			}
			seenKeys[key] = struct{}{}
			if err := h.enqueueDownKey(ctx, enqueueReg, key); err != nil {
				logger.Warn("enqueue ipnet down cidr failed",
					zap.String("key", key),
					zap.Error(err),
				)
			} else {
				enqueued++
			}
			if ipnetIsFullNetwork(child) {
				if err := h.persistIpnetOrOverride(ctx, logger, "", enqueueReg, child); err != nil {
					logger.Warn("persist ipnet down child failed",
						zap.String("key", key),
						zap.Error(err),
					)
				}
			}
		}

		next = resolveRDAPNext(downURL, next)
		if next == "" || next == downURL {
			break
		}
		downURL = next
	}
	logger.Info("rdap-down complete",
		zap.Int("pages", pages),
		zap.Int("children", enqueued),
	)
}

func (h ipnetHandler) fetchRDAPDown(ctx context.Context, logger *zap.Logger, downURL string) (*rdap.Response, crawl.Result, bool) {
	u, err := url.Parse(strings.TrimSpace(downURL))
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
		return nil, crawl.Result{
			Outcome: crawl.OutcomeGone,
			Err:     fmt.Errorf("invalid rdap-down url %q", downURL),
		}, false
	}
	// RawRequest: Server is the full URL. Do not applyRDAPServer — that
	// would pin the host and drop the path.
	return h.tryRDAPRequest(ctx, logger, rdap.NewRawRequest(u), u)
}

func (h ipnetHandler) enqueueDownKey(ctx context.Context, registry, key string) error {
	if h.enqueueDownOverride != nil {
		return h.enqueueDownOverride(ctx, registry, key)
	}
	if h.aggr == nil || h.aggr.Store == nil {
		return nil
	}
	return h.aggr.Store.EnqueueIpnetDownCIDR(ctx, registry, key)
}
