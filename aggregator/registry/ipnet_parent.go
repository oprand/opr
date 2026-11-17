package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

// ipnet parent-walk keys are handle:dN:H.
//
// A successful CIDR persist enqueues the first parent at d0. A successful
// handle:dK persist may enqueue d(K+1) while K+1 <= postgres.IpnetParentHandleMaxDepth
// (5). Cap 5 is O(1) extra jobs per seed CIDR, not a graph walk. cidr0
// prefixes are never enqueued as children.
const (
	rirSearch1Conformance    = "rirSearch1"
	ipnetHandleDepthPrefix   = "d"
	ipnetParentDepthFromCIDR = 0
)

func (w *RegistryWorker) rirSearch1State() (supported, known bool) {
	if w == nil {
		return false, false
	}
	w.rirSearchMu.Lock()
	defer w.rirSearchMu.Unlock()
	return w.rirSearch1, w.rirSearchProbed
}

func (w *RegistryWorker) setRIRSearch1(ok bool) {
	if w == nil {
		return
	}
	w.rirSearchMu.Lock()
	defer w.rirSearchMu.Unlock()
	w.rirSearchProbed = true
	w.rirSearch1 = ok
}

// rirSearchProbeBase is this RIR's own RDAP help URL host. LACNIC probes
// lacnic.net, not registro.br — country is empty and must stay empty.
func (h ipnetHandler) rirSearchProbeBase() string {
	if h.rdapBaseOverride != "" {
		return h.rdapBaseOverride
	}
	return nro.RDAPBaseURL(h.workerName())
}

// supportsRIRSearch1 is the cached rirSearch1 probe. A failed GET does not
// cache, so the next persist can retry. Cached false means this RIR will
// never resolve ips?handle=.
func (h ipnetHandler) supportsRIRSearch1(ctx context.Context) bool {
	if supported, known := h.worker.rirSearch1State(); known {
		return supported
	}
	return h.probeAndCacheRIRSearch1(ctx)
}

func (h ipnetHandler) probeAndCacheRIRSearch1(ctx context.Context) bool {
	ok, err := h.probeRIRSearch1(ctx)
	if err != nil {
		return false
	}
	h.worker.setRIRSearch1(ok)
	return ok
}

func (h ipnetHandler) probeRIRSearch1(ctx context.Context) (bool, error) {
	base := h.rirSearchProbeBase()
	if strings.TrimSpace(base) == "" {
		return false, nil
	}
	if h.aggr == nil {
		return false, fmt.Errorf("nil aggregator for rirSearch1 probe")
	}

	req := applyRDAPServer(rdap.NewHelpRequest(), base)
	rdapResp, _, err := h.aggr.doRDAPRequest(ctx, h.worker, req)
	httpResp := rdapFirstHTTP(rdapResp)
	if httpResp == nil {
		if err != nil {
			return false, err
		}
		return false, fmt.Errorf("no http response for rirSearch1 probe")
	}
	if httpResp.StatusCode != 200 {
		return false, nil
	}
	return rdapResponseHasRIRSearch1(rdapResp), nil
}

func rdapResponseHasRIRSearch1(resp *rdap.Response) bool {
	if resp == nil {
		return false
	}
	if conformanceHasRIRSearch1(rdapConformance(resp.Object)) {
		return true
	}
	return conformanceHasRIRSearch1(rdapConformanceFromBody(resp))
}

func rdapConformance(obj any) []string {
	switch o := obj.(type) {
	case *rdap.Help:
		if o != nil {
			return o.Conformance
		}
	case *rdap.IPNetwork:
		if o != nil {
			return o.Conformance
		}
	case *rdap.Autnum:
		if o != nil {
			return o.Conformance
		}
	}
	return nil
}

func rdapConformanceFromBody(resp *rdap.Response) []string {
	body := rdapHTTPBody(resp)
	if len(body) == 0 {
		return nil
	}
	var env struct {
		Conformance []string `json:"rdapConformance"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	return env.Conformance
}

func conformanceHasRIRSearch1(conf []string) bool {
	for _, c := range conf {
		if strings.EqualFold(strings.TrimSpace(c), rirSearch1Conformance) {
			return true
		}
	}
	return false
}

func rdapHTTPBody(resp *rdap.Response) []byte {
	if resp == nil || len(resp.HTTP) == 0 || resp.HTTP[0] == nil {
		return nil
	}
	return resp.HTTP[0].Body
}

// parseIpnetHandleKey reads handle:dN:H. The prefix is case-insensitive; N
// is a non-negative hop index; H is the remainder (may contain colons).
func parseIpnetHandleKey(key string) (depth int, handle string, ok bool) {
	key = strings.TrimSpace(key)
	if !isIpnetHandleKey(key) {
		return 0, "", false
	}
	rest := key[len(ipnetHandlePrefix):]
	if len(rest) < 3 || !strings.EqualFold(rest[:1], ipnetHandleDepthPrefix) {
		return 0, "", false
	}
	colon := strings.IndexByte(rest, ':')
	if colon < 2 {
		return 0, "", false
	}
	n, err := strconv.Atoi(rest[1:colon])
	if err != nil || n < 0 {
		return 0, "", false
	}
	handle = strings.TrimSpace(rest[colon+1:])
	if handle == "" {
		return 0, "", false
	}
	return n, handle, true
}

// nextParentEnqueueDepth is d0 for a CIDR job and d(K+1) for handle:dK,
// refused when the next hop would exceed the cap.
func nextParentEnqueueDepth(jobDepth int, fromHandle bool) (int, bool) {
	if !fromHandle {
		return ipnetParentDepthFromCIDR, true
	}
	next := jobDepth + 1
	if next > postgres.IpnetParentHandleMaxDepth {
		return 0, false
	}
	return next, true
}

// shouldEnqueueIpnetParent is true when parentHandle is set. Assignment /
// reallocation status is the usual case; parentHandle alone is enough
// (ARIN puts "active" in status and the role in type). cidr0 siblings
// are not consulted — they are never child jobs.
func shouldEnqueueIpnetParent(resp *rdap.IPNetwork) bool {
	return resp != nil && strings.TrimSpace(resp.ParentHandle) != ""
}

func ipnetLooksLikeAssignmentOrReallocation(resp *rdap.IPNetwork) bool {
	if resp == nil {
		return false
	}
	if statusLooksLikeAssignmentOrReallocation(resp.Status) {
		return true
	}
	return typeLooksLikeAssignmentOrReallocation(resp.Type)
}

func statusLooksLikeAssignmentOrReallocation(status []string) bool {
	for _, s := range status {
		if typeLooksLikeAssignmentOrReallocation(s) {
			return true
		}
	}
	return false
}

func typeLooksLikeAssignmentOrReallocation(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	return strings.Contains(s, "assignment") ||
		strings.Contains(s, "reassignment") ||
		strings.Contains(s, "reallocation") ||
		s == "assigned"
}

func (h ipnetHandler) maybeEnqueueParent(ctx context.Context, logger *zap.Logger, registry string, resp *rdap.IPNetwork, jobDepth int, fromHandle bool) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if !shouldEnqueueIpnetParent(resp) {
		return
	}
	next, ok := nextParentEnqueueDepth(jobDepth, fromHandle)
	if !ok {
		return
	}
	if !h.supportsRIRSearch1(ctx) {
		return
	}
	parent := strings.TrimSpace(resp.ParentHandle)
	if err := h.enqueueParentHandle(ctx, registry, parent, next); err != nil {
		logger.Warn("enqueue ipnet parent handle failed",
			zap.String("parent_handle", parent),
			zap.Int("depth", next),
			zap.Error(err),
		)
	}
}

func (h ipnetHandler) enqueueParentHandle(ctx context.Context, registry, handle string, depth int) error {
	if h.enqueueOverride != nil {
		return h.enqueueOverride(ctx, registry, handle, depth)
	}
	if h.aggr == nil || h.aggr.Store == nil {
		return nil
	}
	return h.aggr.Store.EnqueueIpnetParentHandle(ctx, registry, handle, depth)
}

// ipnetHandleSearchRequest is RFC 9910 GET {base}/ips?handle=H.
func ipnetHandleSearchRequest(base, handle string) *rdap.Request {
	base = strings.TrimSpace(base)
	handle = strings.TrimSpace(handle)
	if base == "" || handle == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + "/ips")
	if err != nil || u == nil {
		return nil
	}
	q := u.Query()
	q.Set("handle", handle)
	u.RawQuery = q.Encode()
	return rdap.NewRawRequest(u)
}

// ipNetworkFromRDAPResponse accepts a bare IP network or an RFC 9910
// ipSearchResults envelope (decoded as Help by openrdap).
func ipNetworkFromRDAPResponse(resp *rdap.Response) *rdap.IPNetwork {
	if resp == nil {
		return nil
	}
	if n, ok := resp.Object.(*rdap.IPNetwork); ok && n != nil {
		return n
	}
	body := rdapHTTPBody(resp)
	if len(body) == 0 {
		return nil
	}
	var env struct {
		Results []json.RawMessage `json:"ipSearchResults"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Results) == 0 {
		return nil
	}
	obj, err := rdap.NewDecoder(env.Results[0]).Decode()
	if err != nil {
		return nil
	}
	n, _ := obj.(*rdap.IPNetwork)
	return n
}
