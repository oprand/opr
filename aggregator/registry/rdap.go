package registry

import (
	"context"
	"fmt"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/internal/opconst"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/pkg/openrdap/rdap"

	mapset "github.com/deckarep/golang-set/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// RdapEntities2WhoisRoles will recursively loop on all entities
// and return a slice of whois roles.
// callNb is the current call number to avoid infinite loops.
//
// ARIN (and similar) nests abuse/admin/tech POCs under the registrant org
// rather than as siblings of it:
//
//	autnum.entities[0]  roles=["registrant"]   → WhoisOrganization (not a role)
//	  └─ entities[]     roles=["abuse", ...]   → WhoisRole, NestingLevel==1
//
// We skip the registrant as a role (RdapEntities2WhoisOrgs saves it as an org)
// but still recurse into entity.Entities. The skipped registrant is NOT counted
// in NestingLevel, so those nested POCs come back at the same level as a
// top-level role. persistAutnum / mapAutnumFromRDAP then skip NestingLevel>1
// (true nested-under-role contacts) while still linking registrant-nested
// abuse onto the autnum.
func (aggr *RegistryAggregator) RdapEntities2WhoisRoles(entities *[]rdap.Entity, parent *whoisdb.WhoisRole, rootObjectSource *string, callNb int) []*whoisdb.WhoisRole {

	roles := []*whoisdb.WhoisRole{}

	callNb += 1
	// Stop at 5 level of recursion
	if entities == nil || callNb >= 5 {
		return roles
	}

	for _, entity := range *entities {

		if len(entity.Roles) == 0 {
			continue
		}
		// Registrant is an org, not a role — but its nested POCs are roles.
		// Pass callNb-1 so the recursive increment yields NestingLevel==callNb
		// for those children (same as a sibling non-registrant at this level).
		if slices.Contains(entity.Roles, opconst.RDAP_ROLE_REGISTRANT) {
			if len(entity.Entities) > 0 {
				roles = append(roles, aggr.RdapEntities2WhoisRoles(&entity.Entities, parent, rootObjectSource, callNb-1)...)
			}
			continue
		}

		metaAddedAt := time.Now()
		modified, created := FindEntityDates(entity.Events)
		source, err := nro.FindRegistryByURL(FindSelfLink(entity.Links))
		if err != nil && rootObjectSource != nil {
			source = *rootObjectSource
		}
		kinds := []string{}
		kinds = append(kinds, entity.Roles...)

		role := whoisdb.WhoisRole{
			NicHdl:       entity.Handle,
			RdapRoles:    oputils.NilIfSliceEmpty(kinds),
			Remarks:      RdapRemarks2RemarksStringSlice(entity.Remarks),
			LastModified: modified,
			Created:      created,
			MetaAddedAt:  &metaAddedAt,
			Source:       oputils.NilIfEmpty(source),
			NestingLevel: callNb,
		}
		if entity.VCard != nil {
			var rdapKind string
			if entity.VCard.GetFirst("kind") != nil && len(entity.VCard.GetFirst("kind").Values()) > 0 {
				rdapKind = entity.VCard.GetFirst("kind").Values()[0]
			}
			role.RdapKind = oputils.NilIfEmpty(rdapKind)
			role.Role = oputils.NilIfEmpty(entity.VCard.Name())
			role.Country = oputils.NilIfEmpty(entity.VCard.Country())
			role.CountryCode = FindCountryCodeFromCountryName(entity.VCard.Country())
			role.Address = FindVCardAddress(entity.VCard)
			phones := entity.VCard.Get("tel")
			phoneSet := mapset.NewSet[string]()
			for _, phone := range phones {
				if phone != nil {
					e := strings.Join(phone.Values(), ",")
					phoneSet.Add(e)
				}
			}
			role.Phone = oputils.NilIfSliceEmpty(phoneSet.ToSlice())
			emails := entity.VCard.Get("email")
			emailSet := mapset.NewSet[string]()
			for _, email := range emails {
				if email != nil {
					e := strings.Join(email.Values(), ",")
					emailSet.Add(e)
				}
			}
			role.Email = oputils.NilIfSliceEmpty(emailSet.ToSlice())
			role.FaxNo = oputils.NilSliceIfStringEmpty(entity.VCard.Fax())
			role.Domain = FindDomainFromEmail(entity.VCard.Email())
			// RDAP vCard has email, not a separate abuse-mailbox attribute
			// (WHOIS dumps do). For an abuse POC the vCard email *is* the
			// abuse mailbox; keep Email as well so domain extraction and
			// generic contact lookup still work.
			if slices.Contains(entity.Roles, opconst.RDAP_ROLE_ABUSE) && role.Email != nil {
				copied := append([]string(nil), *role.Email...)
				role.AbuseMailbox = &copied
			}
		}

		// If country info not found yet, try from addresses
		if role.Country == nil && role.Address != nil && len(*role.Address) > 0 {
			addr := strings.Join(*role.Address, "\n")
			name, code, err := FindCountryInfoFromAddresses(&addr)
			if err == nil {
				role.Country = &name
				role.CountryCode = &code
			}
		}

		if parent != nil {
			for _, kind := range kinds {
				if kind == opconst.RDAP_ROLE_TECH {
					if parent.TechC == nil {
						parent.TechC = &[]string{role.NicHdl}
					} else {
						a := append(*parent.TechC, role.NicHdl)
						parent.TechC = &a
					}
				}
				if kind == opconst.RDAP_ROLE_ADMIN {
					if parent.AdminC == nil {
						parent.AdminC = &[]string{role.NicHdl}
					} else {
						a := append(*parent.AdminC, role.NicHdl)
						parent.AdminC = &a
					}
				}
			}
		}

		roles = append(roles, &role)

		// Find nested entities
		if len(entity.Entities) > 0 {
			// NOTE: If a role has a nested org (i.e. a registrant nested *under a
			//       role*), it still won't be returned here — registrants are
			//       skipped as roles. RdapEntities2WhoisOrgs walks top-level
			//       registrants. A nested-registrant-under-role is left as a
			//       TODO unless a fixture proves we need it (AS15169 does not).
			roles = append(roles, aggr.RdapEntities2WhoisRoles(&entity.Entities, &role, rootObjectSource, callNb)...)
			// add source if not already set
			for _, r := range roles {
				if r.Source == nil {
					if source != "" {
						r.Source = oputils.NilIfEmpty(source)
					} else {
						r.Source = rootObjectSource
					}
				}
			}
			// Callers (persistAutnum / mapAutnumFromRDAP, route persist)
			// SaveWhoisRole on the returned slice. Do not flush mid-recursion
			// — that double-wrote the same rows on the autnum path.
		}

	}

	return roles

}

// RdapEntities2WhoisOrgs will recursively loop on all entities
// and return a slice of whois organizations.
// Second argument is the current call number to avoid infinite loops.
// Any entites with a registrant role will be returned as an org.
func (aggr *RegistryAggregator) RdapEntities2WhoisOrgs(entities *[]rdap.Entity, rootObjectSource *string, callNb int) []*whoisdb.WhoisOrganization {

	orgs := []*whoisdb.WhoisOrganization{}

	callNb += 1
	// Stop at 5 level of recursion
	if entities == nil || callNb >= 5 {
		return orgs
	}

	for _, entity := range *entities {

		// only save registrant roles as org
		if len(entity.Roles) == 0 {
			continue
		} else if !slices.Contains(entity.Roles, opconst.RDAP_ROLE_REGISTRANT) {
			continue
		}

		metaAddedAt := time.Now()
		lastModified, created := FindEntityDates(entity.Events)
		source, _ := nro.FindRegistryByURL(FindSelfLink(entity.Links))
		if source == "" && rootObjectSource != nil {
			source = *rootObjectSource
		}
		if source == "" {
			aggr.Logger.Error("cannot find source for entity, not saving", zap.String("handle", entity.Handle), zap.Any("links", entity.Links))
			continue
		}
		org := whoisdb.WhoisOrganization{
			Organization: entity.Handle,
			OrgName:      oputils.NilIfEmpty(entity.VCard.Name()),
			OrgType:      oputils.NilIfEmpty(strings.Join(entity.VCard.GetFirst("kind").Values(), ",")),
			Remarks:      RdapRemarks2RemarksStringSlice(entity.Remarks),
			Descr:        RdapRemarks2DescriptionStringSlice(entity.Remarks),
			LastModified: lastModified,
			Created:      created,
			Source:       oputils.NilIfEmpty(source),
			MetaAddedAt:  &metaAddedAt,
			NestingLevel: callNb,
		}
		if entity.VCard != nil {
			org.Country = oputils.NilIfEmpty(entity.VCard.Country())
			org.CountryCode = FindCountryCodeFromCountryName(entity.VCard.Country())
			org.Address = FindVCardAddress(entity.VCard)
			org.Phone = oputils.NilSliceIfStringEmpty(entity.VCard.Tel())
			org.Email = oputils.NilSliceIfStringEmpty(entity.VCard.Email())
			org.FaxNo = oputils.NilSliceIfStringEmpty(entity.VCard.Fax())
			org.Domain = FindDomainFromEmail(entity.VCard.Email())
		}

		// If country info not found yet, try from addresses
		if org.Country == nil && org.Address != nil && len(*org.Address) > 0 {
			addr := strings.Join(*org.Address, "\n")
			name, code, err := FindCountryInfoFromAddresses(&addr)
			if err == nil {
				org.Country = &name
				org.CountryCode = &code
			}
		}

		// Find nested entities. Nested POCs are also returned by
		// RdapEntities2WhoisRoles (registrant skip+recurse) and persisted by
		// the caller; here we only copy their nic-hdls onto the org.
		if len(entity.Entities) > 0 {
			roles := aggr.RdapEntities2WhoisRoles(&entity.Entities, nil, &source, callNb)

			for _, role := range roles {
				if role == nil || role.RdapRoles == nil {
					continue
				}
				if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_TECH) {
					if org.TechC == nil {
						org.TechC = &[]string{role.NicHdl}
					} else {
						a := append(*org.TechC, role.NicHdl)
						org.TechC = &a
					}
				}
				if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ADMIN) {
					if org.AdminC == nil {
						org.AdminC = &[]string{role.NicHdl}
					} else {
						a := append(*org.AdminC, role.NicHdl)
						org.AdminC = &a
					}
				}
				if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_NOC) {
					if org.NocC == nil {
						org.NocC = &[]string{role.NicHdl}
					} else {
						a := append(*org.NocC, role.NicHdl)
						org.NocC = &a
					}
				}
				if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ROUTING) {
					if org.RoutingC == nil {
						org.RoutingC = &[]string{role.NicHdl}
					} else {
						a := append(*org.RoutingC, role.NicHdl)
						org.RoutingC = &a
					}
				}
				if slices.Contains(*role.RdapRoles, opconst.RDAP_ROLE_ABUSE) {
					if org.AbuseC == nil {
						org.AbuseC = &role.NicHdl
					}
				}
			}
		}

		orgs = append(orgs, &org)

	}

	return orgs

}

func (aggr *RegistryAggregator) doRDAPRequest(ctx context.Context, regWorker *RegistryWorker, req *rdap.Request) (*rdap.Response, bool, error) {

	if ctx == nil {
		ctx = context.Background()
	}

	logger := zap.NewNop()
	if aggr != nil && aggr.Logger != nil {
		logger = aggr.Logger
	}
	regName := ""
	if regWorker != nil {
		regName = regWorker.Name
	}
	logger = logger.With(
		zap.String("registry", regName),
		zap.String("type", req.Type.String()),
		zap.String("query", req.Query),
	)

	// Pin the destination before Wait so AIMD follows the host we intend to hit.
	// If the handler already set Server (BR → registro.br, or 404 fallback →
	// lacnic.net), keep it. Otherwise look up country from the crawl key (ASN
	// or CIDR) so ipnet fetches get NIC.br without a second seam.
	if req.Server == nil {
		if base := aggr.resolveRDAPBase(ctx, regName, req); base != "" {
			if u, err := url.Parse(base); err == nil {
				req = req.WithServer(u)
			} else {
				logger.Warn("could not parse rdap base url", zap.String("base_url", base), zap.Error(err))
			}
		}
	}
	if req.Server != nil {
		logger = logger.With(zap.String("rdap_host", req.Server.Hostname()))
	}

	lim := aggr.limiterForRDAP(regWorker, req.Server)

	// 1. Throttle on the destination host, independent of which proxy we use.
	//    A lacnic.net pause must not stall rdap.registro.br.
	if lim != nil {
		if err := lim.Wait(ctx); err != nil {
			logger.Warn("error while waiting for rate limiter, skipping", zap.Error(err))
			return nil, true, err
		}
	}

	// 2. Pick a long-lived transport from the pool. The proxy owns its own
	//    rdap.Client/Transport, so connections are reused and nothing shared is mutated.
	if regWorker == nil || regWorker.ProxyRing == nil {
		return nil, true, fmt.Errorf("no transport available for registry %s", regName)
	}
	proxy := regWorker.ProxyRing.GetNextProxy()
	if proxy == nil {
		return nil, true, fmt.Errorf("no transport available for registry %s", regName)
	}
	if proxy.URL != nil {
		logger = logger.With(zap.String("proxy", proxy.URL.Host))
	} else {
		logger = logger.With(zap.String("proxy", "direct"))
	}

	// 3. Query RDAP server using this proxy's own client.
	rdapResp, err := proxy.RdapClient.Do(req)
	logRDAPHTTPExchange(logger, rdapResp)
	if rdapResp == nil || len(rdapResp.HTTP) == 0 {
		logger.Warn("no http response received, trying again", zap.Error(err))
		return rdapResp, true, nil
	}

	// Check if the error is a timeout error
	if os.IsTimeout(err) {
		logger.Warn("request timed out", zap.Error(err))
		return rdapResp, true, err
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		logger.Warn("network timeout error", zap.Error(err))
		return rdapResp, true, err
	}

	httpResp := rdapResp.HTTP[0].Response
	if httpResp == nil {
		logger.Warn("nil http response received, trying again")
		return rdapResp, true, nil
	}
	logger = logger.With(zap.Stringer("url", httpResp.Request.URL), zap.Int("status_code", httpResp.StatusCode))

	// 4. Adaptive reaction on the intended host. shouldRetry is false on
	//    429/403 so the caller (autnumHandler) returns OutcomeRetry instead of
	//    spinning in this process.
	switch {
	case httpResp.StatusCode == http.StatusTooManyRequests || httpResp.StatusCode == http.StatusForbidden:
		retryAfter := parseRetryAfter(httpResp.Header.Get("Retry-After"))
		if lim != nil {
			lim.OnThrottle(retryAfter)
		}
		rate := 0.0
		if lim != nil {
			rate = lim.CurrentRate()
		}
		logger.Warn("throttled by rir, decreasing rate",
			zap.Duration("retry_after", retryAfter),
			zap.Float64("new_rate_rps", rate))
		return rdapResp, false, nil
	case httpResp.StatusCode != http.StatusOK:
		logger.Warn("non-200 status code from rdap endpoint, skipping")
		return rdapResp, false, nil
	}

	// 5.1. check for error now
	if err != nil {
		return rdapResp, true, err
	}

	// 6. Success: additively increase the rate toward the server's real ceiling.
	if lim != nil {
		lim.OnSuccess()
	}

	return rdapResp, false, nil

}

// resolveRDAPBase picks req.Server from the live NRO country lookup. LACNIC+BR
// → registro.br; empty country → parent RIR (lacnic.net).
func (aggr *RegistryAggregator) resolveRDAPBase(ctx context.Context, registry string, req *rdap.Request) string {
	country := aggr.countryForRDAPRequest(ctx, req)
	return nro.RDAPBaseURLFor(registry, country)
}

// rdapBasesForCrawl is the primary RDAP URL plus an optional parent-RIR
// fallback used after a NIC.br 404 (mis-tagged BR). Non-BR LACNIC has no
// fallback so a real miss still goes gone on the first 404.
func rdapBasesForCrawl(registry, country string) (primary, fallback string) {
	primary = nro.RDAPBaseURLFor(registry, country)
	if nro.HostIsRegistroBR(primary) {
		fallback = nro.RDAPBaseURL(opconst.LACNIC)
	}
	return primary, fallback
}

func (aggr *RegistryAggregator) countryForRDAPRequest(ctx context.Context, req *rdap.Request) string {
	if aggr == nil || aggr.Resolver == nil || req == nil {
		return ""
	}
	switch req.Type {
	case rdap.AutnumRequest:
		n, err := strconv.ParseUint(strings.TrimSpace(req.Query), 10, 32)
		if err != nil {
			return ""
		}
		cc, err := aggr.Resolver.CountryForASN(ctx, uint32(n))
		if err != nil {
			return ""
		}
		return cc
	case rdap.IPRequest:
		ip := ipFromRDAPQuery(req.Query)
		if ip == nil {
			return ""
		}
		cc, err := aggr.Resolver.CountryForIP(ctx, ip)
		if err != nil {
			return ""
		}
		return cc
	}
	return ""
}

// ipFromRDAPQuery returns the network address of a CIDR, or a parsed IP.
func ipFromRDAPQuery(q string) net.IP {
	q = strings.TrimSpace(q)
	if _, ipnet, err := net.ParseCIDR(q); err == nil {
		return ipnet.IP
	}
	return net.ParseIP(q)
}

// parseRetryAfter parses a Retry-After header (RFC 9110):
//   - delta-seconds: integer number of seconds from now ("120")
//   - HTTP-date: IMF-fixdate / RFC850 / asctime; we return time.Until(t)
//     so a date in the past yields 0
//
// Returns 0 when the header is absent or unparseable. The crawl worker then
// uses 30s << consecutive_failures (cap 1h) for crawl_target.next_retry_at.
// The limiter still halves its rate on 429/403 even when this is 0; it only
// sets pausedUntil when retryAfter > 0.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// logRDAPHTTPExchange logs the actual network hop when the logger is at debug
// (--log-level debug / LOG_LEVEL=debug). Info/warn already record registry,
// type, query, proxy, URL, and status; this adds method, duration, and body
// size from rdapResp.HTTP[0] without dumping the body or secrets.
func logRDAPHTTPExchange(logger *zap.Logger, rdapResp *rdap.Response) {
	if logger == nil || !logger.Core().Enabled(zapcore.DebugLevel) {
		return
	}
	if rdapResp == nil || len(rdapResp.HTTP) == 0 || rdapResp.HTTP[0] == nil {
		logger.Debug("rdap http exchange: no hop recorded")
		return
	}
	hop := rdapResp.HTTP[0]
	fields := []zap.Field{
		zap.String("url", hop.URL),
		zap.Duration("duration", hop.Duration),
		zap.Int("body_bytes", len(hop.Body)),
	}
	if hop.Response != nil {
		fields = append(fields, zap.Int("status_code", hop.Response.StatusCode))
		if req := hop.Response.Request; req != nil {
			fields = append(fields, zap.String("method", req.Method))
			if hop.URL == "" && req.URL != nil {
				fields[0] = zap.String("url", req.URL.String())
			}
		}
		if headers := safeRDAPResponseHeaders(hop.Response.Header); len(headers) > 0 {
			fields = append(fields, zap.Any("headers", headers))
		}
	}
	logger.Debug("rdap http exchange", fields...)
}

// hop-by-hop (RFC 9110) plus credentials. We may still log Content-Type and
// Retry-After because those explain status/duration without leaking secrets.
var rdapDebugSkipHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"TE":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func safeRDAPResponseHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if _, skip := rdapDebugSkipHeaders[http.CanonicalHeaderKey(k)]; skip {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
