package registry

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	mapset "github.com/deckarep/golang-set/v2"
)

// mapIpnetFromRDAP turns a decoded RDAP IP network into whoisdb inetnum/inet6num
// rows. Pure mapping: no Postgres, no StampFetch, no crawl_target writes.
// persistIpnet stamps RDAP then SaveWhois*.
//
// Prefixes: cidr0_cidrs are this object's netblocks (siblings, UNIQUE
// (netblock, source)). If cidr0 is empty, start/end (or the queried CIDR)
// become the single prefix. The CIDR matching queried (t.Key) is listed first.
// Never enqueue child crawl_target jobs for extra cidr0 prefixes.
func mapIpnetFromRDAP(aggr *RegistryAggregator, queried string, respData *rdap.IPNetwork, source, defaultSource string) ([]*whoisdb.WhoisInetNum, []*whoisdb.WhoisInet6Num, []*whoisdb.WhoisRole, []*whoisdb.WhoisOrganization) {
	if respData == nil {
		return nil, nil, nil, nil
	}
	if source == "" {
		source = defaultSource
	}

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
			if abuseC == "" {
				abuseC = role.NicHdl
			}
		}
	}
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
	geofeed := geofeedFromRDAP(respData)
	prefixes := ipnetPrefixesFromRDAP(queried, respData)
	metaAddedAt := time.Now()

	var inet4 []*whoisdb.WhoisInetNum
	var inet6 []*whoisdb.WhoisInet6Num
	for _, p := range prefixes {
		if p == nil {
			continue
		}
		start, end := ipnetBounds(p)
		if len(prefixes) == 1 {
			if sa := strings.TrimSpace(respData.StartAddress); sa != "" {
				start = sa
			}
			if ea := strings.TrimSpace(respData.EndAddress); ea != "" {
				end = ea
			}
		}
		cidr := p.String()
		nb := cloneIPNet(p)
		if ipnetIsV4(p) {
			inet4 = append(inet4, &whoisdb.WhoisInetNum{
				Inetnum:      cidr,
				Netname:      oputils.NilIfEmpty(respData.Name),
				Descr:        RdapRemarks2DescriptionStringSlice(respData.Remarks),
				CountryCode:  oputils.NilIfEmpty(countryCode),
				Geofeed:      oputils.NilIfEmpty(geofeed),
				Org:          preferredOrg,
				AdminC:       oputils.NilIfSliceEmpty(adminC.ToSlice()),
				TechC:        oputils.NilIfSliceEmpty(techC.ToSlice()),
				AbuseC:       oputils.NilIfEmpty(abuseC),
				NocC:         oputils.NilIfSliceEmpty(nocC.ToSlice()),
				RoutingC:     oputils.NilIfSliceEmpty(routingC.ToSlice()),
				Status:       oputils.NilIfEmpty(status),
				Type:         oputils.NilIfEmpty(respData.Type),
				Remarks:      RdapRemarks2RemarksStringSlice(respData.Remarks),
				LastModified: lastModified,
				Created:      created,
				Source:       oputils.NilIfEmpty(source),
				Netblock:     nb,
				StartAddr:    oputils.NilIfEmpty(start),
				EndAddr:      oputils.NilIfEmpty(end),
				Country:      oputils.NilIfEmpty(country),
				Domain:       domain,
				MetaAddedAt:  &metaAddedAt,
			})
			continue
		}
		inet6 = append(inet6, &whoisdb.WhoisInet6Num{
			Inet6num:     cidr,
			Netname:      oputils.NilIfEmpty(respData.Name),
			Descr:        RdapRemarks2DescriptionStringSlice(respData.Remarks),
			CountryCode:  oputils.NilIfEmpty(countryCode),
			Geofeed:      oputils.NilIfEmpty(geofeed),
			Org:          preferredOrg,
			AdminC:       oputils.NilIfSliceEmpty(adminC.ToSlice()),
			TechC:        oputils.NilIfSliceEmpty(techC.ToSlice()),
			AbuseC:       oputils.NilIfEmpty(abuseC),
			NocC:         oputils.NilIfSliceEmpty(nocC.ToSlice()),
			RoutingC:     oputils.NilIfSliceEmpty(routingC.ToSlice()),
			Status:       oputils.NilIfEmpty(status),
			Type:         oputils.NilIfEmpty(respData.Type),
			Remarks:      RdapRemarks2RemarksStringSlice(respData.Remarks),
			LastModified: lastModified,
			Created:      created,
			Source:       oputils.NilIfEmpty(source),
			Netblock:     nb,
			StartAddr:    oputils.NilIfEmpty(start),
			EndAddr:      oputils.NilIfEmpty(end),
			Country:      oputils.NilIfEmpty(country),
			Domain:       domain,
			MetaAddedAt:  &metaAddedAt,
		})
	}
	return inet4, inet6, roles, orgs
}

func stampIpnetRDAPFetch(inet4 []*whoisdb.WhoisInetNum, inet6 []*whoisdb.WhoisInet6Num, roles []*whoisdb.WhoisRole, orgs []*whoisdb.WhoisOrganization) {
	for _, n := range inet4 {
		n.StampFetch(whoisdb.FetchMethodRDAP)
	}
	for _, n := range inet6 {
		n.StampFetch(whoisdb.FetchMethodRDAP)
	}
	for _, r := range roles {
		r.StampFetch(whoisdb.FetchMethodRDAP)
	}
	for _, o := range orgs {
		o.StampFetch(whoisdb.FetchMethodRDAP)
	}
}

// ipnetPrefixesFromRDAP collects this object's prefixes. cidr0 wins when
// present (including cidr0-only objects). Otherwise start/end, else queried.
// Matching queried is moved to the front; extra cidr0 entries stay siblings.
func ipnetPrefixesFromRDAP(queried string, resp *rdap.IPNetwork) []*net.IPNet {
	var out []*net.IPNet
	seen := map[string]struct{}{}
	add := func(n *net.IPNet) {
		if n == nil {
			return
		}
		k := n.String()
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, n)
	}

	if resp != nil {
		for _, c := range resp.CIDR0Cidrs {
			add(cidr0ToIPNet(c))
		}
		if len(out) == 0 {
			add(rangeToIPNet(resp.StartAddress, resp.EndAddress))
		}
	}
	q := parseIPNet(queried)
	if len(out) == 0 {
		add(q)
	}
	if q != nil {
		want := q.String()
		for i, p := range out {
			if p.String() == want {
				if i > 0 {
					out[0], out[i] = out[i], out[0]
				}
				break
			}
		}
	}
	return out
}

func cidr0ToIPNet(c rdap.CIDR0Cidr) *net.IPNet {
	var base string
	switch {
	case strings.TrimSpace(c.V4Prefix) != "":
		base = strings.TrimSpace(c.V4Prefix)
	case strings.TrimSpace(c.V6Prefix) != "":
		base = strings.TrimSpace(c.V6Prefix)
	default:
		return nil
	}
	if strings.Contains(base, "/") {
		return parseIPNet(base)
	}
	if c.Length < 0 {
		return nil
	}
	return parseIPNet(fmt.Sprintf("%s/%d", base, c.Length))
}

func rangeToIPNet(start, end string) *net.IPNet {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" {
		return nil
	}
	if end == "" || start == end {
		if n := parseIPNet(start); n != nil {
			return n
		}
		ip := net.ParseIP(start)
		if ip == nil {
			return nil
		}
		if ip.To4() != nil {
			return parseIPNet(ip.String() + "/32")
		}
		return parseIPNet(ip.String() + "/128")
	}
	// Same shape as dump HandleInetNum: a single covering CIDR when the
	// start/end pair is one prefix. Non-contiguous ranges stay unmapped here
	// so cidr0 (or the queried key) can supply the real netblocks.
	dummy := &whoisdb.WhoisInetNum{}
	if ip := net.ParseIP(start); ip != nil && ip.To4() == nil {
		v6 := &whoisdb.WhoisInet6Num{}
		v6.HandleInet6Num("inet6num:" + start + " - " + end)
		return cloneIPNet(v6.Netblock)
	}
	dummy.HandleInetNum("inetnum:" + start + " - " + end)
	return cloneIPNet(dummy.Netblock)
}

func parseIPNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return n
}

func ipnetIsV4(n *net.IPNet) bool {
	return n != nil && n.IP.To4() != nil
}

func cloneIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	mask := make(net.IPMask, len(n.Mask))
	copy(mask, n.Mask)
	return &net.IPNet{IP: ip, Mask: mask}
}

func ipnetBounds(n *net.IPNet) (start, end string) {
	if n == nil {
		return "", ""
	}
	start = n.IP.String()
	if len(n.Mask) != len(n.IP) {
		return start, ""
	}
	last := make(net.IP, len(n.IP))
	for i := range n.IP {
		last[i] = n.IP[i] | ^n.Mask[i]
	}
	return start, last.String()
}

// geofeedFromRDAP reads RFC 9877 geofeed1 / rel=geofeed (and type
// application/geofeed+csv) from the IP network's links.
func geofeedFromRDAP(resp *rdap.IPNetwork) string {
	if resp == nil {
		return ""
	}
	if u := geofeedFromLinks(resp.Links); u != "" {
		return u
	}
	for _, r := range resp.Remarks {
		if u := geofeedFromLinks(r.Links); u != "" {
			return u
		}
	}
	return ""
}

func geofeedFromLinks(links []rdap.Link) string {
	for _, l := range links {
		rel := strings.ToLower(strings.TrimSpace(l.Rel))
		typ := strings.ToLower(strings.TrimSpace(l.Type))
		if (rel == "geofeed" || strings.Contains(typ, "geofeed")) && strings.TrimSpace(l.Href) != "" {
			if u := geofeeds.CanonicalizeURL(strings.TrimSpace(l.Href)); u != "" {
				return u
			}
		}
	}
	return ""
}

// catalogGeofeedURLs collects unique canonical geofeed URLs from mapped
// inetnum/inet6num rows for SaveGeofeeds. Empty/non-http values are dropped.
func catalogGeofeedURLs(inet4 []*whoisdb.WhoisInetNum, inet6 []*whoisdb.WhoisInet6Num) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw *string) {
		if raw == nil {
			return
		}
		u := geofeeds.CanonicalizeURL(*raw)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	for _, r := range inet4 {
		if r != nil {
			add(r.Geofeed)
		}
	}
	for _, r := range inet6 {
		if r != nil {
			add(r.Geofeed)
		}
	}
	return out
}
