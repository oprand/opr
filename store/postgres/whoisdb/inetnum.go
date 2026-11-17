package whoisdb

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"

	"github.com/c-robinson/iplib"
)

type WhoisInetNum struct {
	// raw data points
	Inetnum      string     `db:"inetnum" json:"inetnum"`
	Netname      *string    `db:"netname" json:"netname"`
	Descr        *[]string  `db:"descr" json:"descr"`
	CountryCode  *string    `db:"country_code" json:"country_code"`
	Geofeed      *string    `db:"geofeed" json:"geofeed,omitempty"`
	Geoloc       *string    `db:"geoloc" json:"geoloc,omitempty"`
	Language     *[]string  `db:"language" json:"language,omitempty"`
	Org          *string    `db:"org" json:"org,omitempty"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c"`
	TechC        *[]string  `db:"tech_c" json:"tech_c"`
	AbuseC       *string    `db:"abuse_c" json:"abuse_c,omitempty"`
	NocC         *[]string  `db:"noc_c" json:"noc_c"`
	RoutingC     *[]string  `db:"routing_c" json:"routing_c"`
	Status       *string    `db:"status" json:"status"`
	Type         *string    `db:"type" json:"type"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	Notify       *[]string  `db:"notify" json:"notify,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by"`
	MntLower     *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	MntRoutes    *[]string  `db:"mnt_routes" json:"mnt_routes,omitempty"`
	MntIrt       *[]string  `db:"mnt_irt" json:"mnt_irt"`
	MntDomains   *[]string  `db:"mnt_domains" json:"mnt_domains"`
	Changed      *[]string  `db:"changed" json:"changed"`
	LastModified *time.Time `db:"last_modified" json:"last_modified"`
	Created      *time.Time `db:"created" json:"created"`
	Source       *string    `db:"source" json:"source"`
	// Only for LACNIC
	City *string `db:"city" json:"city"`
	// Expanded data points
	Netblock        *net.IPNet `db:"netblock" json:"netblock"`
	StartAddr       *string    `db:"start_addr" json:"start_addr"`
	EndAddr         *string    `db:"end_addr" json:"end_addr"`
	Country         *string    `db:"country" json:"country"`
	Domain          *string    `db:"domain" json:"domain"`
	GeolocLatitude  *float64   `db:"geoloc_lat" json:"geoloc_lat"`
	GeolocLongitude *float64   `db:"geoloc_lon" json:"geoloc_lon"`
	// Meta
	MetaAddedAt *time.Time `db:"meta_added_at" json:"meta_added_at"`
	// Freshness / provenance. Same six columns as whoisdb_autnum (migration 0064).
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
	// USed when fetching for building prefix tree
	OrgName *string `db:"org_name" json:"org_name"`
}

// StampFetch records that this inetnum was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisInetNum) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisInetNum) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeInetNum
}

func (w *WhoisInetNum) HandleMultiLine(prevItem string, line string) {
	switch prevItem {
	case "descr":
		w.HandleDescr(line)
	case "import":
		w.HandleImport(line)
	case "export":
		w.HandleExport(line)
	case "remarks":
		w.HandleRemarks(line)
	}
}

// normalizeIPv4CIDR expands abbreviated IPv4 prefixes used in LACNIC dumps
// (e.g. "2.152.0/22" → "2.152.0.0/22") so net.ParseCIDR can parse them.
// IPv6 and already-canonical IPv4 are returned unchanged.
func normalizeIPv4CIDR(cidr string) string {
	host, prefix, ok := strings.Cut(cidr, "/")
	if !ok || strings.Contains(host, ":") {
		return cidr
	}
	n := strings.Count(host, ".") + 1
	if n >= 4 {
		return cidr
	}
	return host + strings.Repeat(".0", 4-n) + "/" + prefix
}

func (w *WhoisInetNum) HandleInetNum(line string) {
	// fmt.Println(line)
	inetnum := strings.TrimSpace(strings.TrimPrefix(line, "inetnum:"))
	if inetnum != "" {
		w.Inetnum = inetnum
	}

	// find CIDR notation

	// Some RIR (like LACNIC) return CIDR notation and not
	// a range of IPs. LACNIC also abbreviates IPv4 (2.152.0/22).
	if strings.Contains(inetnum, "/") {
		_, ipnet, err := net.ParseCIDR(normalizeIPv4CIDR(inetnum))
		if err != nil {
			w.Netblock = nil
			return
		}
		w.Netblock = ipnet
		return
	}

	var ipv4From, ipv4To string
	_, err := fmt.Sscanf(inetnum, "%s - %s", &ipv4From, &ipv4To)
	if err != nil {
		w.Netblock = nil
		return
	}

	w.StartAddr = &ipv4From
	w.EndAddr = &ipv4To

	if ipv4From == "" || ipv4To == "" {
		w.Netblock = nil
		return
	}

	ipStart := net.ParseIP(ipv4From)
	ipEnd := net.ParseIP(ipv4To)
	if ipStart == nil || ipEnd == nil {
		w.Netblock = nil
		return
	} else if ipStart.IsUnspecified() || ipEnd.IsUnspecified() {
		w.Netblock = nil
		return
	}

	if ipStart.Equal(ipEnd) {
		_, ipnet, err := net.ParseCIDR(ipv4From + "/32")
		if err != nil {
			w.Netblock = nil
			return
		}
		w.Netblock = ipnet
		return
	}

	if iplib.NextIP(ipStart).Equal(ipEnd) {
		_, ipnet, err := net.ParseCIDR(ipv4From + "/31")
		if err != nil {
			w.Netblock = nil
			return
		}
		w.Netblock = ipnet
		return
	}

	netsub, ok, err := iplib.NewNetBetween(ipStart, ipEnd)
	if err != nil || !ok {
		w.Netblock = nil
		return
	}

	if netsub.String() == "" {
		w.Netblock = nil
		return
	}
	_, ipnet, err := net.ParseCIDR(netsub.String())
	if err != nil {
		w.Netblock = nil
		return
	}
	w.Netblock = ipnet
}

func (w *WhoisInetNum) HandleMntDomains(line string) {
	if w.MntDomains == nil {
		w.MntDomains = &[]string{}
	}
	*w.MntDomains = append(*w.MntDomains, strings.TrimSpace(strings.TrimPrefix(line, "mnt-domains:")))
}

func (w *WhoisInetNum) HandleChanged(line string) {
	changed := strings.TrimSpace(strings.TrimPrefix(line, "changed:"))
	if w.Changed == nil {
		w.Changed = &[]string{}
	}
	// if changed value is just a timestamp use it as last modified
	// LACNIC only shows changed, no last_modified
	if changed != "" {
		if !strings.Contains(changed, "T") {
			changed = changed + "T00:00:00Z"
		}
		parsedTime, err := time.Parse(time.RFC3339, changed)
		if err != nil {
			return
		} else {
			w.LastModified = &parsedTime
		}
	}

	*w.Changed = append(*w.Changed, changed)
}

func (w *WhoisInetNum) HandleNetName(line string) {
	netname := strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
	if netname != "" {
		w.Netname = &netname
	} else {
		w.Netname = nil
	}
}

func (w *WhoisInetNum) HandleDescr(line string) {
	// TODO: Extract country code from description
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if w.Descr == nil {
		w.Descr = &[]string{}
	}
	*w.Descr = append(*w.Descr, description)

	if description != "" {
		// Check if country code is in the description
		for cc, name := range opconst.CountryCode {
			if strings.EqualFold(description, name) {
				w.Country = &name
				w.CountryCode = &cc
				return
			}
		}
	}

}

func (w *WhoisInetNum) HandleCountryCode(line string) {
	countryCode := strings.TrimSpace(strings.TrimPrefix(line, "country:"))

	// Remove any comments
	if strings.Contains(countryCode, "#") {
		countryCode = countryCode[:strings.Index(countryCode, "#")]
		countryCode = strings.TrimSpace(countryCode)
	}

	countryCode = strings.ToUpper(countryCode)

	w.CountryCode = &countryCode
	country, ok := opconst.CountryCode[countryCode]
	if ok {
		w.Country = &country
	}

}

func (w *WhoisInetNum) HandleGeoloc(line string) {
	geoloc := strings.TrimSpace(strings.TrimPrefix(line, "geoloc:"))
	if geoloc != "" {
		w.Geoloc = &geoloc
		info := strings.Split(geoloc, " ")
		if len(info) >= 2 {
			lat, err := strconv.ParseFloat(strings.TrimSpace(info[0]), 64)
			if err == nil {
				w.GeolocLatitude = &lat
			}
			lon, err := strconv.ParseFloat(strings.TrimSpace(info[1]), 64)
			if err == nil {
				w.GeolocLongitude = &lon
			}
		}
	}
}

func (w *WhoisInetNum) HandleLanguage(line string) {
	language := strings.TrimSpace(strings.TrimPrefix(line, "language:"))
	if language != "" {
		if w.Language == nil {
			w.Language = &[]string{}
		}
		*w.Language = append(*w.Language, language)
	}
}

func (w *WhoisInetNum) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		w.Org = &org
	}
}

func (w *WhoisInetNum) HandleAdminC(line string) {
	adminC := strings.TrimSpace(strings.TrimPrefix(line, "admin-c:"))
	if adminC != "" {
		if strings.Contains(strings.ToLower(adminC), "dumy") {
			return
		}
		if w.AdminC == nil {
			w.AdminC = &[]string{}
		}
		*w.AdminC = append(*w.AdminC, adminC)
	}

}

func (w *WhoisInetNum) HandleTechC(line string) {
	techC := strings.TrimSpace(strings.TrimPrefix(line, "tech-c:"))
	if techC != "" {
		if strings.Contains(strings.ToLower(techC), "dumy") {
			return
		}
		if w.TechC == nil {
			w.TechC = &[]string{}
		}
		*w.TechC = append(*w.TechC, techC)
	}

}

func (w *WhoisInetNum) HandleLastModified(line string) {
	lastModified := strings.TrimSpace(strings.TrimPrefix(line, "last-modified:"))
	if lastModified != "" {
		if !strings.Contains(lastModified, "T") {
			lastModified = lastModified + "T00:00:00Z"
		}
		parsedTime, err := time.Parse(time.RFC3339, lastModified)
		if err != nil {
			return
		} else {
			w.LastModified = &parsedTime
		}
	}
}

func (w *WhoisInetNum) HandleCreated(line string) {
	created := strings.TrimSpace(strings.TrimPrefix(line, "created:"))
	if created != "" {
		if !strings.Contains(created, "T") {
			created = created + "T00:00:00Z"
		}
		parsedTime, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return
		} else {
			w.Created = &parsedTime
		}
	}
}

func (w *WhoisInetNum) HandleAbuseC(line string) {
	abuseC := strings.TrimSpace(strings.TrimPrefix(line, "abuse-c:"))
	if abuseC != "" {
		if strings.Contains(strings.ToLower(abuseC), "dumy") {
			return
		}
		w.AbuseC = &abuseC
	}
}

// Status from WhoisDB is assigned or allocated or something similar
// But RDAP responses call that field as Type. We store WhoisDB status in Type field.
func (w *WhoisInetNum) HandleStatus(line string) {
	status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
	if status != "" {
		w.Type = &status
	}
}

func (w *WhoisInetNum) HandleRemarks(line string) {
	if w.Remarks == nil {
		w.Remarks = &[]string{}
	}
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisInetNum) HandleNotify(line string) {
	notify := strings.TrimSpace(strings.TrimPrefix(line, "notify:"))
	if notify != "" {
		if w.Notify == nil {
			w.Notify = &[]string{}
		}
		*w.Notify = append(*w.Notify, notify)
		// extract domain
		for _, segment := range strings.Split(notify, " ") {
			domain := strings.Index(segment, "@")
			if domain != -1 {
				domainPart := segment[domain+1:]
				w.Domain = &domainPart
			}
		}
	}
}

func (w *WhoisInetNum) HandleMntBy(line string) {
	if w.MntBy == nil {
		w.MntBy = &[]string{}
	}
	*w.MntBy = append(*w.MntBy, strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:")))
}

func (w *WhoisInetNum) HandleMntLower(line string) {
	if w.MntLower == nil {
		w.MntLower = &[]string{}
	}
	*w.MntLower = append(*w.MntLower, strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:")))
}

func (w *WhoisInetNum) HandleMntRoutes(line string) {
	if w.MntRoutes == nil {
		w.MntRoutes = &[]string{}
	}
	*w.MntRoutes = append(*w.MntRoutes, strings.TrimSpace(strings.TrimPrefix(line, "mnt-routes:")))
}

func (w *WhoisInetNum) HandleMntIrt(line string) {
	if w.MntIrt == nil {
		w.MntIrt = &[]string{}
	}
	*w.MntIrt = append(*w.MntIrt, strings.TrimSpace(strings.TrimPrefix(line, "mnt-irt:")))
}

func (w *WhoisInetNum) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}

	switch source {
	case "TWNIC":
		cc := "TW"
		w.CountryCode = &cc
	case "JPNIC":
		cc := "JP"
		w.CountryCode = &cc
	case "KRNIC":
		cc := "KR"
		w.CountryCode = &cc
	default:
		return
	}

	cc := *w.CountryCode
	country, ok := opconst.CountryCode[cc]
	if ok {
		w.Country = &country
	}

}

func (w *WhoisInetNum) HandleCity(line string) {
	if line == "" {
		return
	}
	city := strings.TrimSpace(strings.TrimPrefix(line, "city:"))
	if city != "" {
		w.City = &city
	}
}

// Below are methods that are not used in the current implementation,
// since inetnum object do not provide these fields.

func (w *WhoisInetNum) HandleSponsoringOrg(line string)  {}
func (w *WhoisInetNum) HandleRefNfy(line string)         {}
func (w *WhoisInetNum) HandlePhone(line string)          {}
func (w *WhoisInetNum) HandleOrgType(line string)        {}
func (w *WhoisInetNum) HandleOrgName(line string)        {}
func (w *WhoisInetNum) HandleNicHdl(line string)         {}
func (w *WhoisInetNum) HandleMpImport(line string)       {}
func (w *WhoisInetNum) HandleMpExport(line string)       {}
func (w *WhoisInetNum) HandleMpDefault(line string)      {}
func (w *WhoisInetNum) HandleExportVia(line string)      {}
func (w *WhoisInetNum) HandleImportVia(line string)      {}
func (w *WhoisInetNum) HandleInject(line string)         {}
func (w *WhoisInetNum) HandleMemberOf(line string)       {}
func (w *WhoisInetNum) HandleAbuseMailbox(line string)   {}
func (w *WhoisInetNum) HandleAddress(line string)        {}
func (w *WhoisInetNum) HandleDefault(line string)        {}
func (w *WhoisInetNum) HandleDomain(line string)         {}
func (w *WhoisInetNum) HandleEmail(line string)          {}
func (w *WhoisInetNum) HandleFaxNo(line string)          {}
func (w *WhoisInetNum) HandleAutNum(line string)         {}
func (w *WhoisInetNum) HandleAsName(line string)         {}
func (w *WhoisInetNum) HandleInet6Num(line string)       {}
func (w *WhoisInetNum) HandleImport(line string)         {}
func (w *WhoisInetNum) HandleExport(line string)         {}
func (w *WhoisInetNum) HandleAssignmentSize(line string) {}
func (w *WhoisInetNum) HandleOrganization(line string)   {}
func (w *WhoisInetNum) HandleMntRef(line string)         {}
func (w *WhoisInetNum) HandleRole(line string)           {}
func (w *WhoisInetNum) HandleAggrMtd(line string)        {}
func (w *WhoisInetNum) HandleAggrBndry(line string)      {}
func (w *WhoisInetNum) HandleExportComps(line string)    {}
func (w *WhoisInetNum) HandleComponents(line string)     {}
func (w *WhoisInetNum) HandleRoute(line string)          {}
func (w *WhoisInetNum) HandleRoute6(line string)         {}
func (w *WhoisInetNum) HandleHoles(line string)          {}

func (w *WhoisInetNum) HandleOrigin(line string) {}
