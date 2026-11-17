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

type WhoisInet6Num struct {
	// raw data points
	Inet6num       string     `db:"inet6num" json:"inet6num"`
	Netname        *string    `db:"netname" json:"netname"`
	Descr          *[]string  `db:"descr" json:"descr"`
	CountryCode    *string    `db:"country_code" json:"country_code"`
	Geofeed        *string    `db:"geofeed" json:"geofeed,omitempty"`
	Geoloc         *string    `db:"geoloc" json:"geoloc,omitempty"`
	Language       *[]string  `db:"language" json:"language,omitempty"`
	Org            *string    `db:"org" json:"org,omitempty"`
	AdminC         *[]string  `db:"admin_c" json:"admin_c"`
	TechC          *[]string  `db:"tech_c" json:"tech_c"`
	AbuseC         *string    `db:"abuse_c" json:"abuse_c,omitempty"`
	NocC           *[]string  `db:"noc_c" json:"noc_c"`
	RoutingC       *[]string  `db:"routing_c" json:"routing_c"`
	Status         *string    `db:"status" json:"status"`
	Type           *string    `db:"type" json:"type"`
	Remarks        *[]string  `db:"remarks" json:"remarks,omitempty"`
	Notify         *[]string  `db:"notify" json:"notify,omitempty"`
	MntBy          *[]string  `db:"mnt_by" json:"mnt_by"`
	MntLower       *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	MntRoutes      *[]string  `db:"mnt_routes" json:"mnt_routes,omitempty"`
	MntDomains     *[]string  `db:"mnt_domains" json:"mnt_domains"`
	MntIrt         *[]string  `db:"mnt_irt" json:"mnt_irt"`
	AssignmentSize *string    `db:"assignment_size" json:"assignment_size"`
	Changed        *[]string  `db:"changed" json:"changed"`
	LastModified   *time.Time `db:"last_modified" json:"last_modified"`
	Created        *time.Time `db:"created" json:"created"`
	Source         *string    `db:"source" json:"source"`
	// Only for LACNIC
	City *string `db:"city" json:"city"`
	// Expanded data points
	Netblock        *net.IPNet `db:"netblock" json:"netblock"`
	StartAddr       *string    `db:"start_addr" json:"start_addr"`
	EndAddr         *string    `db:"end_addr" json:"end_addr"`
	Country         *string    `db:"country" json:"country"`
	Domain          *string    `db:"domain" json:"domain"`
	GeolocLatitude  *float64   `db:"geooc_lat" json:"geooc_lat"`
	GeolocLongitude *float64   `db:"geooc_lon" json:"geooc_lon"`
	// Meta
	MetaAddedAt *time.Time `db:"meta_added_at" json:"meta_added_at"`
	// Freshness / provenance. Same six columns as whoisdb_autnum (migration 0064).
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
}

// StampFetch records that this inet6num was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisInet6Num) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisInet6Num) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeInet6Num
}

func (w *WhoisInet6Num) HandleMultiLine(prevItem string, line string) {
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

func (w *WhoisInet6Num) HandleInet6Num(line string) {

	inet6num := strings.TrimSpace(strings.TrimPrefix(line, "inet6num:"))
	if inet6num != "" {
		w.Inet6num = inet6num
	}

	// find CIDR notation

	// Some RIR (like LACNIC) return CIDR notation and not
	// a range of IPs
	if strings.Contains(inet6num, "/") {
		_, ipnet, err := net.ParseCIDR(inet6num)
		if err != nil {
			w.Netblock = nil
			return
		}
		w.Netblock = ipnet
		return
	}

	var ipv4From, ipv4To string
	_, err := fmt.Sscanf(inet6num, "%s - %s", &ipv4From, &ipv4To)
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
		_, ipnet, err := net.ParseCIDR(ipv4From + "/128")
		if err != nil {
			w.Netblock = nil
			return
		}
		w.Netblock = ipnet
		return
	}

	// TODO: this seems to be wrong for ipv6
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

func (w *WhoisInet6Num) HandleAssignmentSize(line string) {
	assignmentSize := strings.TrimSpace(strings.TrimPrefix(line, "assignment-size:"))
	if assignmentSize != "" {
		w.AssignmentSize = &assignmentSize
	}
}

func (w *WhoisInet6Num) HandleChanged(line string) {
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

func (w *WhoisInet6Num) HandleNetName(line string) {
	netname := strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
	if netname != "" {
		w.Netname = &netname
	}
}

func (w *WhoisInet6Num) HandleDescr(line string) {
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

func (w *WhoisInet6Num) HandleCountryCode(line string) {
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

func (w *WhoisInet6Num) HandleMntDomains(line string) {
	if w.MntDomains == nil {
		w.MntDomains = &[]string{}
	}
	*w.MntDomains = append(*w.MntDomains, strings.TrimSpace(strings.TrimPrefix(line, "mnt-domains:")))
}

func (w *WhoisInet6Num) HandleGeoloc(line string) {
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

func (w *WhoisInet6Num) HandleLanguage(line string) {
	language := strings.TrimSpace(strings.TrimPrefix(line, "language:"))
	if language != "" {
		if w.Language == nil {
			w.Language = &[]string{}
		}
		*w.Language = append(*w.Language, language)
	}
}

func (w *WhoisInet6Num) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		w.Org = &org
	}
}

func (w *WhoisInet6Num) HandleAdminC(line string) {
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

func (w *WhoisInet6Num) HandleTechC(line string) {
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

func (w *WhoisInet6Num) HandleLastModified(line string) {
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

func (w *WhoisInet6Num) HandleCreated(line string) {
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

func (w *WhoisInet6Num) HandleAbuseC(line string) {
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
func (w *WhoisInet6Num) HandleStatus(line string) {
	status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
	if status != "" {
		w.Type = &status
	}
}

func (w *WhoisInet6Num) HandleRemarks(line string) {
	if w.Remarks == nil {
		w.Remarks = &[]string{}
	}
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisInet6Num) HandleNotify(line string) {
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

func (w *WhoisInet6Num) HandleMntBy(line string) {
	if w.MntBy == nil {
		w.MntBy = &[]string{}
	}
	*w.MntBy = append(*w.MntBy, strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:")))
}

func (w *WhoisInet6Num) HandleMntLower(line string) {
	if w.MntLower == nil {
		w.MntLower = &[]string{}
	}
	*w.MntLower = append(*w.MntLower, strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:")))
}

func (w *WhoisInet6Num) HandleMntRoutes(line string) {
	if w.MntRoutes == nil {
		w.MntRoutes = &[]string{}
	}
	*w.MntRoutes = append(*w.MntRoutes, strings.TrimSpace(strings.TrimPrefix(line, "mnt-routes:")))
}

func (w *WhoisInet6Num) HandleMntIrt(line string) {
	if w.MntIrt == nil {
		w.MntIrt = &[]string{}
	}
	*w.MntIrt = append(*w.MntIrt, strings.TrimSpace(strings.TrimPrefix(line, "mnt-irt:")))
}

func (w *WhoisInet6Num) HandleSource(line string) {
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

func (w *WhoisInet6Num) HandleCity(line string) {
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

func (w *WhoisInet6Num) HandleSponsoringOrg(line string) {}
func (w *WhoisInet6Num) HandleRefNfy(line string)        {}
func (w *WhoisInet6Num) HandlePhone(line string)         {}
func (w *WhoisInet6Num) HandleOrgType(line string)       {}
func (w *WhoisInet6Num) HandleOrgName(line string)       {}
func (w *WhoisInet6Num) HandleNicHdl(line string)        {}
func (w *WhoisInet6Num) HandleMpImport(line string)      {}
func (w *WhoisInet6Num) HandleMpExport(line string)      {}
func (w *WhoisInet6Num) HandleMpDefault(line string)     {}
func (w *WhoisInet6Num) HandleExportVia(line string)     {}
func (w *WhoisInet6Num) HandleImportVia(line string)     {}
func (w *WhoisInet6Num) HandleInject(line string)        {}
func (w *WhoisInet6Num) HandleMemberOf(line string)      {}
func (w *WhoisInet6Num) HandleAbuseMailbox(line string)  {}
func (w *WhoisInet6Num) HandleAddress(line string)       {}
func (w *WhoisInet6Num) HandleDefault(line string)       {}
func (w *WhoisInet6Num) HandleDomain(line string)        {}
func (w *WhoisInet6Num) HandleEmail(line string)         {}
func (w *WhoisInet6Num) HandleFaxNo(line string)         {}
func (w *WhoisInet6Num) HandleAutNum(line string)        {}
func (w *WhoisInet6Num) HandleAsName(line string)        {}
func (w *WhoisInet6Num) HandleInetNum(line string)       {}
func (w *WhoisInet6Num) HandleImport(line string)        {}
func (w *WhoisInet6Num) HandleExport(line string)        {}
func (w *WhoisInet6Num) HandleOrganization(line string)  {}
func (w *WhoisInet6Num) HandleMntRef(line string)        {}
func (w *WhoisInet6Num) HandleRole(line string)          {}
func (w *WhoisInet6Num) HandleAggrMtd(line string)       {}
func (w *WhoisInet6Num) HandleAggrBndry(line string)     {}
func (w *WhoisInet6Num) HandleExportComps(line string)   {}
func (w *WhoisInet6Num) HandleComponents(line string)    {}
func (w *WhoisInet6Num) HandleRoute(line string)         {}
func (w *WhoisInet6Num) HandleRoute6(line string)        {}
func (w *WhoisInet6Num) HandleHoles(line string)         {}
func (w *WhoisInet6Num) HandleOrigin(line string)        {}
