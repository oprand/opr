package whoisdb

import (
	"github.com/oprand/opr/internal/opconst"
	"strconv"
	"strings"
	"time"
)

type WhoisRoute struct {
	Route       string    `db:"route" json:"route"`
	Descr       *[]string `db:"descr" json:"descr"`
	CountryCode *string   `db:"country_code" json:"country_code"`
	Origin      *uint32   `db:"origin" json:"origin"`
	Holes       *[]string `db:"holes" json:"holes,omitempty"`
	MemberOf    *[]string `db:"member_of" json:"member_of,omitempty"`
	Inject      *[]string `db:"inject" json:"inject,omitempty"`
	AggrMtd     *string   `db:"aggr_mtd" json:"aggr_mtd,omitempty"`
	AggrBndry   *string   `db:"aggr_bndry" json:"aggr_bndry,omitempty"`
	ExportComps *string   `db:"export_comps" json:"export_comps,omitempty"`
	Components  *string   `db:"components" json:"components,omitempty"`
	Remarks     *[]string `db:"remarks" json:"remarks,omitempty"`
	Notify      *[]string `db:"notify" json:"notify,omitempty"`
	MntLower    *[]string `db:"mnt_lower" json:"mnt_lower,omitempty"`
	MntRoutes   *[]string `db:"mnt_routes" json:"mnt_routes,omitempty"`
	MntBy       *[]string `db:"mnt_by" json:"mnt_by"`
	// TODO: convert these next 2 as timestamp in database
	LastModified *string   `db:"last_modified" json:"last_modified"`
	Created      *string   `db:"created" json:"created"`
	Source       *string   `db:"source" json:"source"`
	Changed      *[]string `db:"changed" json:"changed"`
	TechC        *[]string `db:"tech_c" json:"tech_c"`
	AdminC       *[]string `db:"admin_c" json:"admin_c"`
	AbuseC       *[]string `db:"abuse_c" json:"abuse_c"`
	// Only for LACNIC
	City *string `db:"city" json:"city"`
	// Expanded data points
	Country *string `db:"country" json:"country"`
	Domain  *string `db:"domain" json:"domain"`
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

// StampFetch records that this route was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisRoute) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisRoute) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeRoute
}

func (w *WhoisRoute) HandleRoute(line string) {
	w.Route = strings.TrimSpace(strings.TrimPrefix(line, "route:"))
}

func (w *WhoisRoute) HandleMntBy(line string) {
	if w.MntBy == nil {
		w.MntBy = &[]string{}
	}
	*w.MntBy = append(*w.MntBy, strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:")))
}

func (w *WhoisRoute) HandleAggrMtd(line string) {
	aggrMtd := strings.TrimSpace(strings.TrimPrefix(line, "aggr-mtd:"))
	if aggrMtd != "" {
		w.AggrMtd = &aggrMtd
	}
}

func (w *WhoisRoute) HandleAggrBndry(line string) {
	aggrBndry := strings.TrimSpace(strings.TrimPrefix(line, "aggr-bndry:"))
	if aggrBndry != "" {
		w.AggrBndry = &aggrBndry
	}
}

func (w *WhoisRoute) HandleExportComps(line string) {
	exportComps := strings.TrimSpace(strings.TrimPrefix(line, "export-comps:"))
	if exportComps != "" {
		w.ExportComps = &exportComps
	}
}

func (w *WhoisRoute) HandleComponents(line string) {
	components := strings.TrimSpace(strings.TrimPrefix(line, "components:"))
	if components != "" {
		w.Components = &components
	}
}

func (w *WhoisRoute) HandleInject(line string) {
	inject := strings.TrimSpace(strings.TrimPrefix(line, "inject:"))
	if w.Inject == nil {
		w.Inject = &[]string{}
	}
	*w.Inject = append(*w.Inject, inject)
}

func (w *WhoisRoute) HandleHoles(line string) {
	holes := strings.TrimSpace(strings.TrimPrefix(line, "holes:"))
	if w.Holes == nil {
		w.Holes = &[]string{}
	}
	*w.Holes = append(*w.Holes, holes)
}

func (w *WhoisRoute) HandleCountryCode(line string) {
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

func (w *WhoisRoute) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisRoute) HandleOrigin(line string) {
	origin := strings.TrimSpace(strings.TrimPrefix(line, "origin:"))
	if origin != "" {
		origin = strings.TrimSpace(strings.TrimPrefix(origin, "AS"))
		originInt, err := strconv.ParseUint(origin, 10, 32)
		if err != nil {
			return
		}
		originInt32 := uint32(originInt)
		w.Origin = &originInt32
	}
}

func (w *WhoisRoute) HandleMultiLine(prevItem, line string) {
	// Implementation for handling multi-line fields
	switch prevItem {
	case "descr":
		w.HandleDescr(line)
	case "remarks":
		w.HandleRemarks(line)
	case "address":
		w.HandleAddress(line)
	}
}

func (w *WhoisRoute) HandleRemarks(line string) {
	if w.Remarks == nil {
		w.Remarks = &[]string{}
	}
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisRoute) HandleNotify(line string) {
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

func (w *WhoisRoute) HandleMntLower(line string) {
	if w.MntLower == nil {
		w.MntLower = &[]string{}
	}
	*w.MntLower = append(*w.MntLower, strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:")))
}

func (w *WhoisRoute) HandleMntRoutes(line string) {
	if w.MntRoutes == nil {
		w.MntRoutes = &[]string{}
	}
	*w.MntRoutes = append(*w.MntRoutes, strings.TrimSpace(strings.TrimPrefix(line, "mnt-routes:")))
}

func (w *WhoisRoute) HandleLastModified(line string) {
	lastModified := strings.TrimSpace(strings.TrimPrefix(line, "last-modified:"))
	if lastModified != "" {
		if !strings.Contains(lastModified, "T") {
			lastModified = lastModified + "T00:00:00Z"
		}
		w.LastModified = &lastModified
		// parsedTime, err := time.Parse(time.RFC3339, lastModified)
		// if err != nil {
		// 	return
		// } else {
		// 	w.LastModified = &parsedTime
		// }
	}
}
func (w *WhoisRoute) HandleDescr(line string) {
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if w.Descr == nil {
		w.Descr = &[]string{}
	}
	*w.Descr = append(*w.Descr, description)
}

func (w *WhoisRoute) HandleMemberOf(line string) {
	memberOf := strings.TrimSpace(strings.TrimPrefix(line, "member-of:"))
	if memberOf != "" {
		if w.MemberOf == nil {
			w.MemberOf = &[]string{}
		}
		*w.MemberOf = append(*w.MemberOf, memberOf)
	}
}

func (w *WhoisRoute) HandleCreated(line string) {
	created := strings.TrimSpace(strings.TrimPrefix(line, "created:"))
	if created != "" {
		if !strings.Contains(created, "T") {
			created = created + "T00:00:00Z"
		}
		w.Created = &created
		// parsedTime, err := time.Parse(time.RFC3339, created)
		// if err != nil {
		// 	return
		// } else {
		// 	w.Created = &parsedTime
		// }
	}
}

func (w *WhoisRoute) HandleCity(line string) {
	if line == "" {
		return
	}
	city := strings.TrimSpace(strings.TrimPrefix(line, "city:"))
	if city != "" {
		w.City = &city
	}
}

func (w *WhoisRoute) HandleTechC(line string) {
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

func (w *WhoisRoute) HandleChanged(line string) {
	changed := strings.TrimSpace(strings.TrimPrefix(line, "changed:"))
	if changed != "" {
		if w.Changed == nil {
			w.Changed = &[]string{}
		}
		*w.Changed = append(*w.Changed, changed)
		// extract domain
		for _, segment := range strings.Split(changed, " ") {
			domain := strings.Index(segment, "@")
			if domain != -1 {
				domainPart := segment[domain+1:]
				w.Domain = &domainPart
			}
		}
	}
}

func (w *WhoisRoute) HandleImportVia(line string)      {}
func (w *WhoisRoute) HandleExportVia(line string)      {}
func (w *WhoisRoute) HandleImport(line string)         {}
func (w *WhoisRoute) HandleExport(line string)         {}
func (w *WhoisRoute) HandleDefault(line string)        {}
func (w *WhoisRoute) HandleMpImport(line string)       {}
func (w *WhoisRoute) HandleMpExport(line string)       {}
func (w *WhoisRoute) HandleMpDefault(line string)      {}
func (w *WhoisRoute) HandleRefNfy(line string)         {}
func (w *WhoisRoute) HandleAssignmentSize(line string) {}
func (w *WhoisRoute) HandleAutNum(line string)         {}
func (w *WhoisRoute) HandleInetNum(line string)        {}
func (w *WhoisRoute) HandleInet6Num(line string)       {}
func (w *WhoisRoute) HandleNetName(line string)        {}
func (w *WhoisRoute) HandleGeoloc(line string)         {}
func (w *WhoisRoute) HandleLanguage(line string)       {}
func (w *WhoisRoute) HandleOrg(line string)            {}
func (w *WhoisRoute) HandleAdminC(line string)         {}
func (w *WhoisRoute) HandleAbuseC(line string)         {}
func (w *WhoisRoute) HandleStatus(line string)         {}
func (w *WhoisRoute) HandleMntDomains(line string)     {}
func (w *WhoisRoute) HandleMntIrt(line string)         {}
func (w *WhoisRoute) HandleRole(line string)           {}
func (w *WhoisRoute) HandleOrganization(line string)   {}
func (w *WhoisRoute) HandleMntRef(line string)         {}
func (w *WhoisRoute) HandleDomain(line string)         {}
func (w *WhoisRoute) HandlePhone(line string)          {}
func (w *WhoisRoute) HandleFaxNo(line string)          {}
func (w *WhoisRoute) HandleEmail(line string)          {}
func (w *WhoisRoute) HandleAddress(line string)        {}
func (w *WhoisRoute) HandleNicHdl(line string)         {}
func (w *WhoisRoute) HandleAbuseMailbox(line string)   {}
func (w *WhoisRoute) HandleSponsoringOrg(line string)  {}
func (w *WhoisRoute) HandleOrgType(line string)        {}
func (w *WhoisRoute) HandleOrgName(line string)        {}
func (w *WhoisRoute) HandleAsName(line string)         {}
func (w *WhoisRoute) HandleRoute6(line string)         {}
