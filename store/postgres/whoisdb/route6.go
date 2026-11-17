package whoisdb

import (
	"github.com/oprand/opr/internal/opconst"
	"strconv"
	"strings"
	"time"
)

type WhoisRoute6 struct {
	Route6       string     `db:"route6" json:"route6"`
	Descr        *[]string  `db:"descr" json:"descr"`
	CountryCode  *string    `db:"country_code" json:"country_code"`
	Origin       *uint32    `db:"origin" json:"origin"`
	Holes        *[]string  `db:"holes" json:"holes,omitempty"`
	Org          *[]string  `db:"org" json:"org,omitempty"`
	MemberOf     *[]string  `db:"member_of" json:"member_of,omitempty"`
	Inject       *[]string  `db:"inject" json:"inject,omitempty"`
	TechC        *[]string  `db:"tech_c" json:"tech_c,omitempty"`
	AggrMtd      *string    `db:"aggr_mtd" json:"aggr_mtd,omitempty"`
	AggrBndry    *string    `db:"aggr_bndry" json:"aggr_bndry,omitempty"`
	ExportComps  *string    `db:"export_comps" json:"export_comps,omitempty"`
	Components   *string    `db:"components" json:"components,omitempty"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	Notify       *[]string  `db:"notify" json:"notify,omitempty"`
	MntLower     *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	MntRoutes    *[]string  `db:"mnt_routes" json:"mnt_routes,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by"`
	LastModified *time.Time `db:"last_modified" json:"last_modified"`
	Source       *string    `db:"source" json:"source"`
	Created      *time.Time `db:"created" json:"created"`
	Changed      *[]string  `db:"changed" json:"changed"`
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

// StampFetch records that this route6 was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisRoute6) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisRoute6) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeRoute6
}

func (w *WhoisRoute6) HandleRoute6(line string) {
	w.Route6 = strings.TrimSpace(strings.TrimPrefix(line, "route6:"))
}

func (w *WhoisRoute6) HandleMntBy(line string) {
	if w.MntBy == nil {
		w.MntBy = &[]string{}
	}
	*w.MntBy = append(*w.MntBy, strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:")))
}

func (w *WhoisRoute6) HandleAggrMtd(line string) {
	aggrMtd := strings.TrimSpace(strings.TrimPrefix(line, "aggr-mtd:"))
	if aggrMtd != "" {
		w.AggrMtd = &aggrMtd
	}
}

func (w *WhoisRoute6) HandleAggrBndry(line string) {
	aggrBndry := strings.TrimSpace(strings.TrimPrefix(line, "aggr-bndry:"))
	if aggrBndry != "" {
		w.AggrBndry = &aggrBndry
	}
}

func (w *WhoisRoute6) HandleExportComps(line string) {
	exportComps := strings.TrimSpace(strings.TrimPrefix(line, "export-comps:"))
	if exportComps != "" {
		w.ExportComps = &exportComps
	}
}

func (w *WhoisRoute6) HandleComponents(line string) {
	components := strings.TrimSpace(strings.TrimPrefix(line, "components:"))
	if components != "" {
		w.Components = &components
	}
}

func (w *WhoisRoute6) HandleInject(line string) {
	inject := strings.TrimSpace(strings.TrimPrefix(line, "inject:"))
	if w.Inject == nil {
		w.Inject = &[]string{}
	}
	*w.Inject = append(*w.Inject, inject)
}

func (w *WhoisRoute6) HandleHoles(line string) {
	holes := strings.TrimSpace(strings.TrimPrefix(line, "holes:"))
	if w.Holes == nil {
		w.Holes = &[]string{}
	}
	*w.Holes = append(*w.Holes, holes)
}

func (w *WhoisRoute6) HandleCountryCode(line string) {
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

func (w *WhoisRoute6) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisRoute6) HandleOrigin(line string) {
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

func (w *WhoisRoute6) HandleMultiLine(prevItem, line string) {
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

func (w *WhoisRoute6) HandleRemarks(line string) {
	if w.Remarks == nil {
		w.Remarks = &[]string{}
	}
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisRoute6) HandleNotify(line string) {
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

func (w *WhoisRoute6) HandleMntLower(line string) {
	if w.MntLower == nil {
		w.MntLower = &[]string{}
	}
	*w.MntLower = append(*w.MntLower, strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:")))
}

func (w *WhoisRoute6) HandleMntRoutes(line string) {
	if w.MntRoutes == nil {
		w.MntRoutes = &[]string{}
	}
	*w.MntRoutes = append(*w.MntRoutes, strings.TrimSpace(strings.TrimPrefix(line, "mnt-routes:")))
}

func (w *WhoisRoute6) HandleLastModified(line string) {
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
func (w *WhoisRoute6) HandleDescr(line string) {
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if w.Descr == nil {
		w.Descr = &[]string{}
	}
	*w.Descr = append(*w.Descr, description)
}

func (w *WhoisRoute6) HandleMemberOf(line string) {
	memberOf := strings.TrimSpace(strings.TrimPrefix(line, "member-of:"))
	if memberOf != "" {
		if w.MemberOf == nil {
			w.MemberOf = &[]string{}
		}
		*w.MemberOf = append(*w.MemberOf, memberOf)
	}
}

func (w *WhoisRoute6) HandleCreated(line string) {
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

func (w *WhoisRoute6) HandleCity(line string) {
	if line == "" {
		return
	}
	city := strings.TrimSpace(strings.TrimPrefix(line, "city:"))
	if city != "" {
		w.City = &city
	}
}

func (w *WhoisRoute6) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		if w.Org == nil {
			w.Org = &[]string{}
		}
		*w.Org = append(*w.Org, org)
	}
}

func (w *WhoisRoute6) HandleChanged(line string) {
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

func (w *WhoisRoute6) HandleTechC(line string) {
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

func (w *WhoisRoute6) HandleImportVia(line string)      {}
func (w *WhoisRoute6) HandleExportVia(line string)      {}
func (w *WhoisRoute6) HandleImport(line string)         {}
func (w *WhoisRoute6) HandleExport(line string)         {}
func (w *WhoisRoute6) HandleDefault(line string)        {}
func (w *WhoisRoute6) HandleMpImport(line string)       {}
func (w *WhoisRoute6) HandleMpExport(line string)       {}
func (w *WhoisRoute6) HandleMpDefault(line string)      {}
func (w *WhoisRoute6) HandleRefNfy(line string)         {}
func (w *WhoisRoute6) HandleAssignmentSize(line string) {}
func (w *WhoisRoute6) HandleAutNum(line string)         {}
func (w *WhoisRoute6) HandleInetNum(line string)        {}
func (w *WhoisRoute6) HandleInet6Num(line string)       {}
func (w *WhoisRoute6) HandleNetName(line string)        {}
func (w *WhoisRoute6) HandleGeoloc(line string)         {}
func (w *WhoisRoute6) HandleLanguage(line string)       {}
func (w *WhoisRoute6) HandleAdminC(line string)         {}
func (w *WhoisRoute6) HandleAbuseC(line string)         {}
func (w *WhoisRoute6) HandleStatus(line string)         {}
func (w *WhoisRoute6) HandleMntDomains(line string)     {}
func (w *WhoisRoute6) HandleMntIrt(line string)         {}
func (w *WhoisRoute6) HandleRole(line string)           {}
func (w *WhoisRoute6) HandleOrganization(line string)   {}
func (w *WhoisRoute6) HandleMntRef(line string)         {}
func (w *WhoisRoute6) HandleDomain(line string)         {}
func (w *WhoisRoute6) HandlePhone(line string)          {}
func (w *WhoisRoute6) HandleFaxNo(line string)          {}
func (w *WhoisRoute6) HandleEmail(line string)          {}
func (w *WhoisRoute6) HandleAddress(line string)        {}
func (w *WhoisRoute6) HandleNicHdl(line string)         {}
func (w *WhoisRoute6) HandleAbuseMailbox(line string)   {}
func (w *WhoisRoute6) HandleSponsoringOrg(line string)  {}
func (w *WhoisRoute6) HandleOrgType(line string)        {}
func (w *WhoisRoute6) HandleOrgName(line string)        {}
func (w *WhoisRoute6) HandleAsName(line string)         {}
func (w *WhoisRoute6) HandleRoute(line string)          {}
