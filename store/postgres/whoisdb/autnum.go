package whoisdb

import (
	"fmt"
	"github.com/oprand/opr/internal/opconst"
	"strconv"
	"strings"
	"time"
)

type WhoisAutNum struct {
	AutNum        uint32     `db:"aut_num" json:"aut_num"`
	ASName        string     `db:"as_name" json:"as_name"`
	Descr         *[]string  `db:"descr" json:"descr"`
	CountryCode   *string    `db:"country_code" json:"country_code"`
	Status        *string    `db:"status" json:"status"`
	MemberOf      *[]string  `db:"member_of" json:"member_of,omitempty"`
	ImportVia     *[]string  `db:"import_via" json:"import_via,omitempty"`
	Import        *[]string  `db:"import" json:"import,omitempty"`
	MpImport      *[]string  `db:"mp_import" json:"mp_import,omitempty"`
	ExportVia     *[]string  `db:"export_via" json:"export_via,omitempty"`
	Export        *[]string  `db:"export" json:"export,omitempty"`
	MpExport      *[]string  `db:"mp_export" json:"mp_export,omitempty"`
	DefaultNet    *[]string  `db:"default_net" json:"default_net,omitempty"`
	MpDefault     *[]string  `db:"mp_default" json:"mp_default,omitempty"`
	Remarks       *[]string  `db:"remarks" json:"remarks,omitempty"`
	Org           *string    `db:"org" json:"org"`
	SponsoringOrg *string    `db:"sponsoring_org" json:"sponsoring_org,omitempty"`
	AdminC        *[]string  `db:"admin_c" json:"admin_c"`
	TechC         *[]string  `db:"tech_c" json:"tech_c"`
	NocC          *[]string  `db:"noc_c" json:"noc_c"`
	RoutingC      *[]string  `db:"routing_c" json:"routing_c"`
	AbuseC        *string    `db:"abuse_c" json:"abuse_c,omitempty"`
	Notify        *[]string  `db:"notify" json:"notify,omitempty"`
	MntLower      *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	MntRoutes     *[]string  `db:"mnt_routes" json:"mnt_routes,omitempty"`
	MntBy         *[]string  `db:"mnt_by" json:"mnt_by"`
	MntIrt        *[]string  `db:"mnt_irt" json:"mnt_irt"`
	Changed       *[]string  `db:"changed" json:"changed"`
	LastModified  *time.Time `db:"last_modified" json:"last_modified"`
	Created       *time.Time `db:"created" json:"created"`
	Source        *string    `db:"source" json:"source"`
	// Only for LACNIC
	City *string `db:"city" json:"city"`
	// Expanded data points
	Country *string `db:"country" json:"country"`
	Domain  *string `db:"domain" json:"domain"`
	// Meta
	MetaAddedAt *time.Time `db:"meta_added_at" json:"meta_added_at"`
	// Freshness / provenance. Distinct from registry last_modified/created:
	// last_fetched_at is when we last successfully retrieved this row;
	// last_seen_in_source_at is when it was present in that source;
	// last_changed_at/content_hash track when *our* stored payload changed
	// (not computed yet). fetch_method is how it was retrieved; see constants.
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
}

// StampFetch records that this object was observed via method (a FetchMethod*
// constant). Sets last_fetched_at and last_seen_in_source_at to now. Nil-safe
// for callers that never stamp: SaveWhoisAutNum COALESCE-leaves existing values.
func (w *WhoisAutNum) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisAutNum) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeAutNum
}

func (w *WhoisAutNum) HandleMultiLine(prevItem string, line string) {
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

func (w *WhoisAutNum) HandleAutNum(line string) {
	val := strings.TrimSpace(strings.TrimPrefix(line, "aut-num:"))
	val = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(val), "AS"))
	autNum, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	w.AutNum = uint32(autNum)
}

func (w *WhoisAutNum) HandleCity(line string) {
	if line == "" {
		return
	}
	city := strings.TrimSpace(strings.TrimPrefix(line, "city:"))
	if city != "" {
		w.City = &city
	}
}

func (w *WhoisAutNum) HandleAsName(line string) {
	w.ASName = strings.TrimSpace(strings.TrimPrefix(line, "as-name:"))
}

func (w *WhoisAutNum) HandleNetName(line string) {}

func (w *WhoisAutNum) HandleDescr(line string) {
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

func (w *WhoisAutNum) HandleChanged(line string) {
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

func (w *WhoisAutNum) HandleCountryCode(line string) {
	countryCode := strings.TrimSpace(strings.TrimPrefix(line, "country:"))
	if w.CountryCode == nil {
		w.CountryCode = &countryCode
	}

	// Remove any comments
	if strings.Contains(countryCode, "#") {
		countryCode = countryCode[:strings.Index(countryCode, "#")]
		countryCode = strings.TrimSpace(countryCode)
	}

	countryCode = strings.ToUpper(countryCode)

	country, ok := opconst.CountryCode[countryCode]
	if ok {
		w.Country = &country
	}

}

func (w *WhoisAutNum) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		w.Org = &org
	}
}

func (w *WhoisAutNum) HandleAdminC(line string) {
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

func (w *WhoisAutNum) HandleTechC(line string) {
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

func (w *WhoisAutNum) HandleAbuseC(line string) {
	abuseC := strings.TrimSpace(strings.TrimPrefix(line, "abuse-c:"))
	if abuseC != "" {
		if strings.Contains(strings.ToLower(abuseC), "dumy") {
			return
		}
		w.AbuseC = &abuseC
	}
}

func (w *WhoisAutNum) HandleStatus(line string) {
	status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
	if status != "" {
		w.Status = &status
	}
}

func (w *WhoisAutNum) HandleRemarks(line string) {
	if w.Remarks == nil {
		w.Remarks = &[]string{}
	}
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisAutNum) HandleNotify(line string) {
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

func (w *WhoisAutNum) HandleMntBy(line string) {
	if w.MntBy == nil {
		w.MntBy = &[]string{}
	}
	*w.MntBy = append(*w.MntBy, strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:")))
}

func (w *WhoisAutNum) HandleMntLower(line string) {
	if w.MntLower == nil {
		w.MntLower = &[]string{}
	}
	*w.MntLower = append(*w.MntLower, strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:")))
}

func (w *WhoisAutNum) HandleMntRoutes(line string) {
	if w.MntRoutes == nil {
		w.MntRoutes = &[]string{}
	}
	*w.MntRoutes = append(*w.MntRoutes, strings.TrimSpace(strings.TrimPrefix(line, "mnt-routes:")))
}

func (w *WhoisAutNum) HandleMntIrt(line string) {
	if w.MntIrt == nil {
		w.MntIrt = &[]string{}
	}
	*w.MntIrt = append(*w.MntIrt, strings.TrimSpace(strings.TrimPrefix(line, "mnt-irt:")))
}

func (w *WhoisAutNum) HandleLastModified(line string) {
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

func (w *WhoisAutNum) HandleCreated(line string) {
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

func (w *WhoisAutNum) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

// Below are methods that are not used in the current implementation,
// since inetnum object do not provide these fields.

func (w *WhoisAutNum) HandleSponsoringOrg(line string) {
	sponsoringOrg := strings.TrimSpace(strings.TrimPrefix(line, "sponsoring-org:"))
	if sponsoringOrg != "" {
		w.SponsoringOrg = &sponsoringOrg
	}
}

func (w *WhoisAutNum) HandleMpImport(line string) {
	mpImport := strings.TrimSpace(strings.TrimPrefix(line, "mp-import:"))
	if mpImport != "" {
		if w.MpImport == nil {
			w.MpImport = &[]string{}
		}
		*w.MpImport = append(*w.MpImport, mpImport)
	}
}
func (w *WhoisAutNum) HandleMpExport(line string) {
	mpExport := strings.TrimSpace(strings.TrimPrefix(line, "mp-export:"))
	if mpExport != "" {
		if w.MpExport == nil {
			w.MpExport = &[]string{}
		}
		*w.MpExport = append(*w.MpExport, mpExport)
	}
}
func (w *WhoisAutNum) HandleMpDefault(line string) {
	mpDefault := strings.TrimSpace(strings.TrimPrefix(line, "mp-default:"))
	if mpDefault != "" {
		if w.MpDefault == nil {
			w.MpDefault = &[]string{}
		}
		*w.MpDefault = append(*w.MpDefault, mpDefault)
	}
}
func (w *WhoisAutNum) HandleExportVia(line string) {
	exportVia := strings.TrimSpace(strings.TrimPrefix(line, "export-via:"))
	if exportVia != "" {
		if w.ExportVia == nil {
			w.ExportVia = &[]string{}
		}
		*w.ExportVia = append(*w.ExportVia, exportVia)
	}
}
func (w *WhoisAutNum) HandleImportVia(line string) {
	importVia := strings.TrimSpace(strings.TrimPrefix(line, "import-via:"))
	if importVia != "" {
		if w.ImportVia == nil {
			w.ImportVia = &[]string{}
		}
		*w.ImportVia = append(*w.ImportVia, importVia)
	}
}
func (w *WhoisAutNum) HandleMemberOf(line string) {
	memberOf := strings.TrimSpace(strings.TrimPrefix(line, "member-of:"))
	if memberOf != "" {
		if w.MemberOf == nil {
			w.MemberOf = &[]string{}
		}
		*w.MemberOf = append(*w.MemberOf, memberOf)
	}
}

func (w *WhoisAutNum) HandleDefault(line string) {
	defaultStr := strings.TrimSpace(strings.TrimPrefix(line, "default:"))
	if defaultStr != "" {
		if w.DefaultNet == nil {
			w.DefaultNet = &[]string{}
		}
		*w.DefaultNet = append(*w.DefaultNet, defaultStr)
	}
}

func (w *WhoisAutNum) HandleImport(line string) {
	import_ := strings.TrimSpace(strings.TrimPrefix(line, "import:"))
	if import_ != "" {
		if w.Import == nil {
			w.Import = &[]string{}
		}
		*w.Import = append(*w.Import, import_)
	}
}

func (w *WhoisAutNum) HandleExport(line string) {
	export := strings.TrimSpace(strings.TrimPrefix(line, "export:"))
	if export != "" {
		if w.Export == nil {
			w.Export = &[]string{}
		}
		*w.Export = append(*w.Export, export)
	}
}

func (w *WhoisAutNum) HandleGeoloc(line string)         {}
func (w *WhoisAutNum) HandleLanguage(line string)       {}
func (w *WhoisAutNum) HandleRefNfy(line string)         {}
func (w *WhoisAutNum) HandlePhone(line string)          {}
func (w *WhoisAutNum) HandleOrgType(line string)        {}
func (w *WhoisAutNum) HandleOrgName(line string)        {}
func (w *WhoisAutNum) HandleNicHdl(line string)         {}
func (w *WhoisAutNum) HandleAbuseMailbox(line string)   {}
func (w *WhoisAutNum) HandleAddress(line string)        {}
func (w *WhoisAutNum) HandleDomain(line string)         {}
func (w *WhoisAutNum) HandleEmail(line string)          {}
func (w *WhoisAutNum) HandleFaxNo(line string)          {}
func (w *WhoisAutNum) HandleInetNum(line string)        {}
func (w *WhoisAutNum) HandleInet6Num(line string)       {}
func (w *WhoisAutNum) HandleMntDomains(line string)     {}
func (w *WhoisAutNum) HandleAssignmentSize(line string) {}
func (w *WhoisAutNum) HandleOrganization(line string)   {}
func (w *WhoisAutNum) HandleMntRef(line string)         {}
func (w *WhoisAutNum) HandleRole(line string)           {}
func (w *WhoisAutNum) HandleOrigin(line string)         {}
func (w *WhoisAutNum) HandleAggrMtd(line string)        {}
func (w *WhoisAutNum) HandleAggrBndry(line string)      {}
func (w *WhoisAutNum) HandleExportComps(line string)    {}
func (w *WhoisAutNum) HandleComponents(line string)     {}
func (w *WhoisAutNum) HandleInject(line string)         {}
func (w *WhoisAutNum) HandleRoute(line string)          {}
func (w *WhoisAutNum) HandleRoute6(line string)         {}
func (w *WhoisAutNum) HandleHoles(line string)          {}
