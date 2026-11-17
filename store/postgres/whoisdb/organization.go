package whoisdb

import (
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

type WhoisOrganization struct {
	Organization string     `db:"organization" json:"organization"`
	OrgName      *string    `db:"org_name" json:"org_name"`
	Descr        *[]string  `db:"descr" json:"descr,omitempty"`
	CountryCode  *string    `db:"country_code" json:"country_code"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	Address      *[]string  `db:"address" json:"address"`
	Phone        *[]string  `db:"phone" json:"phone,omitempty"`
	FaxNo        *[]string  `db:"fax_no" json:"fax_no,omitempty"`
	Email        *[]string  `db:"email" json:"email"`
	Org          *[]string  `db:"org" json:"org,omitempty"`
	OrgType      *string    `db:"org_type" json:"org_type"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c,omitempty"`
	TechC        *[]string  `db:"tech_c" json:"tech_c,omitempty"`
	NocC         *[]string  `db:"noc_c" json:"noc_c,omitempty"`
	RoutingC     *[]string  `db:"routing_c" json:"routing_c,omitempty"`
	AbuseC       *string    `db:"abuse_c" json:"abuse_c,omitempty"`
	RefNfy       *[]string  `db:"ref_nfy" json:"ref_nfy,omitempty"`
	MntRef       *[]string  `db:"mnt_ref" json:"mnt_ref"`
	Notify       *[]string  `db:"notify" json:"notify,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by"`
	LastModified *time.Time `db:"last_modified" json:"last_modified"`
	Created      *time.Time `db:"created" json:"created"`
	Source       *string    `db:"source" json:"source"`
	// Expanded data points
	Country *string `db:"country" json:"country"`
	Domain  *string `db:"domain" json:"domain"`
	// Used to determine if this is a nested org, not saved in database
	NestingLevel int `db:"-" json:"-"`
	// Meta
	MetaAddedAt *time.Time `db:"meta_added_at" json:"meta_added_at"`
	// Freshness / provenance. Same six columns as whoisdb_autnum (migration 0064).
	// StampFetch(rdap) on the live RDAP autnum path; StampFetch(bulk_dump) on dump ingest.
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
}

// StampFetch records that this org was observed via method. Nil-safe; upsert
// COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisOrganization) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisOrganization) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeOrg
}

func (w *WhoisOrganization) HandleMultiLine(prevItem, line string) {
	// Implementation for handling multi-line fields
	switch prevItem {
	case "descr":
		w.HandleDescr(line)
	case "import":
		w.HandleImport(line)
	case "export":
		w.HandleExport(line)
	case "remarks":
		w.HandleRemarks(line)
	case "address":
		w.HandleAddress(line)
	}
}

func (w *WhoisOrganization) HandleCountryCode(line string) {
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

func (w *WhoisOrganization) HandleAutNum(line string) {
	// WhoisOrganization does not handle aut-num
}

func (w *WhoisOrganization) HandleInetNum(line string) {
	// WhoisOrganization does not handle inetnum
}

func (w *WhoisOrganization) HandleInet6Num(line string) {
	// WhoisOrganization does not handle inet6num
}

func (w *WhoisOrganization) HandleNetName(line string) {
	// WhoisOrganization does not handle netname
}

func (w *WhoisOrganization) HandleGeoloc(line string) {
	// WhoisOrganization does not handle geoloc
}

func (w *WhoisOrganization) HandleLanguage(line string) {
	// WhoisOrganization does not handle language
}

func (w *WhoisOrganization) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		if w.Org == nil {
			w.Org = &[]string{}
		}
		*w.Org = append(*w.Org, org)
	}
}

func (w *WhoisOrganization) HandleAdminC(line string) {
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

func (w *WhoisOrganization) HandleTechC(line string) {
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

func (w *WhoisOrganization) HandleAbuseC(line string) {
	// WhoisOrganization does not handle abuse-c
}

func (w *WhoisOrganization) HandleStatus(line string) {
	// WhoisOrganization does not handle status
}

func (w *WhoisOrganization) HandleRemarks(line string) {
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		if w.Remarks == nil {
			w.Remarks = &[]string{}
		}
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisOrganization) HandleNotify(line string) {
	notify := strings.TrimSpace(strings.TrimPrefix(line, "notify:"))
	if notify != "" {
		if w.Notify == nil {
			w.Notify = &[]string{}
		}
		*w.Notify = append(*w.Notify, notify)
		// extract domain
		// notify: field is usually after email: field,
		// so only collect it from here if we didn't
		// get any domain from email: field
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

func (w *WhoisOrganization) HandleMntBy(line string) {
	mntBy := strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:"))
	if mntBy != "" {
		if w.MntBy == nil {
			w.MntBy = &[]string{}
		}
		*w.MntBy = append(*w.MntBy, mntBy)
	}
}

func (w *WhoisOrganization) HandleMntLower(line string) {
	// WhoisOrganization does not handle mnt-lower
}

func (w *WhoisOrganization) HandleMntRoutes(line string) {
	// WhoisOrganization does not handle mnt-routes
}

func (w *WhoisOrganization) HandleMntDomains(line string) {
	// WhoisOrganization does not handle mnt-domains
}

func (w *WhoisOrganization) HandleMntIrt(line string) {
	// WhoisOrganization does not handle mnt-irt
}

func (w *WhoisOrganization) HandleLastModified(line string) {
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

func (w *WhoisOrganization) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisOrganization) HandleOrganization(line string) {
	organization := strings.TrimSpace(strings.TrimPrefix(line, "organisation:"))
	if organization != "" {
		w.Organization = organization
	}
}

func (w *WhoisOrganization) HandleDomain(line string) {
	// WhoisOrganization does not handle domain
}

func (w *WhoisOrganization) HandlePhone(line string) {
	phone := strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
	if phone != "" {
		if w.Phone == nil {
			w.Phone = &[]string{}
		}
		*w.Phone = append(*w.Phone, phone)
	}
}

func (w *WhoisOrganization) HandleFaxNo(line string) {
	faxNo := strings.TrimSpace(strings.TrimPrefix(line, "fax-no:"))
	if faxNo != "" {
		if w.FaxNo == nil {
			w.FaxNo = &[]string{}
		}
		*w.FaxNo = append(*w.FaxNo, faxNo)
	}
}

func (w *WhoisOrganization) HandleEmail(line string) {
	email := strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
	if email != "" {
		// if all characters are the same, ignore and keep nil value
		if strings.Trim(email, string(email[0])) == "" {
			return
		}
		// if RIPE unread dummy email address, ignore and keep nil value
		if strings.Contains(strings.ToLower(email), "unread@ripe.net") {
			return
		}
		if w.Email == nil {
			w.Email = &[]string{}
		}
		*w.Email = append(*w.Email, email)
		// extract domain
		domain := strings.Index(email, "@")
		if domain != -1 {
			domainPart := email[domain+1:]
			w.Domain = &domainPart
		}
	}
}

func (w *WhoisOrganization) HandleAddress(line string) {
	address := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
	// Skip dummy addresses
	if strings.Contains(strings.ToLower(line), "dummy") {
		return
	}
	if address != "" {
		if w.Address == nil {
			w.Address = &[]string{}
		}
		*w.Address = append(*w.Address, address)
	}
}

func (w *WhoisOrganization) HandleNicHdl(line string) {
	// WhoisOrganization does not handle nic-hdl
}

func (w *WhoisOrganization) HandleAbuseMailbox(line string) {
	// WhoisOrganization does not handle abuse-mailbox
}

func (w *WhoisOrganization) HandleSponsoringOrg(line string) {
	// WhoisOrganization does not handle sponsoring-org
}

func (w *WhoisOrganization) HandleOrgType(line string) {
	orgType := strings.TrimSpace(strings.TrimPrefix(line, "org-type:"))
	if orgType != "" {
		w.OrgType = &orgType
	}
}

func (w *WhoisOrganization) HandleOrgName(line string) {
	orgName := strings.TrimSpace(strings.TrimPrefix(line, "org-name:"))
	if orgName != "" {
		w.OrgName = &orgName
	}
}

func (w *WhoisOrganization) HandleDescr(line string) {
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if description != "" {
		if w.Descr == nil {
			w.Descr = &[]string{}
		}
		*w.Descr = append(*w.Descr, description)
	}

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

func (w *WhoisOrganization) HandleMntRef(line string) {
	mntRef := strings.TrimSpace(strings.TrimPrefix(line, "mnt-ref:"))
	if mntRef != "" {
		if w.MntRef == nil {
			w.MntRef = &[]string{}
		}
		*w.MntRef = append(*w.MntRef, mntRef)
	}
}

func (w *WhoisOrganization) HandleMemberOf(line string) {
	// WhoisOrganization does not handle member-of
}

func (w *WhoisOrganization) HandleImportVia(line string) {
	// WhoisOrganization does not handle import-via
}

func (w *WhoisOrganization) HandleExportVia(line string) {
	// WhoisOrganization does not handle export-via
}

func (w *WhoisOrganization) HandleDefault(line string) {
	// WhoisOrganization does not handle default
}

func (w *WhoisOrganization) HandleMpImport(line string) {
	// WhoisOrganization does not handle mp-import
}

func (w *WhoisOrganization) HandleMpExport(line string) {
	// WhoisOrganization does not handle mp-export
}

func (w *WhoisOrganization) HandleMpDefault(line string) {
	// WhoisOrganization does not handle mp-default
}

func (w *WhoisOrganization) HandleRefNfy(line string) {
	refNfy := strings.TrimSpace(strings.TrimPrefix(line, "ref-nfy:"))
	if refNfy != "" {
		if w.RefNfy == nil {
			w.RefNfy = &[]string{}
		}
		*w.RefNfy = append(*w.RefNfy, refNfy)
	}
}

func (w *WhoisOrganization) HandleCreated(line string) {
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

func (w *WhoisOrganization) HandleChanged(line string)        {}
func (w *WhoisOrganization) HandleAsName(line string)         {}
func (w *WhoisOrganization) HandleCity(line string)           {}
func (w *WhoisOrganization) HandleAssignmentSize(line string) {}
func (w *WhoisOrganization) HandleImport(line string)         {}
func (w *WhoisOrganization) HandleExport(line string)         {}
func (w *WhoisOrganization) HandleRole(line string)           {}
func (w *WhoisOrganization) HandleAggrMtd(line string)        {}
func (w *WhoisOrganization) HandleAggrBndry(line string)      {}
func (w *WhoisOrganization) HandleExportComps(line string)    {}
func (w *WhoisOrganization) HandleComponents(line string)     {}
func (w *WhoisOrganization) HandleRoute(line string)          {}
func (w *WhoisOrganization) HandleRoute6(line string)         {}
func (w *WhoisOrganization) HandleHoles(line string)          {}
func (w *WhoisOrganization) HandleOrigin(line string)         {}
func (w *WhoisOrganization) HandleInject(line string)         {}
