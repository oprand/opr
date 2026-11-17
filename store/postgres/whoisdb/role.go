package whoisdb

import (
	"fmt"
	"github.com/oprand/opr/internal/opconst"
	"strings"
	"time"
)

type WhoisRole struct {
	Role         *string    `db:"role" json:"role"`
	NicHdl       string     `db:"nic_hdl" json:"nic_hdl"`
	Address      *[]string  `db:"address" json:"address,omitempty"`
	CountryCode  *string    `db:"country_code" json:"country_code"`
	Phone        *[]string  `db:"phone" json:"phone,omitempty"`
	FaxNo        *[]string  `db:"fax_no" json:"fax_no,omitempty"`
	Email        *[]string  `db:"email" json:"email,omitempty"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c"`
	TechC        *[]string  `db:"tech_c" json:"tech_c"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	Notify       *[]string  `db:"notify" json:"notify,omitempty"`
	AbuseMailbox *[]string  `db:"abuse_mailbox" json:"abuse_mailbox,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by"`
	LastModified *time.Time `db:"last_modified" json:"last_modified"`
	Source       *string    `db:"source" json:"source"`
	Changed      *[]string  `db:"changed" json:"changed"`
	RdapKind     *string    `db:"rdap_kind" json:"rdap_kind"` // RDAP kind (individual, org, group, etc)
	Created      *time.Time `db:"created" json:"created"`
	// Expanded data points
	Country *string `db:"country" json:"country"`
	Domain  *string `db:"domain" json:"domain"`
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
	// Used when marshalling to find top-most abuse role
	NestingLevel int
	// Used when marshalling to assign roles to related object (inet, autnum)
	RdapRoles *[]string `db:"-" json:"-"` // Rdap roles array, not whoisdb role
}

// StampFetch records that this role was observed via method. Nil-safe; upsert
// COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisRole) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w *WhoisRole) HandleRole(line string) {
	role := strings.TrimSpace(strings.TrimPrefix(line, "role:"))
	if role != "" {
		if w.Role != nil && *w.Role != "" {
			role = fmt.Sprintf("%s, %s", *w.Role, role)
			w.Role = &role
		} else {
			w.Role = &role
		}
	}
}

// HandlePerson maps a RPSL person: object onto WhoisRole. Person and role share
// the nic-hdl namespace (RIPE/APNIC/AFRINIC); contacts are joined from
// whoisdb_role, and whoisdb_person is unused. RdapKind=individual distinguishes
// dump persons from role: objects (same unique key: nic_hdl, source).
func (w *WhoisRole) HandlePerson(line string) {
	person := strings.TrimSpace(strings.TrimPrefix(line, "person:"))
	if person != "" {
		if w.Role != nil && *w.Role != "" {
			person = fmt.Sprintf("%s, %s", *w.Role, person)
			w.Role = &person
		} else {
			w.Role = &person
		}
	}
	if w.RdapKind == nil {
		kind := "individual"
		w.RdapKind = &kind
	}
}

func (w *WhoisRole) HandleCreated(line string) {
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

func (w *WhoisRole) HandleNicHdl(line string) {
	nicHdl := strings.TrimSpace(strings.TrimPrefix(line, "nic-hdl:"))
	if nicHdl != "" {
		w.NicHdl = nicHdl
	}
}

func (w *WhoisRole) HandleAddress(line string) {
	// Skip dummy addresses
	if strings.Contains(strings.ToLower(line), "dummy") {
		return
	}
	address := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
	if address != "" {
		if w.Address == nil {
			w.Address = &[]string{}
		}
		*w.Address = append(*w.Address, strings.Split(address, ",")...)
	}
}

func (w *WhoisRole) HandlePhone(line string) {
	phone := strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
	if phone != "" {
		if w.Phone == nil {
			w.Phone = &[]string{}
		}
		*w.Phone = append(*w.Phone, phone)
	}
}

func (w *WhoisRole) HandleFaxNo(line string) {
	faxNo := strings.TrimSpace(strings.TrimPrefix(line, "fax-no:"))
	if faxNo != "" {
		if w.FaxNo == nil {
			w.FaxNo = &[]string{}
		}
		*w.FaxNo = append(*w.FaxNo, faxNo)
	}
}

func (w *WhoisRole) HandleEmail(line string) {
	email := strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))

	if email != "" {
		// if RIPE unread dummy email address, ignore and keep nil value
		if strings.Contains(strings.ToLower(email), "unread@ripe.net") {
			return
		}
		// if all characters are the same, ignore and keep nil value
		if strings.Trim(email, string(email[0])) == "" {
			return
		}
		if w.Email == nil {
			w.Email = &[]string{}
		}
		*w.Email = append(*w.Email, email)
	}
}

func (w *WhoisRole) HandleAdminC(line string) {
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

func (w *WhoisRole) HandleTechC(line string) {
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

func (w *WhoisRole) HandleRemarks(line string) {
	remarks := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remarks != "" {
		if w.Remarks == nil {
			w.Remarks = &[]string{}
		}
		*w.Remarks = append(*w.Remarks, remarks)
	}
}

func (w *WhoisRole) HandleNotify(line string) {
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

func (w *WhoisRole) HandleAbuseMailbox(line string) {
	abuseMailbox := strings.TrimSpace(strings.TrimPrefix(line, "abuse-mailbox:"))
	if abuseMailbox != "" {
		// if RIPE unread dummy email address, ignore and keep nil value
		if strings.Contains(strings.ToLower(abuseMailbox), "unread@ripe.net") {
			return
		}
		// if all characters are the same, ignore and keep nil value
		if strings.Trim(abuseMailbox, string(abuseMailbox[0])) == "" {
			return
		}
		if w.AbuseMailbox == nil {
			w.AbuseMailbox = &[]string{}
		}
		*w.AbuseMailbox = append(*w.AbuseMailbox, abuseMailbox)
	}
}

func (w *WhoisRole) HandleMntBy(line string) {
	mntBy := strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:"))
	if mntBy != "" {
		if w.MntBy == nil {
			w.MntBy = &[]string{}
		}
		*w.MntBy = append(*w.MntBy, mntBy)
	}
}

func (w *WhoisRole) HandleLastModified(line string) {
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

func (w *WhoisRole) HandleDomain(line string) {
	domain := strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
	if domain != "" {
		w.Domain = &domain
	}
}

func (w WhoisRole) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeRole
}

func (w *WhoisRole) HandleCountryCode(line string) {
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

func (w *WhoisRole) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisRole) HandleChanged(line string) {
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

func (w *WhoisRole) HandleMultiLine(prevItem string, line string) {
	// Implementation for handling multi-line fields
	switch prevItem {
	case "role":
		w.HandleRole(line)
	case "person":
		w.HandlePerson(line)
	case "remarks":
		w.HandleRemarks(line)
	case "address":
		w.HandleAddress(line)
	}
}

func (w *WhoisRole) HandleCity(line string)           {}
func (w *WhoisRole) HandleImport(line string)         {}
func (w *WhoisRole) HandleExport(line string)         {}
func (w *WhoisRole) HandleOrganization(line string)   {}
func (w *WhoisRole) HandleAbuseC(line string)         {}
func (w *WhoisRole) HandleAsName(line string)         {}
func (w *WhoisRole) HandleAsSet(line string)          {}
func (w *WhoisRole) HandleAssignmentSize(line string) {}
func (w *WhoisRole) HandleAutNum(line string)         {}
func (w *WhoisRole) HandleInetNum(line string)        {}
func (w *WhoisRole) HandleOrg(line string)            {}
func (w *WhoisRole) HandleOrgName(line string)        {}
func (w *WhoisRole) HandleOrgType(line string)        {}
func (w *WhoisRole) HandleInet6Num(line string)       {}
func (w *WhoisRole) HandleNetName(line string)        {}
func (w *WhoisRole) HandleGeoloc(line string)         {}
func (w *WhoisRole) HandleLanguage(line string)       {}
func (w *WhoisRole) HandleStatus(line string)         {}
func (w *WhoisRole) HandleMntRef(line string)         {}
func (w *WhoisRole) HandleMntLower(line string)       {}
func (w *WhoisRole) HandleMntRoutes(line string)      {}
func (w *WhoisRole) HandleMntDomains(line string)     {}
func (w *WhoisRole) HandleMntIrt(line string)         {}
func (w *WhoisRole) HandleSponsoringOrg(line string)  {}
func (w *WhoisRole) HandleDescr(line string)          {}
func (w *WhoisRole) HandleMemberOf(line string)       {}
func (w *WhoisRole) HandleImportVia(line string)      {}
func (w *WhoisRole) HandleExportVia(line string)      {}
func (w *WhoisRole) HandleDefault(line string)        {}
func (w *WhoisRole) HandleMpImport(line string)       {}
func (w *WhoisRole) HandleMpExport(line string)       {}
func (w *WhoisRole) HandleMpDefault(line string)      {}
func (w *WhoisRole) HandleRefNfy(line string)         {}
func (w *WhoisRole) HandleAggrMtd(line string)        {}
func (w *WhoisRole) HandleAggrBndry(line string)      {}
func (w *WhoisRole) HandleExportComps(line string)    {}
func (w *WhoisRole) HandleComponents(line string)     {}
func (w *WhoisRole) HandleRoute(line string)          {}
func (w *WhoisRole) HandleRoute6(line string)         {}
func (w *WhoisRole) HandleHoles(line string)          {}
func (w *WhoisRole) HandleOrigin(line string)         {}
func (w *WhoisRole) HandleInject(line string)         {}
