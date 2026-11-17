package whoisdb

import (
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

// WhoisIrt is an RPSL irt (Incident Response Team) object.
type WhoisIrt struct {
	Irt          string     `db:"irt" json:"irt"`
	Address      *[]string  `db:"address" json:"address,omitempty"`
	Email        *[]string  `db:"email" json:"email,omitempty"`
	AbuseMailbox *[]string  `db:"abuse_mailbox" json:"abuse_mailbox,omitempty"`
	Phone        *[]string  `db:"phone" json:"phone,omitempty"`
	FaxNo        *[]string  `db:"fax_no" json:"fax_no,omitempty"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c,omitempty"`
	TechC        *[]string  `db:"tech_c" json:"tech_c,omitempty"`
	Auth         *[]string  `db:"auth" json:"auth,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by,omitempty"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	LastModified *time.Time `db:"last_modified" json:"last_modified,omitempty"`
	Created      *time.Time `db:"created" json:"created,omitempty"`
	Source       *string    `db:"source" json:"source"`
	Domain       *string    `db:"-" json:"domain,omitempty"`
	MetaAddedAt  *time.Time `db:"meta_added_at" json:"meta_added_at,omitempty"`
	// Freshness / provenance. Same six columns as whoisdb_autnum (migration 0064).
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
}

// StampFetch records that this irt was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisIrt) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisIrt) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeIrt
}

// HandleIrt is not on WhoisRecord; the parser type-asserts onto this struct
// (same idea as HandlePerson on role).
func (w *WhoisIrt) HandleIrt(line string) {
	irt := strings.TrimSpace(strings.TrimPrefix(line, "irt:"))
	if irt != "" {
		w.Irt = irt
	}
}

// HandleAuth is not on WhoisRecord; the parser type-asserts onto WhoisIrt.
func (w *WhoisIrt) HandleAuth(line string) {
	auth := strings.TrimSpace(strings.TrimPrefix(line, "auth:"))
	if auth == "" {
		return
	}
	if w.Auth == nil {
		w.Auth = &[]string{}
	}
	*w.Auth = append(*w.Auth, auth)
}

func (w *WhoisIrt) HandleMultiLine(prevItem, line string) {
	switch prevItem {
	case "address":
		w.HandleAddress(line)
	case "remarks":
		w.HandleRemarks(line)
	case "auth":
		w.HandleAuth(line)
	}
}

func (w *WhoisIrt) HandleAddress(line string) {
	if strings.Contains(strings.ToLower(line), "dummy") {
		return
	}
	address := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
	if address == "" {
		return
	}
	if w.Address == nil {
		w.Address = &[]string{}
	}
	*w.Address = append(*w.Address, address)
}

func (w *WhoisIrt) HandleEmail(line string) {
	email := strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
	if email == "" {
		return
	}
	if strings.Contains(strings.ToLower(email), "unread@ripe.net") {
		return
	}
	if strings.Trim(email, string(email[0])) == "" {
		return
	}
	if w.Email == nil {
		w.Email = &[]string{}
	}
	*w.Email = append(*w.Email, email)
	domain := strings.Index(email, "@")
	if domain != -1 {
		domainPart := email[domain+1:]
		w.Domain = &domainPart
	}
}

func (w *WhoisIrt) HandleAbuseMailbox(line string) {
	abuseMailbox := strings.TrimSpace(strings.TrimPrefix(line, "abuse-mailbox:"))
	if abuseMailbox == "" {
		return
	}
	if strings.Contains(strings.ToLower(abuseMailbox), "unread@ripe.net") {
		return
	}
	if strings.Trim(abuseMailbox, string(abuseMailbox[0])) == "" {
		return
	}
	if w.AbuseMailbox == nil {
		w.AbuseMailbox = &[]string{}
	}
	*w.AbuseMailbox = append(*w.AbuseMailbox, abuseMailbox)
}

func (w *WhoisIrt) HandlePhone(line string) {
	phone := strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
	if phone == "" {
		return
	}
	if w.Phone == nil {
		w.Phone = &[]string{}
	}
	*w.Phone = append(*w.Phone, phone)
}

func (w *WhoisIrt) HandleFaxNo(line string) {
	faxNo := strings.TrimSpace(strings.TrimPrefix(line, "fax-no:"))
	if faxNo == "" {
		return
	}
	if w.FaxNo == nil {
		w.FaxNo = &[]string{}
	}
	*w.FaxNo = append(*w.FaxNo, faxNo)
}

func (w *WhoisIrt) HandleAdminC(line string) {
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

func (w *WhoisIrt) HandleTechC(line string) {
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

func (w *WhoisIrt) HandleMntBy(line string) {
	mntBy := strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:"))
	if mntBy != "" {
		if w.MntBy == nil {
			w.MntBy = &[]string{}
		}
		*w.MntBy = append(*w.MntBy, mntBy)
	}
}

func (w *WhoisIrt) HandleRemarks(line string) {
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		if w.Remarks == nil {
			w.Remarks = &[]string{}
		}
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisIrt) HandleLastModified(line string) {
	lastModified := strings.TrimSpace(strings.TrimPrefix(line, "last-modified:"))
	if lastModified == "" {
		return
	}
	if !strings.Contains(lastModified, "T") {
		lastModified = lastModified + "T00:00:00Z"
	}
	parsedTime, err := time.Parse(time.RFC3339, lastModified)
	if err != nil {
		return
	}
	w.LastModified = &parsedTime
}

func (w *WhoisIrt) HandleCreated(line string) {
	created := strings.TrimSpace(strings.TrimPrefix(line, "created:"))
	if created == "" {
		return
	}
	if !strings.Contains(created, "T") {
		created = created + "T00:00:00Z"
	}
	parsedTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return
	}
	w.Created = &parsedTime
}

func (w *WhoisIrt) HandleSource(line string) {
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisIrt) HandleCountryCode(line string)    {}
func (w *WhoisIrt) HandleOrganization(line string)   {}
func (w *WhoisIrt) HandleAutNum(line string)         {}
func (w *WhoisIrt) HandleInetNum(line string)        {}
func (w *WhoisIrt) HandleInet6Num(line string)       {}
func (w *WhoisIrt) HandleNetName(line string)        {}
func (w *WhoisIrt) HandleGeoloc(line string)         {}
func (w *WhoisIrt) HandleLanguage(line string)       {}
func (w *WhoisIrt) HandleOrg(line string)            {}
func (w *WhoisIrt) HandleAbuseC(line string)         {}
func (w *WhoisIrt) HandleStatus(line string)         {}
func (w *WhoisIrt) HandleNotify(line string)         {}
func (w *WhoisIrt) HandleMntRef(line string)         {}
func (w *WhoisIrt) HandleMntLower(line string)       {}
func (w *WhoisIrt) HandleMntRoutes(line string)      {}
func (w *WhoisIrt) HandleMntDomains(line string)     {}
func (w *WhoisIrt) HandleMntIrt(line string)         {}
func (w *WhoisIrt) HandleRole(line string)           {}
func (w *WhoisIrt) HandleDomain(line string)         {}
func (w *WhoisIrt) HandleNicHdl(line string)         {}
func (w *WhoisIrt) HandleSponsoringOrg(line string)  {}
func (w *WhoisIrt) HandleOrgType(line string)        {}
func (w *WhoisIrt) HandleOrgName(line string)        {}
func (w *WhoisIrt) HandleDescr(line string)          {}
func (w *WhoisIrt) HandleMemberOf(line string)       {}
func (w *WhoisIrt) HandleImportVia(line string)      {}
func (w *WhoisIrt) HandleExportVia(line string)      {}
func (w *WhoisIrt) HandleImport(line string)         {}
func (w *WhoisIrt) HandleExport(line string)         {}
func (w *WhoisIrt) HandleDefault(line string)        {}
func (w *WhoisIrt) HandleMpImport(line string)       {}
func (w *WhoisIrt) HandleMpExport(line string)       {}
func (w *WhoisIrt) HandleMpDefault(line string)      {}
func (w *WhoisIrt) HandleRefNfy(line string)         {}
func (w *WhoisIrt) HandleChanged(line string)        {}
func (w *WhoisIrt) HandleAsName(line string)         {}
func (w *WhoisIrt) HandleCity(line string)           {}
func (w *WhoisIrt) HandleAssignmentSize(line string) {}
func (w *WhoisIrt) HandleOrigin(line string)         {}
func (w *WhoisIrt) HandleInject(line string)         {}
func (w *WhoisIrt) HandleAggrMtd(line string)        {}
func (w *WhoisIrt) HandleAggrBndry(line string)      {}
func (w *WhoisIrt) HandleExportComps(line string)    {}
func (w *WhoisIrt) HandleComponents(line string)     {}
func (w *WhoisIrt) HandleHoles(line string)          {}
func (w *WhoisIrt) HandleRoute(line string)          {}
func (w *WhoisIrt) HandleRoute6(line string)         {}
