package whoisdb

import (
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

// WhoisAsSet is an RPSL as-set object (named collection of ASNs / as-sets).
type WhoisAsSet struct {
	AsSet        string     `db:"as_set" json:"as_set"`
	Descr        *[]string  `db:"descr" json:"descr,omitempty"`
	Members      *[]string  `db:"members" json:"members,omitempty"`
	MbrsByRef    *[]string  `db:"mbrs_by_ref" json:"mbrs_by_ref,omitempty"`
	Org          *string    `db:"org" json:"org,omitempty"`
	TechC        *[]string  `db:"tech_c" json:"tech_c,omitempty"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by,omitempty"`
	MntLower     *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	Notify       *[]string  `db:"notify" json:"notify,omitempty"`
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

// StampFetch records that this as-set was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisAsSet) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisAsSet) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeAsSet
}

// HandleAsSet is not on WhoisRecord; the parser type-asserts onto this struct
// (same idea as HandlePerson on role).
func (w *WhoisAsSet) HandleAsSet(line string) {
	name := strings.TrimSpace(strings.TrimPrefix(line, "as-set:"))
	if name != "" {
		w.AsSet = name
	}
}

// HandleMembers is not on WhoisRecord; the parser type-asserts onto WhoisAsSet.
func (w *WhoisAsSet) HandleMembers(line string) {
	member := strings.TrimSpace(strings.TrimPrefix(line, "members:"))
	if member == "" {
		return
	}
	if w.Members == nil {
		w.Members = &[]string{}
	}
	*w.Members = append(*w.Members, member)
}

// HandleMbrsByRef is not on WhoisRecord; the parser type-asserts onto WhoisAsSet.
func (w *WhoisAsSet) HandleMbrsByRef(line string) {
	ref := strings.TrimSpace(strings.TrimPrefix(line, "mbrs-by-ref:"))
	if ref == "" {
		return
	}
	if w.MbrsByRef == nil {
		w.MbrsByRef = &[]string{}
	}
	*w.MbrsByRef = append(*w.MbrsByRef, ref)
}

func (w *WhoisAsSet) HandleMultiLine(prevItem, line string) {
	switch prevItem {
	case "descr":
		w.HandleDescr(line)
	case "remarks":
		w.HandleRemarks(line)
	case "members":
		w.HandleMembers(line)
	case "mbrs-by-ref":
		w.HandleMbrsByRef(line)
	case "notify":
		w.HandleNotify(line)
	}
}

func (w *WhoisAsSet) HandleDescr(line string) {
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if description != "" {
		if w.Descr == nil {
			w.Descr = &[]string{}
		}
		*w.Descr = append(*w.Descr, description)
	}
}

func (w *WhoisAsSet) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		w.Org = &org
	}
}

func (w *WhoisAsSet) HandleAdminC(line string) {
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

func (w *WhoisAsSet) HandleTechC(line string) {
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

func (w *WhoisAsSet) HandleMntBy(line string) {
	mntBy := strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:"))
	if mntBy != "" {
		if w.MntBy == nil {
			w.MntBy = &[]string{}
		}
		*w.MntBy = append(*w.MntBy, mntBy)
	}
}

func (w *WhoisAsSet) HandleMntLower(line string) {
	mntLower := strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:"))
	if mntLower != "" {
		if w.MntLower == nil {
			w.MntLower = &[]string{}
		}
		*w.MntLower = append(*w.MntLower, mntLower)
	}
}

func (w *WhoisAsSet) HandleRemarks(line string) {
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		if w.Remarks == nil {
			w.Remarks = &[]string{}
		}
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisAsSet) HandleNotify(line string) {
	notify := strings.TrimSpace(strings.TrimPrefix(line, "notify:"))
	if notify == "" {
		return
	}
	if w.Notify == nil {
		w.Notify = &[]string{}
	}
	*w.Notify = append(*w.Notify, notify)
	for _, segment := range strings.Split(notify, " ") {
		domain := strings.Index(segment, "@")
		if domain != -1 {
			domainPart := segment[domain+1:]
			w.Domain = &domainPart
		}
	}
}

func (w *WhoisAsSet) HandleLastModified(line string) {
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

func (w *WhoisAsSet) HandleCreated(line string) {
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

func (w *WhoisAsSet) HandleSource(line string) {
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisAsSet) HandleCountryCode(line string)    {}
func (w *WhoisAsSet) HandleOrganization(line string)   {}
func (w *WhoisAsSet) HandleAutNum(line string)         {}
func (w *WhoisAsSet) HandleInetNum(line string)        {}
func (w *WhoisAsSet) HandleInet6Num(line string)       {}
func (w *WhoisAsSet) HandleNetName(line string)        {}
func (w *WhoisAsSet) HandleGeoloc(line string)         {}
func (w *WhoisAsSet) HandleLanguage(line string)       {}
func (w *WhoisAsSet) HandleAbuseC(line string)         {}
func (w *WhoisAsSet) HandleStatus(line string)         {}
func (w *WhoisAsSet) HandleMntRef(line string)         {}
func (w *WhoisAsSet) HandleMntRoutes(line string)      {}
func (w *WhoisAsSet) HandleMntDomains(line string)     {}
func (w *WhoisAsSet) HandleMntIrt(line string)         {}
func (w *WhoisAsSet) HandleRole(line string)           {}
func (w *WhoisAsSet) HandleDomain(line string)         {}
func (w *WhoisAsSet) HandlePhone(line string)          {}
func (w *WhoisAsSet) HandleFaxNo(line string)          {}
func (w *WhoisAsSet) HandleEmail(line string)          {}
func (w *WhoisAsSet) HandleAddress(line string)        {}
func (w *WhoisAsSet) HandleNicHdl(line string)         {}
func (w *WhoisAsSet) HandleAbuseMailbox(line string)   {}
func (w *WhoisAsSet) HandleSponsoringOrg(line string)  {}
func (w *WhoisAsSet) HandleOrgType(line string)        {}
func (w *WhoisAsSet) HandleOrgName(line string)        {}
func (w *WhoisAsSet) HandleMemberOf(line string)       {}
func (w *WhoisAsSet) HandleImportVia(line string)      {}
func (w *WhoisAsSet) HandleExportVia(line string)      {}
func (w *WhoisAsSet) HandleImport(line string)         {}
func (w *WhoisAsSet) HandleExport(line string)         {}
func (w *WhoisAsSet) HandleDefault(line string)        {}
func (w *WhoisAsSet) HandleMpImport(line string)       {}
func (w *WhoisAsSet) HandleMpExport(line string)       {}
func (w *WhoisAsSet) HandleMpDefault(line string)      {}
func (w *WhoisAsSet) HandleRefNfy(line string)         {}
func (w *WhoisAsSet) HandleChanged(line string)        {}
func (w *WhoisAsSet) HandleAsName(line string)         {}
func (w *WhoisAsSet) HandleCity(line string)           {}
func (w *WhoisAsSet) HandleAssignmentSize(line string) {}
func (w *WhoisAsSet) HandleOrigin(line string)         {}
func (w *WhoisAsSet) HandleInject(line string)         {}
func (w *WhoisAsSet) HandleAggrMtd(line string)        {}
func (w *WhoisAsSet) HandleAggrBndry(line string)      {}
func (w *WhoisAsSet) HandleExportComps(line string)    {}
func (w *WhoisAsSet) HandleComponents(line string)     {}
func (w *WhoisAsSet) HandleHoles(line string)          {}
func (w *WhoisAsSet) HandleRoute(line string)          {}
func (w *WhoisAsSet) HandleRoute6(line string)         {}
