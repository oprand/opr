package whoisdb

import (
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
)

// WhoisAsBlock is an RPSL as-block object (inclusive ASN range).
type WhoisAsBlock struct {
	AsBlock      string     `db:"as_block" json:"as_block"`
	AsnStart     uint32     `db:"asn_start" json:"asn_start"`
	AsnEnd       uint32     `db:"asn_end" json:"asn_end"`
	Descr        *[]string  `db:"descr" json:"descr,omitempty"`
	CountryCode  *string    `db:"country_code" json:"country_code,omitempty"`
	Org          *string    `db:"org" json:"org,omitempty"`
	AdminC       *[]string  `db:"admin_c" json:"admin_c,omitempty"`
	TechC        *[]string  `db:"tech_c" json:"tech_c,omitempty"`
	MntBy        *[]string  `db:"mnt_by" json:"mnt_by,omitempty"`
	MntLower     *[]string  `db:"mnt_lower" json:"mnt_lower,omitempty"`
	Remarks      *[]string  `db:"remarks" json:"remarks,omitempty"`
	LastModified *time.Time `db:"last_modified" json:"last_modified,omitempty"`
	Created      *time.Time `db:"created" json:"created,omitempty"`
	Source       *string    `db:"source" json:"source"`
	Country      *string    `db:"-" json:"country,omitempty"`
	MetaAddedAt  *time.Time `db:"meta_added_at" json:"meta_added_at,omitempty"`
	// Freshness / provenance. Same six columns as whoisdb_autnum (migration 0064).
	LastFetchedAt      *time.Time `db:"last_fetched_at" json:"last_fetched_at,omitempty"`
	LastChangedAt      *time.Time `db:"last_changed_at" json:"last_changed_at,omitempty"`
	ContentHash        *string    `db:"content_hash" json:"content_hash,omitempty"`
	FetchMethod        *string    `db:"fetch_method" json:"fetch_method,omitempty"`
	IsPartial          *bool      `db:"is_partial" json:"is_partial,omitempty"`
	LastSeenInSourceAt *time.Time `db:"last_seen_in_source_at" json:"last_seen_in_source_at,omitempty"`
}

// StampFetch records that this as-block was observed via method. Nil-safe;
// upsert COALESCE leaves existing freshness when these pointers stay nil.
func (w *WhoisAsBlock) StampFetch(method string) {
	if w == nil {
		return
	}
	w.FetchMethod, w.LastFetchedAt, w.LastSeenInSourceAt = stampFetch(method)
}

func (w WhoisAsBlock) GetRecordType() opconst.RecordType {
	return opconst.RecordTypeAsBlock
}

// ParseAsBlockRange parses an RPSL as-block value into inclusive ASN bounds.
// Accepts "AS37945 - AS37950", "AS147191-AS147290", optional "AS" prefix on
// either side, and a single ASN (start==end). Comments after # are stripped.
// Returns ok=false for junk, incomplete values, ASN 0, or inverted ranges.
func ParseAsBlockRange(value string) (start, end uint32, ok bool) {
	value = strings.TrimSpace(value)
	if i := strings.Index(value, "#"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if value == "" {
		return 0, 0, false
	}

	parts := strings.Split(value, "-")
	switch len(parts) {
	case 1:
		n, parsed := parseASNToken(parts[0])
		if !parsed {
			return 0, 0, false
		}
		return n, n, true
	case 2:
		a, okA := parseASNToken(parts[0])
		b, okB := parseASNToken(parts[1])
		if !okA || !okB || a > b {
			return 0, 0, false
		}
		return a, b, true
	default:
		return 0, 0, false
	}
}

func parseASNToken(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// HandleAsBlock is not on WhoisRecord; the parser type-asserts onto this struct
// (same idea as HandlePerson on role).
func (w *WhoisAsBlock) HandleAsBlock(line string) {
	val := strings.TrimSpace(strings.TrimPrefix(line, "as-block:"))
	if val == "" {
		return
	}
	if i := strings.Index(val, "#"); i >= 0 {
		val = strings.TrimSpace(val[:i])
	}
	w.AsBlock = val
	if start, end, ok := ParseAsBlockRange(val); ok {
		w.AsnStart = start
		w.AsnEnd = end
	}
}

func (w *WhoisAsBlock) HandleMultiLine(prevItem, line string) {
	switch prevItem {
	case "descr":
		w.HandleDescr(line)
	case "remarks":
		w.HandleRemarks(line)
	}
}

func (w *WhoisAsBlock) HandleDescr(line string) {
	description := strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
	if description != "" {
		if w.Descr == nil {
			w.Descr = &[]string{}
		}
		*w.Descr = append(*w.Descr, description)
	}
}

func (w *WhoisAsBlock) HandleCountryCode(line string) {
	countryCode := strings.TrimSpace(strings.TrimPrefix(line, "country:"))
	if strings.Contains(countryCode, "#") {
		countryCode = countryCode[:strings.Index(countryCode, "#")]
		countryCode = strings.TrimSpace(countryCode)
	}
	countryCode = strings.ToUpper(countryCode)
	if countryCode == "" {
		return
	}
	w.CountryCode = &countryCode
	country, ok := opconst.CountryCode[countryCode]
	if ok {
		w.Country = &country
	}
}

func (w *WhoisAsBlock) HandleOrg(line string) {
	org := strings.TrimSpace(strings.TrimPrefix(line, "org:"))
	if org != "" {
		w.Org = &org
	}
}

func (w *WhoisAsBlock) HandleAdminC(line string) {
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

func (w *WhoisAsBlock) HandleTechC(line string) {
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

func (w *WhoisAsBlock) HandleMntBy(line string) {
	mntBy := strings.TrimSpace(strings.TrimPrefix(line, "mnt-by:"))
	if mntBy != "" {
		if w.MntBy == nil {
			w.MntBy = &[]string{}
		}
		*w.MntBy = append(*w.MntBy, mntBy)
	}
}

func (w *WhoisAsBlock) HandleMntLower(line string) {
	mntLower := strings.TrimSpace(strings.TrimPrefix(line, "mnt-lower:"))
	if mntLower != "" {
		if w.MntLower == nil {
			w.MntLower = &[]string{}
		}
		*w.MntLower = append(*w.MntLower, mntLower)
	}
}

func (w *WhoisAsBlock) HandleRemarks(line string) {
	remark := strings.TrimSpace(strings.TrimPrefix(line, "remarks:"))
	if remark != "" {
		if w.Remarks == nil {
			w.Remarks = &[]string{}
		}
		*w.Remarks = append(*w.Remarks, remark)
	}
}

func (w *WhoisAsBlock) HandleLastModified(line string) {
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

func (w *WhoisAsBlock) HandleCreated(line string) {
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

func (w *WhoisAsBlock) HandleSource(line string) {
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisAsBlock) HandleOrganization(line string)   {}
func (w *WhoisAsBlock) HandleAutNum(line string)         {}
func (w *WhoisAsBlock) HandleInetNum(line string)        {}
func (w *WhoisAsBlock) HandleInet6Num(line string)       {}
func (w *WhoisAsBlock) HandleNetName(line string)        {}
func (w *WhoisAsBlock) HandleGeoloc(line string)         {}
func (w *WhoisAsBlock) HandleLanguage(line string)       {}
func (w *WhoisAsBlock) HandleAbuseC(line string)         {}
func (w *WhoisAsBlock) HandleStatus(line string)         {}
func (w *WhoisAsBlock) HandleNotify(line string)         {}
func (w *WhoisAsBlock) HandleMntRef(line string)         {}
func (w *WhoisAsBlock) HandleMntRoutes(line string)      {}
func (w *WhoisAsBlock) HandleMntDomains(line string)     {}
func (w *WhoisAsBlock) HandleMntIrt(line string)         {}
func (w *WhoisAsBlock) HandleRole(line string)           {}
func (w *WhoisAsBlock) HandleDomain(line string)         {}
func (w *WhoisAsBlock) HandlePhone(line string)          {}
func (w *WhoisAsBlock) HandleFaxNo(line string)          {}
func (w *WhoisAsBlock) HandleEmail(line string)          {}
func (w *WhoisAsBlock) HandleAddress(line string)        {}
func (w *WhoisAsBlock) HandleNicHdl(line string)         {}
func (w *WhoisAsBlock) HandleAbuseMailbox(line string)   {}
func (w *WhoisAsBlock) HandleSponsoringOrg(line string)  {}
func (w *WhoisAsBlock) HandleOrgType(line string)        {}
func (w *WhoisAsBlock) HandleOrgName(line string)        {}
func (w *WhoisAsBlock) HandleMemberOf(line string)       {}
func (w *WhoisAsBlock) HandleImportVia(line string)      {}
func (w *WhoisAsBlock) HandleExportVia(line string)      {}
func (w *WhoisAsBlock) HandleImport(line string)         {}
func (w *WhoisAsBlock) HandleExport(line string)         {}
func (w *WhoisAsBlock) HandleDefault(line string)        {}
func (w *WhoisAsBlock) HandleMpImport(line string)       {}
func (w *WhoisAsBlock) HandleMpExport(line string)       {}
func (w *WhoisAsBlock) HandleMpDefault(line string)      {}
func (w *WhoisAsBlock) HandleRefNfy(line string)         {}
func (w *WhoisAsBlock) HandleChanged(line string)        {}
func (w *WhoisAsBlock) HandleAsName(line string)         {}
func (w *WhoisAsBlock) HandleCity(line string)           {}
func (w *WhoisAsBlock) HandleAssignmentSize(line string) {}
func (w *WhoisAsBlock) HandleOrigin(line string)         {}
func (w *WhoisAsBlock) HandleInject(line string)         {}
func (w *WhoisAsBlock) HandleAggrMtd(line string)        {}
func (w *WhoisAsBlock) HandleAggrBndry(line string)      {}
func (w *WhoisAsBlock) HandleExportComps(line string)    {}
func (w *WhoisAsBlock) HandleComponents(line string)     {}
func (w *WhoisAsBlock) HandleHoles(line string)          {}
func (w *WhoisAsBlock) HandleRoute(line string)          {}
func (w *WhoisAsBlock) HandleRoute6(line string)         {}
