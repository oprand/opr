package whoisdb

import (
	"github.com/oprand/opr/internal/opconst"
	"strings"
	"time"
)

// WhoisPerson matches the unused whoisdb_person table (migration 0048).
// Bulk dump ingest does not persist this type: RPSL person: objects share the
// nic-hdl namespace with role and are stored as WhoisRole (rdap_kind=individual)
// so admin-c/tech-c/abuse-c lookups against whoisdb_role resolve. Do not add a
// parallel SaveWhoisPerson path without joining whoisdb_person in those views.

type WhoisPerson struct {
	Person       *string   `db:"person" json:"person"`
	NicHdl       string    `db:"nic_hdl" json:"nic_hdl"`
	Address      *[]string `db:"address" json:"address"`
	CountryCode  *string   `db:"country_code" json:"country_code"`
	Phone        []string  `db:"phone" json:"phone"`
	FaxNo        *[]string `db:"fax_no" json:"fax_no,omitempty"`
	Email        *[]string `db:"email" json:"email"`
	Remarks      *[]string `db:"remarks" json:"remarks,omitempty"`
	Notify       *[]string `db:"notify" json:"notify,omitempty"`
	AbuseMailbox *[]string `db:"abuse_mailbox" json:"abuse_mailbox,omitempty"`
	MntBy        *[]string `db:"mnt_by" json:"mnt_by"`
	LastModified *string   `db:"last_modified" json:"last_modified"`
	Source       *string   `db:"source" json:"source"`
	// Expanded data points
	Domain  *string `db:"domain" json:"domain"`
	Country *string `db:"country" json:"country"`
	// Meta
	MetaAddedAt *time.Time `db:"meta_added_at" json:"meta_added_at"`
}

func (w WhoisPerson) GetRecordType() opconst.RecordType {
	return opconst.RecordTypePerson
}
func (w *WhoisPerson) HandleImport(line string)       {}
func (w *WhoisPerson) HandleExport(line string)       {}
func (w *WhoisPerson) HandleOrganization(line string) {}

func (w *WhoisPerson) HandleCountryCode(line string) {
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

func (w *WhoisPerson) HandleSource(line string) {
	// Remove any comments
	if strings.Contains(line, "#") {
		line = line[:strings.Index(line, "#")]
	}
	source := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "source:")))
	if source != "" {
		w.Source = &source
	}
}

func (w *WhoisPerson) HandleAggrMtd(line string)     {}
func (w *WhoisPerson) HandleAggrBndry(line string)   {}
func (w *WhoisPerson) HandleExportComps(line string) {}
func (w *WhoisPerson) HandleComponents(line string)  {}

func (w *WhoisPerson) HandleRoute(line string)  {}
func (w *WhoisPerson) HandleRoute6(line string) {}
func (w *WhoisPerson) HandleHoles(line string)  {}

func (w *WhoisPerson) HandleOrigin(line string) {}
