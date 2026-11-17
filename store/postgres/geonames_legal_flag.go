package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Legal / treaty flag names in store/postgres/seed/country_legal_flag.sql,
// applied by `opr geonames flags --apply`. Superset clubs are
// separate flags, so WHERE flag = LegalFlagFiveEyes stays exactly the five.
//
// A flag name says exactly what WHERE flag = '<name>' returns. Where a
// club has a looser everyday meaning than the seeded list, the name
// carries the qualifier: eea_efta is the non-EU remainder of the EEA (the
// full EEA is eu ∪ eea_efta) and ofac_comprehensive is the country-wide
// embargo programs only, not every sanctions program.
const (
	LegalFlagEU                = "eu"
	LegalFlagGDPR              = "gdpr"
	LegalFlagEEAEFTA           = "eea_efta"
	LegalFlagUKGDPR            = "uk_gdpr"
	LegalFlagCHFADP            = "ch_fadp"
	LegalFlagEUAdequacy        = "eu_adequacy"
	LegalFlagEUAdequacyUSDPF   = "eu_adequacy_us_dpf"
	LegalFlagUSCCPA            = "us_ccpa"
	LegalFlagOFACComprehensive = "ofac_comprehensive"
	LegalFlagFiveEyes          = "five_eyes"
	LegalFlagNineEyes          = "nine_eyes"
	LegalFlagFourteenEyes      = "fourteen_eyes"
	LegalFlagAUKUS             = "aukus"
	LegalFlagNATO              = "nato"
	LegalFlagSchengen          = "schengen"
	LegalFlagOECD              = "oecd"
	LegalFlagCouncilOfEurope   = "council_of_europe"
)

// LegalFlagSubsetOf are containment invariants the legal-flag seed must satisfy:
// every country carrying the first flag also carries the second. They are
// the reason supersets are seeded as their own flags instead of being
// derived at query time.
var LegalFlagSubsetOf = [][2]string{
	{LegalFlagAUKUS, LegalFlagFiveEyes},
	{LegalFlagFiveEyes, LegalFlagNineEyes},
	{LegalFlagNineEyes, LegalFlagFourteenEyes},
	{LegalFlagEU, LegalFlagGDPR},
	{LegalFlagEEAEFTA, LegalFlagGDPR},
}

// LegalFlagGDPRTerritories are territories that geoip and GeoNames report
// under their own alpha-2 code but that are part of an EU member state, so
// EU law and the GDPR reach them. Without a row of their own they resolve
// to zero flags, which reads as "GDPR does not apply" and is wrong.
//
// They are seeded gdpr, never eu: eu is the member-state list, and a
// territory is covered through its member state rather than in its own
// right. LegalFlagSchengenTerritories is the part of this list the
// Schengen acquis actually reaches. The seed file comment carries the
// per-territory reasoning.
var LegalFlagGDPRTerritories = []string{"AX", "GF", "GP", "MQ", "RE", "YT", "MF"}

// LegalFlagSchengenTerritories are the LegalFlagGDPRTerritories inside the
// Schengen area. Only Åland: the French outermost regions are EU territory
// but the Schengen acquis stops at the European territory of France, so
// they are an external border with their own entry rules.
var LegalFlagSchengenTerritories = []string{"AX"}

// LegalFlagNonEULegalTerritories are the neighbouring codes that must stay
// out of gdpr, so that a hand edit adding "the rest of the overseas
// territories" fails a test instead of asserting EU law where there is
// none. Annex II TFEU overseas countries and territories (BL, PM, NC, PF,
// AW, CW, SX, BQ, GL, WF, TF) plus Svalbard, which Norway's EEA accession
// excludes.
var LegalFlagNonEULegalTerritories = []string{"AW", "BL", "BQ", "CW", "GL", "NC", "PF", "PM", "SJ", "SX", "TF", "WF"}

// LegalDateLayout is how a SQL `date` renders in JSON and on the board.
const LegalDateLayout = "2006-01-02"

// LegalDate wraps the time.Time behind a SQL `date` column so it does not
// marshal as an RFC3339 midnight timestamp. country_legal_flag.as_of is
// the day a list was last confirmed and has no time or zone; emitting
// 2026-09-09T00:00:00Z invites a reader to compare it against a clock.
type LegalDate struct {
	time.Time
}

// NewLegalDate keeps only the calendar day, in UTC.
func NewLegalDate(t time.Time) LegalDate {
	t = t.UTC()
	return LegalDate{Time: time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)}
}

func (d LegalDate) String() string { return d.Format(LegalDateLayout) }

func (d LegalDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(d.Format(LegalDateLayout))), nil
}

func (d *LegalDate) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("as_of must be a %q string: %w", LegalDateLayout, err)
	}
	t, err := time.Parse(LegalDateLayout, s)
	if err != nil {
		return fmt.Errorf("as_of %q is not %q: %w", s, LegalDateLayout, err)
	}
	d.Time = t
	return nil
}

// CountryLegalFlag is one country_legal_flag row. Admin1Code is empty for
// a country-wide flag and an ISO 3166-2 suffix (CA, matching
// geonames_admin1.code 'US.CA') when the list is place-specific. The json
// tags match GeoNamesStatusSnapshot: snake_case, so `--json` is one
// vocabulary across the geonames commands.
type CountryLegalFlag struct {
	ISO        string    `json:"iso"`
	Flag       string    `json:"flag"`
	Admin1Code string    `json:"admin1_code"`
	Source     string    `json:"source"`
	AsOf       LegalDate `json:"as_of"`
	Notes      *string   `json:"notes"`
}

// CountryWide reports whether the row applies to the whole country rather
// than a single admin1.
func (f CountryLegalFlag) CountryWide() bool {
	return f.Admin1Code == ""
}

// listCountryLegalFlagsSQL is an exact by-ISO read: the caller has already
// resolved a country_info.iso. Index scan on the (iso, flag, admin1_code)
// unique key.
const listCountryLegalFlagsSQL = `
SELECT f.iso, f.flag, f.admin1_code, f.source, f.as_of, f.notes
FROM country_legal_flag f
WHERE f.iso = $1
ORDER BY f.flag, f.admin1_code
`

// resolveLegalFlagsSQL is the geoip join path: a raw geoip/geofeed country
// code goes through country_code_remap first (UK→GB, EL→GR) so vendor and
// reserved codes hit the seed. A code with no remap row and no seed row
// (EU, AP) simply matches nothing. Country-wide rows have admin1_code = ”
// and always match; place rows only match the requested admin1.
//
// $3 is IntentionalISOOverrides, the remap sources that are current ISO
// countries themselves (CV). Following those here would give Cabo Verde
// Portugal's flags, so they are excluded from the remap lookup exactly as
// RemapCountryCodeForLegal excludes them in Go. The guard is repeated in
// SQL rather than left to the caller because country_code_remap is a table
// that can drift from the Go seed, and a stale CV→PT row must not be able
// to reintroduce the bug.
const resolveLegalFlagsSQL = `
WITH q AS (
	SELECT
		COALESCE(
			(
				SELECT r.to_code
				FROM country_code_remap r
				WHERE r.from_code = UPPER(TRIM($1))
					AND NOT (r.from_code = ANY($3::text[]))
			),
			NULLIF(UPPER(TRIM($1)), '')
		) AS cc,
		NULLIF(UPPER(TRIM($2)), '') AS admin1
)
SELECT f.iso, f.flag, f.admin1_code, f.source, f.as_of, f.notes
FROM q
JOIN country_legal_flag f ON f.iso = q.cc
WHERE f.admin1_code = '' OR f.admin1_code = q.admin1
ORDER BY f.flag, f.admin1_code
`

// LegalFlagISOsMissingFromCountryInfoSQL is the seed drift check. There is
// no FK (country_info.iso has no unique constraint and the dump may not be
// loaded when the seed is applied), so this is how a seeded ISO that GeoNames does
// not publish gets found. Empty result means the seed is consistent.
const LegalFlagISOsMissingFromCountryInfoSQL = `
SELECT DISTINCT f.iso
FROM country_legal_flag f
WHERE NOT EXISTS (
	SELECT 1 FROM country_info ci WHERE UPPER(ci.iso) = f.iso
)
ORDER BY 1
`

// ListCountryLegalFlags returns every flag for one country_info.iso,
// country-wide and place rows alike. It does not remap, it only uppercases
// and trims: pass an ISO you already trust, and use ResolveLegalFlags for
// an untrusted geoip or geofeed country code.
func (st *Store) ListCountryLegalFlags(ctx context.Context, iso string) ([]CountryLegalFlag, error) {
	iso = strings.ToUpper(strings.TrimSpace(iso))
	if iso == "" {
		return nil, nil
	}
	return st.collectLegalFlags(ctx, listCountryLegalFlagsSQL, iso)
}

// ResolveLegalFlags maps a geoip place tuple onto country_legal_flag
// through country_code_remap. regionCode may be an ISO 3166-2 code with or
// without the country prefix (US-CA or CA); an empty regionCode returns
// country-wide flags only. An unmapped code returns no rows and no error.
//
// The remap is RemapCountryCodeForLegal, not RemapCountryCode: a code that
// is a live ISO country stays itself, so CV resolves as Cabo Verde and not
// as Portugal.
func (st *Store) ResolveLegalFlags(ctx context.Context, countryCode, regionCode string) ([]CountryLegalFlag, error) {
	cc := RemapCountryCodeForLegal(countryCode)
	if cc == "" {
		return nil, nil
	}
	return st.collectLegalFlags(ctx, resolveLegalFlagsSQL, cc, StripISO31662(regionCode), intentionalISOOverrideList())
}

// ListLegalFlagISOsMissingFromCountryInfo is the drift check behind
// `opr geonames flags --check`. It needs a loaded countryInfo dump; an
// empty country_info makes every seeded ISO look missing.
func (st *Store) ListLegalFlagISOsMissingFromCountryInfo(ctx context.Context) ([]string, error) {
	rows, err := st.DB.Query(ctx, LegalFlagISOsMissingFromCountryInfoSQL)
	if err != nil {
		return nil, fmt.Errorf("list legal flag isos missing from country_info: %w", err)
	}
	defer rows.Close()
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("collect legal flag isos missing from country_info: %w", err)
	}
	return out, nil
}

func (st *Store) collectLegalFlags(ctx context.Context, sql string, args ...any) ([]CountryLegalFlag, error) {
	rows, err := st.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query country_legal_flag: %w", err)
	}
	defer rows.Close()

	out := make([]CountryLegalFlag, 0)
	for rows.Next() {
		var f CountryLegalFlag
		var asOf time.Time
		if err := rows.Scan(&f.ISO, &f.Flag, &f.Admin1Code, &f.Source, &asOf, &f.Notes); err != nil {
			return nil, fmt.Errorf("scan country_legal_flag: %w", err)
		}
		f.AsOf = NewLegalDate(asOf)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query country_legal_flag: %w", err)
	}
	return out, nil
}
