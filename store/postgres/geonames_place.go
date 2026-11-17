package postgres

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/text/unicode/norm"
)

// CountryCodeRemap is the static seed also loaded into country_code_remap.
// Reserved/obsolete ISO codes map onto a current country_info.iso. CV→PT is
// the todo.md geofeed bug. Do not map EU/AP/A1/O1/XX (no ISO country).
var CountryCodeRemap = map[string]string{
	"UK": "GB",
	"EL": "GR",
	"CV": "PT",
	"FX": "FR",
	"TP": "TL",
	"ZR": "CD",
	"DD": "DE",
	"BU": "MM",
}

// IntentionalISOOverrides are CountryCodeRemap sources that are themselves
// current ISO countries. CV→PT is the todo.md geofeed bug (Cabo Verde code
// used for Portugal). Anything not in this set must not shadow country_info.
// These are also exactly the entries the legal-flag path must not follow;
// see RemapCountryCodeForLegal.
var IntentionalISOOverrides = map[string]struct{}{
	"CV": {},
}

// UnmappedGeoIPCodes are codes that show up in geoip/geofeeds but must not
// be rewritten to a country. Discovery logs them; it does not insert rows.
var UnmappedGeoIPCodes = map[string]struct{}{
	"EU": {},
	"AP": {},
	"A1": {},
	"A2": {},
	"O1": {},
	"XX": {},
	"ZZ": {},
}

// NormalizeLookupKey matches ingest-time unaccent(lower(trim(...))):
// Unicode lower, NFD, drop combining marks. İstanbul → istanbul.
func NormalizeLookupKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range norm.NFD.String(s) {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// RemapCountryCode applies country_code_remap. Unknown codes pass through.
func RemapCountryCode(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if to, ok := CountryCodeRemap[cc]; ok {
		return to
	}
	return cc
}

// RemapCountryCodeForLegal is RemapCountryCode narrowed for the
// country_legal_flag path: it refuses to follow a remap whose source is
// itself a current ISO country, i.e. any key of IntentionalISOOverrides.
//
// The two functions differ because the two questions differ. Guessing a
// gazetteer centroid for a mislabelled geofeed is a best effort, so
// RemapCountryCode sends CV to Portugal and gets a usable place. A legal
// flag is an assertion about which law reaches an address, so the same
// rewrite would hand Cabo Verde the whole Portuguese set (eu, gdpr,
// schengen, nato, council_of_europe, oecd, nine_eyes, ...). Cabo Verde
// carries none of those, and a wrong yes here is worse than no answer.
//
// Every other remap source is a withdrawn or vendor code with no country
// of its own, so UK→GB, EL→GR, FX→FR, TP→TL, ZR→CD, DD→DE and BU→MM still
// apply. Non-country codes (EU, AP, A1, XX, ...) pass through unchanged
// and simply match no seed row.
func RemapCountryCodeForLegal(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if _, override := IntentionalISOOverrides[cc]; override {
		return cc
	}
	return RemapCountryCode(cc)
}

// RemapDecision is the result of matching geoip country codes against
// country_info.iso and CountryCodeRemap.
type RemapDecision struct {
	Insert   map[string]string // from → to, only if to is in country_info
	Unmapped []string          // leftover (EU/AP, XK if absent, …)
}

// DecideCountryCodeRemaps chooses INSERT rows for geoip codes that are not
// in country_info and not already remapped. Target must exist in isoSet.
func DecideCountryCodeRemaps(geoipCodes []string, isoSet, existing map[string]struct{}) RemapDecision {
	d := RemapDecision{Insert: map[string]string{}}
	seenUnmapped := map[string]struct{}{}
	for _, raw := range geoipCodes {
		cc := strings.ToUpper(strings.TrimSpace(raw))
		if cc == "" {
			continue
		}
		if _, ok := isoSet[cc]; ok {
			if _, override := IntentionalISOOverrides[cc]; !override {
				continue
			}
		}
		if existing != nil {
			if _, ok := existing[cc]; ok {
				continue
			}
		}
		if _, skip := UnmappedGeoIPCodes[cc]; skip {
			if _, ok := seenUnmapped[cc]; !ok {
				seenUnmapped[cc] = struct{}{}
				d.Unmapped = append(d.Unmapped, cc)
			}
			continue
		}
		if to, ok := CountryCodeRemap[cc]; ok {
			if _, ok := isoSet[to]; ok {
				d.Insert[cc] = to
				continue
			}
		}
		if _, ok := seenUnmapped[cc]; ok {
			continue
		}
		seenUnmapped[cc] = struct{}{}
		d.Unmapped = append(d.Unmapped, cc)
	}
	sort.Strings(d.Unmapped)
	return d
}

// StripISO31662 turns US-CA into CA. A bare CA stays CA.
func StripISO31662(regionCode string) string {
	s := strings.ToUpper(strings.TrimSpace(regionCode))
	if s == "" {
		return ""
	}
	cc, rest, ok := strings.Cut(s, "-")
	if ok && len(cc) == 2 && rest != "" {
		return rest
	}
	return s
}

// ZipLookupKeys returns the raw zip and a US ZIP5 variant when the input
// looks like ZIP+4 (80202-1234 or 802021234 → 80202). zip5 is empty when
// it would duplicate raw.
func ZipLookupKeys(zip string) (raw, zip5 string) {
	raw = strings.TrimSpace(zip)
	if raw == "" {
		return "", ""
	}
	digits := zipDigitsOnly(raw)
	if looksLikeUSZIP4(raw, digits) {
		zip5 = digits[:5]
		if zip5 == raw {
			return raw, ""
		}
		return raw, zip5
	}
	return raw, ""
}

func zipDigitsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func looksLikeUSZIP4(raw, digits string) bool {
	if len(digits) != 9 {
		return false
	}
	if raw == digits {
		return true
	}
	left, right, ok := strings.Cut(raw, "-")
	if !ok {
		return false
	}
	return zipDigitsOnly(left) == left && len(left) == 5 &&
		zipDigitsOnly(right) == right && len(right) == 4
}

// GeoNamesPlace is one resolved gazetteer hit. City is display-only for
// fill-if-empty; never used to overwrite a geofeed/LACNIC city.
type GeoNamesPlace struct {
	GeonameID     *int64
	Lat           *float64
	Lon           *float64
	Timezone      *string
	ZipForDisplay *string
	AdminName1    *string
	MatchKind     string
	City          *string
	CountryCode   string
	CallCode      *string
	CCTLD         *string
	Currency      *string
	CurrencyCode  *string
}

// GeoNamesLookupRow is one geonames_lookup key, used by the in-memory
// cascade that locks priority order without a live dump.
type GeoNamesLookupRow struct {
	CountryCode   string
	Admin1ISO     string
	CityNorm      string
	Zipcode       string
	AliasNorm     string
	GeonameID     int64
	Lat           float64
	Lon           float64
	Timezone      string
	Population    int64
	ZipForDisplay string
	AdminName1    string
	MatchKind     string
}

// GeoNamesCountryMeta is the country_info + timezone grain the cascade
// needs for the remapped ISO check and country-only fallback.
type GeoNamesCountryMeta struct {
	Capital   string
	Timezones []string
}

type geoNamesPlaceInput struct {
	CC         string
	Zip        string
	Zip5       string
	Admin1     string
	CityNorm   string
	RegionNorm string
}

func prepareGeoNamesPlaceInput(countryCode, regionCode, region, city, zip string) geoNamesPlaceInput {
	raw, zip5 := ZipLookupKeys(zip)
	return geoNamesPlaceInput{
		CC:         RemapCountryCode(countryCode),
		Zip:        raw,
		Zip5:       zip5,
		Admin1:     StripISO31662(regionCode),
		CityNorm:   NormalizeLookupKey(city),
		RegionNorm: NormalizeLookupKey(region),
	}
}

func lookupNameMatches(row GeoNamesLookupRow, norm string) bool {
	return norm != "" && (row.CityNorm == norm || row.AliasNorm == norm)
}

func zipMatches(row GeoNamesLookupRow, in geoNamesPlaceInput) bool {
	if row.Zipcode == "" {
		return false
	}
	if in.Zip != "" && row.Zipcode == in.Zip {
		return true
	}
	return in.Zip5 != "" && row.Zipcode == in.Zip5
}

func cascadePriority(row GeoNamesLookupRow, in geoNamesPlaceInput) (int, bool) {
	if zipMatches(row, in) {
		return 1, true
	}
	if in.CityNorm != "" && in.Admin1 != "" && row.Admin1ISO == in.Admin1 && lookupNameMatches(row, in.CityNorm) {
		return 2, true
	}
	if in.CityNorm != "" && in.RegionNorm != "" && lookupNameMatches(row, in.CityNorm) && NormalizeLookupKey(row.AdminName1) == in.RegionNorm {
		return 2, true
	}
	if in.CityNorm != "" && in.RegionNorm != "" && lookupNameMatches(row, in.RegionNorm) && NormalizeLookupKey(row.AdminName1) == in.CityNorm {
		return 3, true
	}
	if in.CityNorm != "" && lookupNameMatches(row, in.CityNorm) {
		return 4, true
	}
	if in.CityNorm == "" && in.RegionNorm != "" && lookupNameMatches(row, in.RegionNorm) {
		return 5, true
	}
	return 0, false
}

func singleTimezone(meta GeoNamesCountryMeta) (string, bool) {
	seen := make(map[string]struct{}, len(meta.Timezones))
	var tz string
	for _, id := range meta.Timezones {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		tz = id
	}
	if len(seen) != 1 {
		return "", false
	}
	return tz, true
}

func betterPlaceHit(best, cand GeoNamesLookupRow, bestPri, candPri int) bool {
	if candPri != bestPri {
		return candPri < bestPri
	}
	bestCap := best.MatchKind == "capital"
	candCap := cand.MatchKind == "capital"
	if candCap != bestCap {
		return candCap
	}
	return cand.Population > best.Population
}

func placeFromLookupRow(row GeoNamesLookupRow, cc string, meta GeoNamesCountryMeta, tzFallback string) *GeoNamesPlace {
	p := &GeoNamesPlace{
		MatchKind:   row.MatchKind,
		CountryCode: cc,
	}
	if row.GeonameID != 0 {
		id := row.GeonameID
		p.GeonameID = &id
	}
	lat, lon := row.Lat, row.Lon
	p.Lat, p.Lon = &lat, &lon
	tz := row.Timezone
	if tz == "" {
		tz = tzFallback
	}
	if tz != "" {
		p.Timezone = &tz
	}
	if row.ZipForDisplay != "" {
		z := row.ZipForDisplay
		p.ZipForDisplay = &z
	}
	if row.AdminName1 != "" {
		a := row.AdminName1
		p.AdminName1 = &a
	}
	if row.CityNorm != "" {
		c := row.CityNorm
		p.City = &c
	} else if meta.Capital != "" && row.MatchKind == "capital" {
		c := meta.Capital
		p.City = &c
	}
	return p
}

// ResolvePlaceFromLookup is the production cascade over in-memory rows.
// SQL in ResolveGeoNamesPlaceSQL must keep the same priority order.
func ResolvePlaceFromLookup(rows []GeoNamesLookupRow, countries map[string]GeoNamesCountryMeta, countryCode, regionCode, region, city, zip string) *GeoNamesPlace {
	in := prepareGeoNamesPlaceInput(countryCode, regionCode, region, city, zip)
	if in.CC == "" {
		return nil
	}
	meta, ok := countries[in.CC]
	if !ok {
		return nil
	}
	tzFallback, singleTZ := singleTimezone(meta)

	var (
		best    GeoNamesLookupRow
		bestPri int
		found   bool
	)
	consider := func(row GeoNamesLookupRow, pri int) {
		if !found || betterPlaceHit(best, row, bestPri, pri) {
			best, bestPri, found = row, pri, true
		}
	}

	capitalNorm := NormalizeLookupKey(meta.Capital)
	for _, row := range rows {
		if row.CountryCode != in.CC {
			continue
		}
		if pri, ok := cascadePriority(row, in); ok {
			consider(row, pri)
		}
		if singleTZ && (row.MatchKind == "capital" || (capitalNorm != "" && lookupNameMatches(row, capitalNorm))) {
			consider(row, 6)
		}
	}
	if found {
		return placeFromLookupRow(best, in.CC, meta, tzFallback)
	}
	if !singleTZ || meta.Capital == "" {
		return nil
	}
	return &GeoNamesPlace{
		Timezone:    &tzFallback,
		MatchKind:   "capital",
		City:        &meta.Capital,
		CountryCode: in.CC,
	}
}

// ResolveGeoNamesPlaceSQL is one indexed round-trip. Query-side names are
// already normalized in Go; equality is on stored city_norm / alias_norm.
// UNACCENT is only used on unindexed admin_name_1 / country_info.capital.
const ResolveGeoNamesPlaceSQL = `
WITH q AS (
	SELECT
		COALESCE(
			(SELECT r.to_code FROM country_code_remap r WHERE r.from_code = UPPER(TRIM($1))),
			NULLIF(UPPER(TRIM($1)), '')
		) AS cc,
		NULLIF(TRIM($2), '') AS zip,
		NULLIF(TRIM($3), '') AS zip5,
		NULLIF(UPPER(TRIM($4)), '') AS admin1,
		NULLIF($5, '') AS city_norm,
		NULLIF($6, '') AS region_norm
)
SELECT
	m.geonameid,
	m.lat,
	m.lon,
	COALESCE(NULLIF(m.timezone, ''), tz.timezone_id) AS timezone,
	m.zip_for_display,
	m.admin_name_1,
	m.match_kind,
	COALESCE(city.name, ci.capital) AS city,
	q.cc,
	ci.phone,
	ci.tld,
	ci.currency_name,
	ci.currency_code
FROM q
JOIN country_info ci ON ci.iso = q.cc
LEFT JOIN LATERAL (
	SELECT MIN(t.timezone_id) AS timezone_id
	FROM geonames_timezone t
	WHERE t.country_code = q.cc
	HAVING COUNT(*) = 1
) tz ON TRUE
JOIN LATERAL (
	SELECT
		hits.geonameid,
		hits.lat,
		hits.lon,
		hits.timezone,
		hits.zip_for_display,
		hits.admin_name_1,
		hits.match_kind,
		hits.population,
		hits.priority
	FROM (
		SELECT 1 AS priority, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.zip IS NOT NULL
			AND l.zipcode = q.zip

		UNION ALL

		SELECT 1, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.zip5 IS NOT NULL
			AND q.zip5 IS DISTINCT FROM q.zip
			AND l.zipcode = q.zip5

		UNION ALL

		SELECT 2, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.admin1 IS NOT NULL
			AND q.city_norm IS NOT NULL
			AND l.admin1_iso = q.admin1
			AND l.city_norm = q.city_norm

		UNION ALL

		SELECT 2, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.admin1 IS NOT NULL
			AND q.city_norm IS NOT NULL
			AND l.admin1_iso = q.admin1
			AND l.alias_norm = q.city_norm

		UNION ALL

		SELECT 2, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NOT NULL
			AND q.region_norm IS NOT NULL
			AND l.city_norm = q.city_norm
			AND unaccent(lower(trim(COALESCE(l.admin_name_1, '')))) = q.region_norm

		UNION ALL

		SELECT 3, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NOT NULL
			AND q.region_norm IS NOT NULL
			AND l.city_norm = q.region_norm
			AND unaccent(lower(trim(COALESCE(l.admin_name_1, '')))) = q.city_norm

		UNION ALL

		SELECT 3, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NOT NULL
			AND q.region_norm IS NOT NULL
			AND l.alias_norm = q.region_norm
			AND unaccent(lower(trim(COALESCE(l.admin_name_1, '')))) = q.city_norm

		UNION ALL

		SELECT 4, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NOT NULL
			AND l.city_norm = q.city_norm

		UNION ALL

		SELECT 4, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NOT NULL
			AND l.alias_norm = q.city_norm

		UNION ALL

		SELECT 5, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NULL
			AND q.region_norm IS NOT NULL
			AND l.city_norm = q.region_norm

		UNION ALL

		SELECT 5, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND q.city_norm IS NULL
			AND q.region_norm IS NOT NULL
			AND l.alias_norm = q.region_norm

		UNION ALL

		SELECT 6, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND l.match_kind = 'capital'
			AND tz.timezone_id IS NOT NULL

		UNION ALL

		SELECT 6, l.geonameid, l.lat, l.lon, l.timezone, l.zip_for_display, l.admin_name_1, l.match_kind, l.population
		FROM geonames_lookup l
		WHERE l.country_code = q.cc
			AND tz.timezone_id IS NOT NULL
			AND l.city_norm = unaccent(lower(trim(COALESCE(ci.capital, ''))))

		UNION ALL

		SELECT 6, ci.geoname_id::bigint, NULL::double precision, NULL::double precision,
			tz.timezone_id, NULL::text, NULL::text, 'capital', NULL::bigint
		WHERE tz.timezone_id IS NOT NULL
	) hits
	ORDER BY
		hits.priority,
		CASE WHEN hits.match_kind = 'capital' THEN 0 ELSE 1 END,
		hits.population DESC NULLS LAST
	LIMIT 1
) m ON TRUE
LEFT JOIN geonames_city city ON city.geonameid = m.geonameid
`

// ResolveGeoNamesPlace maps a GeoIP place tuple onto geonames_lookup.
// Pass RegionCode (ISO 3166-2) and zip; Region is the display-name fallback.
func (st *Store) ResolveGeoNamesPlace(ctx context.Context, countryCode, regionCode, region, city, zip string) (*GeoNamesPlace, error) {
	in := prepareGeoNamesPlaceInput(countryCode, regionCode, region, city, zip)
	if in.CC == "" {
		return nil, nil
	}

	var p GeoNamesPlace
	err := st.DB.QueryRow(ctx, ResolveGeoNamesPlaceSQL,
		in.CC, in.Zip, in.Zip5, in.Admin1, in.CityNorm, in.RegionNorm,
	).Scan(
		&p.GeonameID,
		&p.Lat,
		&p.Lon,
		&p.Timezone,
		&p.ZipForDisplay,
		&p.AdminName1,
		&p.MatchKind,
		&p.City,
		&p.CountryCode,
		&p.CallCode,
		&p.CCTLD,
		&p.Currency,
		&p.CurrencyCode,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		st.logger.Error("failed to resolve geonames place",
			zap.Error(err),
			zap.String("country_code", in.CC),
			zap.String("region_code", in.Admin1),
			zap.String("city_norm", in.CityNorm),
		)
		return nil, err
	}
	return &p, nil
}
