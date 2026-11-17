package geonames

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/internal/oputils"
	"github.com/oprand/opr/store/postgres"
)

// KeepAltNameLanguages is the isolanguage set always retained from
// alternateNames, including ISO 3166-2 codes and airport/short names.
var KeepAltNameLanguages = map[string]struct{}{
	"abbr": {},
	"iata": {},
	"icao": {},
	"iso":  {},
}

// CountryCodeRemap is the static seed also loaded into country_code_remap.
// More rows can be discovered via geoip.country_code EXCEPT country_info.iso.
var CountryCodeRemap = postgres.CountryCodeRemap

func newTSVReader(r io.Reader) *csv.Reader {
	cr := csv.NewReader(r)
	cr.Comma = '\t'
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	return cr
}

func skipTSVRecord(record []string) bool {
	if len(record) == 0 {
		return true
	}
	first := strings.TrimSpace(record[0])
	return first == "" || strings.HasPrefix(first, "#")
}

func parseFloat(s string) (*float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, true
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, false
	}
	return &v, true
}

func parseInt(s string) (*int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, true
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil, false
	}
	return &v, true
}

func parseInt64(s string) (*int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, true
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, false
	}
	return &v, true
}

func parseBool01(s string) *bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	v := s == "1"
	return &v
}

func splitAdminCode(code string) (country, rest string) {
	code = strings.TrimSpace(code)
	cc, after, ok := strings.Cut(code, ".")
	if !ok {
		return code, ""
	}
	return cc, after
}

// NormalizeLookupKey matches ingest-time unaccent(lower(trim(...))).
func NormalizeLookupKey(s string) string { return postgres.NormalizeLookupKey(s) }

// RemapCountryCode applies country_code_remap. Unknown codes pass through.
func RemapCountryCode(cc string) string { return postgres.RemapCountryCode(cc) }

// StripISO31662 turns US-CA into CA. A bare CA stays CA.
func StripISO31662(regionCode string) string { return postgres.StripISO31662(regionCode) }

// ZipLookupKeys returns the raw zip and a US ZIP5 variant when present.
func ZipLookupKeys(zip string) (raw, zip5 string) { return postgres.ZipLookupKeys(zip) }

// KeepAlternateName retains iso/abbr/iata/icao rows plus any alias whose
// geonameid is in cities500 / country_info (capitals / country features).
func KeepAlternateName(geonameid int64, isolanguage string, knownIDs map[int64]struct{}) bool {
	lang := strings.ToLower(strings.TrimSpace(isolanguage))
	if _, ok := KeepAltNameLanguages[lang]; ok {
		return true
	}
	if knownIDs == nil {
		return false
	}
	_, ok := knownIDs[geonameid]
	return ok
}

// CountryInfoRecord is a parsed dump/countryInfo.txt row.
type CountryInfoRecord struct {
	ISO              *string
	ISO3             *string
	ISONumeric       *string
	FIPS             *string
	Country          *string
	Capital          *string
	Area             *float64
	Population       *int
	Continent        *string
	TLD              *string
	CurrencyCode     *string
	CurrencyName     *string
	Phone            *string
	PostalCodeFormat *string
	PostalCodeRegex  *string
	Languages        *[]string
	GeonameID        *int
	Neighbours       *[]string
	EquivalentFIPS   *string
}

func ParseCountryInfoRecord(record []string) (CountryInfoRecord, bool) {
	if skipTSVRecord(record) || len(record) < 19 {
		return CountryInfoRecord{}, false
	}
	area, ok := parseFloat(record[6])
	if !ok {
		return CountryInfoRecord{}, false
	}
	population, ok := parseInt(record[7])
	if !ok {
		return CountryInfoRecord{}, false
	}
	geonameid, ok := parseInt(record[16])
	if !ok {
		return CountryInfoRecord{}, false
	}
	var areaVal float64
	if area != nil {
		areaVal = *area
	}
	var popVal int
	if population != nil {
		popVal = *population
	}
	var geoVal int
	if geonameid != nil {
		geoVal = *geonameid
	}
	return CountryInfoRecord{
		ISO:              oputils.NilIfEmpty(strings.TrimSpace(record[0])),
		ISO3:             oputils.NilIfEmpty(record[1]),
		ISONumeric:       oputils.NilIfEmpty(record[2]),
		FIPS:             oputils.NilIfEmpty(record[3]),
		Country:          oputils.NilIfEmpty(record[4]),
		Capital:          oputils.NilIfEmpty(record[5]),
		Area:             oputils.NilIfEmptyFloat(areaVal),
		Population:       oputils.NilIfEmptyInt(popVal),
		Continent:        oputils.NilIfEmpty(record[8]),
		TLD:              oputils.NilIfEmpty(record[9]),
		CurrencyCode:     oputils.NilIfEmpty(record[10]),
		CurrencyName:     oputils.NilIfEmpty(record[11]),
		Phone:            oputils.NilIfEmpty(record[12]),
		PostalCodeFormat: oputils.NilIfEmpty(record[13]),
		PostalCodeRegex:  oputils.NilIfEmpty(record[14]),
		Languages:        oputils.NilSliceIfStringEmpty(record[15]),
		GeonameID:        oputils.NilIfEmptyInt(geoVal),
		Neighbours:       oputils.NilSliceIfStringEmpty(record[17]),
		EquivalentFIPS:   oputils.NilIfEmpty(record[18]),
	}, true
}

func ReadCountryInfo(r io.Reader) ([]CountryInfoRecord, error) {
	cr := newTSVReader(r)
	var out []CountryInfoRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := ParseCountryInfoRecord(record)
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// CityRecord is a parsed dump/cities500.txt row.
type CityRecord struct {
	GeonameID    int64
	Name         string
	ASCIIName    string
	AltNames     []string
	Latitude     float64
	Longitude    float64
	FeatureClass string
	FeatureCode  string
	CountryCode  string
	CC2          string
	Admin1Code   string
	Admin2Code   string
	Admin3Code   string
	Admin4Code   string
	Population   *int64
	Elevation    *int
	DEM          *int
	Timezone     string
	Modified     *time.Time
}

func ParseCities500Record(record []string) (CityRecord, bool) {
	if skipTSVRecord(record) || len(record) < 19 {
		return CityRecord{}, false
	}
	if strings.TrimSpace(record[0]) == "" || strings.TrimSpace(record[1]) == "" || strings.TrimSpace(record[8]) == "" {
		return CityRecord{}, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(record[0]), 10, 64)
	if err != nil {
		return CityRecord{}, false
	}
	lat, err := strconv.ParseFloat(strings.TrimSpace(record[4]), 64)
	if err != nil {
		return CityRecord{}, false
	}
	lon, err := strconv.ParseFloat(strings.TrimSpace(record[5]), 64)
	if err != nil {
		return CityRecord{}, false
	}
	var population *int64
	if p, ok := parseInt64(record[14]); ok {
		population = p
	}
	var elevation *int
	if e, ok := parseInt(record[15]); ok {
		elevation = e
	}
	var dem *int
	if d, ok := parseInt(record[16]); ok {
		dem = d
	}
	var modified *time.Time
	if t, err := time.Parse("2006-01-02", strings.TrimSpace(record[18])); err == nil {
		modified = &t
	}
	var altNames []string
	if record[3] != "" {
		altNames = strings.Split(record[3], ",")
	}
	return CityRecord{
		GeonameID:    id,
		Name:         record[1],
		ASCIIName:    record[2],
		AltNames:     altNames,
		Latitude:     lat,
		Longitude:    lon,
		FeatureClass: record[6],
		FeatureCode:  record[7],
		CountryCode:  strings.TrimSpace(record[8]),
		CC2:          record[9],
		Admin1Code:   record[10],
		Admin2Code:   record[11],
		Admin3Code:   record[12],
		Admin4Code:   record[13],
		Population:   population,
		Elevation:    elevation,
		DEM:          dem,
		Timezone:     record[17],
		Modified:     modified,
	}, true
}

func ReadCities500(r io.Reader) ([]CityRecord, error) {
	cr := newTSVReader(r)
	var out []CityRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := ParseCities500Record(record)
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// PostalRecord is a parsed zip/allCountries.txt row.
type PostalRecord struct {
	CountryCode string
	PostalCode  string
	PlaceName   string
	AdminName1  string
	AdminCode1  string
	AdminName2  string
	AdminCode2  string
	AdminName3  string
	AdminCode3  string
	Latitude    float64
	Longitude   float64
	Accuracy    *int
}

func ParsePostalRecord(record []string) (PostalRecord, bool) {
	if skipTSVRecord(record) || len(record) < 12 {
		return PostalRecord{}, false
	}
	if strings.TrimSpace(record[0]) == "" || strings.TrimSpace(record[1]) == "" || strings.TrimSpace(record[2]) == "" {
		return PostalRecord{}, false
	}
	lat, err := strconv.ParseFloat(strings.TrimSpace(record[9]), 64)
	if err != nil {
		return PostalRecord{}, false
	}
	lon, err := strconv.ParseFloat(strings.TrimSpace(record[10]), 64)
	if err != nil {
		return PostalRecord{}, false
	}
	acc, _ := parseInt(record[11])
	return PostalRecord{
		CountryCode: strings.TrimSpace(record[0]),
		PostalCode:  record[1],
		PlaceName:   record[2],
		AdminName1:  record[3],
		AdminCode1:  record[4],
		AdminName2:  record[5],
		AdminCode2:  record[6],
		AdminName3:  record[7],
		AdminCode3:  record[8],
		Latitude:    lat,
		Longitude:   lon,
		Accuracy:    acc,
	}, true
}

func ReadPostal(r io.Reader) ([]PostalRecord, error) {
	cr := newTSVReader(r)
	var out []PostalRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := ParsePostalRecord(record)
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// AdminRecord is a parsed admin1CodesASCII.txt / admin2Codes.txt row.
type AdminRecord struct {
	Code        string
	CountryCode string
	Admin1Code  string
	Admin2Code  string
	Name        string
	ASCIIName   string
	GeonameID   int64
}

func ParseAdmin1Record(record []string) (AdminRecord, bool) {
	if skipTSVRecord(record) || len(record) < 4 {
		return AdminRecord{}, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(record[3]), 10, 64)
	if err != nil {
		return AdminRecord{}, false
	}
	code := strings.TrimSpace(record[0])
	cc, rest := splitAdminCode(code)
	return AdminRecord{
		Code:        code,
		CountryCode: cc,
		Admin1Code:  rest,
		Name:        record[1],
		ASCIIName:   record[2],
		GeonameID:   id,
	}, true
}

func ParseAdmin2Record(record []string) (AdminRecord, bool) {
	if skipTSVRecord(record) || len(record) < 4 {
		return AdminRecord{}, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(record[3]), 10, 64)
	if err != nil {
		return AdminRecord{}, false
	}
	code := strings.TrimSpace(record[0])
	cc, rest := splitAdminCode(code)
	admin1, admin2, _ := strings.Cut(rest, ".")
	return AdminRecord{
		Code:        code,
		CountryCode: cc,
		Admin1Code:  admin1,
		Admin2Code:  admin2,
		Name:        record[1],
		ASCIIName:   record[2],
		GeonameID:   id,
	}, true
}

func ReadAdmin1(r io.Reader) ([]AdminRecord, error) {
	return readAdmin(r, ParseAdmin1Record)
}

func ReadAdmin2(r io.Reader) ([]AdminRecord, error) {
	return readAdmin(r, ParseAdmin2Record)
}

func readAdmin(r io.Reader, parse func([]string) (AdminRecord, bool)) ([]AdminRecord, error) {
	cr := newTSVReader(r)
	var out []AdminRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := parse(record)
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// TimezoneRecord is a parsed dump/timeZones.txt row.
type TimezoneRecord struct {
	CountryCode string
	TimezoneID  string
	GMTOffset   float64
	DSTOffset   float64
	RawOffset   float64
}

func ParseTimezoneRecord(record []string) (TimezoneRecord, bool) {
	if skipTSVRecord(record) || len(record) < 5 {
		return TimezoneRecord{}, false
	}
	if strings.EqualFold(strings.TrimSpace(record[0]), "CountryCode") {
		return TimezoneRecord{}, false
	}
	gmt, ok := parseFloat(record[2])
	if !ok || gmt == nil {
		return TimezoneRecord{}, false
	}
	dst, ok := parseFloat(record[3])
	if !ok || dst == nil {
		return TimezoneRecord{}, false
	}
	raw, ok := parseFloat(record[4])
	if !ok || raw == nil {
		return TimezoneRecord{}, false
	}
	tz := strings.TrimSpace(record[1])
	if tz == "" {
		return TimezoneRecord{}, false
	}
	return TimezoneRecord{
		CountryCode: strings.TrimSpace(record[0]),
		TimezoneID:  tz,
		GMTOffset:   *gmt,
		DSTOffset:   *dst,
		RawOffset:   *raw,
	}, true
}

func ReadTimezones(r io.Reader) ([]TimezoneRecord, error) {
	cr := newTSVReader(r)
	var out []TimezoneRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := ParseTimezoneRecord(record)
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

// AltNameRecord is a parsed alternateNames / alternateNamesV2 row.
type AltNameRecord struct {
	AltNameID     int64
	GeonameID     int64
	ISOLanguage   string
	AlternateName string
	IsPreferred   *bool
	IsShort       *bool
	IsColloquial  *bool
	IsHistoric    *bool
}

func ParseAltNameRecord(record []string) (AltNameRecord, bool) {
	if skipTSVRecord(record) || len(record) < 4 {
		return AltNameRecord{}, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(record[0]), 10, 64)
	if err != nil {
		return AltNameRecord{}, false
	}
	gid, err := strconv.ParseInt(strings.TrimSpace(record[1]), 10, 64)
	if err != nil {
		return AltNameRecord{}, false
	}
	name := record[3]
	if strings.TrimSpace(name) == "" {
		return AltNameRecord{}, false
	}
	item := AltNameRecord{
		AltNameID:     id,
		GeonameID:     gid,
		ISOLanguage:   record[2],
		AlternateName: name,
	}
	if len(record) > 4 {
		item.IsPreferred = parseBool01(record[4])
	}
	if len(record) > 5 {
		item.IsShort = parseBool01(record[5])
	}
	if len(record) > 6 {
		item.IsColloquial = parseBool01(record[6])
	}
	if len(record) > 7 {
		item.IsHistoric = parseBool01(record[7])
	}
	return item, true
}

func ReadAltNames(r io.Reader, knownIDs map[int64]struct{}) ([]AltNameRecord, error) {
	cr := newTSVReader(r)
	var out []AltNameRecord
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		item, ok := ParseAltNameRecord(record)
		if !ok {
			continue
		}
		if !KeepAlternateName(item.GeonameID, item.ISOLanguage, knownIDs) {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}
