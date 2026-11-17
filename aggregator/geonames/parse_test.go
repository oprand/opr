package geonames

import (
	"strings"
	"testing"
)

func TestParseCountryInfo(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`#ISO	ISO3	ISO-Numeric	fips	Country	Capital	Area(in sq km)	Population	Continent	tld	CurrencyCode	CurrencyName	Phone	Postal Code Format	Postal Code Regex	Languages	geonameid	neighbours	EquivalentFipsCode
TR	TUR	792	TU	Turkey	Ankara	783562	84339067	AS	.tr	TRY	Lira	90	#####	\d{5}	tr-TR,en	298795	GR,BG,GE,AM,AZ,IR,IQ,SY	
`)
	got, err := ReadCountryInfo(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].ISO == nil || *got[0].ISO != "TR" {
		t.Fatalf("ISO = %v", got[0].ISO)
	}
	if got[0].Capital == nil || *got[0].Capital != "Ankara" {
		t.Fatalf("Capital = %v", got[0].Capital)
	}
	if got[0].GeonameID == nil || *got[0].GeonameID != 298795 {
		t.Fatalf("GeonameID = %v", got[0].GeonameID)
	}
}

func TestParseCities500(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("745044\tIstanbul\tIstanbul\tConstantinople,Byzantium\t41.01384\t28.94966\tP\tPPLA\tTR\t\t34\t7733237\t\t\t14840319\t40\t39\tEurope/Istanbul\t2024-01-01\n")
	got, err := ReadCities500(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	c := got[0]
	if c.GeonameID != 745044 || c.Name != "Istanbul" || c.CountryCode != "TR" || c.Admin1Code != "34" {
		t.Fatalf("unexpected city: %+v", c)
	}
	if c.Timezone != "Europe/Istanbul" {
		t.Fatalf("timezone %q", c.Timezone)
	}
	if len(c.AltNames) != 2 || c.AltNames[0] != "Constantinople" {
		t.Fatalf("alt names %v", c.AltNames)
	}
}

func TestParsePostal(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("TR\t34096\tAksaray\tİstanbul\t34\tFatih\t7733237\t\t\t41.0087\t28.9502\t4\n")
	got, err := ReadPostal(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	p := got[0]
	if p.CountryCode != "TR" || p.PostalCode != "34096" || p.PlaceName != "Aksaray" || p.AdminCode1 != "34" {
		t.Fatalf("unexpected postal: %+v", p)
	}
	if p.Accuracy == nil || *p.Accuracy != 4 {
		t.Fatalf("accuracy %v", p.Accuracy)
	}
}

func TestParseAdmin1AndTimezone(t *testing.T) {
	t.Parallel()
	admins, err := ReadAdmin1(strings.NewReader("TR.34\tIstanbul\tIstanbul\t745044\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 1 || admins[0].CountryCode != "TR" || admins[0].Admin1Code != "34" || admins[0].Name != "Istanbul" {
		t.Fatalf("admin1 %+v", admins)
	}

	tz, err := ReadTimezones(strings.NewReader("CountryCode\tTimeZoneId\tGMT\tDST\traw\nTR\tEurope/Istanbul\t3.0\t3.0\t3.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tz) != 1 || tz[0].TimezoneID != "Europe/Istanbul" || tz[0].CountryCode != "TR" {
		t.Fatalf("timezone %+v", tz)
	}
}

func TestParseAdmin2(t *testing.T) {
	t.Parallel()
	got, err := ReadAdmin2(strings.NewReader("US.CA.037\tLos Angeles County\tLos Angeles County\t5368381\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	a := got[0]
	if a.CountryCode != "US" || a.Admin1Code != "CA" || a.Admin2Code != "037" || a.GeonameID != 5368381 {
		t.Fatalf("admin2 %+v", a)
	}
}

func TestParseAltNameAndFilter(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(strings.Join([]string{
		"1\t745044\ten\tConstantinople\t1\t\t\t1",
		"2\t745044\tabbr\tIST",
		"3\t999999\ten\tShouldDrop",
		"4\t123\tiso\tTR-34",
		"5\t745044\tiata\tIST",
		"",
	}, "\n"))
	known := map[int64]struct{}{745044: {}}
	got, err := ReadAltNames(in, known)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, n := range got {
		names = append(names, n.ISOLanguage+":"+n.AlternateName)
	}
	wantKeep := map[string]bool{
		"en:Constantinople": true,
		"abbr:IST":          true,
		"iso:TR-34":         true,
		"iata:IST":          true,
	}
	if len(got) != 4 {
		t.Fatalf("got %d rows %v, want 4", len(got), names)
	}
	for _, n := range got {
		key := n.ISOLanguage + ":" + n.AlternateName
		if !wantKeep[key] {
			t.Errorf("unexpected kept %q", key)
		}
	}
}

func TestKeepAlternateName(t *testing.T) {
	t.Parallel()
	known := map[int64]struct{}{10: {}, 20: {}}
	cases := []struct {
		id   int64
		lang string
		want bool
	}{
		{10, "en", true},
		{10, "de", true},
		{99, "en", false},
		{99, "iso", true},
		{99, "abbr", true},
		{99, "iata", true},
		{99, "icao", true},
		{99, "ISO", true},
		{20, "", true},
	}
	for _, tc := range cases {
		if got := KeepAlternateName(tc.id, tc.lang, known); got != tc.want {
			t.Errorf("KeepAlternateName(%d, %q) = %v, want %v", tc.id, tc.lang, got, tc.want)
		}
	}
}

func TestCountryCodeRemap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"UK", "GB"},
		{"uk", "GB"},
		{"EL", "GR"},
		{"CV", "PT"},
		{"FX", "FR"},
		{"US", "US"},
		{"EU", "EU"},
		{"  tr ", "TR"},
	}
	for _, tc := range cases {
		if got := RemapCountryCode(tc.in); got != tc.want {
			t.Errorf("RemapCountryCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStripISO31662(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"US-CA", "CA"},
		{"CA", "CA"},
		{"us-co", "CO"},
		{"TR-34", "34"},
	}
	for _, tc := range cases {
		if got := StripISO31662(tc.in); got != tc.want {
			t.Errorf("StripISO31662(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestZipLookupKeys(t *testing.T) {
	t.Parallel()
	raw, zip5 := ZipLookupKeys("80202-1234")
	if raw != "80202-1234" || zip5 != "80202" {
		t.Fatalf("ZipLookupKeys(80202-1234) = (%q, %q)", raw, zip5)
	}
	raw, zip5 = ZipLookupKeys("80202")
	if raw != "80202" || zip5 != "" {
		t.Fatalf("ZipLookupKeys(80202) = (%q, %q)", raw, zip5)
	}
}

func TestNormalizeLookupKeyIstanbul(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"İstanbul", "istanbul"},
		{"  Istanbul  ", "istanbul"},
		{"İSTANBUL", "istanbul"},
		{"München", "munchen"},
	}
	for _, tc := range cases {
		if got := NormalizeLookupKey(tc.in); got != tc.want {
			t.Errorf("NormalizeLookupKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildLookupKeysZipCityAlias(t *testing.T) {
	t.Parallel()
	pop := int64(15_000_000)
	cities := []CityRecord{{
		GeonameID:   745044,
		Name:        "İstanbul",
		ASCIIName:   "Istanbul",
		Latitude:    41.01,
		Longitude:   28.95,
		CountryCode: "TR",
		Admin1Code:  "34",
		FeatureCode: "PPLA",
		Timezone:    "Europe/Istanbul",
		Population:  &pop,
	}}
	postal := []PostalRecord{{
		CountryCode: "TR",
		PostalCode:  "34096",
		PlaceName:   "Aksaray",
		AdminName1:  "İstanbul",
		AdminCode1:  "34",
		Latitude:    41.0087,
		Longitude:   28.9502,
	}}
	alts := []AltNameRecord{{
		GeonameID:     745044,
		ISOLanguage:   "en",
		AlternateName: "Constantinople",
	}}
	admin1 := []AdminRecord{{
		Code:        "TR.34",
		CountryCode: "TR",
		Admin1Code:  "34",
		Name:        "İstanbul",
		ASCIIName:   "Istanbul",
		GeonameID:   745044,
	}}
	keys := BuildLookupKeys(cities, postal, alts, admin1)

	has := func(kind, city, alias, zip string) bool {
		for _, k := range keys {
			if k.MatchKind == kind && k.CountryCode == "TR" && k.CityNorm == city && k.AliasNorm == alias && k.Zipcode == zip {
				return true
			}
		}
		return false
	}
	if !has(MatchKindCity, "istanbul", "", "") {
		t.Fatalf("missing city key istanbul in %+v", keys)
	}
	if !has(MatchKindAlias, "", "constantinople", "") {
		t.Fatalf("missing alias constantinople in %+v", keys)
	}
	if !has(MatchKindZip, "aksaray", "", "34096") {
		t.Fatalf("missing zip 34096 in %+v", keys)
	}
	if !has(MatchKindCity, "aksaray", "", "") {
		t.Fatalf("missing postal place city key aksaray in %+v", keys)
	}
}
