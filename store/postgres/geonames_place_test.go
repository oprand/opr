package postgres

import (
	"strings"
	"testing"
)

func TestCountryCodeRemapSeedHasNoContinentCodes(t *testing.T) {
	t.Parallel()
	for cc := range UnmappedGeoIPCodes {
		if _, ok := CountryCodeRemap[cc]; ok {
			t.Errorf("CountryCodeRemap must not map %q", cc)
		}
	}
}

func TestListUnmappedGeoIPCountryCodesSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(listUnmappedGeoIPCountryCodesSQL)
	for _, want := range []string{
		"from geoip",
		"country_info",
		"country_code_remap",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("unmapped SQL missing %q", want)
		}
	}
}

func TestIntentionalISOOverridesAreSeeded(t *testing.T) {
	t.Parallel()
	for cc := range IntentionalISOOverrides {
		if _, ok := CountryCodeRemap[cc]; !ok {
			t.Errorf("override %q missing from CountryCodeRemap", cc)
		}
	}
}

func TestDecideCountryCodeRemaps(t *testing.T) {
	t.Parallel()
	iso := map[string]struct{}{"GB": {}, "GR": {}, "PT": {}, "FR": {}, "TL": {}, "US": {}, "CV": {}}
	existing := map[string]struct{}{"UK": {}}
	d := DecideCountryCodeRemaps(
		[]string{"UK", "EL", "EU", "AP", "FX", "us", "  el ", "XX", "XK", "CV"},
		iso,
		existing,
	)
	if _, ok := d.Insert["UK"]; ok {
		t.Fatal("UK already remapped, must not insert again")
	}
	if d.Insert["EL"] != "GR" {
		t.Fatalf("insert EL: %v", d.Insert)
	}
	if d.Insert["FX"] != "FR" {
		t.Fatalf("insert FX: %v", d.Insert)
	}
	if d.Insert["CV"] != "PT" {
		t.Fatalf("CV override must insert despite CV being a live ISO: %v", d.Insert)
	}
	wantUnmapped := []string{"AP", "EU", "XK", "XX"}
	if strings.Join(d.Unmapped, ",") != strings.Join(wantUnmapped, ",") {
		t.Fatalf("unmapped = %v, want %v", d.Unmapped, wantUnmapped)
	}
}

func TestDecideCountryCodeRemapsDoesNotShadowLiveISOWithoutOverride(t *testing.T) {
	t.Parallel()
	iso := map[string]struct{}{"NO": {}, "SE": {}, "PT": {}, "CV": {}}
	d := DecideCountryCodeRemaps([]string{"NO", "CV"}, iso, nil)
	if _, ok := d.Insert["NO"]; ok {
		t.Fatalf("live ISO NO must not be remapped: %v", d.Insert)
	}
	if d.Insert["CV"] != "PT" {
		t.Fatalf("CV override missing: %v", d.Insert)
	}
}

func TestDecideCountryCodeRemapsSkipsWhenTargetMissingFromCountryInfo(t *testing.T) {
	t.Parallel()
	iso := map[string]struct{}{"US": {}}
	d := DecideCountryCodeRemaps([]string{"UK", "EU"}, iso, nil)
	if len(d.Insert) != 0 {
		t.Fatalf("insert = %v, want empty (GB not in country_info)", d.Insert)
	}
	if strings.Join(d.Unmapped, ",") != "EU,UK" {
		t.Fatalf("unmapped = %v", d.Unmapped)
	}
}

func TestRemapCountryCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"UK", "GB"},
		{"uk", "GB"},
		{"EL", "GR"},
		{"CV", "PT"},
		{"FX", "FR"},
		{"TP", "TL"},
		{"US", "US"},
		{"EU", "EU"},
		{"AP", "AP"},
		{"  tr ", "TR"},
		{"", ""},
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
		{"us-ca", "CA"},
		{"CA", "CA"},
		{"US-CO", "CO"},
		{"  US-NY ", "NY"},
		{"TR-34", "34"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := StripISO31662(tc.in); got != tc.want {
			t.Errorf("StripISO31662(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestZipLookupKeys(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, raw, zip5 string
	}{
		{"80202-1234", "80202-1234", "80202"},
		{"802021234", "802021234", "80202"},
		{"80202", "80202", ""},
		{"SW1A 1AA", "SW1A 1AA", ""},
		{"  80202-1234  ", "80202-1234", "80202"},
		{"", "", ""},
	}
	for _, tc := range cases {
		raw, zip5 := ZipLookupKeys(tc.in)
		if raw != tc.raw || zip5 != tc.zip5 {
			t.Errorf("ZipLookupKeys(%q) = (%q, %q), want (%q, %q)", tc.in, raw, zip5, tc.raw, tc.zip5)
		}
	}
}

func TestNormalizeLookupKey(t *testing.T) {
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

func TestResolveGeoNamesPlaceSQLShape(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(ResolveGeoNamesPlaceSQL)
	for _, want := range []string{
		"union all",
		"1 as priority",
		"order by",
		"hits.priority",
		"population desc nulls last",
		"limit 1",
		"country_code_remap",
		"country_info",
		"geonames_lookup",
		"geonames_timezone",
		"l.zipcode = q.zip",
		"l.admin1_iso = q.admin1",
		"l.city_norm = q.city_norm",
		"l.alias_norm = q.city_norm",
		"match_kind = 'capital'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("resolve SQL missing %q", want)
		}
	}
	if strings.Contains(sql, "unaccent(l.city_norm") || strings.Contains(sql, "unaccent(l.alias_norm") {
		t.Fatal("must not wrap indexed city_norm/alias_norm in unaccent")
	}
}

func fixtureCountries() map[string]GeoNamesCountryMeta {
	return map[string]GeoNamesCountryMeta{
		"US": {Capital: "Washington", Timezones: []string{"America/Denver", "America/New_York", "America/Los_Angeles"}},
		"GB": {Capital: "London", Timezones: []string{"Europe/London"}},
		"TR": {Capital: "Ankara", Timezones: []string{"Europe/Istanbul"}},
		"IS": {Capital: "Reykjavik", Timezones: []string{"Atlantic/Reykjavik"}},
	}
}

func fixtureLookupRows() []GeoNamesLookupRow {
	return []GeoNamesLookupRow{
		{CountryCode: "US", Admin1ISO: "CO", CityNorm: "centennial", GeonameID: 5417211, Lat: 39.579, Lon: -104.877, Timezone: "America/Denver", Population: 100377, AdminName1: "Colorado", MatchKind: "city"},
		{CountryCode: "US", Admin1ISO: "WY", CityNorm: "centennial", GeonameID: 5820816, Lat: 41.308, Lon: -106.145, Timezone: "America/Denver", Population: 270, AdminName1: "Wyoming", MatchKind: "city"},
		{CountryCode: "US", Admin1ISO: "CO", CityNorm: "centennial", Zipcode: "80112", ZipForDisplay: "80112", GeonameID: 5417211, Lat: 39.579, Lon: -104.877, Timezone: "America/Denver", Population: 100377, AdminName1: "Colorado", MatchKind: "zip"},
		{CountryCode: "US", Admin1ISO: "CA", CityNorm: "los angeles", GeonameID: 5368361, Lat: 34.05, Lon: -118.24, Timezone: "America/Los_Angeles", Population: 3_898_747, AdminName1: "California", MatchKind: "city"},
		{CountryCode: "US", Admin1ISO: "DC", CityNorm: "washington", GeonameID: 4140963, Lat: 38.9, Lon: -77.0, Timezone: "America/New_York", Population: 689545, AdminName1: "District of Columbia", MatchKind: "capital"},
		{CountryCode: "TR", Admin1ISO: "34", CityNorm: "istanbul", GeonameID: 745044, Lat: 41.01, Lon: 28.95, Timezone: "Europe/Istanbul", Population: 15_000_000, AdminName1: "Istanbul", MatchKind: "city"},
		{CountryCode: "TR", Admin1ISO: "34", AliasNorm: "istanbul", GeonameID: 745044, Lat: 41.01, Lon: 28.95, Timezone: "Europe/Istanbul", Population: 15_000_000, AdminName1: "İstanbul", MatchKind: "admin"},
		{CountryCode: "TR", Admin1ISO: "68", CityNorm: "ankara", GeonameID: 323786, Lat: 39.92, Lon: 32.85, Timezone: "Europe/Istanbul", Population: 3_500_000, AdminName1: "Ankara", MatchKind: "capital"},
		{CountryCode: "GB", Admin1ISO: "ENG", CityNorm: "london", GeonameID: 2643743, Lat: 51.51, Lon: -0.13, Timezone: "Europe/London", Population: 8_000_000, AdminName1: "England", MatchKind: "capital"},
		{CountryCode: "IS", Admin1ISO: "01", CityNorm: "reykjavik", GeonameID: 6692263, Lat: 64.14, Lon: -21.9, Timezone: "Atlantic/Reykjavik", Population: 131136, AdminName1: "Capital Region", MatchKind: "capital"},
	}
}

func TestResolvePlaceFromLookupCascade(t *testing.T) {
	t.Parallel()
	rows := fixtureLookupRows()
	countries := fixtureCountries()

	cases := []struct {
		name                   string
		cc, regionCode, region string
		city, zip              string
		wantID                 int64
		wantKind               string
		wantAdmin              string
		wantNil                bool
	}{
		{
			name: "istanbul region-as-city",
			cc:   "TR", region: "İstanbul",
			wantID: 745044, wantKind: "city", wantAdmin: "Istanbul",
		},
		{
			name: "istanbul swapped names",
			cc:   "TR", region: "Istanbul", city: "İstanbul",
			wantID: 745044, wantKind: "city", wantAdmin: "Istanbul",
		},
		{
			name: "US-CO Centennial must not pick WY",
			cc:   "US", regionCode: "US-CO", city: "Centennial",
			wantID: 5417211, wantKind: "city", wantAdmin: "Colorado",
		},
		{
			name: "UK remaps to GB London",
			cc:   "UK", city: "London",
			wantID: 2643743, wantKind: "capital",
		},
		{
			name: "zip-first wins over city",
			cc:   "US", regionCode: "US-CO", city: "Centennial", zip: "80112-9999",
			wantID: 5417211, wantKind: "zip", wantAdmin: "Colorado",
		},
		{
			name:   "country-only single-TZ Iceland",
			cc:     "IS",
			wantID: 6692263, wantKind: "capital",
		},
		{
			name: "geofeed US-CA empty region",
			cc:   "US", regionCode: "US-CA", city: "Los Angeles",
			wantID: 5368361, wantKind: "city", wantAdmin: "California",
		},
		{
			name: "unknown country is a miss",
			cc:   "XX", city: "Nowhere",
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolvePlaceFromLookup(rows, countries, tc.cc, tc.regionCode, tc.region, tc.city, tc.zip)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected a hit")
			}
			if got.GeonameID == nil || *got.GeonameID != tc.wantID {
				t.Errorf("geonameid = %v, want %d", got.GeonameID, tc.wantID)
			}
			if got.MatchKind != tc.wantKind {
				t.Errorf("match_kind = %q, want %q", got.MatchKind, tc.wantKind)
			}
			if tc.wantAdmin != "" && (got.AdminName1 == nil || *got.AdminName1 != tc.wantAdmin) {
				t.Errorf("admin_name_1 = %v, want %q", got.AdminName1, tc.wantAdmin)
			}
		})
	}
}

func TestResolvePlaceCityOnlyPrefersPopulation(t *testing.T) {
	t.Parallel()
	got := ResolvePlaceFromLookup(fixtureLookupRows(), fixtureCountries(), "US", "", "", "Centennial", "")
	if got == nil || got.GeonameID == nil || *got.GeonameID != 5417211 {
		t.Fatalf("city-only Centennial should pick CO (5417211), got %+v", got)
	}
}

func TestPreparePlaceInputUsesRegionCodeNotBareRegionForAdmin1(t *testing.T) {
	t.Parallel()
	in := prepareGeoNamesPlaceInput("US", "US-CA", "", "Los Angeles", "")
	if in.Admin1 != "CA" {
		t.Fatalf("admin1 = %q, want CA (from RegionCode)", in.Admin1)
	}
	if in.RegionNorm != "" {
		t.Fatalf("empty Region should not invent region_norm, got %q", in.RegionNorm)
	}
}
