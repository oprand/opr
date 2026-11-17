package geonames

import (
	"testing"

	"github.com/oprand/opr/store/postgres"
)

func cascadeFixture() ([]LookupKey, map[string]postgres.GeoNamesCountryMeta) {
	popIST := int64(15_000_000)
	popCO := int64(100_377)
	popWY := int64(270)
	popLA := int64(3_898_747)
	popANK := int64(3_500_000)
	popLON := int64(8_000_000)
	popREK := int64(131_136)

	cities := []CityRecord{
		{GeonameID: 745044, Name: "İstanbul", ASCIIName: "Istanbul", Latitude: 41.01, Longitude: 28.95, CountryCode: "TR", Admin1Code: "34", FeatureCode: "PPLA", Timezone: "Europe/Istanbul", Population: &popIST},
		{GeonameID: 323786, Name: "Ankara", ASCIIName: "Ankara", Latitude: 39.92, Longitude: 32.85, CountryCode: "TR", Admin1Code: "68", FeatureCode: "PPLC", Timezone: "Europe/Istanbul", Population: &popANK},
		{GeonameID: 5417211, Name: "Centennial", ASCIIName: "Centennial", Latitude: 39.579, Longitude: -104.877, CountryCode: "US", Admin1Code: "CO", FeatureCode: "PPL", Timezone: "America/Denver", Population: &popCO},
		{GeonameID: 5820816, Name: "Centennial", ASCIIName: "Centennial", Latitude: 41.308, Longitude: -106.145, CountryCode: "US", Admin1Code: "WY", FeatureCode: "PPL", Timezone: "America/Denver", Population: &popWY},
		{GeonameID: 5368361, Name: "Los Angeles", ASCIIName: "Los Angeles", Latitude: 34.05, Longitude: -118.24, CountryCode: "US", Admin1Code: "CA", FeatureCode: "PPLA", Timezone: "America/Los_Angeles", Population: &popLA},
		{GeonameID: 2643743, Name: "London", ASCIIName: "London", Latitude: 51.51, Longitude: -0.13, CountryCode: "GB", Admin1Code: "ENG", FeatureCode: "PPLC", Timezone: "Europe/London", Population: &popLON},
		{GeonameID: 6692263, Name: "Reykjavik", ASCIIName: "Reykjavik", Latitude: 64.14, Longitude: -21.9, CountryCode: "IS", Admin1Code: "01", FeatureCode: "PPLC", Timezone: "Atlantic/Reykjavik", Population: &popREK},
	}
	postal := []PostalRecord{
		{CountryCode: "US", PostalCode: "80112", PlaceName: "Centennial", AdminName1: "Colorado", AdminCode1: "CO", Latitude: 39.579, Longitude: -104.877},
	}
	admin1 := []AdminRecord{
		{Code: "TR.34", CountryCode: "TR", Admin1Code: "34", Name: "İstanbul", ASCIIName: "Istanbul", GeonameID: 745044},
		{Code: "US.CO", CountryCode: "US", Admin1Code: "CO", Name: "Colorado", ASCIIName: "Colorado", GeonameID: 5417618},
		{Code: "US.WY", CountryCode: "US", Admin1Code: "WY", Name: "Wyoming", ASCIIName: "Wyoming", GeonameID: 5843591},
		{Code: "US.CA", CountryCode: "US", Admin1Code: "CA", Name: "California", ASCIIName: "California", GeonameID: 5332921},
	}
	keys := BuildLookupKeys(cities, postal, nil, admin1)
	countries := map[string]postgres.GeoNamesCountryMeta{
		"US": {Capital: "Washington", Timezones: []string{"America/Denver", "America/New_York", "America/Los_Angeles"}},
		"GB": {Capital: "London", Timezones: []string{"Europe/London"}},
		"TR": {Capital: "Ankara", Timezones: []string{"Europe/Istanbul"}},
		"IS": {Capital: "Reykjavik", Timezones: []string{"Atlantic/Reykjavik"}},
	}
	return keys, countries
}

func TestResolvePlaceFromBuiltLookupKeys(t *testing.T) {
	t.Parallel()
	keys, countries := cascadeFixture()

	cases := []struct {
		name                   string
		cc, regionCode, region string
		city, zip              string
		wantID                 int64
		wantKind               string
	}{
		{name: "istanbul region-as-city", cc: "TR", region: "İstanbul", wantID: 745044},
		{name: "US-CO vs Centennial WY", cc: "US", regionCode: "US-CO", city: "Centennial", wantID: 5417211},
		{name: "UK remaps to GB", cc: "UK", city: "London", wantID: 2643743, wantKind: MatchKindCapital},
		{name: "zip-first over city", cc: "US", regionCode: "US-CO", city: "Centennial", zip: "80112-0001", wantID: 5417211, wantKind: MatchKindZip},
		{name: "country-only single-TZ", cc: "IS", wantID: 6692263, wantKind: MatchKindCapital},
		{name: "geofeed US-CA empty region", cc: "US", regionCode: "US-CA", city: "Los Angeles", wantID: 5368361},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolvePlace(keys, countries, tc.cc, tc.regionCode, tc.region, tc.city, tc.zip)
			if got == nil || got.GeonameID == nil || *got.GeonameID != tc.wantID {
				t.Fatalf("geonameid = %v, want %d (hit %+v)", geonameIDOf(got), tc.wantID, got)
			}
			if tc.wantKind != "" && got.MatchKind != tc.wantKind {
				t.Errorf("match_kind = %q, want %q", got.MatchKind, tc.wantKind)
			}
		})
	}
}

func geonameIDOf(p *postgres.GeoNamesPlace) int64 {
	if p == nil || p.GeonameID == nil {
		return 0
	}
	return *p.GeonameID
}
