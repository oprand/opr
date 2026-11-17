package geonames

import "github.com/oprand/opr/store/postgres"

// ResolvePlace runs the GeoIP→GeoNames cascade over in-memory lookup keys.
// Production uses postgres.ResolveGeoNamesPlace (SQL); this locks priority order
// against BuildLookupKeys fixtures without a dump or DSN.
func ResolvePlace(keys []LookupKey, countries map[string]postgres.GeoNamesCountryMeta, countryCode, regionCode, region, city, zip string) *postgres.GeoNamesPlace {
	rows := make([]postgres.GeoNamesLookupRow, len(keys))
	for i, k := range keys {
		rows[i] = postgres.GeoNamesLookupRow{
			CountryCode:   k.CountryCode,
			Admin1ISO:     k.Admin1ISO,
			CityNorm:      k.CityNorm,
			Zipcode:       k.Zipcode,
			AliasNorm:     k.AliasNorm,
			GeonameID:     k.GeonameID,
			Lat:           k.Lat,
			Lon:           k.Lon,
			Timezone:      k.Timezone,
			Population:    k.Population,
			ZipForDisplay: k.ZipForDisplay,
			AdminName1:    k.AdminName1,
			MatchKind:     k.MatchKind,
		}
	}
	return postgres.ResolvePlaceFromLookup(rows, countries, countryCode, regionCode, region, city, zip)
}
