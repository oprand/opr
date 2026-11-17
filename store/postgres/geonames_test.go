package postgres

import (
	"strings"
	"testing"
)

func TestRebuildGeoNamesLookupSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(RebuildGeoNamesLookupSQL)
	for _, want := range []string{
		"'zip'",
		"'city'",
		"'alias'",
		"'admin'",
		"'capital'",
		"geonames_city",
		"geonames_postal",
		"geonames_altname",
		"geonames_admin1",
		"geonames_lookup_new",
		"city_norm",
		"alias_norm",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("rebuild SQL missing %q", want)
		}
	}
}

func TestGeoNamesCopySwapSpecs(t *testing.T) {
	t.Parallel()
	if geoNamesCitySwap.live != "geonames_city" {
		t.Fatal("city swap target")
	}
	if len(geoNamesCitySwap.columns) == 0 || geoNamesPostalSwap.columns[0] != "country_code" {
		t.Fatal("postal columns")
	}
	if !strings.Contains(strings.ToLower(strings.Join(geoNamesCitySwap.afterCopy, " ")), "unaccent") {
		t.Fatal("city_norm must be written with unaccent at ingest")
	}
	if !strings.Contains(geoNamesLookupSwap.indexes[0].createSQL, "WHERE zipcode IS NOT NULL") {
		t.Fatal("zip index must be partial")
	}
}
