package geonames

import "strings"

const (
	MatchKindZip     = "zip"
	MatchKindCity    = "city"
	MatchKindAlias   = "alias"
	MatchKindAdmin   = "admin"
	MatchKindCapital = "capital"
)

// LookupKey is one searchable key produced by the ingest-time rebuild.
type LookupKey struct {
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

type lookupDedup struct {
	zip   map[string]LookupKey
	city  map[string]LookupKey
	alias map[string]LookupKey
}

func newLookupDedup() *lookupDedup {
	return &lookupDedup{
		zip:   make(map[string]LookupKey),
		city:  make(map[string]LookupKey),
		alias: make(map[string]LookupKey),
	}
}

func cityKey(cc, cityNorm, admin1 string) string {
	return cc + "\x00" + cityNorm + "\x00" + admin1
}

func aliasKey(cc, aliasNorm, admin1 string) string {
	return cc + "\x00" + aliasNorm + "\x00" + admin1
}

func zipKey(cc, zip string) string {
	return cc + "\x00" + zip
}

func (d *lookupDedup) putCity(k LookupKey) {
	if k.CityNorm == "" {
		return
	}
	id := cityKey(k.CountryCode, k.CityNorm, k.Admin1ISO)
	if prev, ok := d.city[id]; ok && prev.Population >= k.Population {
		return
	}
	d.city[id] = k
}

func (d *lookupDedup) putAlias(k LookupKey) {
	if k.AliasNorm == "" || k.AliasNorm == k.CityNorm {
		return
	}
	id := aliasKey(k.CountryCode, k.AliasNorm, k.Admin1ISO)
	if prev, ok := d.alias[id]; ok && prev.Population >= k.Population {
		return
	}
	d.alias[id] = k
}

func (d *lookupDedup) putZip(k LookupKey) {
	if k.Zipcode == "" {
		return
	}
	id := zipKey(k.CountryCode, k.Zipcode)
	if prev, ok := d.zip[id]; ok && prev.Population >= k.Population {
		return
	}
	d.zip[id] = k
}

func (d *lookupDedup) collect() []LookupKey {
	out := make([]LookupKey, 0, len(d.zip)+len(d.city)+len(d.alias))
	for _, k := range d.city {
		out = append(out, k)
	}
	for _, k := range d.alias {
		out = append(out, k)
	}
	for _, k := range d.zip {
		out = append(out, k)
	}
	return out
}

func popOf(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func emptyToBlank(s string) string {
	return strings.TrimSpace(s)
}

// BuildLookupKeys expands searchable keys from in-memory dump rows. Production
// rebuild is SQL (unaccent) in postgres.RebuildGeoNamesLookup; this mirrors it
// for unit tests.
func BuildLookupKeys(cities []CityRecord, postal []PostalRecord, alts []AltNameRecord, admin1 []AdminRecord) []LookupKey {
	d := newLookupDedup()

	type cityRef struct {
		CityRecord
		CityNorm  string
		ASCIINorm string
		Admin1    string
	}
	byID := make(map[int64]cityRef, len(cities))
	adminName := make(map[string]string, len(admin1))
	for _, a := range admin1 {
		adminName[a.CountryCode+"\x00"+a.Admin1Code] = a.Name
	}

	for _, c := range cities {
		ref := cityRef{
			CityRecord: c,
			CityNorm:   NormalizeLookupKey(c.Name),
			ASCIINorm:  NormalizeLookupKey(c.ASCIIName),
			Admin1:     emptyToBlank(c.Admin1Code),
		}
		byID[c.GeonameID] = ref
		kind := MatchKindCity
		if c.FeatureCode == "PPLC" {
			kind = MatchKindCapital
		}
		k := LookupKey{
			CountryCode: c.CountryCode,
			Admin1ISO:   ref.Admin1,
			CityNorm:    ref.CityNorm,
			GeonameID:   c.GeonameID,
			Lat:         c.Latitude,
			Lon:         c.Longitude,
			Timezone:    c.Timezone,
			Population:  popOf(c.Population),
			AdminName1:  adminName[c.CountryCode+"\x00"+ref.Admin1],
			MatchKind:   kind,
		}
		d.putCity(k)
		if ref.ASCIINorm != "" && ref.ASCIINorm != ref.CityNorm {
			ak := k
			ak.AliasNorm = ref.ASCIINorm
			ak.CityNorm = ""
			ak.MatchKind = MatchKindAlias
			d.putAlias(ak)
		}
	}

	for _, n := range alts {
		c, ok := byID[n.GeonameID]
		if !ok {
			continue
		}
		alias := NormalizeLookupKey(n.AlternateName)
		if alias == "" || alias == c.CityNorm {
			continue
		}
		d.putAlias(LookupKey{
			CountryCode: c.CountryCode,
			Admin1ISO:   c.Admin1,
			AliasNorm:   alias,
			GeonameID:   c.GeonameID,
			Lat:         c.Latitude,
			Lon:         c.Longitude,
			Timezone:    c.Timezone,
			Population:  popOf(c.Population),
			AdminName1:  adminName[c.CountryCode+"\x00"+c.Admin1],
			MatchKind:   MatchKindAlias,
		})
	}

	for _, a := range admin1 {
		norm := NormalizeLookupKey(a.Name)
		if norm == "" {
			continue
		}
		var best cityRef
		var found bool
		for _, c := range byID {
			if c.CountryCode == a.CountryCode && c.Admin1 == a.Admin1Code {
				if !found || popOf(c.Population) > popOf(best.Population) {
					best = c
					found = true
				}
			}
		}
		if !found {
			continue
		}
		d.putAlias(LookupKey{
			CountryCode: a.CountryCode,
			Admin1ISO:   a.Admin1Code,
			AliasNorm:   norm,
			GeonameID:   best.GeonameID,
			Lat:         best.Latitude,
			Lon:         best.Longitude,
			Timezone:    best.Timezone,
			Population:  popOf(best.Population),
			AdminName1:  a.Name,
			MatchKind:   MatchKindAdmin,
		})
		ascii := NormalizeLookupKey(a.ASCIIName)
		if ascii != "" && ascii != norm {
			d.putAlias(LookupKey{
				CountryCode: a.CountryCode,
				Admin1ISO:   a.Admin1Code,
				AliasNorm:   ascii,
				GeonameID:   best.GeonameID,
				Lat:         best.Latitude,
				Lon:         best.Longitude,
				Timezone:    best.Timezone,
				Population:  popOf(best.Population),
				AdminName1:  a.Name,
				MatchKind:   MatchKindAdmin,
			})
		}
	}

	for _, p := range postal {
		placeNorm := NormalizeLookupKey(p.PlaceName)
		admin1code := emptyToBlank(p.AdminCode1)
		var match cityRef
		var found bool
		for _, c := range byID {
			if c.CountryCode == p.CountryCode && c.CityNorm == placeNorm && c.Admin1 == admin1code {
				if !found || popOf(c.Population) > popOf(match.Population) {
					match = c
					found = true
				}
			}
		}
		k := LookupKey{
			CountryCode:   p.CountryCode,
			Admin1ISO:     admin1code,
			CityNorm:      placeNorm,
			Zipcode:       p.PostalCode,
			ZipForDisplay: p.PostalCode,
			Lat:           p.Latitude,
			Lon:           p.Longitude,
			AdminName1:    p.AdminName1,
			MatchKind:     MatchKindZip,
		}
		if found {
			k.GeonameID = match.GeonameID
			k.Lat = match.Latitude
			k.Lon = match.Longitude
			k.Timezone = match.Timezone
			k.Population = popOf(match.Population)
			if k.AdminName1 == "" {
				k.AdminName1 = adminName[p.CountryCode+"\x00"+admin1code]
			}
		}
		d.putZip(k)
		if placeNorm != "" {
			ck := LookupKey{
				CountryCode: p.CountryCode,
				Admin1ISO:   admin1code,
				CityNorm:    placeNorm,
				Lat:         k.Lat,
				Lon:         k.Lon,
				Timezone:    k.Timezone,
				Population:  k.Population,
				GeonameID:   k.GeonameID,
				AdminName1:  k.AdminName1,
				MatchKind:   MatchKindCity,
			}
			d.putCity(ck)
		}
	}

	return d.collect()
}
