package postgres

import (
	"time"
)

type CountryInfoItem struct {
	ISO              *string   `db:"iso" json:"iso"`
	ISO3             *string   `db:"iso3" json:"iso3"`
	ISONumeric       *string   `db:"iso_numeric" json:"iso_numeric"`
	FIPS             *string   `db:"fips" json:"fips"`
	Country          *string   `db:"country" json:"country"`
	Capital          *string   `db:"capital" json:"capital"`
	Area             *float64  `db:"area" json:"area"`
	Population       *int      `db:"population" json:"population"`
	Continent        *string   `db:"continent" json:"continent"`
	TLD              *string   `db:"tld" json:"tld"`
	CurrencyCode     *string   `db:"currency_code" json:"currency_code"`
	CurrencyName     *string   `db:"currency_name" json:"currency_name"`
	Phone            *string   `db:"phone" json:"phone"`
	PostalCodeFormat *string   `db:"postal_code_format" json:"postal_code_format"`
	PostalCodeRegex  *string   `db:"postal_code_regex" json:"postal_code_regex"`
	Languages        *[]string `db:"languages" json:"languages"`
	GeonameID        *int      `db:"geoname_id" json:"geoname_id"`
	Neighbours       *[]string `db:"neighbours" json:"neighbours"`
	EquivalentFIPS   *string   `db:"equivalent_fips" json:"equivalent_fips"`
}

type AsPopInfo struct {
	Asn          uint32
	CountryCode  string
	UserCount    uint64
	PercCountry  float64
	PercInternet float64
	SampleCount  uint64
}

type GeoIPItem struct {
	Netblock    string     `db:"netblock"`
	IPVersion   uint       `db:"ip_version"`
	CountryCode *string    `db:"country_code"`
	Country     *string    `db:"country"`
	RegionCode  *string    `db:"region_code"`
	Region      *string    `db:"region"`
	City        *string    `db:"city"`
	ZipCode     *string    `db:"zip_code"`
	Source      *string    `db:"source"`
	SourceURL   *string    `db:"source_url"`
	MetaAddedAt *time.Time `db:"meta_added_at"`
	// type is allocated, assigned, etc. Only in LACNIC dump
	Type *string `db:"type"`
	// IPmap provides lat/lon info and an accuracy score
	// https://ipmap.ripe.net/docs/01.manual
	LocationID *string  `db:"location_id"`
	Latitude   *float64 `db:"latitude"`
	Longitude  *float64 `db:"longitude"`
	Score      *float64 `db:"score"`
	// Org HQ from whoisdb_org on the anycast lookup path (not IPmap city).
	OrgName    *string `db:"org_name"`
	OrgAddress *string `db:"org_address"`
}

// AnycastPrefix is one row of anycast_prefix (bgptools anycatch dumps).
type AnycastPrefix struct {
	Netblock    string     `db:"netblock"`
	ExampleHost *string    `db:"example_host"`
	SourceURL   string     `db:"source_url"`
	MetaAddedAt *time.Time `db:"meta_added_at"`
}

type ResponseMetadataItem struct {
	ID            int64      `db:"internal_id"`
	Url           string     `db:"url"`
	Etag          *string    `db:"etag"`
	LastModified  *time.Time `db:"last_modified"`
	ContentLength *int64     `db:"content_length"`
	ContentType   *string    `db:"content_type"`
	Charset       *string    `db:"charset"`
	MetaAddedAt   *time.Time `db:"meta_added_at"`
}
