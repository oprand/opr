package geoip

import "github.com/oprand/opr/store/postgres"

const (
	LACNIC_DB_CSV = "LACNIC_DB_CSV"
	RIPE_IPMAP    = postgres.GeoIPStatusSourceIPMAP
	GEOFEED       = "GEOFEED"
)
