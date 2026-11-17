package postgres

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultGeoIPStaleAfter flags the geofeeds catalog, the LACNIC CSV, the
// RIPE IPmap dump, and the bgptools anycast dumps as STALE when last fetch /
// ingest is older than this. 168h matches aggregator/geofeeds.DefaultRefreshOlderThan
// (content refresh when Cache-Control did not set cache_until), not the 48h
// NRO delegated-stats clock.
const DefaultGeoIPStaleAfter = 168 * time.Hour

// LacnicCSVURL is the remote_files_metadata key written by HasFileChanged
// during `geoip lacnic`. The file is not in the geofeeds catalog.
const LacnicCSVURL = "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.csv.gz"

// IPMAPDumpURL is the remote_files_metadata key written by FetchIPMAP.
// Ingest uses the same const (aggregator/geoip.IPMAPDumpURL aliases this).
const IPMAPDumpURL = "https://ftp.ripe.net/ripe/ipmap/geolocations-latest"

// Anycast dump URLs are remote_files_metadata keys written by FetchAnycast.
const (
	AnycastV4DumpURL = "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.csv"
	AnycastV6DumpURL = "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.csv"
)

// AnycastDumpURLs is the ingest order for `geoip anycast`.
var AnycastDumpURLs = []string{AnycastV4DumpURL, AnycastV6DumpURL}

// GeoIP status source labels. Always present on the board (zeros included).
// There is no ANYCAST label here: anycast prefixes live in anycast_prefix and
// get their own clocks, and geoip.source is never 'ANYCAST' (only the
// GetIPGeoItem lookup emits GeoIPSourceANYCAST).
const (
	GeoIPStatusSourceGEOFEED = "GEOFEED"
	GeoIPStatusSourceLACNIC  = "LACNIC_DB_CSV"
	GeoIPStatusSourceIPMAP   = "RIPE_IPMAP"
)

var geoIPStatusSources = []string{GeoIPStatusSourceGEOFEED, GeoIPStatusSourceLACNIC, GeoIPStatusSourceIPMAP}

// GeoIPStatusOptions controls FetchGeoIPStatus. Zero Now/StaleAfter/
// RefreshOlderThan/LacnicURL/IPMAPURL/AnycastV4URL/AnycastV6URL are filled
// with UTC now, DefaultGeoIPStaleAfter, DefaultGeoIPStaleAfter (due interval),
// LacnicCSVURL, IPMAPDumpURL, and the two bgptools anycast dump URLs.
type GeoIPStatusOptions struct {
	Now              time.Time
	StaleAfter       time.Duration
	RefreshOlderThan time.Duration
	LacnicURL        string
	IPMAPURL         string
	AnycastV4URL     string
	AnycastV6URL     string
}

// GeoIPStatusSnapshot is the read-only geoip status board. Human output and
// --json are two renderings of the same struct.
type GeoIPStatusSnapshot struct {
	GeneratedAt      time.Time            `json:"generated_at"`
	StaleAfter       string               `json:"stale_after"`
	RefreshOlderThan string               `json:"refresh_older_than"`
	Catalog          GeofeedCatalogStatus `json:"catalog"`
	GeoIP            []GeoIPSourceCount   `json:"geoip"`
	Lacnic           LacnicCSVStatus      `json:"lacnic"`
	IPMap            IPMAPDumpStatus      `json:"ipmap"`
	AnycastV4        AnycastDumpStatus    `json:"anycast_v4"`
	AnycastV6        AnycastDumpStatus    `json:"anycast_v6"`
}

// GeofeedCatalogStatus is advertisement vs content clocks on geofeeds.
type GeofeedCatalogStatus struct {
	URLs            int64      `json:"urls"`
	Fetched         int64      `json:"fetched"`
	NeverFetched    int64      `json:"never_fetched"`
	Due             int64      `json:"due"`
	Quarantined     int64      `json:"quarantined"`
	Invalid         int64      `json:"invalid"`
	LastFetchedAt   *time.Time `json:"last_fetched_at"`
	LastCheckedAt   *time.Time `json:"last_checked_at"`
	LastSeenInWhois *time.Time `json:"last_seen_in_whois"`
	Never           bool       `json:"never"`
	Stale           bool       `json:"stale"`
}

// GeoIPSourceCount is COUNT(*) by geoip.source plus distinct non-empty
// source_url and newest meta_added_at. Empty LACNIC source_url is the CSV
// ingest key, not a catalog URL, so DistinctURLs uses NULLIF(source_url, ”).
type GeoIPSourceCount struct {
	Source        string     `json:"source"`
	Rows          int64      `json:"rows"`
	DistinctURLs  int64      `json:"distinct_urls"`
	NewestAddedAt *time.Time `json:"newest_added_at"`
	Missing       bool       `json:"missing"`
}

// LacnicCSVStatus is the LACNIC inetnum CSV crawl clock (remote_files_metadata)
// plus derived geoip rows with source=LACNIC_DB_CSV.
type LacnicCSVStatus struct {
	URL           string     `json:"url"`
	LastSeen      *time.Time `json:"last_seen"`
	Rows          int64      `json:"rows"`
	NewestAddedAt *time.Time `json:"newest_added_at"`
	Never         bool       `json:"never"`
	Stale         bool       `json:"stale"`
}

// IPMAPDumpStatus is the RIPE IPmap dump crawl clock (remote_files_metadata)
// plus derived geoip rows with source=RIPE_IPMAP. Same NEVER/STALE rules as
// LacnicCSVStatus (DefaultGeoIPStaleAfter).
type IPMAPDumpStatus struct {
	URL           string     `json:"url"`
	LastSeen      *time.Time `json:"last_seen"`
	Rows          int64      `json:"rows"`
	NewestAddedAt *time.Time `json:"newest_added_at"`
	Never         bool       `json:"never"`
	Stale         bool       `json:"stale"`
}

// AnycastDumpStatus is one bgptools anycatch CSV clock (remote_files_metadata)
// plus anycast_prefix rows for that source_url. Same NEVER/STALE rules as
// LacnicCSVStatus (DefaultGeoIPStaleAfter).
type AnycastDumpStatus struct {
	URL           string     `json:"url"`
	LastSeen      *time.Time `json:"last_seen"`
	Rows          int64      `json:"rows"`
	NewestAddedAt *time.Time `json:"newest_added_at"`
	Never         bool       `json:"never"`
	Stale         bool       `json:"stale"`
}

// geoIPCatalogStatusSQL is one snapshot of the geofeeds catalog. $1 is now,
// $2 is refresh-older-than in seconds. Due matches ClaimDueGeofeeds except it
// is read-only: no locked_at lease and no SKIP LOCKED. Quarantined URLs are
// not due. never_fetched is last_fetched_at IS NULL including quarantined.
var geoIPCatalogStatusSQL = `
SELECT
	COUNT(*),
	COUNT(*) FILTER (WHERE last_fetched_at IS NOT NULL),
	COUNT(*) FILTER (WHERE last_fetched_at IS NULL),
	COUNT(*) FILTER (
		WHERE (quarantined_until IS NULL OR quarantined_until < $1)
		  AND (
				last_fetched_at IS NULL
				OR cache_until < $1
				OR last_fetched_at < $1 - ($2 * interval '1 second')
		  )
	),
	COUNT(*) FILTER (WHERE quarantined_until IS NOT NULL AND quarantined_until > $1),
	COUNT(*) FILTER (WHERE is_valid IS FALSE),
	MAX(last_fetched_at),
	MAX(last_checked_at),
	MAX(last_seen_in_whois)
FROM geofeeds`

// geoIPSourceCountSQL groups derived rows. DISTINCT ignores empty source_url
// so LACNIC CSV rows (source_url ”) are not counted as catalog URLs.
var geoIPSourceCountSQL = `
SELECT
	COALESCE(source, ''),
	COUNT(*),
	COUNT(DISTINCT NULLIF(source_url, '')),
	MAX(meta_added_at)
FROM geoip
GROUP BY source`

// FetchGeoIPStatus loads a read-only snapshot. It does not touch the network.
func (st *Store) FetchGeoIPStatus(ctx context.Context, opts GeoIPStatusOptions) (GeoIPStatusSnapshot, error) {
	opts = NormalizeGeoIPStatusOptions(opts)

	var snap GeoIPStatusSnapshot
	snap.GeneratedAt = opts.Now
	snap.StaleAfter = opts.StaleAfter.String()
	snap.RefreshOlderThan = opts.RefreshOlderThan.String()

	catalog, err := st.fetchGeofeedCatalogStatus(ctx, opts.Now, opts.RefreshOlderThan)
	if err != nil {
		return snap, err
	}
	catalog.Never = catalog.URLs == 0
	catalog.Stale = CatalogIsStale(catalog.URLs, catalog.LastSeenInWhois, catalog.LastFetchedAt, opts.StaleAfter, opts.Now)
	snap.Catalog = catalog

	bySource, err := st.countGeoIPBySource(ctx)
	if err != nil {
		return snap, err
	}
	snap.GeoIP = MergeGeoIPSourceCounts(bySource, geoIPStatusSources)
	for i := range snap.GeoIP {
		if snap.GeoIP[i].Source == GeoIPStatusSourceGEOFEED {
			snap.GeoIP[i].Missing = GeoIPGEOFEEDMissing(snap.GeoIP[i].Rows, catalog.Fetched)
		}
	}

	times, err := st.listRemoteFileTimes(ctx, []string{
		opts.LacnicURL, opts.IPMAPURL, opts.AnycastV4URL, opts.AnycastV6URL,
	})
	if err != nil {
		return snap, err
	}
	lacnicRows := bySource[GeoIPStatusSourceLACNIC]
	meta, hasMeta := times[opts.LacnicURL]
	snap.Lacnic = EvaluateLacnicCSV(opts.LacnicURL, hasMeta, meta, lacnicRows.Rows, lacnicRows.NewestAddedAt, opts.StaleAfter, opts.Now)
	ipmapRows := bySource[GeoIPStatusSourceIPMAP]
	ipmapMeta, hasIPMAP := times[opts.IPMAPURL]
	snap.IPMap = EvaluateIPMAPDump(opts.IPMAPURL, hasIPMAP, ipmapMeta, ipmapRows.Rows, ipmapRows.NewestAddedAt, opts.StaleAfter, opts.Now)

	anycastByURL, err := st.countAnycastByURL(ctx)
	if err != nil {
		return snap, err
	}
	v4 := anycastByURL[opts.AnycastV4URL]
	v4Meta, hasV4 := times[opts.AnycastV4URL]
	snap.AnycastV4 = EvaluateAnycastDump(opts.AnycastV4URL, hasV4, v4Meta, v4.Rows, v4.NewestAddedAt, opts.StaleAfter, opts.Now)
	v6 := anycastByURL[opts.AnycastV6URL]
	v6Meta, hasV6 := times[opts.AnycastV6URL]
	snap.AnycastV6 = EvaluateAnycastDump(opts.AnycastV6URL, hasV6, v6Meta, v6.Rows, v6.NewestAddedAt, opts.StaleAfter, opts.Now)
	return snap, nil
}

func (st *Store) countAnycastByURL(ctx context.Context) (map[string]GeoIPSourceCount, error) {
	pgRows, err := st.DB.Query(ctx, anycastStatusByURLSQL)
	if err != nil {
		return nil, fmt.Errorf("geoip status anycast: %w", err)
	}
	defer pgRows.Close()

	out := make(map[string]GeoIPSourceCount)
	for pgRows.Next() {
		var url string
		var row GeoIPSourceCount
		if err := pgRows.Scan(&url, &row.Rows, &row.NewestAddedAt); err != nil {
			return nil, fmt.Errorf("geoip status anycast: %w", err)
		}
		row.Source = url
		out[url] = row
	}
	return out, pgRows.Err()
}

func (st *Store) fetchGeofeedCatalogStatus(ctx context.Context, now time.Time, refreshOlderThan time.Duration) (GeofeedCatalogStatus, error) {
	var c GeofeedCatalogStatus
	err := st.DB.QueryRow(ctx, geoIPCatalogStatusSQL, now, refreshOlderThan.Seconds()).Scan(
		&c.URLs, &c.Fetched, &c.NeverFetched, &c.Due, &c.Quarantined, &c.Invalid,
		&c.LastFetchedAt, &c.LastCheckedAt, &c.LastSeenInWhois,
	)
	if err != nil {
		return GeofeedCatalogStatus{}, fmt.Errorf("geoip status catalog: %w", err)
	}
	return c, nil
}

func (st *Store) countGeoIPBySource(ctx context.Context) (map[string]GeoIPSourceCount, error) {
	pgRows, err := st.DB.Query(ctx, geoIPSourceCountSQL)
	if err != nil {
		return nil, fmt.Errorf("geoip status rows: %w", err)
	}
	defer pgRows.Close()

	out := make(map[string]GeoIPSourceCount)
	for pgRows.Next() {
		var row GeoIPSourceCount
		if err := pgRows.Scan(&row.Source, &row.Rows, &row.DistinctURLs, &row.NewestAddedAt); err != nil {
			return nil, fmt.Errorf("geoip status rows: %w", err)
		}
		out[row.Source] = row
	}
	return out, pgRows.Err()
}

// NormalizeGeoIPStatusOptions fills zero Now / durations / LACNIC URL.
func NormalizeGeoIPStatusOptions(opts GeoIPStatusOptions) GeoIPStatusOptions {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultGeoIPStaleAfter
	}
	if opts.RefreshOlderThan <= 0 {
		opts.RefreshOlderThan = DefaultGeoIPStaleAfter
	}
	if opts.LacnicURL == "" {
		opts.LacnicURL = LacnicCSVURL
	}
	if opts.IPMAPURL == "" {
		opts.IPMAPURL = IPMAPDumpURL
	}
	if opts.AnycastV4URL == "" {
		opts.AnycastV4URL = AnycastV4DumpURL
	}
	if opts.AnycastV6URL == "" {
		opts.AnycastV6URL = AnycastV6DumpURL
	}
	return opts
}

// CatalogIsStale reports advertisement/content clocks for a non-empty catalog.
// Empty catalogs are NEVER, not STALE. STALE when last_seen_in_whois is newer
// than last fetch by staleAfter, or last fetch is older than staleAfter.
func CatalogIsStale(urls int64, lastSeen, lastFetched *time.Time, staleAfter time.Duration, now time.Time) bool {
	if urls == 0 {
		return false
	}
	if lastSeen != nil && !lastSeen.IsZero() && lastFetched != nil && !lastFetched.IsZero() {
		if lastSeen.Sub(*lastFetched) > staleAfter {
			return true
		}
	}
	if lastFetched != nil && !lastFetched.IsZero() {
		return now.Sub(*lastFetched) > staleAfter
	}
	return false
}

// GeoIPGEOFEEDMissing is GEOFEED row count 0 while the catalog has fetched URLs.
func GeoIPGEOFEEDMissing(geofeedRows, catalogFetched int64) bool {
	return geofeedRows == 0 && catalogFetched > 0
}

// EvaluateLacnicCSV sets NEVER (no metadata and no rows) or STALE (ingested
// older than staleAfter). Ingested prefers remote_files_metadata (PickFileTime),
// then newest geoip.meta_added_at for LACNIC_DB_CSV.
func EvaluateLacnicCSV(url string, hasMeta bool, meta RemoteFileTime, rows int64, newest *time.Time, staleAfter time.Duration, now time.Time) LacnicCSVStatus {
	s := LacnicCSVStatus{
		URL:           url,
		Rows:          rows,
		NewestAddedAt: newest,
	}
	s.LastSeen = PickFileTime(meta)
	if s.LastSeen == nil {
		s.LastSeen = newest
	}
	s.Never = !hasMeta && rows == 0
	if s.Never {
		s.LastSeen = nil
		return s
	}
	if s.LastSeen == nil || s.LastSeen.IsZero() {
		s.Stale = true
		return s
	}
	s.Stale = now.Sub(*s.LastSeen) > staleAfter
	return s
}

// EvaluateIPMAPDump is the IPmap dump clock. Same NEVER/STALE convention as
// EvaluateLacnicCSV (DefaultGeoIPStaleAfter).
func EvaluateIPMAPDump(url string, hasMeta bool, meta RemoteFileTime, rows int64, newest *time.Time, staleAfter time.Duration, now time.Time) IPMAPDumpStatus {
	s := EvaluateLacnicCSV(url, hasMeta, meta, rows, newest, staleAfter, now)
	return IPMAPDumpStatus{
		URL:           s.URL,
		LastSeen:      s.LastSeen,
		Rows:          s.Rows,
		NewestAddedAt: s.NewestAddedAt,
		Never:         s.Never,
		Stale:         s.Stale,
	}
}

// EvaluateAnycastDump is one anycast dump clock. Same NEVER/STALE convention
// as EvaluateLacnicCSV (DefaultGeoIPStaleAfter).
func EvaluateAnycastDump(url string, hasMeta bool, meta RemoteFileTime, rows int64, newest *time.Time, staleAfter time.Duration, now time.Time) AnycastDumpStatus {
	s := EvaluateLacnicCSV(url, hasMeta, meta, rows, newest, staleAfter, now)
	return AnycastDumpStatus{
		URL:           s.URL,
		LastSeen:      s.LastSeen,
		Rows:          s.Rows,
		NewestAddedAt: s.NewestAddedAt,
		Never:         s.Never,
		Stale:         s.Stale,
	}
}

// MergeGeoIPSourceCounts emits a row per always source (zeros included) plus
// any extra sources present in the table, always-sources first then alpha.
func MergeGeoIPSourceCounts(bySource map[string]GeoIPSourceCount, always []string) []GeoIPSourceCount {
	names := uniqueStrings(append(slices.Clone(always), mapKeys(bySource)...))
	rank := make(map[string]int, len(always))
	for i, n := range always {
		rank[n] = i
	}
	slices.SortStableFunc(names, func(a, b string) int {
		ra, oka := rank[a]
		rb, okb := rank[b]
		switch {
		case oka && okb:
			return ra - rb
		case oka:
			return -1
		case okb:
			return 1
		default:
			return strings.Compare(a, b)
		}
	})
	out := make([]GeoIPSourceCount, 0, len(names))
	for _, src := range names {
		row := bySource[src]
		row.Source = src
		out = append(out, row)
	}
	return out
}
