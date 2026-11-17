package postgres

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultGeoNamesStaleAfter flags GeoNames dump clocks as STALE when last
// verified (meta_added_at after TouchRemoteFileMetadata on an unchanged
// HEAD, else last_modified) is older than this. 48h is 2× aggregator/
// geonames CrawlInterval so a 24h crawl of a stable dump does not flap
// STALE on content Last-Modified.
const DefaultGeoNamesStaleAfter = 48 * time.Hour

// GeoNames dump URLs written by HasFileChanged / SaveResponseMetadata.
// The aggregator must consume these constants (do not duplicate the strings).
const (
	GeoNamesCountryInfoURL = "https://download.geonames.org/export/dump/countryInfo.txt"
	GeoNamesPostalURL      = "https://download.geonames.org/export/zip/allCountries.zip"
	GeoNamesCities500URL   = "https://download.geonames.org/export/dump/cities500.zip"
	GeoNamesAdmin1URL      = "https://download.geonames.org/export/dump/admin1CodesASCII.txt"
	GeoNamesAdmin2URL      = "https://download.geonames.org/export/dump/admin2Codes.txt"
	GeoNamesTimeZonesURL   = "https://download.geonames.org/export/dump/timeZones.txt"
	GeoNamesAltNamesV2URL  = "https://download.geonames.org/export/dump/alternateNamesV2.zip"
	GeoNamesAltNamesURL    = "https://download.geonames.org/export/dump/alternateNames.zip"
)

// GeoNamesDumpURLs is the pinned dump set status always shows. V2 is the
// primary alternate-names source; V1 is the ingest fallback. Both are
// fetched (or HEAD-checked) so both stay on the board.
var GeoNamesDumpURLs = []string{
	GeoNamesCountryInfoURL,
	GeoNamesPostalURL,
	GeoNamesCities500URL,
	GeoNamesAdmin1URL,
	GeoNamesAdmin2URL,
	GeoNamesTimeZonesURL,
	GeoNamesAltNamesV2URL,
	GeoNamesAltNamesURL,
}

// GeoNamesRemoteFileURLLike selects remote_files_metadata rows written by
// the GeoNames dump crawler (HasFileChanged / SaveResponseMetadata).
const GeoNamesRemoteFileURLLike = "%geonames.org%"

// GeoNames status table labels. Always present on the board (zeros included).
const (
	GeoNamesStatusTableCity        = "geonames_city"
	GeoNamesStatusTablePostal      = "geonames_postal"
	GeoNamesStatusTableAdmin1      = "geonames_admin1"
	GeoNamesStatusTableAdmin2      = "geonames_admin2"
	GeoNamesStatusTableTimezone    = "geonames_timezone"
	GeoNamesStatusTableAltName     = "geonames_altname"
	GeoNamesStatusTableLookup      = "geonames_lookup"
	GeoNamesStatusTableCountryInfo = "country_info"
)

// GeoNames lookup match_kind values from the CHECK on geonames_lookup.
const (
	GeoNamesMatchKindZip     = "zip"
	GeoNamesMatchKindCity    = "city"
	GeoNamesMatchKindAlias   = "alias"
	GeoNamesMatchKindAdmin   = "admin"
	GeoNamesMatchKindCapital = "capital"
)

var geoNamesStatusTables = []string{
	GeoNamesStatusTableCity,
	GeoNamesStatusTablePostal,
	GeoNamesStatusTableAdmin1,
	GeoNamesStatusTableAdmin2,
	GeoNamesStatusTableTimezone,
	GeoNamesStatusTableAltName,
	GeoNamesStatusTableLookup,
	GeoNamesStatusTableCountryInfo,
}

var geoNamesMatchKinds = []string{
	GeoNamesMatchKindZip,
	GeoNamesMatchKindCity,
	GeoNamesMatchKindAlias,
	GeoNamesMatchKindAdmin,
	GeoNamesMatchKindCapital,
}

// GeoNamesStatusOptions controls FetchGeoNamesStatus. Zero Now/StaleAfter
// are filled with UTC now and DefaultGeoNamesStaleAfter.
type GeoNamesStatusOptions struct {
	Now        time.Time
	StaleAfter time.Duration
}

// GeoNamesStatusSnapshot is the read-only geonames status board. Human
// output and --json are two renderings of the same struct.
type GeoNamesStatusSnapshot struct {
	GeneratedAt time.Time                `json:"generated_at"`
	StaleAfter  string                   `json:"stale_after"`
	Tables      []GeoNamesTableCount     `json:"tables"`
	MatchKind   []GeoNamesMatchKindCount `json:"match_kind"`
	Dumps       []GeoNamesDumpClock      `json:"dumps"`
	RemapRows   int64                    `json:"remap_rows"`
	// LegalFlagRows is country_legal_flag (migration 0072 seed). It is a
	// static seed, so a zero here means the migration did not run.
	LegalFlagRows int64 `json:"legal_flag_rows"`
}

// GeoNamesTableCount is COUNT(*) for one dump / lookup table. Missing is
// true when the count is zero (empty table, still listed).
type GeoNamesTableCount struct {
	Table   string `json:"table"`
	Rows    int64  `json:"rows"`
	Missing bool   `json:"missing"`
}

// GeoNamesMatchKindCount is COUNT(*) by geonames_lookup.match_kind.
type GeoNamesMatchKindCount struct {
	Kind string `json:"kind"`
	Rows int64  `json:"rows"`
}

// GeoNamesDumpClock is one pinned dump URL plus remote_files_metadata.
// LastSeen prefers meta_added_at (last verified / touch) over last_modified
// so unchanged HEAD checks move the stale clock. Never and Stale are
// exclusive (geoip LACNIC rule).
type GeoNamesDumpClock struct {
	URL         string     `json:"url"`
	LastSeen    *time.Time `json:"last_seen"`
	MetaAddedAt *time.Time `json:"meta_added_at"`
	ETagPresent bool       `json:"etag_present"`
	Never       bool       `json:"never"`
	Stale       bool       `json:"stale"`
}

// geoNamesTableCountSQL is one snapshot of the split tables plus remap.
// Each scalar subquery is COUNT(*) (0 on an empty table).
var geoNamesTableCountSQL = `
SELECT
	(SELECT COUNT(*) FROM geonames_city),
	(SELECT COUNT(*) FROM geonames_postal),
	(SELECT COUNT(*) FROM geonames_admin1),
	(SELECT COUNT(*) FROM geonames_admin2),
	(SELECT COUNT(*) FROM geonames_timezone),
	(SELECT COUNT(*) FROM geonames_altname),
	(SELECT COUNT(*) FROM geonames_lookup),
	(SELECT COUNT(*) FROM country_info),
	(SELECT COUNT(*) FROM country_code_remap),
	(SELECT COUNT(*) FROM country_legal_flag)`

// geoNamesMatchKindSQL groups lookup keys. COALESCE keeps a blank kind
// visible if a row ever violates the NOT NULL / CHECK.
var geoNamesMatchKindSQL = `
SELECT
	COALESCE(match_kind, ''),
	COUNT(*)
FROM geonames_lookup
GROUP BY 1`

// geoNamesDumpClockSQL is dump freshness from remote_files_metadata.
// ETag present is a non-empty etag; last_modified / meta_added_at are
// scanned so Go can PickFileTime and apply stale-after.
var geoNamesDumpClockSQL = `
SELECT
	url,
	last_modified,
	meta_added_at,
	etag IS NOT NULL AND TRIM(etag) <> ''
FROM remote_files_metadata
WHERE url LIKE '` + GeoNamesRemoteFileURLLike + `'
ORDER BY url`

// FetchGeoNamesStatus loads a read-only snapshot. It does not touch the network.
func (st *Store) FetchGeoNamesStatus(ctx context.Context, opts GeoNamesStatusOptions) (GeoNamesStatusSnapshot, error) {
	opts = NormalizeGeoNamesStatusOptions(opts)

	var snap GeoNamesStatusSnapshot
	snap.GeneratedAt = opts.Now
	snap.StaleAfter = opts.StaleAfter.String()

	counts, err := st.fetchGeoNamesTableCounts(ctx)
	if err != nil {
		return snap, err
	}
	snap.Tables = MergeGeoNamesTableCounts(counts, geoNamesStatusTables)
	snap.RemapRows = counts[geoNamesRemapTable]
	snap.LegalFlagRows = counts[geoNamesLegalFlagTable]

	kinds, err := st.countGeoNamesMatchKinds(ctx)
	if err != nil {
		return snap, err
	}
	snap.MatchKind = MergeGeoNamesMatchKinds(kinds, geoNamesMatchKinds)

	dumps, err := st.listGeoNamesDumpClocks(ctx, opts.StaleAfter, opts.Now)
	if err != nil {
		return snap, err
	}
	snap.Dumps = dumps
	return snap, nil
}

const (
	geoNamesRemapTable     = "country_code_remap"
	geoNamesLegalFlagTable = "country_legal_flag"
)

func (st *Store) fetchGeoNamesTableCounts(ctx context.Context) (map[string]int64, error) {
	var city, postal, admin1, admin2, timezone, altname, lookup, country, remap, legalFlag int64
	err := st.DB.QueryRow(ctx, geoNamesTableCountSQL).Scan(
		&city, &postal, &admin1, &admin2, &timezone, &altname, &lookup, &country, &remap, &legalFlag,
	)
	if err != nil {
		return nil, fmt.Errorf("geonames status tables: %w", err)
	}
	return map[string]int64{
		GeoNamesStatusTableCity:        city,
		GeoNamesStatusTablePostal:      postal,
		GeoNamesStatusTableAdmin1:      admin1,
		GeoNamesStatusTableAdmin2:      admin2,
		GeoNamesStatusTableTimezone:    timezone,
		GeoNamesStatusTableAltName:     altname,
		GeoNamesStatusTableLookup:      lookup,
		GeoNamesStatusTableCountryInfo: country,
		geoNamesRemapTable:             remap,
		geoNamesLegalFlagTable:         legalFlag,
	}, nil
}

func (st *Store) countGeoNamesMatchKinds(ctx context.Context) (map[string]int64, error) {
	pgRows, err := st.DB.Query(ctx, geoNamesMatchKindSQL)
	if err != nil {
		return nil, fmt.Errorf("geonames status match_kind: %w", err)
	}
	defer pgRows.Close()

	out := make(map[string]int64)
	for pgRows.Next() {
		var kind string
		var n int64
		if err := pgRows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("geonames status match_kind: %w", err)
		}
		out[kind] = n
	}
	return out, pgRows.Err()
}

func (st *Store) listGeoNamesDumpClocks(ctx context.Context, staleAfter time.Duration, now time.Time) ([]GeoNamesDumpClock, error) {
	pgRows, err := st.DB.Query(ctx, geoNamesDumpClockSQL)
	if err != nil {
		return nil, fmt.Errorf("geonames status dumps: %w", err)
	}
	defer pgRows.Close()

	out := make([]GeoNamesDumpClock, 0)
	for pgRows.Next() {
		var url string
		var lastModified, metaAdded *time.Time
		var etagPresent bool
		if err := pgRows.Scan(&url, &lastModified, &metaAdded, &etagPresent); err != nil {
			return nil, fmt.Errorf("geonames status dumps: %w", err)
		}
		out = append(out, EvaluateGeoNamesDump(url, lastModified, metaAdded, etagPresent, staleAfter, now))
	}
	if err := pgRows.Err(); err != nil {
		return nil, err
	}
	return MergeGeoNamesDumpClocks(out, GeoNamesDumpURLs, staleAfter, now), nil
}

// NormalizeGeoNamesStatusOptions fills zero Now / StaleAfter.
func NormalizeGeoNamesStatusOptions(opts GeoNamesStatusOptions) GeoNamesStatusOptions {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultGeoNamesStaleAfter
	}
	return opts
}

// EvaluateGeoNamesDump sets LastSeen from meta_added_at (last verified /
// TouchRemoteFileMetadata after an unchanged HEAD), then last_modified.
// Absent metadata is NEVER, never STALE. STALE is last-seen older than
// staleAfter.
func EvaluateGeoNamesDump(url string, lastModified, metaAdded *time.Time, etagPresent bool, staleAfter time.Duration, now time.Time) GeoNamesDumpClock {
	d := GeoNamesDumpClock{
		URL:         url,
		MetaAddedAt: metaAdded,
		ETagPresent: etagPresent,
	}
	hasClock := (lastModified != nil && !lastModified.IsZero()) || (metaAdded != nil && !metaAdded.IsZero())
	if !hasClock && !etagPresent {
		d.Never = true
		return d
	}
	// meta_added_at is last checked after Touch; last_modified is content.
	if metaAdded != nil && !metaAdded.IsZero() {
		d.LastSeen = metaAdded
	} else if lastModified != nil && !lastModified.IsZero() {
		d.LastSeen = lastModified
	}
	if d.LastSeen == nil || d.LastSeen.IsZero() {
		d.Stale = true
		return d
	}
	d.Stale = now.Sub(*d.LastSeen) > staleAfter
	return d
}

// MergeGeoNamesDumpClocks emits a row per expected dump URL (Never when
// metadata is absent) plus any extra geonames.org URLs from the query,
// expected order first then extras by URL.
func MergeGeoNamesDumpClocks(found []GeoNamesDumpClock, expected []string, staleAfter time.Duration, now time.Time) []GeoNamesDumpClock {
	byURL := make(map[string]GeoNamesDumpClock, len(found))
	for _, d := range found {
		byURL[d.URL] = d
	}
	out := make([]GeoNamesDumpClock, 0, len(expected)+len(found))
	seen := make(map[string]bool, len(expected))
	for _, url := range expected {
		seen[url] = true
		if d, ok := byURL[url]; ok {
			out = append(out, d)
			continue
		}
		out = append(out, EvaluateGeoNamesDump(url, nil, nil, false, staleAfter, now))
	}
	extras := make([]string, 0)
	for _, d := range found {
		if !seen[d.URL] {
			extras = append(extras, d.URL)
		}
	}
	slices.Sort(extras)
	for _, url := range extras {
		out = append(out, byURL[url])
	}
	return out
}

// MergeGeoNamesTableCounts emits a row per always table (zeros included).
// Missing is rows == 0. Extra keys in byTable are ignored except that
// callers may store remap alongside.
func MergeGeoNamesTableCounts(byTable map[string]int64, always []string) []GeoNamesTableCount {
	out := make([]GeoNamesTableCount, 0, len(always))
	for _, name := range always {
		rows := byTable[name]
		out = append(out, GeoNamesTableCount{
			Table:   name,
			Rows:    rows,
			Missing: rows == 0,
		})
	}
	return out
}

// MergeGeoNamesMatchKinds emits a row per always kind (zeros included) plus
// any extra kinds present in the table, always-kinds first then alpha.
func MergeGeoNamesMatchKinds(byKind map[string]int64, always []string) []GeoNamesMatchKindCount {
	names := uniqueStrings(append(slices.Clone(always), mapKeys(byKind)...))
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
	out := make([]GeoNamesMatchKindCount, 0, len(names))
	for _, kind := range names {
		out = append(out, GeoNamesMatchKindCount{Kind: kind, Rows: byKind[kind]})
	}
	return out
}
