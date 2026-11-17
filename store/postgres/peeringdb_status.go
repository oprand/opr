package postgres

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// DefaultPeeringDBStaleAfter flags dump clocks as STALE when last verified
// (meta_added_at after TouchRemoteFileMetadata on an unchanged HEAD, else
// last_modified) is older than this. 48h is 2× aggregator/peeringdb
// DefaultCrawlInterval so a stable dump does not flap STALE on content
// Last-Modified.
const DefaultPeeringDBStaleAfter = 48 * time.Hour

// Official peeringdb-py cache dumps (API-shaped {"data":[...]}).
// The aggregator must consume these constants (do not duplicate the strings).
const (
	PeeringDBDumpBaseURL = "https://public.peeringdb.com"

	PeeringDBDumpTagOrg      = "org"
	PeeringDBDumpTagFac      = "fac"
	PeeringDBDumpTagNet      = "net"
	PeeringDBDumpTagIX       = "ix"
	PeeringDBDumpTagIXFac    = "ixfac"
	PeeringDBDumpTagIXLAN    = "ixlan"
	PeeringDBDumpTagIXPfx    = "ixpfx"
	PeeringDBDumpTagPOC      = "poc"
	PeeringDBDumpTagNetFac   = "netfac"
	PeeringDBDumpTagNetIXLAN = "netixlan"

	PeeringDBOrgDumpURL      = PeeringDBDumpBaseURL + "/org-0.json"
	PeeringDBFacDumpURL      = PeeringDBDumpBaseURL + "/fac-0.json"
	PeeringDBNetDumpURL      = PeeringDBDumpBaseURL + "/net-0.json"
	PeeringDBIXDumpURL       = PeeringDBDumpBaseURL + "/ix-0.json"
	PeeringDBIXFacDumpURL    = PeeringDBDumpBaseURL + "/ixfac-0.json"
	PeeringDBIXLANDumpURL    = PeeringDBDumpBaseURL + "/ixlan-0.json"
	PeeringDBIXPfxDumpURL    = PeeringDBDumpBaseURL + "/ixpfx-0.json"
	PeeringDBPOCDumpURL      = PeeringDBDumpBaseURL + "/poc-0.json"
	PeeringDBNetFacDumpURL   = PeeringDBDumpBaseURL + "/netfac-0.json"
	PeeringDBNetIXLANDumpURL = PeeringDBDumpBaseURL + "/netixlan-0.json"
)

// PeeringDBDumpURL returns the pinned https://public.peeringdb.com/{tag}-0.json
// URL. Unknown tags still get the same shape so tests can lock the constant.
func PeeringDBDumpURL(tag string) string {
	return PeeringDBDumpBaseURL + "/" + tag + "-0.json"
}

// PeeringDB status table labels. Always present on the board (zeros included).
const (
	PeeringDBTableOrganization    = "peeringdb_organization"
	PeeringDBTableFacility        = "peeringdb_facility"
	PeeringDBTableNetwork         = "peeringdb_network"
	PeeringDBTableIX              = "peeringdb_ix"
	PeeringDBTableIXFacility      = "peeringdb_ix_facility"
	PeeringDBTableIXLAN           = "peeringdb_ixlan"
	PeeringDBTableIXLANPrefix     = "peeringdb_ixlan_prefix"
	PeeringDBTableNetworkContact  = "peeringdb_network_contact"
	PeeringDBTableNetworkFacility = "peeringdb_network_facility"
	PeeringDBTableNetworkIXLAN    = "peeringdb_network_ixlan"
)

// PeeringDBDumpRef is one official dump tag plus its live table and URL.
type PeeringDBDumpRef struct {
	Tag   string
	Table string
	URL   string
}

// PeeringDBDumps is the pinned dump set ingest and status always use.
var PeeringDBDumps = []PeeringDBDumpRef{
	{Tag: PeeringDBDumpTagOrg, Table: PeeringDBTableOrganization, URL: PeeringDBOrgDumpURL},
	{Tag: PeeringDBDumpTagFac, Table: PeeringDBTableFacility, URL: PeeringDBFacDumpURL},
	{Tag: PeeringDBDumpTagNet, Table: PeeringDBTableNetwork, URL: PeeringDBNetDumpURL},
	{Tag: PeeringDBDumpTagIX, Table: PeeringDBTableIX, URL: PeeringDBIXDumpURL},
	{Tag: PeeringDBDumpTagIXFac, Table: PeeringDBTableIXFacility, URL: PeeringDBIXFacDumpURL},
	{Tag: PeeringDBDumpTagIXLAN, Table: PeeringDBTableIXLAN, URL: PeeringDBIXLANDumpURL},
	{Tag: PeeringDBDumpTagIXPfx, Table: PeeringDBTableIXLANPrefix, URL: PeeringDBIXPfxDumpURL},
	{Tag: PeeringDBDumpTagPOC, Table: PeeringDBTableNetworkContact, URL: PeeringDBPOCDumpURL},
	{Tag: PeeringDBDumpTagNetFac, Table: PeeringDBTableNetworkFacility, URL: PeeringDBNetFacDumpURL},
	{Tag: PeeringDBDumpTagNetIXLAN, Table: PeeringDBTableNetworkIXLAN, URL: PeeringDBNetIXLANDumpURL},
}

// PeeringDBDumpURLs is the pinned dump set status always shows.
var PeeringDBDumpURLs = func() []string {
	out := make([]string, 0, len(PeeringDBDumps))
	for _, d := range PeeringDBDumps {
		out = append(out, d.URL)
	}
	return out
}()

var peeringDBStatusTables = []string{
	PeeringDBTableOrganization,
	PeeringDBTableFacility,
	PeeringDBTableNetwork,
	PeeringDBTableIX,
	PeeringDBTableIXFacility,
	PeeringDBTableIXLAN,
	PeeringDBTableIXLANPrefix,
	PeeringDBTableNetworkContact,
	PeeringDBTableNetworkFacility,
	PeeringDBTableNetworkIXLAN,
}

// PeeringDBRemoteFileURLLike selects remote_files_metadata rows written by
// the PeeringDB dump crawler (HasFileChanged / SaveResponseMetadata).
const PeeringDBRemoteFileURLLike = "%public.peeringdb.com%"

// PeeringDBStatusOptions controls FetchPeeringDBStatus. Zero Now/StaleAfter
// are filled with UTC now and DefaultPeeringDBStaleAfter.
type PeeringDBStatusOptions struct {
	Now        time.Time
	StaleAfter time.Duration
}

// PeeringDBStatusSnapshot is the read-only peeringdb status board. Human
// output and --json are two renderings of the same struct.
type PeeringDBStatusSnapshot struct {
	GeneratedAt time.Time             `json:"generated_at"`
	StaleAfter  string                `json:"stale_after"`
	Tables      []PeeringDBTableCount `json:"tables"`
	Dumps       []PeeringDBDumpClock  `json:"dumps"`
	Sync        PeeringDBSyncClock    `json:"sync"`
}

// PeeringDBTableCount is COUNT(*) for one peeringdb_* table.
// Missing is true when the count is zero (empty table, still listed).
type PeeringDBTableCount struct {
	Table   string `json:"table"`
	Rows    int64  `json:"rows"`
	Missing bool   `json:"missing"`
}

// PeeringDBDumpClock is one pinned dump URL plus remote_files_metadata.
// LastSeen prefers meta_added_at (last verified / touch) over last_modified
// so unchanged HEAD checks move the stale clock. Never and Stale are
// exclusive (geonames / geoip LACNIC rule).
type PeeringDBDumpClock struct {
	URL         string     `json:"url"`
	LastSeen    *time.Time `json:"last_seen"`
	MetaAddedAt *time.Time `json:"meta_added_at"`
	ETagPresent bool       `json:"etag_present"`
	Never       bool       `json:"never"`
	Stale       bool       `json:"stale"`
}

// PeeringDBSyncClock is MAX(updated) across the 10 base peeringdb_* tables.
// Never and Stale are exclusive.
type PeeringDBSyncClock struct {
	LastUpdated *time.Time `json:"last_updated"`
	Never       bool       `json:"never"`
	Stale       bool       `json:"stale"`
}

// peeringDBTableCountSQL is one snapshot of the 10 base tables.
// Each scalar subquery is COUNT(*) (0 on an empty table).
var peeringDBTableCountSQL = `
SELECT
	(SELECT COUNT(*) FROM peeringdb_organization),
	(SELECT COUNT(*) FROM peeringdb_facility),
	(SELECT COUNT(*) FROM peeringdb_network),
	(SELECT COUNT(*) FROM peeringdb_ix),
	(SELECT COUNT(*) FROM peeringdb_ix_facility),
	(SELECT COUNT(*) FROM peeringdb_ixlan),
	(SELECT COUNT(*) FROM peeringdb_ixlan_prefix),
	(SELECT COUNT(*) FROM peeringdb_network_contact),
	(SELECT COUNT(*) FROM peeringdb_network_facility),
	(SELECT COUNT(*) FROM peeringdb_network_ixlan)`

// peeringDBSyncClockSQL is MAX(updated) across the 10 base tables.
var peeringDBSyncClockSQL = `
SELECT MAX(u) FROM (
	SELECT MAX(updated) AS u FROM peeringdb_organization
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_facility
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_network
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_ix
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_ix_facility
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_ixlan
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_ixlan_prefix
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_network_contact
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_network_facility
	UNION ALL
	SELECT MAX(updated) FROM peeringdb_network_ixlan
) t`

// peeringDBDumpClockSQL is dump freshness from remote_files_metadata.
var peeringDBDumpClockSQL = `
SELECT
	url,
	last_modified,
	meta_added_at,
	etag IS NOT NULL AND TRIM(etag) <> ''
FROM remote_files_metadata
WHERE url LIKE '` + PeeringDBRemoteFileURLLike + `'
ORDER BY url`

// FetchPeeringDBStatus loads a read-only snapshot. It does not touch the network.
func (st *Store) FetchPeeringDBStatus(ctx context.Context, opts PeeringDBStatusOptions) (PeeringDBStatusSnapshot, error) {
	opts = NormalizePeeringDBStatusOptions(opts)

	var snap PeeringDBStatusSnapshot
	snap.GeneratedAt = opts.Now
	snap.StaleAfter = opts.StaleAfter.String()

	counts, err := st.fetchPeeringDBTableCounts(ctx)
	if err != nil {
		return snap, err
	}
	snap.Tables = MergePeeringDBTableCounts(counts, peeringDBStatusTables)

	dumps, err := st.listPeeringDBDumpClocks(ctx, opts.StaleAfter, opts.Now)
	if err != nil {
		return snap, err
	}
	snap.Dumps = dumps

	lastUpdated, err := st.fetchPeeringDBSyncClock(ctx)
	if err != nil {
		return snap, err
	}
	snap.Sync = EvaluatePeeringDBSync(lastUpdated, opts.StaleAfter, opts.Now)
	return snap, nil
}

func (st *Store) fetchPeeringDBTableCounts(ctx context.Context) (map[string]int64, error) {
	var org, fac, net, ix, ixfac, ixlan, ixpfx, poc, netfac, netixlan int64
	err := st.DB.QueryRow(ctx, peeringDBTableCountSQL).Scan(
		&org, &fac, &net, &ix, &ixfac, &ixlan, &ixpfx, &poc, &netfac, &netixlan,
	)
	if err != nil {
		return nil, fmt.Errorf("peeringdb status tables: %w", err)
	}
	return map[string]int64{
		PeeringDBTableOrganization:    org,
		PeeringDBTableFacility:        fac,
		PeeringDBTableNetwork:         net,
		PeeringDBTableIX:              ix,
		PeeringDBTableIXFacility:      ixfac,
		PeeringDBTableIXLAN:           ixlan,
		PeeringDBTableIXLANPrefix:     ixpfx,
		PeeringDBTableNetworkContact:  poc,
		PeeringDBTableNetworkFacility: netfac,
		PeeringDBTableNetworkIXLAN:    netixlan,
	}, nil
}

func (st *Store) fetchPeeringDBSyncClock(ctx context.Context) (*time.Time, error) {
	var last *time.Time
	err := st.DB.QueryRow(ctx, peeringDBSyncClockSQL).Scan(&last)
	if err != nil {
		return nil, fmt.Errorf("peeringdb status sync: %w", err)
	}
	return last, nil
}

func (st *Store) listPeeringDBDumpClocks(ctx context.Context, staleAfter time.Duration, now time.Time) ([]PeeringDBDumpClock, error) {
	pgRows, err := st.DB.Query(ctx, peeringDBDumpClockSQL)
	if err != nil {
		return nil, fmt.Errorf("peeringdb status dumps: %w", err)
	}
	defer pgRows.Close()

	out := make([]PeeringDBDumpClock, 0)
	for pgRows.Next() {
		var url string
		var lastModified, metaAdded *time.Time
		var etagPresent bool
		if err := pgRows.Scan(&url, &lastModified, &metaAdded, &etagPresent); err != nil {
			return nil, fmt.Errorf("peeringdb status dumps: %w", err)
		}
		out = append(out, EvaluatePeeringDBDump(url, lastModified, metaAdded, etagPresent, staleAfter, now))
	}
	if err := pgRows.Err(); err != nil {
		return nil, err
	}
	return MergePeeringDBDumpClocks(out, PeeringDBDumpURLs, staleAfter, now), nil
}

// NormalizePeeringDBStatusOptions fills zero Now / StaleAfter.
func NormalizePeeringDBStatusOptions(opts PeeringDBStatusOptions) PeeringDBStatusOptions {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultPeeringDBStaleAfter
	}
	return opts
}

// EvaluatePeeringDBDump sets LastSeen from meta_added_at (last verified /
// TouchRemoteFileMetadata after an unchanged HEAD), then last_modified.
// Absent metadata is NEVER, never STALE. STALE is last-seen older than
// staleAfter.
func EvaluatePeeringDBDump(url string, lastModified, metaAdded *time.Time, etagPresent bool, staleAfter time.Duration, now time.Time) PeeringDBDumpClock {
	d := PeeringDBDumpClock{
		URL:         url,
		MetaAddedAt: metaAdded,
		ETagPresent: etagPresent,
	}
	hasClock := (lastModified != nil && !lastModified.IsZero()) || (metaAdded != nil && !metaAdded.IsZero())
	if !hasClock && !etagPresent {
		d.Never = true
		return d
	}
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

// EvaluatePeeringDBSync flags MAX(updated) across base tables. Absent is
// NEVER, never STALE. STALE is last-updated older than staleAfter.
func EvaluatePeeringDBSync(lastUpdated *time.Time, staleAfter time.Duration, now time.Time) PeeringDBSyncClock {
	s := PeeringDBSyncClock{LastUpdated: lastUpdated}
	if lastUpdated == nil || lastUpdated.IsZero() {
		s.Never = true
		s.LastUpdated = nil
		return s
	}
	s.Stale = now.Sub(*lastUpdated) > staleAfter
	return s
}

// MergePeeringDBDumpClocks emits a row per expected dump URL (Never when
// metadata is absent) plus any extra public.peeringdb.com URLs from the
// query, expected order first then extras by URL.
func MergePeeringDBDumpClocks(found []PeeringDBDumpClock, expected []string, staleAfter time.Duration, now time.Time) []PeeringDBDumpClock {
	byURL := make(map[string]PeeringDBDumpClock, len(found))
	for _, d := range found {
		byURL[d.URL] = d
	}
	out := make([]PeeringDBDumpClock, 0, len(expected)+len(found))
	seen := make(map[string]bool, len(expected))
	for _, url := range expected {
		seen[url] = true
		if d, ok := byURL[url]; ok {
			out = append(out, d)
			continue
		}
		out = append(out, EvaluatePeeringDBDump(url, nil, nil, false, staleAfter, now))
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

// MergePeeringDBTableCounts emits a row per always table (zeros included).
// Missing is rows == 0.
func MergePeeringDBTableCounts(byTable map[string]int64, always []string) []PeeringDBTableCount {
	out := make([]PeeringDBTableCount, 0, len(always))
	for _, name := range always {
		rows := byTable[name]
		out = append(out, PeeringDBTableCount{
			Table:   name,
			Rows:    rows,
			Missing: rows == 0,
		})
	}
	return out
}
