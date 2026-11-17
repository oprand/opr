package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Fetch methods for rdns_delegation.fetch_method.
const (
	FetchMethodZoneFile     = "zone_file"
	FetchMethodIANAZone     = "iana_zone"
	FetchMethodWhoisDomain  = "whois_domain"
	FetchMethodWhoisInetnum = "whois_inetnum"
)

// RDNSSourceIANA is InterNIC parent-zone rows (task 5). Unique (zone, source)
// keeps these beside RIR zone-file rows for the same /8.
const RDNSSourceIANA = "IANA"

// RDNSStatusSources is the five RIRs always shown on `opr rdns status`
// (zeros included). Order matches other CLI registry lists. IANA is a
// separate coverage section, not a sixth SOURCES row.
var RDNSStatusSources = []string{"AFRINIC", "APNIC", "ARIN", "LACNIC", "RIPE"}

// DefaultRDNSStaleAfter flags RIR last-fetch and IANA/WHOIS dump clocks as
// STALE. 168h matches geoip dump clocks: zone files and InterNIC change
// slowly and ingest is not on `opr run`.
const DefaultRDNSStaleAfter = 168 * time.Hour

// InterNIC parent zone URLs (task 5). Both ip6.arpa and ip6.arpa.zone HEAD
// 200; the unsuffixed origin filename is the default.
const (
	IANAInAddrURL = "https://www.internic.net/zones/in-addr.arpa.zone"
	IANAIP6URL    = "https://www.internic.net/zones/ip6.arpa"
)

// WHOIS reverse-domain / LACNIC inetnum dump URLs (tasks 6–7). AFRINIC is
// the mixed dbase already fetched by whoisdb (no second AFRINIC URL).
const (
	RIPEDomainDumpURL  = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.domain.gz"
	APNICDomainDumpURL = "https://ftp.apnic.net/apnic/whois/apnic.db.domain.gz"
	AFRINICWhoisDBURL  = "https://ftp.afrinic.net/dbase/afrinic.db.gz"
	LACNICWhoisDBURL   = "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz"
)

// RDNSDumpURLs is the pinned dump set `opr rdns status` always shows.
var RDNSDumpURLs = []string{
	IANAInAddrURL,
	IANAIP6URL,
	RIPEDomainDumpURL,
	APNICDomainDumpURL,
	AFRINICWhoisDBURL,
	LACNICWhoisDBURL,
}

// RDNSDelegation is one reverse-DNS cut from a RIR zone file, IANA parent
// zone, or WHOIS enrich.
type RDNSDelegation struct {
	Zone               string
	Prefix             string
	Nservers           []string
	DS                 []string
	CNAMETarget        *string
	Source             string
	SourceURL          string
	Org                string
	AdminC             []string
	TechC              []string
	MntBy              []string
	DelegatedRIR       string
	MetaAddedAt        *time.Time
	LastFetchedAt      *time.Time
	LastChangedAt      *time.Time
	ContentHash        *string
	FetchMethod        *string
	IsPartial          bool
	LastSeenInSourceAt *time.Time
}

var rdnsUpsert = whoisUpsertSpec{
	live: "rdns_delegation",
	columns: []string{
		"zone", "prefix", "nservers", "ds", "cname_target",
		"source", "source_url", "org", "admin_c", "tech_c", "mnt_by",
		"delegated_rir", "meta_added_at",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"nservers":      "COALESCE(nservers, '{}')",
		"ds":            "COALESCE(ds, '{}')",
		"admin_c":       "COALESCE(admin_c, '{}')",
		"tech_c":        "COALESCE(tech_c, '{}')",
		"mnt_by":        "COALESCE(mnt_by, '{}')",
		"meta_added_at": "COALESCE(meta_added_at, NOW())",
		"is_partial":    "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (zone, source)
			DO UPDATE SET
				prefix = CASE
					WHEN EXCLUDED.fetch_method IN ('zone_file', 'iana_zone') THEN EXCLUDED.prefix
					ELSE rdns_delegation.prefix
				END,
				nservers = CASE
					WHEN EXCLUDED.fetch_method IN ('zone_file', 'iana_zone') THEN EXCLUDED.nservers
					WHEN cardinality(rdns_delegation.nservers) > 0 THEN rdns_delegation.nservers
					ELSE EXCLUDED.nservers
				END,
				ds = CASE
					WHEN EXCLUDED.fetch_method IN ('zone_file', 'iana_zone') THEN EXCLUDED.ds
					ELSE rdns_delegation.ds
				END,
				cname_target = CASE
					WHEN EXCLUDED.fetch_method IN ('zone_file', 'iana_zone') THEN EXCLUDED.cname_target
					ELSE rdns_delegation.cname_target
				END,
				source_url = CASE
					WHEN rdns_delegation.fetch_method IN ('zone_file', 'iana_zone')
						AND EXCLUDED.fetch_method NOT IN ('zone_file', 'iana_zone')
					THEN rdns_delegation.source_url
					ELSE EXCLUDED.source_url
				END,
				org = COALESCE(NULLIF(EXCLUDED.org, ''), rdns_delegation.org),
				admin_c = CASE
					WHEN cardinality(COALESCE(EXCLUDED.admin_c, '{}')) > 0 THEN EXCLUDED.admin_c
					ELSE rdns_delegation.admin_c
				END,
				tech_c = CASE
					WHEN cardinality(COALESCE(EXCLUDED.tech_c, '{}')) > 0 THEN EXCLUDED.tech_c
					ELSE rdns_delegation.tech_c
				END,
				mnt_by = CASE
					WHEN cardinality(COALESCE(EXCLUDED.mnt_by, '{}')) > 0 THEN EXCLUDED.mnt_by
					ELSE rdns_delegation.mnt_by
				END,
				delegated_rir = COALESCE(NULLIF(EXCLUDED.delegated_rir, ''), rdns_delegation.delegated_rir),
				meta_added_at = EXCLUDED.meta_added_at,
				last_fetched_at = EXCLUDED.last_fetched_at,
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, rdns_delegation.last_changed_at),
				content_hash = EXCLUDED.content_hash,
				fetch_method = CASE
					WHEN rdns_delegation.fetch_method IN ('zone_file', 'iana_zone')
						AND EXCLUDED.fetch_method NOT IN ('zone_file', 'iana_zone')
					THEN rdns_delegation.fetch_method
					ELSE EXCLUDED.fetch_method
				END,
				is_partial = CASE
					WHEN rdns_delegation.fetch_method IN ('zone_file', 'iana_zone')
						AND EXCLUDED.fetch_method NOT IN ('zone_file', 'iana_zone')
					THEN rdns_delegation.is_partial
					ELSE EXCLUDED.is_partial
				END,
				last_seen_in_source_at = EXCLUDED.last_seen_in_source_at`,
}

func rdnsCopyRow(row *RDNSDelegation) []any {
	ns := row.Nservers
	if ns == nil {
		ns = []string{}
	}
	ds := row.DS
	if ds == nil {
		ds = []string{}
	}
	adminC := row.AdminC
	if adminC == nil {
		adminC = []string{}
	}
	techC := row.TechC
	if techC == nil {
		techC = []string{}
	}
	mntBy := row.MntBy
	if mntBy == nil {
		mntBy = []string{}
	}
	return []any{
		row.Zone, row.Prefix, ns, ds, row.CNAMETarget,
		row.Source, row.SourceURL, nullIfEmpty(row.Org), adminC, techC, mntBy,
		nullIfEmpty(row.DelegatedRIR), row.MetaAddedAt,
		row.LastFetchedAt, row.LastChangedAt, row.ContentHash,
		row.FetchMethod, row.IsPartial, row.LastSeenInSourceAt,
	}
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func rdnsConflictKey(row *RDNSDelegation) (string, bool) {
	if row == nil || row.Zone == "" || row.Source == "" || row.Prefix == "" {
		return "", false
	}
	return row.Zone + "\x00" + row.Source, true
}

func dedupRDNSDelegations(rows []RDNSDelegation) []RDNSDelegation {
	return dedupLastWins(rows, func(row RDNSDelegation) (string, bool) {
		return rdnsConflictKey(&row)
	})
}

// replaceRDNSDeleteStaleSQL drops rows for one zone-file URL that are not in
// this successful parse. rdns_delegation_stg is the COPY temp from rdnsUpsert
// (ON COMMIT DROP); it must run in the same transaction as the upsert.
var replaceRDNSDeleteStaleSQL = `
DELETE FROM rdns_delegation
WHERE source_url = $1
  AND NOT EXISTS (
    SELECT 1 FROM rdns_delegation_stg s
    WHERE s.zone = rdns_delegation.zone
      AND s.source = rdns_delegation.source
  )`

var listRDNSSourceURLsSQL = `
SELECT DISTINCT source_url
FROM rdns_delegation
WHERE source = $1
  AND source_url <> ''
ORDER BY source_url`

var countRDNSBySourceURLSQL = `
SELECT COUNT(*) FROM rdns_delegation
WHERE source_url = $1`

var rdnsStatusBySourceSQL = `
SELECT
	source,
	COUNT(*)::bigint,
	MAX(last_fetched_at),
	MAX(last_changed_at)
FROM rdns_delegation
WHERE source <> 'IANA'
GROUP BY source`

var rdnsIANACutsSQL = `
SELECT zone, prefix::text, COALESCE(nservers, '{}'), COALESCE(delegated_rir, '')
FROM rdns_delegation
WHERE source = 'IANA'`

var rdnsFetchedZonesSQL = `
SELECT source, zone
FROM rdns_delegation
WHERE source <> 'IANA'`

var rdnsWhoisEnrichSQL = `
SELECT
	COUNT(*)::bigint,
	COUNT(*) FILTER (
		WHERE (org IS NOT NULL AND btrim(org) <> '')
		   OR cardinality(COALESCE(admin_c, '{}')) > 0
		   OR cardinality(COALESCE(tech_c, '{}')) > 0
		   OR cardinality(COALESCE(mnt_by, '{}')) > 0
	)::bigint
FROM rdns_delegation
WHERE source <> 'IANA'`

var rdnsPTRStatusTotalsSQL = `
SELECT
	COUNT(*)::bigint,
	COUNT(*) FILTER (WHERE ptr IS NOT NULL)::bigint,
	MAX(fetched_at)
FROM rdns_ptr`

var rdnsPTRStatusRcodeSQL = `
SELECT COALESCE(NULLIF(btrim(rcode), ''), 'other'), COUNT(*)::bigint
FROM rdns_ptr
GROUP BY 1`

// RDNSPTRRcodeOrder is the status board rcode column order (zeros included).
var RDNSPTRRcodeOrder = []string{
	"NOERROR", "NXDOMAIN", "NODATA", "SERVFAIL", "REFUSED", "TIMEOUT", "ERROR", "other",
}

var rdnsDumpClockSQL = `
SELECT
	url,
	last_modified,
	meta_added_at,
	etag IS NOT NULL AND TRIM(etag) <> ''
FROM remote_files_metadata
WHERE url = ANY($1)
ORDER BY url`

// ReplaceRDNSBySourceURL replaces all rdns_delegation rows for sourceURL with
// rows in one transaction. It never deletes another URL's rows, and it never
// deletes this URL's rows when rows is empty (callers must not invoke this
// after a failed or empty parse — last good rows stay).
func (st *Store) ReplaceRDNSBySourceURL(ctx context.Context, sourceURL string, rows []RDNSDelegation) error {
	if sourceURL == "" {
		return fmt.Errorf("replace rdns by source_url: empty source_url")
	}

	forced := make([]RDNSDelegation, 0, len(rows))
	for _, row := range rows {
		if row.Zone == "" || row.Source == "" || row.Prefix == "" {
			continue
		}
		row.SourceURL = sourceURL
		forced = append(forced, row)
	}
	forced = dedupRDNSDelegations(forced)
	if len(forced) == 0 {
		return fmt.Errorf("replace rdns by source_url: empty rows must not wipe %s", sourceURL)
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replace rdns by source_url: %w", err)
	}
	defer tx.Rollback(context.Background())

	if err := copyIntoTempThenUpsert(ctx, tx, rdnsUpsert, len(forced), func(i int) ([]any, error) {
		return rdnsCopyRow(&forced[i]), nil
	}); err != nil {
		return fmt.Errorf("replace rdns by source_url: %w", err)
	}

	if _, err := tx.Exec(ctx, replaceRDNSDeleteStaleSQL, sourceURL); err != nil {
		return fmt.Errorf("replace rdns by source_url: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("replace rdns by source_url: %w", err)
	}
	return nil
}

// UpsertRDNSDelegations merges rows without stale-delete. WHOIS enrich uses
// this so zone-file NS and IANA parent rows are not wiped. ON CONFLICT keeps
// zone-file nservers when both exist.
func (st *Store) UpsertRDNSDelegations(ctx context.Context, rows []RDNSDelegation) error {
	forced := make([]RDNSDelegation, 0, len(rows))
	for _, row := range rows {
		if row.Zone == "" || row.Source == "" || row.Prefix == "" {
			continue
		}
		forced = append(forced, row)
	}
	forced = dedupRDNSDelegations(forced)
	if len(forced) == 0 {
		return nil
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("upsert rdns: %w", err)
	}
	defer tx.Rollback(context.Background())

	if err := copyIntoTempThenUpsert(ctx, tx, rdnsUpsert, len(forced), func(i int) ([]any, error) {
		return rdnsCopyRow(&forced[i]), nil
	}); err != nil {
		return fmt.Errorf("upsert rdns: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("upsert rdns: %w", err)
	}
	return nil
}

// CountRDNSBySourceURL is the existing-row count used by zone ingest before
// ReplaceRDNSBySourceURL (replace-floor guard).
func (st *Store) CountRDNSBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	if sourceURL == "" {
		return 0, fmt.Errorf("count rdns by source_url: empty source_url")
	}
	var n int64
	if err := st.DB.QueryRow(ctx, countRDNSBySourceURLSQL, sourceURL).Scan(&n); err != nil {
		return 0, fmt.Errorf("count rdns by source_url: %w", err)
	}
	return n, nil
}

// ListRDNSSourceURLs returns distinct zone-file URLs already stored for a RIR.
func (st *Store) ListRDNSSourceURLs(ctx context.Context, source string) ([]string, error) {
	if source == "" {
		return nil, fmt.Errorf("list rdns source_url: empty source")
	}
	rows, err := st.DB.Query(ctx, listRDNSSourceURLsSQL, source)
	if err != nil {
		return nil, fmt.Errorf("list rdns source_url: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list rdns source_url: %w", err)
	}
	return out, nil
}

// RDNSStatusOptions controls FetchRDNSStatus. Zero Now/StaleAfter are filled
// with UTC now and DefaultRDNSStaleAfter.
type RDNSStatusOptions struct {
	Now        time.Time
	StaleAfter time.Duration
}

// RDNSStatusSnapshot is the read-only board for `opr rdns status`.
type RDNSStatusSnapshot struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	StaleAfter    string            `json:"stale_after"`
	Sources       []RDNSSourceCount `json:"sources"`
	IANA          RDNSIANACoverage  `json:"iana"`
	WhoisEligible int64             `json:"whois_eligible"`
	WhoisEnriched int64             `json:"whois_enriched"`
	PTR           RDNSPTRStatus     `json:"ptr"`
	Dumps         []RDNSDumpClock   `json:"dumps"`
}

// RDNSPTRStatus is cheap aggregates on rdns_ptr (no leaf recompute).
type RDNSPTRStatus struct {
	Rows          int64               `json:"rows"`
	WithPTR       int64               `json:"with_ptr"`
	Empty         int64               `json:"empty"`
	Rcodes        []RDNSPTRRcodeCount `json:"rcodes"`
	LastFetchedAt *time.Time          `json:"last_fetched_at"`
	Never         bool                `json:"never"`
	Stale         bool                `json:"stale"`
}

// RDNSPTRRcodeCount is COUNT(*) for one rcode (zeros included for known codes).
type RDNSPTRRcodeCount struct {
	Rcode string `json:"rcode"`
	Rows  int64  `json:"rows"`
}

// RDNSSourceCount is one RIR's row count and last successful zone ingest.
type RDNSSourceCount struct {
	Source        string     `json:"source"`
	Rows          int64      `json:"rows"`
	LastFetchedAt *time.Time `json:"last_fetched_at"`
	LastChangedAt *time.Time `json:"last_changed_at,omitempty"`
	Never         bool       `json:"never"`
	Stale         bool       `json:"stale"`
}

// RDNSIANACoverage is InterNIC expected cuts vs RIR zone-file rows.
type RDNSIANACoverage struct {
	Expected int      `json:"expected"`
	Fetched  int      `json:"fetched"`
	Missing  int      `json:"missing"`
	Gaps     []string `json:"gaps,omitempty"`
}

// RDNSDumpClock is one pinned dump URL plus remote_files_metadata.
type RDNSDumpClock struct {
	URL         string     `json:"url"`
	LastSeen    *time.Time `json:"last_seen"`
	MetaAddedAt *time.Time `json:"meta_added_at,omitempty"`
	ETagPresent bool       `json:"etag_present"`
	Never       bool       `json:"never"`
	Stale       bool       `json:"stale"`
}

const rdnsIANAGapCap = 20

// NormalizeRDNSStatusOptions fills zero Now / StaleAfter.
func NormalizeRDNSStatusOptions(opts RDNSStatusOptions) RDNSStatusOptions {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultRDNSStaleAfter
	}
	return opts
}

// FetchRDNSStatus reads counts per RIR, IANA expected vs fetched, WHOIS
// enrich coverage, cheap rdns_ptr aggregates, and dump clocks. Missing RIRs
// are present with zero rows (empty table → all NEVER). Missing rdns_ptr
// (pre-0079) is treated as empty PTR NEVER.
func (st *Store) FetchRDNSStatus(ctx context.Context, opts RDNSStatusOptions) (RDNSStatusSnapshot, error) {
	opts = NormalizeRDNSStatusOptions(opts)
	snap := RDNSStatusSnapshot{
		GeneratedAt: opts.Now.UTC(),
		StaleAfter:  opts.StaleAfter.String(),
	}

	if err := st.fillRDNSSourceCounts(ctx, &snap, opts); err != nil {
		return snap, err
	}
	if err := st.fillRDNSIANACoverage(ctx, &snap); err != nil {
		return snap, err
	}
	if err := st.fillRDNSWhoisCoverage(ctx, &snap); err != nil {
		return snap, err
	}
	if err := st.fillRDNSPTRStatus(ctx, &snap, opts); err != nil {
		return snap, err
	}
	dumps, err := st.listRDNSDumpClocks(ctx, opts.StaleAfter, opts.Now)
	if err != nil {
		return snap, err
	}
	snap.Dumps = dumps
	return snap, nil
}

func (st *Store) fillRDNSSourceCounts(ctx context.Context, snap *RDNSStatusSnapshot, opts RDNSStatusOptions) error {
	rows, err := st.DB.Query(ctx, rdnsStatusBySourceSQL)
	if err != nil {
		return fmt.Errorf("rdns status: %w", err)
	}
	type srcRow struct {
		Source        string
		Rows          int64
		LastFetchedAt *time.Time
		LastChangedAt *time.Time
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[srcRow])
	if err != nil {
		return fmt.Errorf("rdns status: %w", err)
	}
	by := make(map[string]srcRow, len(got))
	for _, r := range got {
		by[strings.ToUpper(r.Source)] = r
	}

	snap.Sources = make([]RDNSSourceCount, 0, len(RDNSStatusSources))
	for _, name := range RDNSStatusSources {
		r := by[name]
		c := RDNSSourceCount{
			Source:        name,
			Rows:          r.Rows,
			LastFetchedAt: r.LastFetchedAt,
			LastChangedAt: r.LastChangedAt,
			Never:         r.Rows == 0,
		}
		if !c.Never && r.LastFetchedAt != nil && !r.LastFetchedAt.IsZero() {
			c.Stale = opts.Now.Sub(*r.LastFetchedAt) > opts.StaleAfter
		}
		snap.Sources = append(snap.Sources, c)
	}
	return nil
}

func (st *Store) fillRDNSIANACoverage(ctx context.Context, snap *RDNSStatusSnapshot) error {
	ianaRows, err := st.DB.Query(ctx, rdnsIANACutsSQL)
	if err != nil {
		return fmt.Errorf("rdns status iana: %w", err)
	}
	type ianaCut struct {
		Zone         string
		Prefix       string
		Nservers     []string
		DelegatedRIR string
	}
	cuts, err := pgx.CollectRows(ianaRows, pgx.RowToStructByPos[ianaCut])
	if err != nil {
		return fmt.Errorf("rdns status iana: %w", err)
	}

	fetchedRows, err := st.DB.Query(ctx, rdnsFetchedZonesSQL)
	if err != nil {
		return fmt.Errorf("rdns status fetched: %w", err)
	}
	type fetchedKey struct {
		Source string
		Zone   string
	}
	fetched, err := pgx.CollectRows(fetchedRows, pgx.RowToStructByPos[fetchedKey])
	if err != nil {
		return fmt.Errorf("rdns status fetched: %w", err)
	}
	have := make(map[string]struct{}, len(fetched))
	for _, f := range fetched {
		have[strings.ToUpper(f.Source)+"\x00"+canonicalRDNSZone(f.Zone)] = struct{}{}
	}

	var gaps []string
	expected := 0
	covered := 0
	for _, cut := range cuts {
		rirs := rirsFromIANACut(cut.Nservers, cut.DelegatedRIR)
		if len(rirs) == 0 {
			continue
		}
		zone := canonicalRDNSZone(cut.Zone)
		for _, rir := range rirs {
			expected++
			if _, ok := have[rir+"\x00"+zone]; ok {
				covered++
				continue
			}
			if len(gaps) < rdnsIANAGapCap {
				gaps = append(gaps, rir+" "+strings.TrimSuffix(zone, "."))
			}
		}
	}
	snap.IANA = RDNSIANACoverage{
		Expected: expected,
		Fetched:  covered,
		Missing:  expected - covered,
		Gaps:     gaps,
	}
	return nil
}

func (st *Store) fillRDNSWhoisCoverage(ctx context.Context, snap *RDNSStatusSnapshot) error {
	var eligible, enriched int64
	if err := st.DB.QueryRow(ctx, rdnsWhoisEnrichSQL).Scan(&eligible, &enriched); err != nil {
		return fmt.Errorf("rdns status whois: %w", err)
	}
	snap.WhoisEligible = eligible
	snap.WhoisEnriched = enriched
	return nil
}

func (st *Store) fillRDNSPTRStatus(ctx context.Context, snap *RDNSStatusSnapshot, opts RDNSStatusOptions) error {
	var rows, withPTR int64
	var last *time.Time
	err := st.DB.QueryRow(ctx, rdnsPTRStatusTotalsSQL).Scan(&rows, &withPTR, &last)
	if rdnsPTRTableMissing(err) {
		snap.PTR = EvaluateRDNSPTRStatus(0, 0, nil, nil, opts.StaleAfter, opts.Now)
		return nil
	}
	if err != nil {
		return fmt.Errorf("rdns status ptr: %w", err)
	}

	pgRows, err := st.DB.Query(ctx, rdnsPTRStatusRcodeSQL)
	if rdnsPTRTableMissing(err) {
		snap.PTR = EvaluateRDNSPTRStatus(0, 0, nil, nil, opts.StaleAfter, opts.Now)
		return nil
	}
	if err != nil {
		return fmt.Errorf("rdns status ptr rcode: %w", err)
	}
	type rcRow struct {
		Rcode string
		Rows  int64
	}
	got, err := pgx.CollectRows(pgRows, pgx.RowToStructByPos[rcRow])
	if err != nil {
		return fmt.Errorf("rdns status ptr rcode: %w", err)
	}
	by := make(map[string]int64, len(got))
	for _, r := range got {
		by[normalizeRDNSPTRRcode(r.Rcode)] += r.Rows
	}
	snap.PTR = EvaluateRDNSPTRStatus(rows, withPTR, last, by, opts.StaleAfter, opts.Now)
	return nil
}

func rdnsPTRTableMissing(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UndefinedTable
}

func normalizeRDNSPTRRcode(rcode string) string {
	key := strings.TrimSpace(rcode)
	if key == "" || strings.EqualFold(key, "other") {
		return "other"
	}
	return strings.ToUpper(key)
}

// EvaluateRDNSPTRStatus fills NEVER/STALE and the pinned rcode list.
// Empty table (or missing rdns_ptr) is NEVER, never STALE.
func EvaluateRDNSPTRStatus(rows, withPTR int64, last *time.Time, byRcode map[string]int64, staleAfter time.Duration, now time.Time) RDNSPTRStatus {
	s := RDNSPTRStatus{
		Rows:          rows,
		WithPTR:       withPTR,
		Empty:         rows - withPTR,
		LastFetchedAt: last,
		Never:         rows == 0,
	}
	if s.Empty < 0 {
		s.Empty = 0
	}
	if !s.Never && last != nil && !last.IsZero() {
		s.Stale = now.Sub(*last) > staleAfter
	}
	seen := make(map[string]struct{}, len(RDNSPTRRcodeOrder))
	s.Rcodes = make([]RDNSPTRRcodeCount, 0, len(RDNSPTRRcodeOrder)+len(byRcode))
	for _, name := range RDNSPTRRcodeOrder {
		seen[name] = struct{}{}
		n := int64(0)
		if byRcode != nil {
			n = byRcode[name]
		}
		s.Rcodes = append(s.Rcodes, RDNSPTRRcodeCount{Rcode: name, Rows: n})
	}
	if byRcode != nil {
		var extra []string
		for k := range byRcode {
			if _, ok := seen[k]; ok {
				continue
			}
			extra = append(extra, k)
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			for _, name := range extra {
				s.Rcodes = append(s.Rcodes, RDNSPTRRcodeCount{Rcode: name, Rows: byRcode[name]})
			}
		}
	}
	return s
}

func (st *Store) listRDNSDumpClocks(ctx context.Context, staleAfter time.Duration, now time.Time) ([]RDNSDumpClock, error) {
	pgRows, err := st.DB.Query(ctx, rdnsDumpClockSQL, RDNSDumpURLs)
	if err != nil {
		return nil, fmt.Errorf("rdns status dumps: %w", err)
	}
	defer pgRows.Close()

	found := make([]RDNSDumpClock, 0)
	for pgRows.Next() {
		var url string
		var lastModified, metaAdded *time.Time
		var etagPresent bool
		if err := pgRows.Scan(&url, &lastModified, &metaAdded, &etagPresent); err != nil {
			return nil, fmt.Errorf("rdns status dumps: %w", err)
		}
		found = append(found, EvaluateRDNSDump(url, lastModified, metaAdded, etagPresent, staleAfter, now))
	}
	if err := pgRows.Err(); err != nil {
		return nil, err
	}
	return MergeRDNSDumpClocks(found, RDNSDumpURLs, staleAfter, now), nil
}

// EvaluateRDNSDump sets LastSeen from meta_added_at (last verified HEAD),
// then last_modified. Absent metadata is NEVER, never STALE.
func EvaluateRDNSDump(url string, lastModified, metaAdded *time.Time, etagPresent bool, staleAfter time.Duration, now time.Time) RDNSDumpClock {
	d := RDNSDumpClock{
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

// MergeRDNSDumpClocks emits a row per expected dump URL (Never when
// metadata is absent).
func MergeRDNSDumpClocks(found []RDNSDumpClock, expected []string, staleAfter time.Duration, now time.Time) []RDNSDumpClock {
	byURL := make(map[string]RDNSDumpClock, len(found))
	for _, d := range found {
		byURL[d.URL] = d
	}
	out := make([]RDNSDumpClock, 0, len(expected))
	for _, url := range expected {
		if d, ok := byURL[url]; ok {
			out = append(out, d)
			continue
		}
		out = append(out, EvaluateRDNSDump(url, nil, nil, false, staleAfter, now))
	}
	return out
}

func canonicalRDNSZone(z string) string {
	z = strings.ToLower(strings.TrimSpace(z))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return ""
	}
	return z + "."
}

func rirsFromIANACut(nservers []string, delegated string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(name string) {
		name = strings.ToUpper(strings.TrimSpace(name))
		if name == "" || name == RDNSSourceIANA {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, ns := range nservers {
		add(RIRFromNameserver(ns))
	}
	if len(out) == 0 {
		add(delegated)
	}
	return out
}

// RIRFromNameserver maps an IANA parent NS hostname to a RIR. arin is
// checked before ripe so arin.authdns.ripe.net counts as ARIN.
func RIRFromNameserver(ns string) string {
	n := strings.ToLower(strings.TrimSpace(ns))
	n = strings.TrimSuffix(n, ".")
	switch {
	case strings.Contains(n, "afrinic"):
		return "AFRINIC"
	case strings.Contains(n, "apnic"):
		return "APNIC"
	case strings.Contains(n, "lacnic"):
		return "LACNIC"
	case strings.Contains(n, "arin"):
		return "ARIN"
	case strings.Contains(n, "ripe"):
		return "RIPE"
	default:
		return ""
	}
}
