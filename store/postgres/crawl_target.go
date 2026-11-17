package postgres

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"github.com/jackc/pgx/v5"
)

// Crawl target kinds. Entity workers land in a later task.
const (
	CrawlKindAutnum  = "autnum"
	CrawlKindIpnet   = "ipnet"
	CrawlKindGeofeed = "geofeed"
)

// Crawl target states. Seed always inserts pending; workers claim rows
// and move them through in_progress / done / failed / gone.
const (
	CrawlStatePending    = "pending"
	CrawlStateInProgress = "in_progress"
	CrawlStateDone       = "done"
	CrawlStateFailed     = "failed"
	CrawlStateGone       = "gone"
)

// crawl_target.priority defaults to 0 (routine). ClaimDue orders
// priority DESC, so a small bump puts LACNIC+BR ahead of the rest of
// the never-succeeded LACNIC queue without touching RDAP routing.
const (
	CrawlPriorityDefault      int16 = 0
	CrawlPriorityParentHandle int16 = 1
	CrawlPriorityLacnicBR     int16 = 10
)

// Ipnet parent-walk keys are handle:dN:H. A CIDR job enqueues the first
// parent at N=0; each successful handle:dK job may enqueue d(K+1) while
// K+1 <= IpnetParentHandleMaxDepth. Cap 5 is O(1) extra jobs per seed CIDR.
const IpnetParentHandleMaxDepth = 5

const ipnetHandleKeyPrefix = "handle:"

// IpnetParentHandleKey is the crawl_target.key for one parent hop.
func IpnetParentHandleKey(handle string, depth int) string {
	return fmt.Sprintf("%sd%d:%s", ipnetHandleKeyPrefix, depth, strings.TrimSpace(handle))
}

// crawlPriority is the seed-time priority for one (registry, NRO country)
// pair. Only LACNIC resources tagged BR are raised; MX/CL/AR stay default
// so they are not pulled ahead of Brazil or misrouted to registro.br.
func crawlPriority(registry, country string) int16 {
	if strings.EqualFold(registry, opconst.LACNIC) && strings.EqualFold(strings.TrimSpace(country), "BR") {
		return CrawlPriorityLacnicBR
	}
	return CrawlPriorityDefault
}

// crawlPrioritySQL is the SQL equivalent of crawlPriority, evaluated
// against columns already on the seed row (no extra CountryFor* lookup).
func crawlPrioritySQL(registryExpr, countryExpr string) string {
	return fmt.Sprintf(
		`CASE WHEN %s = '%s' AND UPPER(TRIM(%s)) = 'BR' THEN %d ELSE %d END`,
		registryExpr, opconst.LACNIC, countryExpr, CrawlPriorityLacnicBR, CrawlPriorityDefault,
	)
}

// CrawlTarget is one durable job-queue row. Seed enumerates crawlable ASNs
// from the NRO delegated_stats snapshot; workers claim due rows, fetch
// RDAP, and record success/failure here so retries survive process restarts.
type CrawlTarget struct {
	ID                  int64
	Kind                string
	Key                 string
	Registry            string
	Priority            int16
	State               string
	NextRetryAt         *time.Time
	LastAttemptAt       *time.Time
	LastSuccessAt       *time.Time
	LastFetchedAt       *time.Time
	AttemptCount        int
	ConsecutiveFailures int
	LastStatusCode      *int
	LastError           *string
	LockedAt            *time.Time
	LockedBy            *string
	CreatedAt           time.Time
}

// CrawlStatusRow is a (registry, state) count for one crawl kind, used to
// inspect queue depth by hand after seed (and later, after workers run).
type CrawlStatusRow struct {
	Registry string
	State    string
	Count    int64
}

// seedAutnumSQL expands each delegated ASN range in Postgres via generate_series
// so we never materialize millions of ASNs in the Go process. reserved /
// available / iana rows are not crawlable (no RDAP object to fetch). ON CONFLICT
// keeps re-seeds idempotent: existing jobs (including ones already in progress)
// are left untouched.
var seedAutnumSQL = `
INSERT INTO crawl_target (kind, key, registry, priority)
SELECT '` + CrawlKindAutnum + `', generate_series(asn_start, asn_end)::text, registry,
  ` + crawlPrioritySQL("registry", "country_code") + `
FROM delegated_stats
WHERE resource_type = 'asn'
  AND status IN ('allocated', 'assigned')
  AND asn_start IS NOT NULL AND asn_end IS NOT NULL`

// SeedAutnumTargets inserts one pending autnum job per allocated/assigned ASN
// in delegated_stats. registry values are already opconst names (ARIN, RIPE,
// …) from NRO ingest. LACNIC+BR rows take CrawlPriorityLacnicBR from the NRO
// country_code on the same delegated row. An empty registries slice means all
// five RIRs; a non-empty slice restricts to those names. A re-seed also bumps
// already-pending LACNIC+BR jobs that were inserted at the default priority.
func (st *Store) SeedAutnumTargets(ctx context.Context, registries []string) (int64, error) {
	q := seedAutnumSQL
	var args []any
	if len(registries) > 0 {
		q += ` AND registry = ANY($1)`
		args = append(args, registries)
	}
	q += ` ON CONFLICT (kind, key, registry) DO NOTHING`

	tag, err := st.DB.Exec(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("seed autnum crawl targets: %w", err)
	}
	if err := st.bumpLacnicBRPriority(ctx); err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected(), nil
}

var seedGeofeedTargetsSQL = `
INSERT INTO crawl_target (kind, key, registry)
SELECT '` + CrawlKindGeofeed + `', url, ''
FROM unnest($1::text[]) AS url
ON CONFLICT (kind, key, registry) DO NOTHING`

// SeedGeofeedTargets inserts one pending crawl_target row per geofeed URL
// (kind=geofeed, key=url, registry empty). Re-seeds are idempotent.
// Bulk harvest no longer calls this; CSV fetch is geoip crawl-geofeeds.
// Kept so leftover kind=geofeed rows can still be marked gone by
// PruneStaleGeofeeds for one release.
func (st *Store) SeedGeofeedTargets(ctx context.Context, urls []string) error {
	urls = uniqueCIDRs(urls)
	if len(urls) == 0 {
		return nil
	}
	if _, err := st.DB.Exec(ctx, seedGeofeedTargetsSQL, urls); err != nil {
		return fmt.Errorf("seed geofeed crawl targets: %w", err)
	}
	return nil
}

const enqueueIpnetParentHandleSQL = `
INSERT INTO crawl_target (kind, key, registry, priority, state)
VALUES ($1, $2, $3, $4, '` + CrawlStatePending + `')
ON CONFLICT (kind, key, registry) DO NOTHING`

// EnqueueIpnetParentHandle inserts one pending ipnet job for a parentHandle
// walk (key=handle:dN:H, priority=1). ON CONFLICT DO NOTHING so an
// in_progress sibling is not flipped. Empty handle/registry or depth
// outside 0..IpnetParentHandleMaxDepth is a no-op.
func (st *Store) EnqueueIpnetParentHandle(ctx context.Context, registry, handle string, depth int) error {
	handle = strings.TrimSpace(handle)
	registry = strings.TrimSpace(registry)
	if handle == "" || registry == "" {
		return nil
	}
	if depth < 0 || depth > IpnetParentHandleMaxDepth {
		return nil
	}

	key := IpnetParentHandleKey(handle, depth)
	if _, err := st.DB.Exec(ctx, enqueueIpnetParentHandleSQL,
		CrawlKindIpnet, key, registry, CrawlPriorityParentHandle); err != nil {
		return fmt.Errorf("enqueue ipnet parent handle: %w", err)
	}
	return nil
}

// EnqueueIpnetDownCIDR inserts one pending ipnet job for an RFC 9910
// rdap-down child. key is a canonical CIDR, or handle:d0:H when the
// search hit has no prefix. priority=1. ON CONFLICT DO NOTHING so an
// in_progress sibling is not flipped. Empty key or registry is a no-op.
func (st *Store) EnqueueIpnetDownCIDR(ctx context.Context, registry, key string) error {
	key = strings.TrimSpace(key)
	registry = strings.TrimSpace(registry)
	if key == "" || registry == "" {
		return nil
	}

	if _, err := st.DB.Exec(ctx, enqueueIpnetParentHandleSQL,
		CrawlKindIpnet, key, registry, CrawlPriorityParentHandle); err != nil {
		return fmt.Errorf("enqueue ipnet down cidr: %w", err)
	}
	return nil
}

// IpnetSeedRegistries are the only registries whose IP space is worth queueing
// as ipnet jobs: ARIN and LACNIC publish incomplete bulk dumps, so their
// inetnums have to come from RDAP. RIPE/APNIC/AFRINIC (and the NIRs) are fully
// covered by `registry-crawl bulk`, which marks their rows done anyway.
var IpnetSeedRegistries = []string{opconst.ARIN, opconst.LACNIC}

// IpnetSeedRegistriesFor applies a caller filter to IpnetSeedRegistries. An
// empty filter means both, matching the SeedAutnumTargets convention. A filter
// that names none of them yields nil, which callers must treat as "nothing to
// seed" rather than "no filter" - the RIB pass in particular should not spend
// minutes decoding archives whose result would be discarded.
func IpnetSeedRegistriesFor(registries []string) []string {
	if len(registries) == 0 {
		return slices.Clone(IpnetSeedRegistries)
	}
	var out []string
	for _, r := range IpnetSeedRegistries {
		if slices.Contains(registries, r) {
			out = append(out, r)
		}
	}
	return out
}

// crawlTargetSeedBatch bounds how many rows one COPY + INSERT transaction
// carries. The RIB pass feeds ~1M CIDRs through here; batching keeps a single
// transaction (and its temp table) from growing unbounded.
const crawlTargetSeedBatch = 50000

// ipnetTarget is one (key, registry) pair about to become a crawl_target row.
// addr is the prefix's network address as a bare host address, used only by the
// RIB path for the delegated-range containment lookup. priority is set from
// the NRO row's country when the seed already has it (NRO ipnet path).
type ipnetTarget struct {
	cidr     string
	registry string
	addr     string
	priority int16
}

// listCrawlableIPRangesSQL reads the delegated ip ranges into Go instead of
// expanding them server-side. Postgres cannot do this part safely: inet_merge
// over [ip_start, ip_end] can return a prefix that covers addresses outside the
// delegated range, and there is no built-in that yields the minimal covering
// CIDR set. range_value is cast to bigint because the column is NUMERIC.
const listCrawlableIPRangesSQL = `
SELECT registry, resource_type, host(ip_start), host(ip_end), range_value::bigint, country_code
FROM delegated_stats
WHERE resource_type IN ('ipv4', 'ipv6')
  AND status IN ('allocated', 'assigned')
  AND ip_start IS NOT NULL AND ip_end IS NOT NULL
  AND registry = ANY($1)`

// SeedIpnetFromNRO inserts one pending ipnet job per canonical CIDR covering the
// delegated ARIN/LACNIC ip space in delegated_stats, and returns how many rows
// were actually inserted (re-runs insert nothing).
//
// registries is intersected with IpnetSeedRegistries; an empty slice means both.
// A filter naming neither is a no-op.
func (st *Store) SeedIpnetFromNRO(ctx context.Context, registries []string) (int64, error) {
	targets := IpnetSeedRegistriesFor(registries)
	if len(targets) == 0 {
		return 0, nil
	}

	pgRows, err := st.DB.Query(ctx, listCrawlableIPRangesSQL, targets)
	if err != nil {
		return 0, fmt.Errorf("list crawlable ip ranges: %w", err)
	}
	defer pgRows.Close()

	var rows []ipnetTarget
	for pgRows.Next() {
		var registry, resourceType, start, end string
		var rangeValue int64
		var country *string
		if err := pgRows.Scan(&registry, &resourceType, &start, &end, &rangeValue, &country); err != nil {
			return 0, fmt.Errorf("list crawlable ip ranges: %w", err)
		}
		cc := ""
		if country != nil {
			cc = *country
		}
		pri := crawlPriority(registry, cc)
		for _, cidr := range delegatedRowCIDRs(resourceType, start, end, rangeValue) {
			rows = append(rows, ipnetTarget{cidr: cidr, registry: registry, priority: pri})
		}
	}
	if err := pgRows.Err(); err != nil {
		return 0, fmt.Errorf("list crawlable ip ranges: %w", err)
	}
	pgRows.Close()

	n, err := st.insertIpnetTargets(ctx, dedupIpnetTargets(rows))
	if err != nil {
		return n, err
	}
	if err := st.bumpLacnicBRPriority(ctx); err != nil {
		return n, err
	}
	return n, nil
}

// delegatedRowCIDRs turns one delegated_stats ip row into canonical CIDR keys.
//
// The two resource types are not symmetric (see migration 0062 column comments):
// an ipv6 row's range_value IS the prefix length, while an ipv4 row's is an
// address COUNT that is frequently not a power of two (e.g. 196608), so the
// [start, end] range has to be split into a set of prefixes. Rows that do not
// parse, and the two default routes, are dropped.
func delegatedRowCIDRs(resourceType, start, end string, rangeValue int64) []string {
	switch resourceType {
	case "ipv6":
		if rangeValue < 0 || rangeValue > 128 {
			return nil
		}
		cidr, ok := canonicalCIDR(fmt.Sprintf("%s/%d", start, rangeValue))
		if !ok || isDefaultRoute(cidr) {
			return nil
		}
		return []string{cidr}
	case "ipv4":
		s, okStart := ipv4ToUint32(start)
		e, okEnd := ipv4ToUint32(end)
		if !okStart || !okEnd {
			return nil
		}
		cidrs := ipv4RangeToCIDRs(s, e)
		return slices.DeleteFunc(cidrs, isDefaultRoute)
	default:
		return nil
	}
}

// ipv4RangeToCIDRs splits the inclusive range [start, end] into the minimal set
// of prefixes that covers it exactly. Each step takes the largest block that is
// aligned on the current address and does not overshoot the remaining count,
// which is what keeps the result from covering any address outside the range.
func ipv4RangeToCIDRs(start, end uint32) []string {
	if start > end {
		return nil
	}
	var out []string
	for {
		// A block starting here can be at most 2^(trailing zero bits) wide.
		// 0.0.0.0 has no set bits, so all 32 are available.
		alignBits := 32
		if start != 0 {
			alignBits = bits.TrailingZeros32(start)
		}
		// Largest power of two that still fits in what is left. Computed on
		// uint64 so a full 2^32 remainder does not wrap.
		remaining := uint64(end) - uint64(start) + 1
		sizeBits := bits.Len64(remaining) - 1
		if alignBits < sizeBits {
			sizeBits = alignBits
		}
		out = append(out, fmt.Sprintf("%s/%d", uint32ToIPv4(start).String(), 32-sizeBits))

		next := uint64(start) + uint64(1)<<uint(sizeBits)
		if next > uint64(end) {
			return out
		}
		start = uint32(next)
	}
}

func ipv4ToUint32(s string) (uint32, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

func uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// canonicalCIDR normalizes a prefix to its masked network form, which is what
// crawl_target.key must always hold.
func canonicalCIDR(s string) (string, bool) {
	_, netw, err := net.ParseCIDR(s)
	if err != nil || netw == nil {
		return "", false
	}
	return netw.String(), true
}

// isDefaultRoute filters the two prefixes that name the whole address space.
// They are announced by some peers and appear in reserved NRO rows, and neither
// corresponds to a crawlable registry object.
func isDefaultRoute(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// dedupIpnetTargets drops repeats of the same (key, registry) pair so the COPY
// stays as small as the resulting row count.
func dedupIpnetTargets(rows []ipnetTarget) []ipnetTarget {
	if len(rows) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rows))
	out := make([]ipnetTarget, 0, len(rows))
	for _, r := range rows {
		k := r.registry + "|" + r.cidr
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// insertIpnetTargets bulk-loads pending ipnet rows in batches: COPY into a
// session TEMP table, then one INSERT … SELECT … ON CONFLICT DO NOTHING, the
// same shape the whoisdb_* upserts use. Per-row Exec would be hundreds of
// thousands of round trips.
func (st *Store) insertIpnetTargets(ctx context.Context, rows []ipnetTarget) (int64, error) {
	var total int64
	for start := 0; start < len(rows); start += crawlTargetSeedBatch {
		end := min(start+crawlTargetSeedBatch, len(rows))
		n, err := st.insertIpnetTargetBatch(ctx, rows[start:end])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (st *Store) insertIpnetTargetBatch(ctx context.Context, rows []ipnetTarget) (int64, error) {
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("seed ipnet crawl targets: %w", err)
	}
	defer tx.Rollback(context.Background())

	// ON COMMIT DROP: a failed batch leaves nothing behind, and the fixed name
	// is safe because TEMP tables are per-session and these seeds do not nest.
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE crawl_target_ipnet_stg (key TEXT, registry TEXT, priority SMALLINT) ON COMMIT DROP`); err != nil {
		return 0, fmt.Errorf("create temp crawl_target_ipnet_stg: %w", err)
	}
	if _, err := tx.CopyFrom(ctx,
		pgx.Identifier{"crawl_target_ipnet_stg"},
		[]string{"key", "registry", "priority"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			return []any{rows[i].cidr, rows[i].registry, rows[i].priority}, nil
		}),
	); err != nil {
		return 0, fmt.Errorf("copy into crawl_target_ipnet_stg: %w", err)
	}

	const q = `
INSERT INTO crawl_target (kind, key, registry, priority)
SELECT '` + CrawlKindIpnet + `', key, registry, priority FROM crawl_target_ipnet_stg
ON CONFLICT (kind, key, registry) DO NOTHING`
	tag, err := tx.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("seed ipnet crawl targets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("seed ipnet crawl targets: %w", err)
	}
	return tag.RowsAffected(), nil
}

// IpnetSeedResult reports what one CIDR-set seed did. NoCover and OtherRegistry
// are the two reasons an announced prefix is not queued, and are worth logging
// separately: the first is bogon/hijack/reserved space, the second is space a
// bulk dump already covers.
type IpnetSeedResult struct {
	Inserted      int64
	NoCover       int64
	OtherRegistry int64
	Invalid       int64
}

// seedIpnetFromCIDRsSQL attributes each announced prefix to the RIR whose
// delegated range covers it - the same "most specific covering range" rule as
// RegistryForIP, NOT the origin ASN's RIR and NOT the IANA RDAP bootstrap - then
// inserts the ARIN/LACNIC subset.
//
// The lookup joins on addr (the prefix's network address as a /32 or /128 host
// address), not on the prefix itself: Postgres orders inet by address and THEN
// by netmask length, so '192.0.2.0/24' sorts below the delegated range's
// '192.0.2.0' /32 boundary and a BETWEEN on the prefix would miss it.
//
// LEFT JOIN plus a MATERIALIZED CTE so the insert and both drop counts come out
// of a single pass; an inner join would need a second pass to count what it
// discarded.
var seedIpnetFromCIDRsSQL = `
WITH covered AS MATERIALIZED (
	SELECT c.cidr, ds.registry, ds.country_code
	FROM crawl_target_rib_stg c
	LEFT JOIN LATERAL (
		SELECT registry, country_code FROM delegated_stats
		WHERE resource_type IN ('ipv4', 'ipv6')
		  AND family(ip_start) = family(c.addr)
		  AND c.addr BETWEEN ip_start AND ip_end
		  AND status IN ('allocated', 'assigned')
		ORDER BY ip_start DESC
		LIMIT 1
	) ds ON TRUE
), ins AS (
	INSERT INTO crawl_target (kind, key, registry, priority)
	SELECT '` + CrawlKindIpnet + `', cidr, registry,
	  ` + crawlPrioritySQL("registry", "country_code") + `
	FROM covered
	WHERE registry = ANY($1)
	ON CONFLICT (kind, key, registry) DO NOTHING
	RETURNING 1
)
SELECT
	(SELECT COUNT(*) FROM ins),
	(SELECT COUNT(*) FROM covered WHERE registry IS NULL),
	(SELECT COUNT(*) FROM covered WHERE registry IS NOT NULL AND NOT (registry = ANY($1)))`

// SeedIpnetFromCIDRs inserts pending ipnet jobs for a set of announced CIDRs
// (the RouteViews RIB leftovers), keeping only the ones whose covering NRO range
// belongs to a seedable registry. Input need not be canonical or deduplicated;
// registries follows the IpnetSeedRegistriesFor convention.
func (st *Store) SeedIpnetFromCIDRs(ctx context.Context, cidrs []string, registries []string) (IpnetSeedResult, error) {
	targets := IpnetSeedRegistriesFor(registries)
	if len(targets) == 0 {
		return IpnetSeedResult{}, nil
	}

	rows, invalid := canonicalIpnetTargets(cidrs)
	res := IpnetSeedResult{Invalid: invalid}
	for start := 0; start < len(rows); start += crawlTargetSeedBatch {
		end := min(start+crawlTargetSeedBatch, len(rows))
		batch, err := st.seedIpnetFromCIDRBatch(ctx, rows[start:end], targets)
		res.Inserted += batch.Inserted
		res.NoCover += batch.NoCover
		res.OtherRegistry += batch.OtherRegistry
		if err != nil {
			return res, err
		}
	}
	if err := st.bumpLacnicBRPriority(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// bumpLacnicBRPriority raises already-queued LACNIC+BR jobs so a re-seed
// does not leave them behind default-priority LACNIC work. Country comes
// from the most-specific covering delegated_stats row (same rule as
// CountryForASN / CountryForIP). Done and gone rows are left alone.
func (st *Store) bumpLacnicBRPriority(ctx context.Context) error {
	const due = `'` + CrawlStatePending + `', '` + CrawlStateFailed + `', '` + CrawlStateInProgress + `'`

	autnum := `
UPDATE crawl_target ct
SET priority = $1
WHERE ct.kind = '` + CrawlKindAutnum + `'
  AND ct.registry = $2
  AND ct.state IN (` + due + `)
  AND ct.priority < $1
  AND ct.key ~ '^[0-9]+$'
  AND EXISTS (
	SELECT 1
	FROM (
		SELECT registry, country_code
		FROM delegated_stats
		WHERE resource_type = 'asn'
		  AND ct.key::bigint BETWEEN asn_start AND asn_end
		ORDER BY asn_start DESC
		LIMIT 1
	) ds
	WHERE ds.registry = $2
	  AND UPPER(TRIM(ds.country_code)) = 'BR'
  )`
	if _, err := st.DB.Exec(ctx, autnum, CrawlPriorityLacnicBR, opconst.LACNIC); err != nil {
		return fmt.Errorf("bump lacnic br autnum priority: %w", err)
	}

	ipnet := `
UPDATE crawl_target ct
SET priority = $1
WHERE ct.kind = '` + CrawlKindIpnet + `'
  AND ct.registry = $2
  AND ct.state IN (` + due + `)
  AND ct.priority < $1
  AND EXISTS (
	SELECT 1
	FROM (
		SELECT registry, country_code
		FROM delegated_stats
		WHERE resource_type IN ('ipv4', 'ipv6')
		  AND family(ip_start) = family(host(ct.key::cidr)::inet)
		  AND host(ct.key::cidr)::inet BETWEEN ip_start AND ip_end
		ORDER BY ip_start DESC
		LIMIT 1
	) ds
	WHERE ds.registry = $2
	  AND UPPER(TRIM(ds.country_code)) = 'BR'
  )`
	if _, err := st.DB.Exec(ctx, ipnet, CrawlPriorityLacnicBR, opconst.LACNIC); err != nil {
		return fmt.Errorf("bump lacnic br ipnet priority: %w", err)
	}
	return nil
}

func (st *Store) seedIpnetFromCIDRBatch(ctx context.Context, rows []ipnetTarget, registries []string) (IpnetSeedResult, error) {
	var res IpnetSeedResult

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("seed ipnet crawl targets from cidrs: %w", err)
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE crawl_target_rib_stg (cidr TEXT, addr INET) ON COMMIT DROP`); err != nil {
		return res, fmt.Errorf("create temp crawl_target_rib_stg: %w", err)
	}
	if _, err := tx.CopyFrom(ctx,
		pgx.Identifier{"crawl_target_rib_stg"},
		[]string{"cidr", "addr"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			return []any{rows[i].cidr, rows[i].addr}, nil
		}),
	); err != nil {
		return res, fmt.Errorf("copy into crawl_target_rib_stg: %w", err)
	}

	if err := tx.QueryRow(ctx, seedIpnetFromCIDRsSQL, registries).
		Scan(&res.Inserted, &res.NoCover, &res.OtherRegistry); err != nil {
		return res, fmt.Errorf("seed ipnet crawl targets from cidrs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("seed ipnet crawl targets from cidrs: %w", err)
	}
	return res, nil
}

// canonicalIpnetTargets normalizes announced prefixes into crawl_target keys,
// dropping the default routes and anything unparseable, and returns how many
// were unparseable. The registry column stays empty: SQL fills it from the
// covering delegated range.
func canonicalIpnetTargets(cidrs []string) ([]ipnetTarget, int64) {
	var invalid int64
	out := make([]ipnetTarget, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, c := range cidrs {
		_, netw, err := net.ParseCIDR(c)
		if err != nil || netw == nil {
			invalid++
			continue
		}
		key := netw.String()
		if isDefaultRoute(key) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ipnetTarget{cidr: key, addr: netw.IP.String()})
	}
	return out, invalid
}

// CrawlStatus returns per-registry, per-state counts for the given kind so a
// human can see what seed (and later, workers) produced without dumping the
// whole queue.
func (st *Store) CrawlStatus(ctx context.Context, kind string) ([]CrawlStatusRow, error) {
	const q = `SELECT registry, state, COUNT(*)
		FROM crawl_target
		WHERE kind = $1
		GROUP BY registry, state
		ORDER BY registry, state`
	pgRows, err := st.DB.Query(ctx, q, kind)
	if err != nil {
		return nil, fmt.Errorf("crawl status: %w", err)
	}
	defer pgRows.Close()

	var out []CrawlStatusRow
	for pgRows.Next() {
		var row CrawlStatusRow
		if err := pgRows.Scan(&row.Registry, &row.State, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, pgRows.Err()
}

// ListPendingAutnumKeys returns crawl_target autnum keys that are still
// pending and that whoisdb_autnum does not already own via a dump or RDAP
// row. Asnames backfill intersects this set with asn.txt so it cannot stamp
// fetch_method=asnames onto a richer object, and cannot mark coverage
// (asnames rows persist source=”). Failed rows are left for the worker.
func (st *Store) ListPendingAutnumKeys(ctx context.Context) ([]string, error) {
	const q = `
SELECT p.key
FROM (
	SELECT key
	FROM crawl_target
	WHERE kind = $1
	  AND state = $2
	  AND key ~ '^[0-9]+$'
) p
LEFT JOIN whoisdb_autnum w ON w.aut_num = p.key::numeric
WHERE w.aut_num IS NULL
   OR (
	COALESCE(w.source, '') = ''
	AND COALESCE(w.fetch_method, '') IN ('', $3)
   )`
	pgRows, err := st.DB.Query(ctx, q, CrawlKindAutnum, CrawlStatePending, whoisdb.FetchMethodASNames)
	if err != nil {
		return nil, fmt.Errorf("list pending autnum keys: %w", err)
	}
	defer pgRows.Close()

	var out []string
	for pgRows.Next() {
		var key string
		if err := pgRows.Scan(&key); err != nil {
			return nil, fmt.Errorf("list pending autnum keys: %w", err)
		}
		if key == "" {
			continue
		}
		out = append(out, key)
	}
	return out, pgRows.Err()
}

const crawlTargetReturning = `id, kind, key, registry, priority, state,
	next_retry_at, last_attempt_at, last_success_at, last_fetched_at,
	attempt_count, consecutive_failures, last_status_code, last_error,
	locked_at, locked_by, created_at`

func scanCrawlTarget(row interface{ Scan(dest ...any) error }, t *CrawlTarget) error {
	return row.Scan(
		&t.ID, &t.Kind, &t.Key, &t.Registry, &t.Priority, &t.State,
		&t.NextRetryAt, &t.LastAttemptAt, &t.LastSuccessAt, &t.LastFetchedAt,
		&t.AttemptCount, &t.ConsecutiveFailures, &t.LastStatusCode, &t.LastError,
		&t.LockedAt, &t.LockedBy, &t.CreatedAt,
	)
}

// ClaimDue atomically takes up to `batch` due jobs of `kind` for this worker.
// Due means pending/failed and next_retry_at is null or in the past, or
// in_progress with a lease older than `lease` (crashed worker). SKIP LOCKED
// lets concurrent workers share the table without waiting on each other.
// Order matches crawl_target_due_kind_reg_idx: highest priority, then longest
// since last success (never-fetched first). Stale leases use crawl_target_lease_idx.
func (st *Store) ClaimDue(ctx context.Context, kind string, registries []string, lockedBy string, batch int, lease time.Duration) ([]CrawlTarget, error) {
	if batch < 1 {
		return nil, fmt.Errorf("claim due crawl targets: batch must be >= 1")
	}
	if lease <= 0 {
		return nil, fmt.Errorf("claim due crawl targets: lease must be > 0")
	}

	q := `
UPDATE crawl_target
SET
	state = '` + CrawlStateInProgress + `',
	locked_at = now(),
	locked_by = $2,
	last_attempt_at = now(),
	attempt_count = attempt_count + 1
WHERE id IN (
	SELECT id
	FROM crawl_target
	WHERE kind = $1
	  AND (
			(state IN ('` + CrawlStatePending + `', '` + CrawlStateFailed + `')
			 AND (next_retry_at IS NULL OR next_retry_at <= now()))
		 OR (state = '` + CrawlStateInProgress + `'
			 AND locked_at < now() - ($3 * interval '1 second'))
	  )`
	args := []any{kind, lockedBy, lease.Seconds(), batch}
	if len(registries) > 0 {
		q += `
	  AND registry = ANY($5)`
		args = append(args, registries)
	}
	q += `
	ORDER BY priority DESC, last_success_at ASC NULLS FIRST
	LIMIT $4
	FOR UPDATE SKIP LOCKED
)
RETURNING ` + crawlTargetReturning

	pgRows, err := st.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("claim due crawl targets: %w", err)
	}
	defer pgRows.Close()

	var out []CrawlTarget
	for pgRows.Next() {
		var t CrawlTarget
		if err := scanCrawlTarget(pgRows, &t); err != nil {
			return nil, fmt.Errorf("claim due crawl targets: %w", err)
		}
		out = append(out, t)
	}
	if err := pgRows.Err(); err != nil {
		return nil, fmt.Errorf("claim due crawl targets: %w", err)
	}
	return out, nil
}

// NIRParent maps a National Internet Registry onto its parent RIR.
// NRO delegated_stats attributes NIR-economy resources to the parent
// (APNIC), so crawl_target coverage must mark both the dump source and
// the parent. whoisdb_*.source is not rewritten — JPNIC remains the
// provenance; this only changes which crawl_target.registry a finding
// satisfies.
var NIRParent = map[string]string{
	opconst.JPNIC: opconst.APNIC,
	opconst.KRNIC: opconst.APNIC,
	opconst.TWNIC: opconst.APNIC,
}

// CoverageRegistries returns the crawl_target.registry values that a dump
// object with this source satisfies. NIR sources also cover the parent RIR
// that seed used. Unknown sources return just themselves; callers still
// filter incomplete dumps (ARIN/LACNIC) before marking.
func CoverageRegistries(source string) []string {
	if parent, ok := NIRParent[source]; ok {
		return []string{source, parent}
	}
	return []string{source}
}

// MarkAutnumCoveredByBulk upserts crawl_target rows as done for ASNs observed
// in a complete WHOIS dump (RIPE/APNIC/AFRINIC/NIRs). Bulk is the source of
// truth for those registries, so RDAP workers should not re-fetch them.
//
// Upsert (not UPDATE-only) so a dump that lands before seed still records
// coverage. Re-running on already-done rows refreshes timestamps. Empty
// asns is a no-op. ASN 0 is skipped the same way SaveWhoisAutNum skips it.
func (st *Store) MarkAutnumCoveredByBulk(ctx context.Context, asns []uint32, registry string) error {
	ids := uniquePositiveASNs(asns)
	if len(ids) == 0 {
		return nil
	}

	const q = `
INSERT INTO crawl_target (kind, key, registry, state, last_success_at, last_fetched_at)
SELECT '` + CrawlKindAutnum + `', asn::text, $2, '` + CrawlStateDone + `', now(), now()
FROM unnest($1::bigint[]) AS asn
ON CONFLICT (kind, key, registry) DO UPDATE SET
	state = '` + CrawlStateDone + `',
	last_success_at = now(),
	last_fetched_at = now(),
	consecutive_failures = 0,
	locked_at = NULL,
	locked_by = NULL,
	last_error = NULL`

	if _, err := st.DB.Exec(ctx, q, ids, registry); err != nil {
		return fmt.Errorf("mark autnum covered by bulk: %w", err)
	}
	return nil
}

// MarkAutnumRangeSiblingsDone marks existing autnum crawl_target rows for
// asns as done (MarkSuccess-equivalent) without inserting keys NRO never
// seeded. in_progress rows are left alone: another worker holds the lease,
// and whoisdb persist is idempotent. pending/failed/gone siblings are
// flipped so they are not re-fetched. This is not bulk-dump coverage —
// crawl_target has no fetch_method; RDAP provenance lives on whoisdb_autnum.
func (st *Store) MarkAutnumRangeSiblingsDone(ctx context.Context, asns []uint32, registry string) error {
	ids := uniquePositiveASNs(asns)
	if len(ids) == 0 || registry == "" {
		return nil
	}

	const q = `
UPDATE crawl_target
SET
	state = '` + CrawlStateDone + `',
	last_success_at = now(),
	last_fetched_at = now(),
	consecutive_failures = 0,
	last_error = NULL,
	last_status_code = NULL,
	locked_at = NULL,
	locked_by = NULL,
	next_retry_at = NULL
WHERE kind = '` + CrawlKindAutnum + `'
  AND registry = $2
  AND key IN (SELECT asn::text FROM unnest($1::bigint[]) AS asn)
  AND state <> '` + CrawlStateInProgress + `'`

	if _, err := st.DB.Exec(ctx, q, ids, registry); err != nil {
		return fmt.Errorf("mark autnum range siblings done: %w", err)
	}
	return nil
}

// MarkIpnetCoveredByBulk upserts crawl_target rows as done for prefixes observed
// in a complete WHOIS dump (RIPE/APNIC/AFRINIC/NIRs). Bulk is the source of
// truth for those registries, so RDAP workers should not re-fetch them.
//
// Upsert (not UPDATE-only) so a dump that lands before seed still records
// coverage. Re-running on already-done rows refreshes timestamps. Empty
// cidrs is a no-op. Empty strings are skipped.
func (st *Store) MarkIpnetCoveredByBulk(ctx context.Context, cidrs []string, registry string) error {
	keys := uniqueCIDRs(cidrs)
	if len(keys) == 0 {
		return nil
	}

	const q = `
INSERT INTO crawl_target (kind, key, registry, state, last_success_at, last_fetched_at)
SELECT '` + CrawlKindIpnet + `', cidr, $2, '` + CrawlStateDone + `', now(), now()
FROM unnest($1::text[]) AS cidr
ON CONFLICT (kind, key, registry) DO UPDATE SET
	state = '` + CrawlStateDone + `',
	last_success_at = now(),
	last_fetched_at = now(),
	consecutive_failures = 0,
	locked_at = NULL,
	locked_by = NULL,
	last_error = NULL`

	if _, err := st.DB.Exec(ctx, q, keys, registry); err != nil {
		return fmt.Errorf("mark ipnet covered by bulk: %w", err)
	}
	return nil
}

// InetnumCIDRCount is a per-source count of dump inetnum+inet6num rows, used
// by `registry-crawl mark-ipnet-bulk --dry-run` to preview coverage without
// writing crawl_target.
type InetnumCIDRCount struct {
	Source string
	Count  int64
}

// CountWhoisInetnumCIDRsBySource counts inetnum and inet6num rows whose
// source is in sources. Used for dry-run backfill of ipnet coverage.
func (st *Store) CountWhoisInetnumCIDRsBySource(ctx context.Context, sources []string) ([]InetnumCIDRCount, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	const q = `
SELECT source, COUNT(*)
FROM (
	SELECT source FROM whoisdb_inetnum WHERE source = ANY($1)
	UNION ALL
	SELECT source FROM whoisdb_inet6num WHERE source = ANY($1)
) t
GROUP BY source
ORDER BY source`
	pgRows, err := st.DB.Query(ctx, q, sources)
	if err != nil {
		return nil, fmt.Errorf("count whois inetnum cidrs: %w", err)
	}
	defer pgRows.Close()

	var out []InetnumCIDRCount
	for pgRows.Next() {
		var row InetnumCIDRCount
		if err := pgRows.Scan(&row.Source, &row.Count); err != nil {
			return nil, fmt.Errorf("count whois inetnum cidrs: %w", err)
		}
		out = append(out, row)
	}
	if err := pgRows.Err(); err != nil {
		return nil, fmt.Errorf("count whois inetnum cidrs: %w", err)
	}
	return out, nil
}

const markIpnetFromWhoisDBBatch = 5000

// MarkIpnetCoveredFromWhoisDB reads canonical CIDR text from whoisdb_inetnum
// and whoisdb_inet6num for the given sources and upserts crawl_target as
// done (kind=ipnet). NIR sources are also marked under their parent RIR
// (see CoverageRegistries). Used to backfill coverage after a prior dump
// ingest without re-downloading. Empty sources is a no-op.
func (st *Store) MarkIpnetCoveredFromWhoisDB(ctx context.Context, sources []string) (int, error) {
	if len(sources) == 0 {
		return 0, nil
	}
	const q = `
SELECT netblock::text, source
FROM (
	SELECT netblock, source FROM whoisdb_inetnum WHERE source = ANY($1)
	UNION ALL
	SELECT netblock, source FROM whoisdb_inet6num WHERE source = ANY($1)
) t
ORDER BY source`
	pgRows, err := st.DB.Query(ctx, q, sources)
	if err != nil {
		return 0, fmt.Errorf("mark ipnet covered from whoisdb: %w", err)
	}
	defer pgRows.Close()

	var (
		curSrc     string
		batchCIDRs []string
		total      int
	)
	flush := func() error {
		if len(batchCIDRs) == 0 {
			return nil
		}
		n := len(uniqueCIDRs(batchCIDRs))
		for _, registry := range CoverageRegistries(curSrc) {
			if err := st.MarkIpnetCoveredByBulk(ctx, batchCIDRs, registry); err != nil {
				return err
			}
			total += n
		}
		batchCIDRs = batchCIDRs[:0]
		return nil
	}

	for pgRows.Next() {
		var cidr, src string
		if err := pgRows.Scan(&cidr, &src); err != nil {
			return total, fmt.Errorf("mark ipnet covered from whoisdb: %w", err)
		}
		if cidr == "" || src == "" {
			continue
		}
		if curSrc != "" && src != curSrc {
			if err := flush(); err != nil {
				return total, err
			}
		}
		curSrc = src
		batchCIDRs = append(batchCIDRs, cidr)
		if len(batchCIDRs) >= markIpnetFromWhoisDBBatch {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := flush(); err != nil {
		return total, err
	}
	if err := pgRows.Err(); err != nil {
		return total, fmt.Errorf("mark ipnet covered from whoisdb: %w", err)
	}
	return total, nil
}

const markAutnumFromWhoisDBBatch = 5000

// MarkAutnumCoveredFromWhoisDB is the autnum counterpart of
// MarkIpnetCoveredFromWhoisDB: it reads ASNs out of whoisdb_autnum for the given
// sources and upserts crawl_target as done (kind=autnum). NIR sources are also
// marked under their parent RIR (see CoverageRegistries) so NRO-seeded
// registry=APNIC rows are satisfied. Bulk calls it once per run so a dump that
// was ETag-skipped still records its coverage - otherwise the RDAP worker
// re-fetches space the dumps already have. Empty sources is a no-op.
// whoisdb_autnum.source is not rewritten.
//
// aut_num is NUMERIC in the schema, so it is cast for the scan.
func (st *Store) MarkAutnumCoveredFromWhoisDB(ctx context.Context, sources []string) (int, error) {
	if len(sources) == 0 {
		return 0, nil
	}
	const q = `
SELECT aut_num::bigint, source
FROM whoisdb_autnum
WHERE source = ANY($1)
ORDER BY source`
	pgRows, err := st.DB.Query(ctx, q, sources)
	if err != nil {
		return 0, fmt.Errorf("mark autnum covered from whoisdb: %w", err)
	}
	defer pgRows.Close()

	var (
		curSrc    string
		batchASNs []uint32
		total     int
	)
	flush := func() error {
		if len(batchASNs) == 0 {
			return nil
		}
		n := len(uniquePositiveASNs(batchASNs))
		for _, registry := range CoverageRegistries(curSrc) {
			if err := st.MarkAutnumCoveredByBulk(ctx, batchASNs, registry); err != nil {
				return err
			}
			total += n
		}
		batchASNs = batchASNs[:0]
		return nil
	}

	for pgRows.Next() {
		var asn int64
		var src string
		if err := pgRows.Scan(&asn, &src); err != nil {
			return total, fmt.Errorf("mark autnum covered from whoisdb: %w", err)
		}
		if asn <= 0 || asn > math.MaxUint32 || src == "" {
			continue
		}
		if curSrc != "" && src != curSrc {
			if err := flush(); err != nil {
				return total, err
			}
		}
		curSrc = src
		batchASNs = append(batchASNs, uint32(asn))
		if len(batchASNs) >= markAutnumFromWhoisDBBatch {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := flush(); err != nil {
		return total, err
	}
	if err := pgRows.Err(); err != nil {
		return total, fmt.Errorf("mark autnum covered from whoisdb: %w", err)
	}
	return total, nil
}

// uniquePositiveASNs dedupes and drops 0 so a single INSERT ... ON CONFLICT
// cannot try to update the same (kind, key, registry) row twice.
func uniquePositiveASNs(asns []uint32) []int64 {
	if len(asns) == 0 {
		return nil
	}
	seen := make(map[uint32]struct{}, len(asns))
	out := make([]int64, 0, len(asns))
	for _, a := range asns {
		if a == 0 {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, int64(a))
	}
	return out
}

// uniqueCIDRs dedupes and drops empty keys so a single INSERT ... ON CONFLICT
// cannot try to update the same (kind, key, registry) row twice.
func uniqueCIDRs(cidrs []string) []string {
	if len(cidrs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(cidrs))
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// MarkSuccess records a completed fetch: done, timestamps now, failures reset, lock cleared.
func (st *Store) MarkSuccess(ctx context.Context, id int64) error {
	const q = `
UPDATE crawl_target
SET
	state = '` + CrawlStateDone + `',
	last_success_at = now(),
	last_fetched_at = now(),
	consecutive_failures = 0,
	last_error = NULL,
	last_status_code = NULL,
	locked_at = NULL,
	locked_by = NULL,
	next_retry_at = NULL
WHERE id = $1`
	if _, err := st.DB.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("mark crawl target success: %w", err)
	}
	return nil
}

// MarkFailed schedules a retry. consecutive_failures is the input the worker
// uses for queue-level exponential backoff; next_retry_at is now+retryAfter.
func (st *Store) MarkFailed(ctx context.Context, id int64, statusCode *int, errMsg string, retryAfter time.Duration) error {
	var lastErr any
	if errMsg != "" {
		lastErr = errMsg
	}
	const q = `
UPDATE crawl_target
SET
	state = '` + CrawlStateFailed + `',
	consecutive_failures = consecutive_failures + 1,
	next_retry_at = now() + ($4 * interval '1 second'),
	last_error = $3,
	last_status_code = $2,
	locked_at = NULL,
	locked_by = NULL
WHERE id = $1`
	if _, err := st.DB.Exec(ctx, q, id, statusCode, lastErr, retryAfter.Seconds()); err != nil {
		return fmt.Errorf("mark crawl target failed: %w", err)
	}
	return nil
}

// MarkGone is a terminal state for 404 / permanently unassigned objects, and
// for RDAP 200 as-blocks that are not a single aut-num. They stay out of the
// due index until an operator reseeds or deletes them. errMsg is stored in
// last_error (nil/empty clears it) so as-block handles are visible without
// changing gone semantics.
func (st *Store) MarkGone(ctx context.Context, id int64, statusCode *int, errMsg string) error {
	var lastErr any
	if errMsg != "" {
		lastErr = errMsg
	}
	const q = `
UPDATE crawl_target
SET
	state = '` + CrawlStateGone + `',
	last_status_code = $2,
	last_error = $3,
	locked_at = NULL,
	locked_by = NULL
WHERE id = $1`
	if _, err := st.DB.Exec(ctx, q, id, statusCode, lastErr); err != nil {
		return fmt.Errorf("mark crawl target gone: %w", err)
	}
	return nil
}
