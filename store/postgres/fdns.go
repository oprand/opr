package postgres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// List dump URLs are remote_files_metadata keys written by fdns ingest-lists.
const (
	TrancoListURL   = "https://tranco-list.eu/top-1m.csv.zip"
	UmbrellaListURL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
	CrUXListURL     = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
)

// Common Crawl Host Index (testing v2). ingest-cc discovers a crawl id from
// the Host Index paths manifest, downloads Parquet, and loads names into
// ClickHouse fdns_cc_host. It writes no Postgres hostname rows and no
// fdns_host_ip (Host Index parquet has no IPs). Tests override the URLs with httptest.
const (
	CommonCrawlDataURL = "https://data.commoncrawl.org"
	// HostIndexPathsURL lists Host Index testing-v2 parquet keys (gzip).
	HostIndexPathsURL = "https://data.commoncrawl.org/projects/host-index-testing/v2.paths.gz"
	// FDNSCCCrawlMetadataURL is the remote_files_metadata sentinel for the
	// selected Host Index crawl. charset holds the crawl id (CC-MAIN-YYYY-NN).
	FDNSCCCrawlMetadataURL = "fdns:cc-crawl"
	// FDNSCCSeedCursorURL is the remote_files_metadata key for seed-queue
	// --order key paging. charset holds "url_host_tld\\thost_name".
	FDNSCCSeedCursorURL = "fdns:cc-seed-cursor"
)

// DefaultResolveQueueStaleAfter is the skip window when enqueueing: names
// whose resolved_at is newer than this stay out of fdns_resolve_queue. Matches
// aggregator/fdns.DefaultResolveStaleAfter (168h) without importing it.
const DefaultResolveQueueStaleAfter = 168 * time.Hour

// Resolve queue claim order is priority DESC. List ingest (Tranco / Umbrella /
// CrUX) is 1 so a 5M CC seed at 0 cannot starve it.
const (
	ResolveQueuePriorityCC   int16 = 0
	ResolveQueuePriorityList int16 = 1
)

// HostNameSource* are fdns_host_name.source array elements (lowercase).
// UpsertHostNames unions these; source=cc is Host Index membership written
// by seed-queue, not ingest-cc.
const (
	HostNameSourceTranco   = "tranco"
	HostNameSourceUmbrella = "umbrella"
	HostNameSourceCrux     = "crux"
	HostNameSourceCC       = "cc" // Host Index hostname membership (not WARC-IP)
)

// HostIPSource* are fdns_host_ip.source values. Host Index ingest does not
// write source=cc IPs; dns comes from fdns resolve.
const (
	HostIPSourceDNS = "dns"
	HostIPSourceCC  = "cc" // legacy / unused by Host Index ingest-cc
)

// FDNSListURLs is the pinned list set ingest writes and status will show.
var FDNSListURLs = []string{
	TrancoListURL,
	UmbrellaListURL,
	CrUXListURL,
}

// HostName is one row of fdns_host_name: list membership + per-list rank.
type HostName struct {
	Name         string
	Source       []string
	RankTranco   *int
	RankUmbrella *int
	RankCrux     *int
	FirstSeen    time.Time
	LastSeen     time.Time
	ResolvedAt   *time.Time
}

// hostNameUpsert bulk-loads fdns_host_name via COPY then ON CONFLICT (name).
// List ingest unions source and fills only the rank_* column for that list;
// first_seen and resolved_at stay on the existing row.
var hostNameUpsert = whoisUpsertSpec{
	live: "fdns_host_name",
	columns: []string{
		"name", "source", "rank_tranco", "rank_umbrella", "rank_crux",
		"first_seen", "last_seen",
	},
	selectExprs: map[string]string{
		"source":     "COALESCE(source, '{}')",
		"first_seen": "COALESCE(first_seen, NOW())",
		"last_seen":  "COALESCE(last_seen, NOW())",
	},
	onConflict: `
			ON CONFLICT (name)
			DO UPDATE SET
				source = ARRAY(SELECT DISTINCT UNNEST(fdns_host_name.source || EXCLUDED.source)),
				rank_tranco = COALESCE(EXCLUDED.rank_tranco, fdns_host_name.rank_tranco),
				rank_umbrella = COALESCE(EXCLUDED.rank_umbrella, fdns_host_name.rank_umbrella),
				rank_crux = COALESCE(EXCLUDED.rank_crux, fdns_host_name.rank_crux),
				last_seen = EXCLUDED.last_seen`,
}

func hostNameCopyRow(row *HostName) []any {
	src := row.Source
	if src == nil {
		src = []string{}
	}
	first, last := copySeenTimes(row.FirstSeen, row.LastSeen)
	return []any{
		row.Name, src, row.RankTranco, row.RankUmbrella, row.RankCrux,
		first, last,
	}
}

func hostNameConflictKey(row *HostName) (string, bool) {
	if row == nil || row.Name == "" {
		return "", false
	}
	return row.Name, true
}

func dedupHostNames(rows []HostName) []HostName {
	return dedupLastWins(rows, func(row HostName) (string, bool) {
		return hostNameConflictKey(&row)
	})
}

// UpsertHostNames inserts or merges fdns_host_name rows and enqueues due names
// into fdns_resolve_queue in the same transaction (choice B: resolve claims
// only the queue, so list ingest and seed-queue must enqueue). List ingest
// uses priority 1 (ResolveQueuePriorityList). Same name unions source
// (tranco, umbrella, crux, cc) and keeps each list's rank (new rank wins
// when that list is present). Empty input is an error so a failed parse
// cannot look like a successful empty catalog. resolved_at is not written.
// Does not TRUNCATE or delete previous source=cc rows. Names already resolved
// and still fresh (resolved_at newer than DefaultResolveQueueStaleAfter) are
// not queued.
func (st *Store) UpsertHostNames(ctx context.Context, rows []HostName) error {
	_, err := st.upsertHostNamesAndEnqueue(ctx, rows, DefaultResolveQueueStaleAfter, ResolveQueuePriorityList)
	return err
}

// UpsertHostNamesAndEnqueue is UpsertHostNames with a caller-chosen stale
// window for fdns_resolve_queue. staleAfter 0 (or negative) enqueues only
// never-resolved names. Priority is ResolveQueuePriorityCC (0). Returns how
// many queue rows were inserted or had priority bumped (ON CONFLICT).
func (st *Store) UpsertHostNamesAndEnqueue(ctx context.Context, rows []HostName, staleAfter time.Duration) (int64, error) {
	return st.upsertHostNamesAndEnqueue(ctx, rows, staleAfter, ResolveQueuePriorityCC)
}

func (st *Store) upsertHostNamesAndEnqueue(ctx context.Context, rows []HostName, staleAfter time.Duration, priority int16) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if staleAfter < 0 {
		staleAfter = 0
	}
	items := dedupHostNames(rows)
	if len(items) == 0 {
		return 0, fmt.Errorf("upsert fdns_host_name: no rows")
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("upsert fdns_host_name: %w", err)
	}
	defer tx.Rollback(context.Background())

	if err := copyIntoTempThenUpsert(ctx, tx, hostNameUpsert, len(items), func(i int) ([]any, error) {
		return hostNameCopyRow(&items[i]), nil
	}); err != nil {
		return 0, fmt.Errorf("upsert fdns_host_name: %w", err)
	}
	tag, err := tx.Exec(ctx, enqueueResolveQueueSQL, staleAfter.Seconds(), priority)
	if err != nil {
		return 0, fmt.Errorf("enqueue fdns_resolve_queue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("upsert fdns_host_name: %w", err)
	}
	return tag.RowsAffected(), nil
}

// HostIP is one row of fdns_host_ip: a name→IP observation from DNS (or
// legacy source=cc). PK is (name, ip, source). Host Index ingest does not
// write this table.
type HostIP struct {
	Name      string
	IP        string
	Source    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// HostNameResolveQuery selects fdns_host_name rows that need an A/AAAA scan.
// StaleAfter 0 means only never-resolved (resolved_at IS NULL). Limit 0 is
// uncapped.
type HostNameResolveQuery struct {
	StaleAfter time.Duration
	Limit      int
}

// hostIPUpsert bulk-loads fdns_host_ip via COPY then ON CONFLICT (name, ip, source).
var hostIPUpsert = whoisUpsertSpec{
	live:    "fdns_host_ip",
	columns: []string{"name", "ip", "source", "first_seen", "last_seen"},
	selectExprs: map[string]string{
		"first_seen": "COALESCE(first_seen, NOW())",
		"last_seen":  "COALESCE(last_seen, NOW())",
	},
	onConflict: `
			ON CONFLICT (name, ip, source)
			DO UPDATE SET
				last_seen = EXCLUDED.last_seen`,
}

func hostIPCopyRow(row *HostIP) []any {
	first, last := copySeenTimes(row.FirstSeen, row.LastSeen)
	return []any{row.Name, row.IP, row.Source, first, last}
}

// copySeenTimes is for COPY into NOT NULL timestamptz columns. Postgres
// CREATE TEMP … LIKE … INCLUDING DEFAULTS still copies NOT NULL, and COPY
// of an explicit NULL does not apply DEFAULT — COALESCE in insertSQL runs
// after COPY and never sees the row. A missing bound reuses the other
// caller time so resolve can set only LastSeen without inverting first/last.
func copySeenTimes(first, last time.Time) (time.Time, time.Time) {
	switch {
	case first.IsZero() && last.IsZero():
		now := time.Now().UTC()
		return now, now
	case first.IsZero():
		return last, last
	case last.IsZero():
		return first, first
	default:
		return first, last
	}
}

func hostIPConflictKey(row *HostIP) (string, bool) {
	if row == nil || row.Name == "" || row.Source == "" {
		return "", false
	}
	ip := net.ParseIP(row.IP)
	if ip == nil {
		return "", false
	}
	return row.Name + "\x00" + ip.String() + "\x00" + row.Source, true
}

func dedupHostIPs(rows []HostIP) []HostIP {
	canon := make([]HostIP, 0, len(rows))
	for _, row := range rows {
		ip := net.ParseIP(row.IP)
		if ip == nil {
			continue
		}
		row.IP = ip.String()
		canon = append(canon, row)
	}
	return dedupLastWins(canon, func(row HostIP) (string, bool) {
		return hostIPConflictKey(&row)
	})
}

func uniqHostNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// listHostNamesToResolveSQL is names never queried, or whose resolved_at is
// older than $1 seconds. NXDOMAIN/NODATA stamp resolved_at with zero dns rows,
// so they are not selected again until they go stale. $2 LIMIT 0 → NULL (no cap).
var listHostNamesToResolveSQL = `
SELECT name
FROM fdns_host_name
WHERE resolved_at IS NULL
   OR ($1::double precision > 0 AND resolved_at < NOW() - ($1::double precision * INTERVAL '1 second'))
ORDER BY resolved_at NULLS FIRST, name
LIMIT NULLIF($2::int, 0)`

var touchHostNameResolvedAtSQL = `
UPDATE fdns_host_name
SET resolved_at = $2
WHERE name = ANY($1::text[])`

// enqueueResolveQueueSQL copies this upsert's staging names into the claim
// queue, skipping names already resolved and still fresh. $1 is stale-after
// in seconds; 0 (or negative) means only never-resolved names. $2 is priority
// (list ingest = 1, CC seed = 0). Staging is fdns_host_name_stg
// (whoisUpsertSpec.stg) and still exists until COMMIT DROP.
// ON CONFLICT bumps priority when list ingest promotes a CC-seeded row; the
// WHERE keeps a priority-0 re-seed from counting as a write or resetting a
// lease (locked_at is not in the SET list).
var enqueueResolveQueueSQL = `
INSERT INTO fdns_resolve_queue (name, priority)
SELECT s.name, $2::smallint
FROM fdns_host_name_stg s
WHERE NOT EXISTS (
	SELECT 1 FROM fdns_host_name n
	WHERE n.name = s.name
	  AND n.resolved_at IS NOT NULL
	  AND ($1::double precision <= 0 OR n.resolved_at > NOW() - ($1::double precision * INTERVAL '1 second'))
)
ON CONFLICT (name) DO UPDATE SET
	priority = EXCLUDED.priority
WHERE fdns_resolve_queue.priority < EXCLUDED.priority`

// claimUnlockedResolveQueueSQL is the resolve-queue hot path: LIMIT on
// locked_at IS NULL, ordered to match fdns_resolve_queue_due_idx (priority
// DESC, enqueued_at, name). Geofeed-style UPDATE + subquery SKIP LOCKED so
// the lease survives commit. $1 is locked_by; $2 is LIMIT.
//
// OR-ing stale locks into this SELECT cannot use due_idx and sorts the whole
// matching set. Stale reclaim is a second statement (claimStaleResolveQueueSQL).
var claimUnlockedResolveQueueSQL = `
UPDATE fdns_resolve_queue q
SET locked_at = now(), locked_by = $1, attempts = q.attempts + 1
WHERE q.name IN (
	SELECT name FROM fdns_resolve_queue
	WHERE locked_at IS NULL
	ORDER BY priority DESC, enqueued_at, name
	LIMIT $2
	FOR UPDATE SKIP LOCKED
)
RETURNING q.name`

// claimStaleResolveQueueSQL reclaims crashed-worker leases: locked_at IS NOT
// NULL AND older than $2 seconds, oldest lease first so
// fdns_resolve_queue_lease_idx can be used. Same UPDATE SET / SKIP LOCKED as
// the unlocked claim. $1 is locked_by; $3 is LIMIT (remainder after unlocked).
// Not OR-ed with locked_at IS NULL (see ClaimDueResolveQueue drawbacks).
var claimStaleResolveQueueSQL = `
UPDATE fdns_resolve_queue q
SET locked_at = now(), locked_by = $1, attempts = q.attempts + 1
WHERE q.name IN (
	SELECT name FROM fdns_resolve_queue
	WHERE locked_at IS NOT NULL
	  AND locked_at < now() - ($2 * interval '1 second')
	ORDER BY locked_at ASC
	LIMIT $3
	FOR UPDATE SKIP LOCKED
)
RETURNING q.name`

var deleteResolveQueueSQL = `
DELETE FROM fdns_resolve_queue
WHERE name = ANY($1::text[])`

var unlockResolveQueueSQL = `
UPDATE fdns_resolve_queue
SET locked_at = NULL, locked_by = NULL
WHERE name = ANY($1::text[])
  AND locked_by = $2
  AND locked_at IS NOT NULL`

// approxResolveQueueSQL is pg_class.reltuples for fdns_resolve_queue — a cheap
// planner estimate, not count(*). It lags ANALYZE, includes locked and
// unlocked rows, and does NOT apply the due predicate (locked_at IS NULL OR
// locked_at < now()-lease). to_regclass returns NULL if the table is missing
// (no error). reltuples is -1 when the table has never been vacuumed/analyzed.
// GREATEST(..., 0) maps missing and -1 to 0; 0 can mean empty or unanalyzed.
var approxResolveQueueSQL = `
SELECT GREATEST(COALESCE((
	SELECT reltuples::bigint
	FROM pg_class
	WHERE oid = to_regclass('fdns_resolve_queue')
), 0), 0)`

// ListHostNamesToResolve returns names that need an A/AAAA scan: never
// resolved, or resolved_at older than StaleAfter (when StaleAfter > 0).
func (st *Store) ListHostNamesToResolve(ctx context.Context, q HostNameResolveQuery) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	staleSecs := q.StaleAfter.Seconds()
	limit := q.Limit
	if limit < 0 {
		limit = 0
	}
	rows, err := st.DB.Query(ctx, listHostNamesToResolveSQL, staleSecs, limit)
	if err != nil {
		return nil, fmt.Errorf("list fdns_host_name to resolve: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("list fdns_host_name to resolve: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list fdns_host_name to resolve: %w", err)
	}
	return names, nil
}

// UpsertHostIPs inserts or bumps last_seen on fdns_host_ip. Empty input is a
// no-op (NXDOMAIN/NODATA produce zero dns rows). first_seen stays on conflict.
func (st *Store) UpsertHostIPs(ctx context.Context, rows []HostIP) error {
	return st.ApplyHostResolve(ctx, rows, nil, time.Time{})
}

// TouchHostNamesResolvedAt stamps fdns_host_name.resolved_at for names that
// were queried, including NXDOMAIN/NODATA. Empty input is a no-op.
func (st *Store) TouchHostNamesResolvedAt(ctx context.Context, names []string, at time.Time) error {
	return st.ApplyHostResolve(ctx, nil, names, at)
}

// ApplyHostResolve upserts dns/cc IPs and stamps resolved_at in one
// transaction. Either slice may be empty. Does not TRUNCATE.
func (st *Store) ApplyHostResolve(ctx context.Context, ips []HostIP, names []string, at time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	items := dedupHostIPs(ips)
	names = uniqHostNames(names)
	if len(items) == 0 && len(names) == 0 {
		return nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("apply fdns resolve: %w", err)
	}
	defer tx.Rollback(context.Background())

	if len(items) > 0 {
		if err := copyIntoTempThenUpsert(ctx, tx, hostIPUpsert, len(items), func(i int) ([]any, error) {
			return hostIPCopyRow(&items[i]), nil
		}); err != nil {
			return fmt.Errorf("upsert fdns_host_ip: %w", err)
		}
	}
	if len(names) > 0 {
		if _, err := tx.Exec(ctx, touchHostNameResolvedAtSQL, names, at); err != nil {
			return fmt.Errorf("touch fdns_host_name.resolved_at: %w", err)
		}
		if _, err := tx.Exec(ctx, deleteResolveQueueSQL, names); err != nil {
			return fmt.Errorf("delete fdns_resolve_queue: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("apply fdns resolve: %w", err)
	}
	return nil
}

// ClaimDueResolveQueue atomically claims up to batch due queue names for
// lockedBy. lease is how long locked_at keeps the name skipped by other
// claimers. batch and lease must be positive; lockedBy must be non-empty.
//
// Two statements, never OR-ed: unlocked first (due_idx LIMIT), then stale
// leases to fill the remainder so a short unlocked set still reclaims
// crashes. Exact due COUNT was already removed; this path does not add it
// back.
//
// Drawbacks: (1) stale-lease reclaim (killed worker) is starved while any
// unlocked rows exist if we only query stale when unlocked is empty. Filling
// the remainder when unlocked is short still waits behind a large unlocked
// backlog (e.g. 291M CC names) — a crashed worker's locked rows are not
// mixed into every batch. (2) global ORDER BY priority is not preserved
// across the two sets. A stale priority=1 list name is not claimed before
// unlocked priority=0 CC names. Unlocked always wins. (3) an empty queue
// costs two round-trips (unlocked miss, then stale miss).
func (st *Store) ClaimDueResolveQueue(ctx context.Context, lockedBy string, batch int, lease time.Duration) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lockedBy = strings.TrimSpace(lockedBy)
	if lockedBy == "" {
		return nil, fmt.Errorf("claim due resolve queue: locked_by is empty")
	}
	if batch < 1 {
		return nil, fmt.Errorf("claim due resolve queue: batch must be >= 1")
	}
	if lease <= 0 {
		return nil, fmt.Errorf("claim due resolve queue: lease must be > 0")
	}

	names, err := st.queryResolveQueueNames(ctx, claimUnlockedResolveQueueSQL, lockedBy, batch)
	if err != nil {
		return nil, fmt.Errorf("claim due resolve queue: %w", err)
	}
	if len(names) >= batch {
		return names, nil
	}
	stale, err := st.queryResolveQueueNames(ctx, claimStaleResolveQueueSQL, lockedBy, lease.Seconds(), batch-len(names))
	if err != nil {
		return nil, fmt.Errorf("claim due resolve queue: %w", err)
	}
	if len(stale) == 0 {
		return names, nil
	}
	return append(names, stale...), nil
}

func (st *Store) queryResolveQueueNames(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := st.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// UnlockResolveQueue clears this worker's locked_at so SERVFAIL/timeout
// names are retried. lockedBy must match ClaimDue's locked_by so a late
// unlock cannot steal another worker's lease. Empty names is a no-op.
func (st *Store) UnlockResolveQueue(ctx context.Context, names []string, lockedBy string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	names = uniqHostNames(names)
	if len(names) == 0 {
		return nil
	}
	lockedBy = strings.TrimSpace(lockedBy)
	if lockedBy == "" {
		return fmt.Errorf("unlock fdns_resolve_queue: locked_by is empty")
	}
	if _, err := st.DB.Exec(ctx, unlockResolveQueueSQL, names, lockedBy); err != nil {
		return fmt.Errorf("unlock fdns_resolve_queue: %w", err)
	}
	return nil
}

// CountResolveQueue is an approximate whole-table size of fdns_resolve_queue
// (pg_class.reltuples). It is not count(*) and not a due-row count: ANALYZE
// lag, locked+unlocked rows, missing table / never-vacuumed → 0. Used by
// resolve logs (queue_approx) and seed-queue --queue-high-water so neither
// path seq-scans a hundreds-of-millions-row queue.
func (st *Store) CountResolveQueue(ctx context.Context) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var n int64
	if err := st.DB.QueryRow(ctx, approxResolveQueueSQL).Scan(&n); err != nil {
		return 0, fmt.Errorf("approx fdns_resolve_queue: %w", err)
	}
	if n < 0 {
		// reltuples -1 (never vacuumed); 0 can mean empty or unanalyzed.
		n = 0
	}
	return n, nil
}
