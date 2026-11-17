package postgres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// DelegatedStat is one row of the NRO extended delegated-stats snapshot. It is
// the source of truth for asn/prefix -> registry attribution (replacing the
// IANA RDAP bootstrap cache). See migration 0062 for column semantics.
type DelegatedStat struct {
	Registry     string
	CountryCode  *string
	ResourceType string // asn | ipv4 | ipv6
	RangeStart   string
	RangeValue   int64
	AsnStart     *int64
	AsnEnd       *int64
	IPStart      net.IP
	IPEnd        net.IP
	Status       string // allocated | assigned | reserved | available | iana
	AllocDate    *time.Time
	OpaqueID     *string
	FileDate     *time.Time
}

var delegatedStatsColumns = []string{
	"registry", "country_code", "resource_type", "range_start", "range_value",
	"asn_start", "asn_end", "ip_start", "ip_end", "status",
	"alloc_date", "opaque_id", "file_date",
}

// delegatedStatsSwapIndexes recreates, on the freshly loaded staging table, the
// indexes defined in migration 0062 (the canonical schema source). They are
// built with temporary "_stg" names so they never collide with the live table's
// canonical names, then renamed to canonical after the swap drops the old table.
var delegatedStatsSwapIndexes = []struct {
	stgName   string
	canonical string
	createSQL string
}{
	{
		"delegated_stats_uniq_stg", "delegated_stats_registry_resource_type_range_start_key",
		"CREATE UNIQUE INDEX delegated_stats_uniq_stg ON delegated_stats_new (registry, resource_type, range_start)",
	},
	{
		"delegated_stats_opaque_stg", "idx_delegated_stats_opaque",
		"CREATE INDEX delegated_stats_opaque_stg ON delegated_stats_new (registry, opaque_id)",
	},
	{
		"delegated_stats_type_status_stg", "idx_delegated_stats_type_status",
		"CREATE INDEX delegated_stats_type_status_stg ON delegated_stats_new (resource_type, status)",
	},
	{
		"delegated_stats_asn_range_stg", "idx_delegated_stats_asn_range",
		"CREATE INDEX delegated_stats_asn_range_stg ON delegated_stats_new (asn_start, asn_end) WHERE resource_type = 'asn'",
	},
	{
		"delegated_stats_ip_range_stg", "idx_delegated_stats_ip_range",
		"CREATE INDEX delegated_stats_ip_range_stg ON delegated_stats_new (ip_start, ip_end) WHERE resource_type IN ('ipv4', 'ipv6')",
	},
}

// LIKE does not copy the table-level comment, so re-apply a concise one after
// the swap. Column comments are preserved via INCLUDING COMMENTS.
const delegatedStatsTableComment = `COMMENT ON TABLE delegated_stats IS ` +
	`'Daily FULL snapshot of the NRO extended delegated-stats file, reloaded via rename-swap. ` +
	`Source of truth for asn/prefix -> registry attribution. See migration 0062 for full column semantics.'`

// LoadDelegatedStats replaces the entire delegated_stats table with a fresh
// snapshot using a rename-swap: the new data is bulk-loaded into an off-to-the-
// side staging table (delegated_stats_new) that no reader touches, then swapped
// in via a short metadata-only ALTER TABLE RENAME. Reader lookups
// (RegistryForASN/IP) hit the live table throughout the load and are only
// blocked for the ~millisecond swap, unlike a TRUNCATE+COPY which holds an
// ACCESS EXCLUSIVE lock for the whole load. delegated stats are a FULL daily
// snapshot.
//
// The staging table is created index-less (LIKE ... INCLUDING DEFAULTS) so the
// COPY is fast and tolerant of duplicate keys; the unique index is rebuilt
// afterwards (callers must dedup input to keep it valid).
func (st *Store) LoadDelegatedStats(ctx context.Context, rows []DelegatedStat) (int64, error) {
	// 1. Fresh, index-less staging table. INCLUDING DEFAULTS keeps column
	//    defaults (incl. the id sequence default); INCLUDING COMMENTS keeps
	//    column comments. No indexes/constraints yet -> fast, dup-tolerant COPY.
	if _, err := st.DB.Exec(ctx, "DROP TABLE IF EXISTS delegated_stats_new"); err != nil {
		return 0, fmt.Errorf("drop stale delegated_stats_new: %w", err)
	}
	if _, err := st.DB.Exec(ctx, "CREATE TABLE delegated_stats_new (LIKE delegated_stats INCLUDING DEFAULTS INCLUDING COMMENTS)"); err != nil {
		return 0, fmt.Errorf("create delegated_stats_new: %w", err)
	}

	// 2. Bulk load into the staging table.
	copied, err := st.DB.CopyFrom(
		ctx,
		pgx.Identifier{"delegated_stats_new"},
		delegatedStatsColumns,
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			var ipStart, ipEnd any
			if r.IPStart != nil {
				ipStart = r.IPStart.String()
			}
			if r.IPEnd != nil {
				ipEnd = r.IPEnd.String()
			}
			return []any{
				r.Registry, r.CountryCode, r.ResourceType, r.RangeStart, r.RangeValue,
				r.AsnStart, r.AsnEnd, ipStart, ipEnd, r.Status,
				r.AllocDate, r.OpaqueID, r.FileDate,
			}, nil
		}),
	)
	if err != nil {
		return 0, fmt.Errorf("copy delegated_stats_new: %w", err)
	}

	// 3. Rebuild indexes + primary key AFTER load (faster, and lets the COPY be
	//    dup-tolerant). Temporary names avoid clashing with the live table.
	if _, err := st.DB.Exec(ctx, "ALTER TABLE delegated_stats_new ADD CONSTRAINT delegated_stats_new_pkey PRIMARY KEY (id)"); err != nil {
		return 0, fmt.Errorf("add primary key on delegated_stats_new: %w", err)
	}
	for _, idx := range delegatedStatsSwapIndexes {
		if _, err := st.DB.Exec(ctx, idx.createSQL); err != nil {
			return 0, fmt.Errorf("create index %s: %w", idx.stgName, err)
		}
	}

	// 4. Swap in a short transaction. Only this step locks the live table, and
	//    only for metadata changes (~milliseconds).
	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())

	swapStmts := []string{
		"ALTER TABLE delegated_stats RENAME TO delegated_stats_old",
		"ALTER TABLE delegated_stats_new RENAME TO delegated_stats",
		// The id sequence is still OWNED BY the old table's column; reassign it
		// so DROP TABLE below does not cascade-drop the sequence the new live
		// table's id default depends on.
		"ALTER SEQUENCE delegated_stats_id_seq OWNED BY delegated_stats.id",
		"DROP TABLE delegated_stats_old",
		// Restore canonical names now that the old table (and its indexes) is gone.
		"ALTER INDEX delegated_stats_new_pkey RENAME TO delegated_stats_pkey",
	}
	for _, s := range swapStmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return 0, fmt.Errorf("swap delegated_stats (%q): %w", s, err)
		}
	}
	for _, idx := range delegatedStatsSwapIndexes {
		stmt := fmt.Sprintf("ALTER INDEX %s RENAME TO %s", idx.stgName, idx.canonical)
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return 0, fmt.Errorf("rename index %s -> %s: %w", idx.stgName, idx.canonical, err)
		}
	}
	if _, err := tx.Exec(ctx, delegatedStatsTableComment); err != nil {
		return 0, fmt.Errorf("comment delegated_stats: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return copied, nil
}

// RegistryForASN returns the RIR that administers the given ASN, using an
// indexed BETWEEN lookup over the (disjoint) delegated ranges. Returns an empty
// string with a nil error when no delegated range contains the ASN.
func (st *Store) RegistryForASN(ctx context.Context, asn uint32) (string, error) {
	const q = `SELECT registry FROM delegated_stats
		WHERE resource_type = 'asn' AND $1::bigint BETWEEN asn_start AND asn_end
		LIMIT 1`
	var registry string
	err := st.DB.QueryRow(ctx, q, int64(asn)).Scan(&registry)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return registry, nil
}

// RegistryForIP returns the RIR that administers the given IP, matching the
// delegated range whose [ip_start, ip_end] contains it (same address family).
// Returns an empty string with a nil error when nothing contains the IP.
func (st *Store) RegistryForIP(ctx context.Context, ip net.IP) (string, error) {
	const q = `SELECT registry FROM delegated_stats
		WHERE resource_type IN ('ipv4', 'ipv6')
		  AND family(ip_start) = family($1::inet)
		  AND $1::inet BETWEEN ip_start AND ip_end
		ORDER BY ip_start DESC
		LIMIT 1`
	var registry string
	err := st.DB.QueryRow(ctx, q, ip.String()).Scan(&registry)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return registry, nil
}

// CountryForASN returns the ISO country code from the delegated range that
// contains the ASN. Same BETWEEN predicate as RegistryForASN (no status
// filter). Empty string with a nil error when no range contains the ASN or
// country_code is NULL/blank — callers treat that as the parent RIR RDAP.
func (st *Store) CountryForASN(ctx context.Context, asn uint32) (string, error) {
	const q = `SELECT country_code FROM delegated_stats
		WHERE resource_type = 'asn' AND $1::bigint BETWEEN asn_start AND asn_end
		LIMIT 1`
	var country *string
	err := st.DB.QueryRow(ctx, q, int64(asn)).Scan(&country)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if country == nil {
		return "", nil
	}
	return strings.TrimSpace(*country), nil
}

// CountryForIP returns the ISO country code from the delegated range that
// contains the IP. Same BETWEEN predicate and status-filter shape as
// RegistryForIP (no status filter). Empty string with a nil error when nothing
// contains the IP or country_code is NULL/blank.
func (st *Store) CountryForIP(ctx context.Context, ip net.IP) (string, error) {
	const q = `SELECT country_code FROM delegated_stats
		WHERE resource_type IN ('ipv4', 'ipv6')
		  AND family(ip_start) = family($1::inet)
		  AND $1::inet BETWEEN ip_start AND ip_end
		ORDER BY ip_start DESC
		LIMIT 1`
	var country *string
	err := st.DB.QueryRow(ctx, q, ip.String()).Scan(&country)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if country == nil {
		return "", nil
	}
	return strings.TrimSpace(*country), nil
}

// CountDelegatedStats returns the number of rows in the current NRO snapshot.
// Seed uses this to distinguish "every ASN is already queued" from "nro ingest
// has not been run yet".
func (st *Store) CountDelegatedStats(ctx context.Context) (int64, error) {
	var n int64
	err := st.DB.QueryRow(ctx, `SELECT COUNT(*) FROM delegated_stats`).Scan(&n)
	return n, err
}
