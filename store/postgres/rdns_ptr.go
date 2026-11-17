package postgres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RDNSPTR is one stored PTR outcome. Unique key is (ip).
// NXDOMAIN / NODATA keep ptr NULL; the row still exists so empty space is not
// re-walked as "missing". SourcePrefix is the delegated cut that produced the
// row: a more-specific observation wins over a coarser parent /24.
type RDNSPTR struct {
	IP           string
	PTR          *string
	QueriedNS    string
	FetchedAt    time.Time
	Rcode        string
	SourcePrefix string
}

// RDNSLeaf is a deepest delegated cut (no more-specific rdns_delegation row).
type RDNSLeaf struct {
	Zone     string
	Prefix   string
	Nservers []string
	Source   string
}

// RDNSLeafQuery filters ListRDNSLeaves. Prefix or Zone is required (unscoped
// anti-join is refused). Empty Sources means all RIRs.
type RDNSLeafQuery struct {
	Sources []string
	Prefix  string
	Zone    string
}

var rdnsPTRUpsert = whoisUpsertSpec{
	live:    "rdns_ptr",
	columns: []string{"ip", "ptr", "queried_ns", "fetched_at", "rcode", "source_prefix"},
	onConflict: `
			ON CONFLICT (ip)
			DO UPDATE SET
				ptr = EXCLUDED.ptr,
				queried_ns = EXCLUDED.queried_ns,
				fetched_at = EXCLUDED.fetched_at,
				rcode = EXCLUDED.rcode,
				source_prefix = EXCLUDED.source_prefix
			WHERE rdns_ptr.source_prefix IS NULL
			   OR masklen(EXCLUDED.source_prefix) > masklen(rdns_ptr.source_prefix)
			   OR (
					masklen(EXCLUDED.source_prefix) = masklen(rdns_ptr.source_prefix)
					AND EXCLUDED.ptr IS NOT NULL AND btrim(EXCLUDED.ptr) <> ''
					AND (rdns_ptr.ptr IS NULL OR btrim(rdns_ptr.ptr) = '')
			   )`,
}

func rdnsPTRCopyRow(row *RDNSPTR) []any {
	var src any
	if strings.TrimSpace(row.SourcePrefix) != "" {
		src = row.SourcePrefix
	}
	return []any{row.IP, row.PTR, row.QueriedNS, row.FetchedAt, row.Rcode, src}
}

// ShouldReplaceRDNSPTR is the Go form of the rdns_ptr ON CONFLICT rule.
// Strictly more-specific source_prefix always replaces. Same specificity:
// a real PTR name replaces NODATA/NXDOMAIN/empty. A coarser NODATA never
// replaces a stored PTR name.
func ShouldReplaceRDNSPTR(existing, incoming RDNSPTR) bool {
	inBits := ptrSourcePrefixBits(incoming.SourcePrefix)
	if inBits < 0 {
		return true
	}
	exBits := ptrSourcePrefixBits(existing.SourcePrefix)
	if exBits < 0 {
		return true
	}
	if inBits > exBits {
		return true
	}
	if inBits == exBits && ptrHasName(incoming) && !ptrHasName(existing) {
		return true
	}
	return false
}

func ptrHasName(row RDNSPTR) bool {
	return row.PTR != nil && strings.TrimSpace(*row.PTR) != ""
}

func ptrSourcePrefixBits(cidr string) int {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return -1
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return -1
	}
	ones, _ := ipnet.Mask.Size()
	return ones
}

func rdnsPTRKey(row *RDNSPTR) (string, bool) {
	if row == nil || row.IP == "" || row.Rcode == "" {
		return "", false
	}
	return row.IP, true
}

func dedupRDNSPTR(rows []RDNSPTR) []RDNSPTR {
	return dedupLastWins(rows, func(row RDNSPTR) (string, bool) {
		return rdnsPTRKey(&row)
	})
}

// listRDNSLeavesSQL returns deepest non-IANA cuts. Scope ($2) hits the GiST
// prefix index first so --zone/--prefix do not anti-join the whole table.
// $3 zone matches the cut or, with a scope, any child (prefix <<= scope).
// Unscoped (empty $2 and $3) is refused: the prefix << anti-join over all
// rdns_delegation never returns. Full crawl uses rdns_ptr_block / masklen.
// prefix::text so pgx binary scan fills a string.
var listRDNSLeavesSQL = `
SELECT d.zone, d.prefix::text, COALESCE(d.nservers, '{}'), d.source
FROM rdns_delegation d
WHERE d.source <> 'IANA'
  AND cardinality(COALESCE(d.nservers, '{}')) > 0
  AND (cardinality($1::text[]) = 0 OR d.source = ANY($1))
  AND NOT ($2::text = '' AND $3::text = '')
  AND ($2::text = '' OR d.prefix && $2::inet)
  AND (
    $3::text = ''
    OR lower(rtrim(d.zone, '.')) = lower(rtrim($3::text, '.'))
    OR ($2::text <> '' AND d.prefix <<= $2::inet)
  )
  AND NOT EXISTS (
    SELECT 1 FROM rdns_delegation c
    WHERE c.source <> 'IANA'
      AND family(c.prefix) = family(d.prefix)
      AND ($2::text = '' OR c.prefix && $2::inet)
      AND c.prefix << d.prefix
  )`

// UpsertRDNSPTR writes PTR outcomes by ip. Empty rows are a no-op (must not
// truncate). NXDOMAIN/NODATA rows are valid and must be included by callers.
func (st *Store) UpsertRDNSPTR(ctx context.Context, rows []RDNSPTR) error {
	forced := make([]RDNSPTR, 0, len(rows))
	for _, row := range rows {
		if row.IP == "" || row.Rcode == "" {
			continue
		}
		if row.FetchedAt.IsZero() {
			row.FetchedAt = time.Now().UTC()
		}
		forced = append(forced, row)
	}
	forced = dedupRDNSPTR(forced)
	if len(forced) == 0 {
		return nil
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("upsert rdns_ptr: %w", err)
	}
	defer tx.Rollback(context.Background())

	if err := copyIntoTempThenUpsert(ctx, tx, rdnsPTRUpsert, len(forced), func(i int) ([]any, error) {
		return rdnsPTRCopyRow(&forced[i]), nil
	}); err != nil {
		return fmt.Errorf("upsert rdns_ptr: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("upsert rdns_ptr: %w", err)
	}
	return nil
}

// ListRDNSLeaves returns deepest delegated cuts (source <> IANA, has NS, no
// more-specific child). Coarse /8 / IPv6 /32 filtering is the caller's job.
// Prefix or Zone is required: an unscoped anti-join hangs on large tables.
// Full crawl must use SeedRDNSPTRBlocks / ClaimRDNSPTRBlock instead.
func (st *Store) ListRDNSLeaves(ctx context.Context, q RDNSLeafQuery) ([]RDNSLeaf, error) {
	sources := q.Sources
	if sources == nil {
		sources = []string{}
	}
	prefix := strings.TrimSpace(q.Prefix)
	zone := strings.TrimSpace(q.Zone)
	if prefix == "" && zone == "" {
		return nil, fmt.Errorf("list rdns leaves: unscoped query refused (prefix << anti-join over all rdns_delegation); pass Prefix or Zone, or use the /24 block queue")
	}

	rows, err := st.DB.Query(ctx, listRDNSLeavesSQL, sources, prefix, zone)
	if err != nil {
		return nil, fmt.Errorf("list rdns leaves: %w", err)
	}
	type leafRow struct {
		Zone     string
		Prefix   string
		Nservers []string
		Source   string
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[leafRow])
	if err != nil {
		return nil, fmt.Errorf("list rdns leaves: %w", err)
	}
	out := make([]RDNSLeaf, 0, len(got))
	for _, r := range got {
		ns := r.Nservers
		if ns == nil {
			ns = []string{}
		}
		out = append(out, RDNSLeaf{
			Zone:     r.Zone,
			Prefix:   r.Prefix,
			Nservers: ns,
			Source:   r.Source,
		})
	}
	return out, nil
}
