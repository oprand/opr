package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PTR block queue states (migration 0080).
//
// Finish done only after a successful persist of a walk that is not all
// TIMEOUT/SERVFAIL/ERROR. RFC 8020 NXDOMAIN on the zone is done (empty
// zone). All-soft-error walks are failed; the next Seed resets failed →
// pending. --limit mid-block leaves leased (SKIP LOCKED moves on).
const (
	PTRBlockPending = "pending"
	PTRBlockLeased  = "leased"
	PTRBlockDone    = "done"
	PTRBlockFailed  = "failed"
)

// DefaultPTRBlockLease is how long a claimed /24 stays skipped by other
// workers. A /24 at 5 qps is ~1 minute; 15m covers stalls without blocking
// resume for long after a crash.
const DefaultPTRBlockLease = 15 * time.Minute

// ErrPTRBlockLeaseLost is RowsAffected==0 on Finish/Fail/Release/Heartbeat:
// another worker holds the row. Callers must not treat this as success.
var ErrPTRBlockLeaseLost = errors.New("rdns ptr block: lease lost")

// RDNSPTRBlock is one expandable prefix in the full-crawl queue.
type RDNSPTRBlock struct {
	Prefix   string
	Zone     string
	Nservers []string
	Source   string
	State    string
	LockedBy string
}

// RDNSPTRBlockCounts is pending/leased/done/failed for the 5-minute ticker.
type RDNSPTRBlockCounts struct {
	Pending int64 `json:"pending"`
	Leased  int64 `json:"leased"`
	Done    int64 `json:"done"`
	Failed  int64 `json:"failed"`
}

// seedRDNSPTRBlocksSQL copies IPv4 /24–/32 and IPv6 /120+ cuts into the
// queue. masklen filter only — no prefix << anti-join. ERX duplicates merge
// nservers (GROUP BY prefix). ON CONFLICT resets failed → pending so
// TIMEOUT/SERVFAIL/ERROR walks retry on the next crawl; done/leased/pending
// are left alone. prefix is inet on both sides; seed SELECT keeps inet
// (not text). Returning/list paths use prefix::text for pgx.
var seedRDNSPTRBlocksSQL = `
INSERT INTO rdns_ptr_block (prefix, zone, nservers, source)
WITH blocks AS (
	SELECT prefix, zone, nservers, source
	FROM rdns_delegation
	WHERE source <> 'IANA'
	  AND cardinality(COALESCE(nservers, '{}')) > 0
	  AND (
		(family(prefix) = 4 AND masklen(prefix) BETWEEN 24 AND 32)
		OR (family(prefix) = 6 AND masklen(prefix) >= 120)
	  )
	  AND (cardinality($1::text[]) = 0 OR source = ANY($1))
),
ns AS (
	SELECT prefix, ARRAY_AGG(DISTINCT ns) AS nservers
	FROM blocks
	CROSS JOIN LATERAL unnest(nservers) AS ns
	WHERE btrim(ns) <> ''
	GROUP BY prefix
)
SELECT
	b.prefix,
	(array_agg(b.zone ORDER BY cardinality(COALESCE(b.nservers, '{}')) DESC, b.zone))[1],
	n.nservers,
	(array_agg(b.source ORDER BY b.source))[1]
FROM blocks b
JOIN ns n ON n.prefix = b.prefix
GROUP BY b.prefix, n.nservers
ON CONFLICT (prefix) DO UPDATE SET
	state = 'pending',
	locked_at = NULL,
	locked_by = '',
	done_at = NULL
WHERE rdns_ptr_block.state = 'failed'`

// claimRDNSPTRBlockSQL takes one pending (or stale-leased) block. SKIP LOCKED
// so two workers never wait on / steal the same row. No ORDER BY md5: sorting
// ~2M rows per claim looks like another hang; LIMIT 1 + SKIP LOCKED is enough.
// $3 registry filter: empty array means all sources (same as seed).
var claimRDNSPTRBlockSQL = `
UPDATE rdns_ptr_block
SET
	state = 'leased',
	locked_at = now(),
	locked_by = $1
WHERE prefix IN (
	SELECT prefix
	FROM rdns_ptr_block
	WHERE (
			state = 'pending'
			OR (state = 'leased' AND locked_at < now() - ($2 * interval '1 second'))
		)
	  AND (cardinality($3::text[]) = 0 OR source = ANY($3))
	LIMIT 1
	FOR UPDATE SKIP LOCKED
)
RETURNING prefix::text, zone, COALESCE(nservers, '{}'), source, state, locked_by`

var finishRDNSPTRBlockSQL = `
UPDATE rdns_ptr_block
SET state = 'done', done_at = now(), locked_at = NULL, locked_by = ''
WHERE prefix = $1::inet AND locked_by = $2 AND state = 'leased'`

var failRDNSPTRBlockSQL = `
UPDATE rdns_ptr_block
SET state = 'failed', locked_at = NULL, locked_by = '', done_at = NULL
WHERE prefix = $1::inet AND locked_by = $2 AND state = 'leased'`

var releaseRDNSPTRBlockSQL = `
UPDATE rdns_ptr_block
SET state = 'pending', locked_at = NULL, locked_by = ''
WHERE prefix = $1::inet AND locked_by = $2 AND state = 'leased'`

var heartbeatRDNSPTRBlockSQL = `
UPDATE rdns_ptr_block
SET locked_at = now()
WHERE prefix = $1::inet AND locked_by = $2 AND state = 'leased'`

var countRDNSPTRBlocksSQL = `
SELECT
	COUNT(*) FILTER (WHERE state = 'pending')::bigint,
	COUNT(*) FILTER (WHERE state = 'leased')::bigint,
	COUNT(*) FILTER (WHERE state = 'done')::bigint,
	COUNT(*) FILTER (WHERE state = 'failed')::bigint
FROM rdns_ptr_block`

// SeedRDNSPTRBlocks inserts expandable prefixes into rdns_ptr_block.
// Done/leased/pending rows stay; failed rows become pending (retry).
func (st *Store) SeedRDNSPTRBlocks(ctx context.Context, sources []string) (int64, error) {
	if sources == nil {
		sources = []string{}
	}
	tag, err := st.DB.Exec(ctx, seedRDNSPTRBlocksSQL, sources)
	if err != nil {
		return 0, fmt.Errorf("seed rdns ptr blocks: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ClaimRDNSPTRBlock leases one pending block. nil, nil when the queue is empty.
// sources empty means all registries; otherwise source must match.
func (st *Store) ClaimRDNSPTRBlock(ctx context.Context, lockedBy string, lease time.Duration, sources []string) (*RDNSPTRBlock, error) {
	if lease <= 0 {
		return nil, fmt.Errorf("claim rdns ptr block: lease must be > 0")
	}
	if strings.TrimSpace(lockedBy) == "" {
		lockedBy = "crawl-ptr"
	}
	if sources == nil {
		sources = []string{}
	}
	var b RDNSPTRBlock
	err := st.DB.QueryRow(ctx, claimRDNSPTRBlockSQL, lockedBy, lease.Seconds(), sources).Scan(
		&b.Prefix, &b.Zone, &b.Nservers, &b.Source, &b.State, &b.LockedBy,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim rdns ptr block: %w", err)
	}
	if b.Nservers == nil {
		b.Nservers = []string{}
	}
	return &b, nil
}

// FinishRDNSPTRBlock marks a claimed block done. No-op/error if this worker
// no longer holds the lease.
func (st *Store) FinishRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return execPTRBlockOwnerUpdate(ctx, st, finishRDNSPTRBlockSQL, prefix, lockedBy, "finish")
}

// FailRDNSPTRBlock marks a block failed so the next Seed re-queues it.
func (st *Store) FailRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return execPTRBlockOwnerUpdate(ctx, st, failRDNSPTRBlockSQL, prefix, lockedBy, "fail")
}

// ReleaseRDNSPTRBlock returns a leased block to pending (cancel/shutdown).
func (st *Store) ReleaseRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return execPTRBlockOwnerUpdate(ctx, st, releaseRDNSPTRBlockSQL, prefix, lockedBy, "release")
}

// HeartbeatRDNSPTRBlock renews locked_at so a slow /24 is not stolen.
func (st *Store) HeartbeatRDNSPTRBlock(ctx context.Context, prefix, lockedBy string) error {
	return execPTRBlockOwnerUpdate(ctx, st, heartbeatRDNSPTRBlockSQL, prefix, lockedBy, "heartbeat")
}

func execPTRBlockOwnerUpdate(ctx context.Context, st *Store, sql, prefix, lockedBy, op string) error {
	prefix = strings.TrimSpace(prefix)
	lockedBy = strings.TrimSpace(lockedBy)
	if prefix == "" {
		return fmt.Errorf("%s rdns ptr block: empty prefix", op)
	}
	if lockedBy == "" {
		return fmt.Errorf("%s rdns ptr block: empty locked_by", op)
	}
	tag, err := st.DB.Exec(ctx, sql, prefix, lockedBy)
	if err != nil {
		return fmt.Errorf("%s rdns ptr block: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s rdns ptr block %s: %w", op, prefix, ErrPTRBlockLeaseLost)
	}
	return nil
}

// CountRDNSPTRBlocks is pending/leased/done/failed for the 5-minute ticker.
func (st *Store) CountRDNSPTRBlocks(ctx context.Context) (RDNSPTRBlockCounts, error) {
	var c RDNSPTRBlockCounts
	if err := st.DB.QueryRow(ctx, countRDNSPTRBlocksSQL).Scan(&c.Pending, &c.Leased, &c.Done, &c.Failed); err != nil {
		return c, fmt.Errorf("count rdns ptr blocks: %w", err)
	}
	return c, nil
}
