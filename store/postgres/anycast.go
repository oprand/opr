package postgres

import (
	"context"
	"fmt"
)

// anycastUpsert bulk-loads anycast_prefix via COPY then ON CONFLICT (netblock).
var anycastUpsert = whoisUpsertSpec{
	live: "anycast_prefix",
	columns: []string{
		"netblock", "example_host", "source_url", "meta_added_at",
	},
	selectExprs: map[string]string{
		"meta_added_at": "COALESCE(meta_added_at, NOW())",
	},
	onConflict: `
			ON CONFLICT (netblock)
			DO UPDATE SET
				example_host = EXCLUDED.example_host,
				source_url = EXCLUDED.source_url,
				meta_added_at = EXCLUDED.meta_added_at`,
}

func anycastCopyRow(item *AnycastPrefix) []any {
	var host any
	if item.ExampleHost != nil {
		host = *item.ExampleHost
	}
	return []any{
		item.Netblock, host, item.SourceURL, item.MetaAddedAt,
	}
}

func anycastConflictKey(item *AnycastPrefix) (string, bool) {
	if item == nil || item.Netblock == "" {
		return "", false
	}
	return item.Netblock, true
}

func dedupAnycastPrefixes(items []*AnycastPrefix) []*AnycastPrefix {
	return dedupLastWins(items, anycastConflictKey)
}

var replaceAnycastDeleteStaleSQL = `
DELETE FROM anycast_prefix
WHERE source_url = $1
  AND NOT EXISTS (
    SELECT 1 FROM anycast_prefix_stg s
    WHERE s.netblock = anycast_prefix.netblock
  )`

var replaceAnycastDeleteAllSQL = `
DELETE FROM anycast_prefix
WHERE source_url = $1`

var countAnycastBySourceURLSQL = `
SELECT COUNT(*) FROM anycast_prefix
WHERE source_url = $1`

var anycastStatusByURLSQL = `
SELECT
	source_url,
	COUNT(*),
	MAX(meta_added_at)
FROM anycast_prefix
GROUP BY source_url`

// CountAnycastBySourceURL is the existing-row count used by anycast ingest
// before ReplaceAnycastBySourceURL (replace-floor guard).
func (st *Store) CountAnycastBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	if sourceURL == "" {
		return 0, fmt.Errorf("count anycast by source_url: empty source_url")
	}
	var n int64
	if err := st.DB.QueryRow(ctx, countAnycastBySourceURLSQL, sourceURL).Scan(&n); err != nil {
		return 0, fmt.Errorf("count anycast by source_url: %w", err)
	}
	return n, nil
}

// ReplaceAnycastBySourceURL replaces all anycast_prefix rows for sourceURL
// with items in one transaction. It never deletes another URL's rows. Callers
// must not invoke this after a failed or partial parse. An empty successful
// parse deletes every row for that URL.
func (st *Store) ReplaceAnycastBySourceURL(ctx context.Context, sourceURL string, items []*AnycastPrefix) error {
	if sourceURL == "" {
		return fmt.Errorf("replace anycast by source_url: empty source_url")
	}

	forced := make([]*AnycastPrefix, 0, len(items))
	for _, item := range items {
		if item == nil || item.Netblock == "" {
			continue
		}
		cp := *item
		cp.SourceURL = sourceURL
		forced = append(forced, &cp)
	}
	forced = dedupAnycastPrefixes(forced)

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replace anycast by source_url: %w", err)
	}
	defer tx.Rollback(context.Background())

	if len(forced) == 0 {
		if _, err := tx.Exec(ctx, replaceAnycastDeleteAllSQL, sourceURL); err != nil {
			return fmt.Errorf("replace anycast by source_url: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("replace anycast by source_url: %w", err)
		}
		return nil
	}

	if err := copyIntoTempThenUpsert(ctx, tx, anycastUpsert, len(forced), func(i int) ([]any, error) {
		return anycastCopyRow(forced[i]), nil
	}); err != nil {
		return fmt.Errorf("replace anycast by source_url: %w", err)
	}

	if _, err := tx.Exec(ctx, replaceAnycastDeleteStaleSQL, sourceURL); err != nil {
		return fmt.Errorf("replace anycast by source_url: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("replace anycast by source_url: %w", err)
	}
	return nil
}
