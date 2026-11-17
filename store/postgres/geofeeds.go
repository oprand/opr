package postgres

import (
	"context"
	"fmt"
	"time"
)

// GeofeedRow is one geofeeds catalog row used as the crawl unit (unique URL).
type GeofeedRow struct {
	URL              string
	ETag             *string
	LastModified     *string
	CacheUntil       *time.Time
	LastCheckedAt    *time.Time
	LastFetchedAt    *time.Time
	LastHTTPStatus   *int
	ItemCount        *int
	IsValid          *bool
	QuarantinedUntil *time.Time
}

// GeofeedStamp is HTTP outcome metadata written back to geofeeds.
// 304 should set LastHTTPStatus and leave fetch/parse fields nil so COALESCE
// keeps the last successful body. 200 sets LastFetchedAt, ItemCount, IsValid,
// and ClearQuarantine. 404/HTML sets QuarantinedUntil and IsValid=false.
type GeofeedStamp struct {
	URL              string
	ETag             *string
	LastModified     *string
	CacheUntil       *time.Time
	LastFetchedAt    *time.Time
	LastHTTPStatus   *int
	ItemCount        *int
	IsValid          *bool
	QuarantinedUntil *time.Time
	ClearQuarantine  bool
}

// claimDueGeofeedsSQL takes up to $2 due catalog URLs, matching crawl_target
// ClaimDue: UPDATE locked_at inside the same statement as FOR UPDATE SKIP LOCKED.
// The implicit statement transaction is enough; row locks would drop on commit
// without the lease write. Concurrent claimers skip locked rows, then skip
// recent locked_at until $3 seconds elapse (crashed worker). Unique
// geofeeds.url is the crawl unit, not crawl_target. New URLs (last_fetched_at
// NULL) sort first. Due when not quarantined, lease is free or stale, and any
// of: never fetched, cache_until expired, or last fetch older than $1 seconds.
var claimDueGeofeedsSQL = `
UPDATE geofeeds
SET locked_at = now()
WHERE url IN (
	SELECT url
	FROM geofeeds
	WHERE (quarantined_until IS NULL OR quarantined_until < now())
	  AND (
			last_fetched_at IS NULL
			OR cache_until < now()
			OR last_fetched_at < now() - ($1 * interval '1 second')
	  )
	  AND (locked_at IS NULL OR locked_at < now() - ($3 * interval '1 second'))
	ORDER BY last_fetched_at ASC NULLS FIRST, url ASC
	LIMIT $2
	FOR UPDATE SKIP LOCKED
)
RETURNING
	url, etag, last_modified, cache_until, last_checked_at, last_fetched_at,
	last_http_status, item_count, is_valid, quarantined_until`

// ClaimDueGeofeeds atomically claims up to batch due geofeeds catalog rows.
// refreshOlderThan is the caller interval used when Cache-Control did not set
// a future cache_until (Task 6 --refresh-older-than). lease is how long
// locked_at keeps the URL skipped by other claimers. batch and lease must be
// positive.
func (st *Store) ClaimDueGeofeeds(ctx context.Context, batch int, refreshOlderThan, lease time.Duration) ([]GeofeedRow, error) {
	if batch < 1 {
		return nil, fmt.Errorf("claim due geofeeds: batch must be >= 1")
	}
	if lease <= 0 {
		return nil, fmt.Errorf("claim due geofeeds: lease must be > 0")
	}

	rows, err := st.DB.Query(ctx, claimDueGeofeedsSQL, refreshOlderThan.Seconds(), batch, lease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("claim due geofeeds: %w", err)
	}
	defer rows.Close()

	var out []GeofeedRow
	for rows.Next() {
		var r GeofeedRow
		if err := rows.Scan(
			&r.URL, &r.ETag, &r.LastModified, &r.CacheUntil, &r.LastCheckedAt, &r.LastFetchedAt,
			&r.LastHTTPStatus, &r.ItemCount, &r.IsValid, &r.QuarantinedUntil,
		); err != nil {
			return nil, fmt.Errorf("claim due geofeeds: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("claim due geofeeds: %w", err)
	}
	return out, nil
}

// stampGeofeedSQL writes HTTP validators and clocks. last_checked_at is always
// now(). COALESCE keeps previous etag/body clocks on 304. ClearQuarantine
// ($10) sets quarantined_until NULL after a successful fetch.
var stampGeofeedSQL = `
UPDATE geofeeds SET
	etag = COALESCE($2, etag),
	last_modified = COALESCE($3, last_modified),
	cache_until = COALESCE($4, cache_until),
	last_checked_at = now(),
	last_fetched_at = COALESCE($5, last_fetched_at),
	last_http_status = COALESCE($6, last_http_status),
	item_count = COALESCE($7, item_count),
	is_valid = COALESCE($8, is_valid),
	quarantined_until = CASE
		WHEN $10::boolean THEN NULL
		ELSE COALESCE($9, quarantined_until)
	END
WHERE url = $1`

// StampGeofeed records the HTTP outcome for one catalog URL.
func (st *Store) StampGeofeed(ctx context.Context, stamp GeofeedStamp) error {
	if stamp.URL == "" {
		return fmt.Errorf("stamp geofeed: empty url")
	}
	if _, err := st.DB.Exec(ctx, stampGeofeedSQL,
		stamp.URL,
		stamp.ETag,
		stamp.LastModified,
		stamp.CacheUntil,
		stamp.LastFetchedAt,
		stamp.LastHTTPStatus,
		stamp.ItemCount,
		stamp.IsValid,
		stamp.QuarantinedUntil,
		stamp.ClearQuarantine,
	); err != nil {
		return fmt.Errorf("stamp geofeed: %w", err)
	}
	return nil
}
