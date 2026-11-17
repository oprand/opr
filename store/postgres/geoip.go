package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// GeoIPSourceANYCAST is the synthetic source GetIPGeoItem returns for an IP
// covered by an anycast_prefix. It is never stored in geoip.source; only the
// lookup emits it, so callers can tell "this address answers from many
// places" apart from a real geolocation row.
const GeoIPSourceANYCAST = "ANYCAST"

// IsAnycastGeoIPSource reports whether a GeoIPItem came from the anycast
// branch of GetIPGeoItem. Org-HQ rows are country-only; a GEOFEED fallback
// may include an operator-declared city. Callers must not GeoNames-fill
// city or coordinates from a country-only place.
func IsAnycastGeoIPSource(source *string) bool {
	return source != nil && strings.EqualFold(*source, GeoIPSourceANYCAST)
}

// getIPGeoItemSQL: a covering anycast_prefix (most specific) returns HQ with
// source=ANYCAST and no IPmap coordinates. HQ precedence is the covering
// inetnum org, then a covering GEOFEED row (operator-declared city/region/zip
// allowed). Unicast geoip rows rank GEOFEED, then LACNIC_DB_CSV, then
// everything else (IPmap), each by masklen then newest.
//
// This repo has no live-database test harness, so the query is only
// shape-tested (TestGetIPGeoItemSQL*) and a syntax or type error would first
// surface at runtime. Run EXPLAIN (ANALYZE, BUFFERS) by hand for an anycast
// and a unicast address after editing it.
//
// anycast_cover is MATERIALIZED because the inetnum, geofeed, and unicast
// CTEs reference it, and the whois / geofeed-fallback CTEs are gated on it
// having a row so a unicast lookup never pays for them.
var getIPGeoItemSQL = `
WITH anycast_cover AS MATERIALIZED (
	SELECT netblock, source_url, meta_added_at
	FROM anycast_prefix
	WHERE netblock >>= $1::inet
	ORDER BY masklen(netblock) DESC
	LIMIT 1
),
inet_org AS (
	SELECT
		o.org_name,
		NULLIF(array_to_string(o.address, E'\n'), '') AS org_address,
		NULLIF(BTRIM(o.country_code), '') AS country_code,
		NULLIF(BTRIM(o.country), '') AS country
	FROM (
		SELECT netblock, org, source
		FROM whoisdb_inetnum
		WHERE netblock >>= $1::inet
		  AND netblock != '0.0.0.0/0'
		  AND netblock != '::/0'
		  AND source = ANY (ARRAY['APNIC'::text, 'LACNIC'::text, 'RIPE'::text, 'AFRINIC'::text, 'ARIN'::text])
		  AND EXISTS (SELECT 1 FROM anycast_cover)
		UNION ALL
		SELECT netblock, org, source
		FROM whoisdb_inet6num
		WHERE netblock >>= $1::inet
		  AND netblock != '0.0.0.0/0'
		  AND netblock != '::/0'
		  AND source = ANY (ARRAY['APNIC'::text, 'LACNIC'::text, 'RIPE'::text, 'AFRINIC'::text, 'ARIN'::text])
		  AND EXISTS (SELECT 1 FROM anycast_cover)
	) i
	JOIN whoisdb_org o ON i.org = o.organization AND i.source = o.source
	ORDER BY masklen(i.netblock) DESC, i.source
	LIMIT 1
),
-- Last resort when the covering inetnum org lacks HQ: operator-declared
-- location from a covering GEOFEED row (most specific, then newest).
-- City/region/zip may be copied; IPmap coordinates are not.
geofeed_hq AS (
	SELECT country_code, country, region, region_code, city, zipcode
	FROM geoip
	WHERE $1::inet <<= netblock
	  AND source = 'GEOFEED'
	  AND EXISTS (SELECT 1 FROM anycast_cover)
	ORDER BY
		masklen(netblock) DESC,
		meta_added_at DESC
	LIMIT 1
),
anycast_row AS (
	SELECT
		p.netblock,
		CASE
			WHEN p.use_inet THEN p.io_country_code
			ELSE p.gf_country_code
		END AS country_code,
		CASE
			WHEN p.use_inet THEN p.io_country
			ELSE p.gf_country
		END AS country,
		CASE
			WHEN p.use_inet THEN NULL::text
			ELSE p.gf_region
		END AS region,
		CASE
			WHEN p.use_inet THEN NULL::text
			ELSE p.gf_region_code
		END AS region_code,
		CASE
			WHEN p.use_inet THEN NULL::text
			ELSE p.gf_city
		END AS city,
		CASE
			WHEN p.use_inet THEN NULL::text
			ELSE p.gf_zipcode
		END AS zipcode,
		'ANYCAST'::text AS source, -- GeoIPSourceANYCAST
		p.source_url,
		p.meta_added_at,
		NULL::text AS type,
		NULL::text AS location_id,
		NULL::numeric AS latitude,
		NULL::numeric AS longitude,
		NULL::numeric AS score,
		CASE
			WHEN p.use_inet THEN p.io_org_name
			ELSE NULL
		END AS org_name,
		CASE
			WHEN p.use_inet THEN p.io_org_address
			ELSE NULL
		END AS org_address
	FROM (
		SELECT
			ac.netblock,
			ac.source_url,
			ac.meta_added_at,
			(
				NULLIF(BTRIM(io.org_name), '') IS NOT NULL
				OR io.org_address IS NOT NULL
				OR io.country IS NOT NULL
				OR io.country_code IS NOT NULL
			) AS use_inet,
			io.org_name AS io_org_name,
			io.org_address AS io_org_address,
			io.country_code AS io_country_code,
			io.country AS io_country,
			gf.country_code AS gf_country_code,
			gf.country AS gf_country,
			gf.region AS gf_region,
			gf.region_code AS gf_region_code,
			gf.city AS gf_city,
			gf.zipcode AS gf_zipcode
		FROM anycast_cover ac
		LEFT JOIN inet_org io ON TRUE
		LEFT JOIN geofeed_hq gf ON TRUE
	) p
),
unicast_row AS (
	SELECT
		netblock, country_code, country, region, region_code,
		city, zipcode, source, source_url, meta_added_at, type,
		location_id, latitude, longitude, score,
		NULL::text AS org_name,
		NULL::text AS org_address
	FROM geoip
	WHERE $1::inet <<= netblock
	  AND NOT EXISTS (SELECT 1 FROM anycast_cover)
	ORDER BY
		CASE source
			WHEN 'GEOFEED' THEN 0
			WHEN 'LACNIC_DB_CSV' THEN 1
			ELSE 2
		END,
		masklen(netblock) DESC,
		meta_added_at DESC
	LIMIT 1
)
SELECT
	netblock, country_code, country, region, region_code,
	city, zipcode, source, source_url, meta_added_at, type,
	location_id, latitude, longitude, score, org_name, org_address
FROM anycast_row
UNION ALL
SELECT
	netblock, country_code, country, region, region_code,
	city, zipcode, source, source_url, meta_added_at, type,
	location_id, latitude, longitude, score, org_name, org_address
FROM unicast_row
LIMIT 1
	`

// GetIPGeoItem returns geo information for an IP address.
func (st *Store) GetIPGeoItem(ipNet string) (*GeoIPItem, error) {
	var geoIpRow GeoIPItem

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := st.DB.QueryRow(ctx, getIPGeoItemSQL, ipNet).Scan(
		&geoIpRow.Netblock,
		&geoIpRow.CountryCode,
		&geoIpRow.Country,
		&geoIpRow.Region,
		&geoIpRow.RegionCode,
		&geoIpRow.City,
		&geoIpRow.ZipCode,
		&geoIpRow.Source,
		&geoIpRow.SourceURL,
		&geoIpRow.MetaAddedAt,
		&geoIpRow.Type,
		&geoIpRow.LocationID,
		&geoIpRow.Latitude,
		&geoIpRow.Longitude,
		&geoIpRow.Score,
		&geoIpRow.OrgName,
		&geoIpRow.OrgAddress,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return &geoIpRow, nil
	}
	if err != nil {
		st.logger.Error("error while getting one ip info from database", zap.Error(err))
		return &geoIpRow, err
	}

	st.logger.Debug("ip info retrieved successfully from database")
	return &geoIpRow, nil
}

// geoIPUpsert bulk-loads geoip via COPY then ON CONFLICT (netblock, source_url).
// LACNIC CSV uses source_url ”; RFC 9632 rows use the catalog URL, so the
// same prefix can exist twice.
var geoIPUpsert = whoisUpsertSpec{
	live: "geoip",
	columns: []string{
		"netblock", "country_code", "country", "region", "region_code",
		"city", "zipcode", "source", "source_url", "meta_added_at", "type",
		"location_id", "latitude", "longitude", "score",
	},
	selectExprs: map[string]string{
		"source_url":    "COALESCE(source_url, '')",
		"meta_added_at": "COALESCE(meta_added_at, NOW())",
	},
	onConflict: `
			ON CONFLICT (netblock, source_url)
			DO UPDATE SET
				country_code = EXCLUDED.country_code,
				country = EXCLUDED.country,
				region = EXCLUDED.region,
				region_code = EXCLUDED.region_code,
				city = EXCLUDED.city,
				zipcode = EXCLUDED.zipcode,
				source = EXCLUDED.source,
				meta_added_at = EXCLUDED.meta_added_at,
				type = EXCLUDED.type,
				location_id = EXCLUDED.location_id,
				latitude = EXCLUDED.latitude,
				longitude = EXCLUDED.longitude,
				score = EXCLUDED.score`,
}

func geoIPCopyRow(item *GeoIPItem) []any {
	sourceURL := geoIPSourceURL(item)
	return []any{
		item.Netblock, item.CountryCode, item.Country, item.Region, item.RegionCode,
		item.City, item.ZipCode, item.Source, sourceURL, item.MetaAddedAt, item.Type,
		item.LocationID, item.Latitude, item.Longitude, item.Score,
	}
}

func geoIPSourceURL(item *GeoIPItem) string {
	if item == nil || item.SourceURL == nil {
		return ""
	}
	return *item.SourceURL
}

func geoIPConflictKey(item *GeoIPItem) (string, bool) {
	if item == nil || item.Netblock == "" {
		return "", false
	}
	return item.Netblock + "\x00" + geoIPSourceURL(item), true
}

func dedupGeoIPItems(items []*GeoIPItem) []*GeoIPItem {
	return dedupLastWins(items, geoIPConflictKey)
}

func (st *Store) SaveGeoIPItem(geoIPItem []*GeoIPItem) error {
	items := dedupGeoIPItems(geoIPItem)
	if len(items) == 0 {
		return fmt.Errorf("no geoip items to save")
	}

	startTime := time.Now()
	ctx := context.Background()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, geoIPUpsert, len(items), func(i int) ([]any, error) {
		return geoIPCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("failed to insert geoip item", zap.Error(err))
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		st.logger.Error("failed to commit the geoip item transaction", zap.Error(err))
		return err
	}

	st.logger.Debug(fmt.Sprintf("saved new batch of geoip data in %s", time.Since(startTime).String()))
	return nil
}

// replaceGeoIPDeleteStaleSQL drops derived rows for one catalog URL that are
// not in this successful parse. geoip_stg is the COPY temp from geoIPUpsert
// (ON COMMIT DROP); it must run in the same transaction as the upsert.
var replaceGeoIPDeleteStaleSQL = `
DELETE FROM geoip
WHERE source_url = $1
  AND NOT EXISTS (
    SELECT 1 FROM geoip_stg s
    WHERE s.netblock = geoip.netblock
  )`

var replaceGeoIPDeleteAllSQL = `
DELETE FROM geoip
WHERE source_url = $1`

// ReplaceGeoIPBySourceURL replaces all geoip rows for sourceURL with items in
// one transaction: upsert the new set, then DELETE that URL's netblocks that
// were not in the set. It never deletes another URL's rows. Callers must not
// invoke this after a failed or partial parse. An empty successful parse
// deletes every derived row for that URL.
func (st *Store) ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*GeoIPItem) error {
	if sourceURL == "" {
		return fmt.Errorf("replace geoip by source_url: empty source_url")
	}

	url := sourceURL
	forced := make([]*GeoIPItem, 0, len(items))
	for _, item := range items {
		if item == nil || item.Netblock == "" {
			continue
		}
		cp := *item
		cp.SourceURL = &url
		forced = append(forced, &cp)
	}
	forced = dedupGeoIPItems(forced)

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("replace geoip by source_url: %w", err)
	}
	defer tx.Rollback(context.Background())

	if len(forced) == 0 {
		if _, err := tx.Exec(ctx, replaceGeoIPDeleteAllSQL, sourceURL); err != nil {
			return fmt.Errorf("replace geoip by source_url: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("replace geoip by source_url: %w", err)
		}
		return nil
	}

	if err := copyIntoTempThenUpsert(ctx, tx, geoIPUpsert, len(forced), func(i int) ([]any, error) {
		return geoIPCopyRow(forced[i]), nil
	}); err != nil {
		return fmt.Errorf("replace geoip by source_url: %w", err)
	}

	if _, err := tx.Exec(ctx, replaceGeoIPDeleteStaleSQL, sourceURL); err != nil {
		return fmt.Errorf("replace geoip by source_url: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("replace geoip by source_url: %w", err)
	}
	return nil
}

// pruneOrphanGeoIPSQL deletes derived rows whose source_url is gone from the
// geofeeds catalog. Empty source_url is treated as an orphan (unknown source).
// Filter source = $1 so a GEOFEED prune cannot touch LACNIC_DB_CSV rows.
var pruneOrphanGeoIPSQL = `
DELETE FROM geoip
WHERE source = $1
  AND (source_url = '' OR source_url NOT IN (SELECT url FROM geofeeds))`

var countOrphanGeoIPSQL = `
SELECT COUNT(*) FROM geoip
WHERE source = $1
  AND (source_url = '' OR source_url NOT IN (SELECT url FROM geofeeds))`

var countGeoIPBySourceURLSQL = `
SELECT COUNT(*) FROM geoip
WHERE source_url = $1`

// CountGeoIPBySourceURL is the existing-row count used by IPmap ingest
// before ReplaceGeoIPBySourceURL (replace-floor guard).
func (st *Store) CountGeoIPBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	if sourceURL == "" {
		return 0, fmt.Errorf("count geoip by source_url: empty source_url")
	}
	var n int64
	if err := st.DB.QueryRow(ctx, countGeoIPBySourceURLSQL, sourceURL).Scan(&n); err != nil {
		return 0, fmt.Errorf("count geoip by source_url: %w", err)
	}
	return n, nil
}

// PruneOrphanGeoIP deletes geoip rows for source whose source_url is not in
// geofeeds (and empty source_url). source is typically "GEOFEED"; LACNIC CSV
// rows use a different source and are left alone.
func (st *Store) PruneOrphanGeoIP(ctx context.Context, source string) (int64, error) {
	if source == "" {
		return 0, nil
	}
	tag, err := st.DB.Exec(ctx, pruneOrphanGeoIPSQL, source)
	if err != nil {
		return 0, fmt.Errorf("prune orphan geoip: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountOrphanGeoIP is the dry-run counterpart of PruneOrphanGeoIP.
func (st *Store) CountOrphanGeoIP(ctx context.Context, source string) (int64, error) {
	if source == "" {
		return 0, nil
	}
	var n int64
	if err := st.DB.QueryRow(ctx, countOrphanGeoIPSQL, source).Scan(&n); err != nil {
		return 0, fmt.Errorf("count orphan geoip: %w", err)
	}
	return n, nil
}

// LACNIC CSV rows use empty source_url as the ingest key; do not treat that
// as an orphan. Only drop LACNIC rows that carry a catalog URL no longer in
// geofeeds.
var pruneOrphanGeoIPNonEmptySQL = `
DELETE FROM geoip
WHERE source = $1
  AND source_url <> ''
  AND source_url NOT IN (SELECT url FROM geofeeds)`

var countOrphanGeoIPNonEmptySQL = `
SELECT COUNT(*) FROM geoip
WHERE source = $1
  AND source_url <> ''
  AND source_url NOT IN (SELECT url FROM geofeeds)`

func (st *Store) PruneOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error) {
	if source == "" {
		return 0, nil
	}
	tag, err := st.DB.Exec(ctx, pruneOrphanGeoIPNonEmptySQL, source)
	if err != nil {
		return 0, fmt.Errorf("prune orphan geoip nonempty: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (st *Store) CountOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error) {
	if source == "" {
		return 0, nil
	}
	var n int64
	if err := st.DB.QueryRow(ctx, countOrphanGeoIPNonEmptySQL, source).Scan(&n); err != nil {
		return 0, fmt.Errorf("count orphan geoip nonempty: %w", err)
	}
	return n, nil
}
