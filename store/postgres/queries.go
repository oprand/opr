package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oputils"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// FetchWhoisDBRecordsTypeCountBySource fetches the count of records for each type for whoisdb items by source.
// The count is based on the meta_added_at column, at least since twice the crawl interval.
// Record types are: autnum, inetnum, inet6num, org, role, route, route6, as-set, as-block, irt.
func (st *Store) FetchWhoisDBRecordsTypeCountBySource(ctx context.Context, source string, crawlIntervalHours int) (map[opconst.RecordType]int64, error) {
	query := `
		select '%s' AS record_type, count(1) AS count from whoisdb_autnum where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_inetnum where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_inet6num where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_org where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_role where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_route where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_route6 where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_as_set where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_as_block where source=$1 and meta_added_at > now() - $2::interval
		union all
		select '%s' AS record_type, count(1) AS count from whoisdb_irt where source=$1 and meta_added_at > now() - $2::interval
	`

	query = fmt.Sprintf(query, opconst.RecordTypeAutNum, opconst.RecordTypeInetNum, opconst.RecordTypeInet6Num,
		opconst.RecordTypeOrg, opconst.RecordTypeRole, opconst.RecordTypeRoute, opconst.RecordTypeRoute6,
		opconst.RecordTypeAsSet, opconst.RecordTypeAsBlock, opconst.RecordTypeIrt)

	pgCrawlInterval := pgtype.Interval{
		Microseconds: 2 * int64(crawlIntervalHours) * int64(time.Hour.Microseconds()),
		Valid:        true,
	}
	rows, err := st.DB.Query(ctx, query, source, pgCrawlInterval)
	if err != nil {
		return nil, fmt.Errorf("error fetching whoisdb items most recent timestamp by source: %w", err)
	}
	defer rows.Close()

	mostRecentTimestamps := make(map[opconst.RecordType]int64)

	for rows.Next() {
		var recordType string
		var count int64
		err := rows.Scan(&recordType, &count)
		if err != nil {
			st.logger.Error("error scanning whoisdb items most recent timestamp by source", zap.Error(err))
			continue
		}
		mostRecentTimestamps[opconst.RecordType(recordType)] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating whoisdb items most recent timestamp by source: %w", err)
	}

	return mostRecentTimestamps, nil
}

// TODO: Need to make the unique constraint on more thand route/source to include duplicates,
// but also not store duplicates in the database.
// Same for route6 records.
func (st *Store) SaveWhoisRoute6(ctx context.Context, whoisRoute6Items []*whoisdb.WhoisRoute6) error {

	if len(whoisRoute6Items) == 0 {
		st.logger.Debug("no whois route6 items to update")
		return nil
	}
	st.logger.Debug("saving whois route6 items", zap.Int("count", len(whoisRoute6Items)))

	items := dedupWhoisRoute6(whoisRoute6Items)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisRoute6Upsert, len(items), func(i int) ([]any, error) {
		return whoisRoute6CopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois route6 item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois route6 data",
		zap.Int("count", len(whoisRoute6Items)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisRoute(ctx context.Context, whoisRouteItems []*whoisdb.WhoisRoute) error {

	if len(whoisRouteItems) == 0 {
		st.logger.Debug("no whois route items to update")
		return nil
	}
	st.logger.Debug("saving whois route items", zap.Int("count", len(whoisRouteItems)))

	items := dedupWhoisRoute(whoisRouteItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisRouteUpsert, len(items), func(i int) ([]any, error) {
		return whoisRouteCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois route item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois route data",
		zap.Int("count", len(whoisRouteItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisRole(ctx context.Context, whoisRoleItems []*whoisdb.WhoisRole) error {

	if len(whoisRoleItems) == 0 {
		st.logger.Debug("no whois role items to update")
		return nil
	}
	st.logger.Debug("saving whois role items", zap.Int("count", len(whoisRoleItems)))

	items := dedupWhoisRole(whoisRoleItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisRoleUpsert, len(items), func(i int) ([]any, error) {
		return whoisRoleCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois role item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois role data",
		zap.Int("count", len(whoisRoleItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisOrganization(ctx context.Context, whoisOrganizationItems []*whoisdb.WhoisOrganization) error {

	if len(whoisOrganizationItems) == 0 {
		st.logger.Debug("no whois organization items to update")
		return nil
	}
	st.logger.Debug("saving whois organization items", zap.Int("count", len(whoisOrganizationItems)))

	items := dedupWhoisOrganization(whoisOrganizationItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisOrgUpsert, len(items), func(i int) ([]any, error) {
		return whoisOrgCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois organization item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois organization data",
		zap.Int("count", len(whoisOrganizationItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisInet6Num(ctx context.Context, whoisInet6NumItems []*whoisdb.WhoisInet6Num) error {

	if len(whoisInet6NumItems) == 0 {
		st.logger.Debug("no whois inet6num items to update")
		return nil
	}
	st.logger.Debug("saving whois inet6num items", zap.Int("count", len(whoisInet6NumItems)))

	items := dedupWhoisInet6Num(whoisInet6NumItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisInet6NumUpsert, len(items), func(i int) ([]any, error) {
		return whoisInet6NumCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois inet6num item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois inet6num data",
		zap.Int("count", len(whoisInet6NumItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisInetNum(ctx context.Context, whoisInetNumItems []*whoisdb.WhoisInetNum) error {

	if len(whoisInetNumItems) == 0 {
		st.logger.Debug("no whois inetnum items to update")
		return nil
	}
	st.logger.Debug("saving whois inetnum items", zap.Int("count", len(whoisInetNumItems)))

	items := dedupWhoisInetNum(whoisInetNumItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisInetNumUpsert, len(items), func(i int) ([]any, error) {
		return whoisInetNumCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois inetnum item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois inetnum data",
		zap.Int("count", len(whoisInetNumItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisAutNum(ctx context.Context, whoisAutNumItems []*whoisdb.WhoisAutNum) error {

	if len(whoisAutNumItems) == 0 {
		st.logger.Debug("no whois asn items to update")
		return nil
	}
	st.logger.Debug("saving whois autnum items", zap.Int("count", len(whoisAutNumItems)))

	items := dedupWhoisAutNum(whoisAutNumItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	// Freshness columns COALESCE so callers that leave them nil do not wipe
	// values already on the row. is_partial defaults to false when omitted
	// (COALESCE in the INSERT SELECT, matching previous VALUES COALESCE($39, FALSE)).
	err = copyIntoTempThenUpsert(ctx, tx, whoisAutNumUpsert, len(items), func(i int) ([]any, error) {
		return whoisAutNumCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("failed to update whois asn item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("failed to commit the transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois autnum data",
		zap.Int("count", len(whoisAutNumItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisAsSet(ctx context.Context, whoisAsSetItems []*whoisdb.WhoisAsSet) error {

	if len(whoisAsSetItems) == 0 {
		st.logger.Debug("no whois as-set items to update")
		return nil
	}
	st.logger.Debug("saving whois as-set items", zap.Int("count", len(whoisAsSetItems)))

	items := dedupWhoisAsSet(whoisAsSetItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisAsSetUpsert, len(items), func(i int) ([]any, error) {
		return whoisAsSetCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois as-set item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois as-set data",
		zap.Int("count", len(whoisAsSetItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisAsBlock(ctx context.Context, whoisAsBlockItems []*whoisdb.WhoisAsBlock) error {

	if len(whoisAsBlockItems) == 0 {
		st.logger.Debug("no whois as-block items to update")
		return nil
	}
	st.logger.Debug("saving whois as-block items", zap.Int("count", len(whoisAsBlockItems)))

	items := dedupWhoisAsBlock(whoisAsBlockItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisAsBlockUpsert, len(items), func(i int) ([]any, error) {
		return whoisAsBlockCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois as-block item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois as-block data",
		zap.Int("count", len(whoisAsBlockItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveWhoisIrt(ctx context.Context, whoisIrtItems []*whoisdb.WhoisIrt) error {

	if len(whoisIrtItems) == 0 {
		st.logger.Debug("no whois irt items to update")
		return nil
	}
	st.logger.Debug("saving whois irt items", zap.Int("count", len(whoisIrtItems)))

	items := dedupWhoisIrt(whoisIrtItems)
	if len(items) == 0 {
		return nil
	}

	startTime := time.Now()

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	err = copyIntoTempThenUpsert(ctx, tx, whoisIrtUpsert, len(items), func(i int) ([]any, error) {
		return whoisIrtCopyRow(items[i]), nil
	})
	if err != nil {
		st.logger.Error("error saving whois irt item", zap.Error(err))
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		st.logger.Error("error committing transaction", zap.Error(err))
		return err
	}

	st.logger.Debug("updated whois irt data",
		zap.Int("count", len(whoisIrtItems)),
		zap.Duration("duration", time.Since(startTime)))

	return nil
}

func (st *Store) SaveCountryInfo(countryInfoItems []*CountryInfoItem) error {

	if len(countryInfoItems) == 0 {
		return fmt.Errorf("no country info items to save")
	}

	tx, err := st.DB.Begin(context.TODO())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	// Delete all existing data
	_, err = tx.Exec(context.Background(), "DELETE FROM country_info")
	if err != nil {
		return err
	}

	copyCount, err := tx.CopyFrom(
		context.Background(),
		pgx.Identifier{"country_info"},
		[]string{"iso", "iso3", "iso_numeric", "fips", "country",
			"capital", "area", "population", "continent", "tld",
			"currency_code", "currency_name", "phone", "postal_code_format", "postal_code_regex",
			"languages", "geoname_id", "neighbours", "equivalent_fips", "meta_added_at"},
		pgx.CopyFromSlice(len(countryInfoItems), func(i int) ([]any, error) {
			return []any{countryInfoItems[i].ISO, countryInfoItems[i].ISO3, countryInfoItems[i].ISONumeric, countryInfoItems[i].FIPS, countryInfoItems[i].Country,
				countryInfoItems[i].Capital, countryInfoItems[i].Area, countryInfoItems[i].Population, countryInfoItems[i].Continent, countryInfoItems[i].TLD,
				countryInfoItems[i].CurrencyCode, countryInfoItems[i].CurrencyName, countryInfoItems[i].Phone, countryInfoItems[i].PostalCodeFormat, countryInfoItems[i].PostalCodeRegex,
				countryInfoItems[i].Languages, countryInfoItems[i].GeonameID, countryInfoItems[i].Neighbours, countryInfoItems[i].EquivalentFIPS, time.Now()}, nil
		}),
	)
	if err != nil {
		return err
	}

	st.logger.Info("number of rows copied to country_info", zap.Int64("copyCount", copyCount))

	return tx.Commit(context.Background())
}

func (st *Store) GetResponseMetadata(url string) *ResponseMetadataItem {

	query := `
		SELECT
			url, etag, last_modified, content_length, charset, content_type, meta_added_at
		FROM
			remote_files_metadata
		WHERE url=$1
		`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var respRow ResponseMetadataItem

	rows, err := st.DB.Query(ctx, query, url)
	if err != nil {
		st.logger.Error("error while getting response metadata", zap.Error(err), zap.Any("url", url))
		return &respRow
	}

	respRow, err = pgx.CollectOneRow[ResponseMetadataItem](rows, pgx.RowToStructByNameLax[ResponseMetadataItem])
	if errors.Is(err, pgx.ErrNoRows) {
		return &respRow
	} else if err != nil {
		st.logger.Error("error while collecting row for response metadata", zap.Error(err), zap.Any("url", url))
		return &respRow
	}

	st.logger.Debug("response metadata read successfully from database", zap.Any("url", url))

	return &respRow

}

func (st *Store) SaveResponseMetadata(meta *ResponseMetadataItem) {

	if meta == nil {
		st.logger.Debug("trying to save metadata with a nil response")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := st.DB.Exec(ctx,
		`INSERT INTO
				remote_files_metadata
					("url", "etag", "last_modified", "content_length", "charset", "content_type", "meta_added_at")
				VALUES
					($1, $2, $3, $4, $5, $6, $7)	
				ON CONFLICT (url)
				DO UPDATE
				SET
					etag = EXCLUDED.etag,
					last_modified = EXCLUDED.last_modified,
					content_length = EXCLUDED.content_length,
					charset = EXCLUDED.charset,
					content_type = EXCLUDED.content_type,
					meta_added_at = EXCLUDED.meta_added_at;`,

		oputils.NilIfEmpty(meta.Url),
		meta.Etag,
		meta.LastModified,
		meta.ContentLength,
		meta.Charset,
		meta.ContentType,
		meta.MetaAddedAt,
	)

	if err != nil {
		st.logger.Error("error while inserting response metadata", zap.Error(err), zap.Any("meta", meta))
		return
	}

	st.logger.Debug("response metadata saved successfully", zap.String("url", meta.Url))

}

// saveGeofeedsSQL upserts discovered geofeed URLs without wiping 0064 metadata.
var saveGeofeedsSQL = `
INSERT INTO geofeeds (url, last_seen_in_whois)
SELECT url, now()
FROM unnest($1::text[]) AS url
ON CONFLICT (url) DO UPDATE SET last_seen_in_whois = now()`

// SaveGeofeeds upserts a slice of geofeed URLs. Callers must pass already
// canonical URLs (geofeeds.CanonicalizeURL); empty strings are dropped.
// Existing rows keep first_seen and crawl metadata; last_seen_in_whois is refreshed.
func (s *Store) SaveGeofeeds(ctx context.Context, urls []string) error {
	urls = uniqueCIDRs(urls)
	if len(urls) == 0 {
		return nil
	}

	if _, err := s.DB.Exec(ctx, saveGeofeedsSQL, urls); err != nil {
		s.logger.Error("failed to save geofeeds", zap.Error(err))
		return err
	}

	s.logger.Info("saved geofeeds", zap.Int("count", len(urls)))
	return nil
}

// pruneStaleGeofeedsSQL drops catalog rows not refreshed by this run's upsert.
// NULL last_seen_in_whois covers pre-0064 / never-stamped rows that were not
// in the upsert set.
var pruneStaleGeofeedsSQL = `
DELETE FROM geofeeds
WHERE last_seen_in_whois IS NULL OR last_seen_in_whois < $1`

// markStaleGeofeedTargetsGoneSQL marks geofeed crawl jobs gone when their URL
// was not in this run's harvest. Rows are not deleted.
var markStaleGeofeedTargetsGoneSQL = `
UPDATE crawl_target
SET
	state = '` + CrawlStateGone + `',
	last_error = 'not seen in whois harvest',
	locked_at = NULL,
	locked_by = NULL
WHERE kind = '` + CrawlKindGeofeed + `'
  AND state <> '` + CrawlStateGone + `'
  AND NOT (key = ANY($1::text[]))`

// PruneStaleGeofeeds deletes geofeeds not seen since runStarted and marks
// matching kind=geofeed crawl_target rows gone. seenURLs is this run's upsert
// set; empty is a no-op so a partial harvest cannot wipe the catalog.
func (s *Store) PruneStaleGeofeeds(ctx context.Context, runStarted time.Time, seenURLs []string) (deleted, markedGone int64, err error) {
	seenURLs = uniqueCIDRs(seenURLs)
	if len(seenURLs) == 0 {
		return 0, 0, nil
	}

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("prune stale geofeeds: %w", err)
	}
	defer tx.Rollback(context.Background())

	tag, err := tx.Exec(ctx, pruneStaleGeofeedsSQL, runStarted)
	if err != nil {
		return 0, 0, fmt.Errorf("prune stale geofeeds: %w", err)
	}
	deleted = tag.RowsAffected()

	tag, err = tx.Exec(ctx, markStaleGeofeedTargetsGoneSQL, seenURLs)
	if err != nil {
		return deleted, 0, fmt.Errorf("mark stale geofeed crawl targets gone: %w", err)
	}
	markedGone = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return deleted, markedGone, fmt.Errorf("prune stale geofeeds: %w", err)
	}
	return deleted, markedGone, nil
}
