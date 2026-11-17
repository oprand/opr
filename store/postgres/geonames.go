package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

type geoNamesSwapIndex struct {
	stgName   string
	canonical string
	createSQL string
}

type geoNamesSwapSpec struct {
	live       string
	columns    []string
	pkSQL      string // ALTER TABLE %s ADD CONSTRAINT ... ; empty to skip
	pkStgName  string
	pkLiveName string
	sequence   string // e.g. geonames_postal_id_seq; empty if none
	indexes    []geoNamesSwapIndex
	afterCopy  []string // SQL with %s = staging table name
}

func (st *Store) copyReplaceGeoNames(ctx context.Context, spec geoNamesSwapSpec, n int, rowFn func(int) ([]any, error)) (int64, error) {
	if n == 0 {
		return 0, fmt.Errorf("copy replace %s: no rows", spec.live)
	}
	src := pgx.CopyFromSlice(n, rowFn)
	return st.copyReplaceGeoNamesSrc(ctx, spec, src)
}

func (st *Store) copyReplaceGeoNamesSrc(ctx context.Context, spec geoNamesSwapSpec, src pgx.CopyFromSource) (int64, error) {
	stg := spec.live + "_new"
	if _, err := st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg); err != nil {
		return 0, fmt.Errorf("drop stale %s: %w", stg, err)
	}
	create := fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS INCLUDING COMMENTS)", stg, spec.live)
	if _, err := st.DB.Exec(ctx, create); err != nil {
		return 0, fmt.Errorf("create %s: %w", stg, err)
	}

	copied, err := st.DB.CopyFrom(ctx, pgx.Identifier{stg}, spec.columns, src)
	if err != nil {
		_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return 0, fmt.Errorf("copy %s: %w", stg, err)
	}
	if copied == 0 {
		_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return 0, fmt.Errorf("copy replace %s: no rows copied", spec.live)
	}

	for _, sql := range spec.afterCopy {
		stmt := fmt.Sprintf(sql, stg)
		if _, err := st.DB.Exec(ctx, stmt); err != nil {
			_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
			return 0, fmt.Errorf("after-copy %s: %w", stg, err)
		}
	}

	if spec.pkSQL != "" {
		if _, err := st.DB.Exec(ctx, fmt.Sprintf(spec.pkSQL, stg)); err != nil {
			_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
			return 0, fmt.Errorf("add pk on %s: %w", stg, err)
		}
	}
	for _, idx := range spec.indexes {
		if _, err := st.DB.Exec(ctx, idx.createSQL); err != nil {
			_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
			return 0, fmt.Errorf("create index %s: %w", idx.stgName, err)
		}
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())

	old := spec.live + "_old"
	swapStmts := []string{
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", spec.live, old),
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", stg, spec.live),
	}
	if spec.sequence != "" {
		swapStmts = append(swapStmts,
			fmt.Sprintf("ALTER SEQUENCE %s OWNED BY %s.id", spec.sequence, spec.live),
		)
	}
	swapStmts = append(swapStmts, fmt.Sprintf("DROP TABLE %s", old))
	if spec.pkStgName != "" && spec.pkLiveName != "" {
		swapStmts = append(swapStmts,
			fmt.Sprintf("ALTER INDEX %s RENAME TO %s", spec.pkStgName, spec.pkLiveName),
		)
	}
	for _, s := range swapStmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return 0, fmt.Errorf("swap %s (%q): %w", spec.live, s, err)
		}
	}
	for _, idx := range spec.indexes {
		stmt := fmt.Sprintf("ALTER INDEX %s RENAME TO %s", idx.stgName, idx.canonical)
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return 0, fmt.Errorf("rename index %s -> %s: %w", idx.stgName, idx.canonical, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	st.logger.Info("replaced geonames table via copy-swap",
		zap.String("table", spec.live),
		zap.Int64("rows", copied))
	return copied, nil
}

func (st *Store) execSQLStatements(ctx context.Context, sql string) error {
	for _, stmt := range strings.Split(sql, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := st.DB.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

var geoNamesCitySwap = geoNamesSwapSpec{
	live: "geonames_city",
	columns: []string{
		"geonameid", "name", "ascii_name", "latitude", "longitude",
		"feature_class", "feature_code", "country_code", "cc2",
		"admin1_code", "admin2_code", "admin3_code", "admin4_code",
		"population", "elevation", "dem", "timezone", "modification_date",
		"alternate_names",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_city_new_pkey PRIMARY KEY (geonameid)",
	pkStgName:  "geonames_city_new_pkey",
	pkLiveName: "geonames_city_pkey",
	afterCopy: []string{
		`UPDATE %s SET
			city_norm = unaccent(lower(trim(name))),
			ascii_norm = NULLIF(unaccent(lower(trim(COALESCE(ascii_name, '')))), '')`,
	},
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_city_cc_norm_admin1_stg", "idx_geonames_city_cc_norm_admin1",
			"CREATE INDEX idx_geonames_city_cc_norm_admin1_stg ON geonames_city_new (country_code, city_norm, admin1_code)",
		},
	},
}

var geoNamesPostalSwap = geoNamesSwapSpec{
	live: "geonames_postal",
	columns: []string{
		"country_code", "postal_code", "place_name",
		"admin_name_1", "admin_code_1", "admin_name_2", "admin_code_2",
		"admin_name_3", "admin_code_3", "latitude", "longitude", "accuracy",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_postal_new_pkey PRIMARY KEY (id)",
	pkStgName:  "geonames_postal_new_pkey",
	pkLiveName: "geonames_postal_pkey",
	sequence:   "geonames_postal_id_seq",
	afterCopy: []string{
		`UPDATE %s SET city_norm = unaccent(lower(trim(place_name)))`,
	},
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_postal_cc_zip_stg", "idx_geonames_postal_cc_zip",
			"CREATE INDEX idx_geonames_postal_cc_zip_stg ON geonames_postal_new (country_code, postal_code)",
		},
		{
			"idx_geonames_postal_cc_norm_admin1_stg", "idx_geonames_postal_cc_norm_admin1",
			"CREATE INDEX idx_geonames_postal_cc_norm_admin1_stg ON geonames_postal_new (country_code, city_norm, admin_code_1)",
		},
	},
}

var geoNamesAdmin1Swap = geoNamesSwapSpec{
	live: "geonames_admin1",
	columns: []string{
		"code", "country_code", "admin1_code", "name", "ascii_name", "geonameid",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_admin1_new_pkey PRIMARY KEY (code)",
	pkStgName:  "geonames_admin1_new_pkey",
	pkLiveName: "geonames_admin1_pkey",
	afterCopy: []string{
		`UPDATE %s SET name_norm = unaccent(lower(trim(name)))`,
	},
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_admin1_cc_code_stg", "idx_geonames_admin1_cc_code",
			"CREATE INDEX idx_geonames_admin1_cc_code_stg ON geonames_admin1_new (country_code, admin1_code)",
		},
	},
}

var geoNamesAdmin2Swap = geoNamesSwapSpec{
	live: "geonames_admin2",
	columns: []string{
		"code", "country_code", "admin1_code", "admin2_code", "name", "ascii_name", "geonameid",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_admin2_new_pkey PRIMARY KEY (code)",
	pkStgName:  "geonames_admin2_new_pkey",
	pkLiveName: "geonames_admin2_pkey",
	afterCopy: []string{
		`UPDATE %s SET name_norm = unaccent(lower(trim(name)))`,
	},
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_admin2_cc_codes_stg", "idx_geonames_admin2_cc_codes",
			"CREATE INDEX idx_geonames_admin2_cc_codes_stg ON geonames_admin2_new (country_code, admin1_code, admin2_code)",
		},
	},
}

var geoNamesTimezoneSwap = geoNamesSwapSpec{
	live: "geonames_timezone",
	columns: []string{
		"timezone_id", "country_code", "gmt_offset", "dst_offset", "raw_offset",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_timezone_new_pkey PRIMARY KEY (timezone_id)",
	pkStgName:  "geonames_timezone_new_pkey",
	pkLiveName: "geonames_timezone_pkey",
}

var geoNamesAltNameSwap = geoNamesSwapSpec{
	live: "geonames_altname",
	columns: []string{
		"altname_id", "geonameid", "isolanguage", "alternate_name",
		"is_preferred", "is_short", "is_colloquial", "is_historic",
	},
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_altname_new_pkey PRIMARY KEY (altname_id)",
	pkStgName:  "geonames_altname_new_pkey",
	pkLiveName: "geonames_altname_pkey",
	afterCopy: []string{
		`UPDATE %s SET alias_norm = unaccent(lower(trim(alternate_name)))`,
	},
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_altname_geonameid_stg", "idx_geonames_altname_geonameid",
			"CREATE INDEX idx_geonames_altname_geonameid_stg ON geonames_altname_new (geonameid)",
		},
	},
}

func (st *Store) ReplaceGeoNamesCities(ctx context.Context, rows [][]any) (int64, error) {
	return st.copyReplaceGeoNames(ctx, geoNamesCitySwap, len(rows), func(i int) ([]any, error) {
		return rows[i], nil
	})
}

func (st *Store) ReplaceGeoNamesPostal(ctx context.Context, src pgx.CopyFromSource) (int64, error) {
	return st.copyReplaceGeoNamesSrc(ctx, geoNamesPostalSwap, src)
}

func (st *Store) ReplaceGeoNamesAdmin1(ctx context.Context, rows [][]any) (int64, error) {
	return st.copyReplaceGeoNames(ctx, geoNamesAdmin1Swap, len(rows), func(i int) ([]any, error) {
		return rows[i], nil
	})
}

func (st *Store) ReplaceGeoNamesAdmin2(ctx context.Context, rows [][]any) (int64, error) {
	return st.copyReplaceGeoNames(ctx, geoNamesAdmin2Swap, len(rows), func(i int) ([]any, error) {
		return rows[i], nil
	})
}

func (st *Store) ReplaceGeoNamesTimezones(ctx context.Context, rows [][]any) (int64, error) {
	return st.copyReplaceGeoNames(ctx, geoNamesTimezoneSwap, len(rows), func(i int) ([]any, error) {
		return rows[i], nil
	})
}

func (st *Store) ReplaceGeoNamesAltNames(ctx context.Context, src pgx.CopyFromSource) (int64, error) {
	return st.copyReplaceGeoNamesSrc(ctx, geoNamesAltNameSwap, src)
}

// GeoNamesAltNameTargetIDs is cities500 plus country_info.geoname_id (country
// features / "capitals" in the dump header). Used to filter alternateNames.
func (st *Store) GeoNamesAltNameTargetIDs(ctx context.Context) (map[int64]struct{}, error) {
	rows, err := st.DB.Query(ctx, `
		SELECT geonameid FROM geonames_city
		UNION
		SELECT geoname_id::bigint FROM country_info WHERE geoname_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]struct{}, 250_000)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// RebuildGeoNamesLookupSQL is the ingest-time key expansion. Tested as a
// string so we do not need a live database in unit tests.
const RebuildGeoNamesLookupSQL = `
INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (c.country_code, c.city_norm, COALESCE(c.admin1_code, ''))
	c.country_code,
	NULLIF(c.admin1_code, ''),
	c.city_norm,
	NULL,
	NULL,
	c.geonameid,
	c.latitude,
	c.longitude,
	c.timezone,
	c.population,
	NULL,
	a.name,
	CASE WHEN c.feature_code = 'PPLC' THEN 'capital' ELSE 'city' END
FROM geonames_city c
LEFT JOIN geonames_admin1 a
	ON a.country_code = c.country_code AND a.admin1_code = c.admin1_code
WHERE c.city_norm <> ''
ORDER BY c.country_code, c.city_norm, COALESCE(c.admin1_code, ''), c.population DESC NULLS LAST;

INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (c.country_code, c.ascii_norm, COALESCE(c.admin1_code, ''))
	c.country_code,
	NULLIF(c.admin1_code, ''),
	NULL,
	NULL,
	c.ascii_norm,
	c.geonameid,
	c.latitude,
	c.longitude,
	c.timezone,
	c.population,
	NULL,
	a.name,
	'alias'
FROM geonames_city c
LEFT JOIN geonames_admin1 a
	ON a.country_code = c.country_code AND a.admin1_code = c.admin1_code
WHERE c.ascii_norm IS NOT NULL AND c.ascii_norm <> '' AND c.ascii_norm IS DISTINCT FROM c.city_norm
ORDER BY c.country_code, c.ascii_norm, COALESCE(c.admin1_code, ''), c.population DESC NULLS LAST;

INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (c.country_code, n.alias_norm, COALESCE(c.admin1_code, ''))
	c.country_code,
	NULLIF(c.admin1_code, ''),
	NULL,
	NULL,
	n.alias_norm,
	c.geonameid,
	c.latitude,
	c.longitude,
	c.timezone,
	c.population,
	NULL,
	a.name,
	'alias'
FROM geonames_altname n
JOIN geonames_city c ON c.geonameid = n.geonameid
LEFT JOIN geonames_admin1 a
	ON a.country_code = c.country_code AND a.admin1_code = c.admin1_code
WHERE n.alias_norm <> '' AND n.alias_norm IS DISTINCT FROM c.city_norm
ORDER BY c.country_code, n.alias_norm, COALESCE(c.admin1_code, ''),
	n.is_preferred DESC NULLS LAST, c.population DESC NULLS LAST;

INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (a.country_code, a.name_norm, COALESCE(a.admin1_code, ''))
	a.country_code,
	NULLIF(a.admin1_code, ''),
	NULL,
	NULL,
	a.name_norm,
	c.geonameid,
	c.latitude,
	c.longitude,
	c.timezone,
	c.population,
	NULL,
	a.name,
	'admin'
FROM geonames_admin1 a
JOIN geonames_city c
	ON c.country_code = a.country_code AND c.admin1_code = a.admin1_code
WHERE a.name_norm <> ''
ORDER BY a.country_code, a.name_norm, COALESCE(a.admin1_code, ''), c.population DESC NULLS LAST;

INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (p.country_code, p.postal_code)
	p.country_code,
	COALESCE(NULLIF(c.admin1_code, ''), NULLIF(p.admin_code_1, '')),
	COALESCE(c.city_norm, p.city_norm),
	p.postal_code,
	NULL,
	c.geonameid,
	COALESCE(c.latitude, p.latitude),
	COALESCE(c.longitude, p.longitude),
	c.timezone,
	c.population,
	p.postal_code,
	COALESCE(a.name, p.admin_name_1),
	'zip'
FROM geonames_postal p
LEFT JOIN geonames_city c
	ON c.country_code = p.country_code
	AND c.city_norm = p.city_norm
	AND c.admin1_code IS NOT DISTINCT FROM NULLIF(p.admin_code_1, '')
LEFT JOIN geonames_admin1 a
	ON a.country_code = p.country_code AND a.admin1_code = COALESCE(c.admin1_code, p.admin_code_1)
WHERE p.postal_code <> ''
ORDER BY p.country_code, p.postal_code, p.accuracy DESC NULLS LAST, c.population DESC NULLS LAST;

INSERT INTO geonames_lookup_new (
	country_code, admin1_iso, city_norm, zipcode, alias_norm,
	geonameid, lat, lon, timezone, population, zip_for_display, admin_name_1, match_kind
)
SELECT DISTINCT ON (p.country_code, p.city_norm, COALESCE(p.admin_code_1, ''))
	p.country_code,
	NULLIF(p.admin_code_1, ''),
	p.city_norm,
	NULL,
	NULL,
	c.geonameid,
	COALESCE(c.latitude, p.latitude),
	COALESCE(c.longitude, p.longitude),
	c.timezone,
	c.population,
	NULL,
	COALESCE(a.name, p.admin_name_1),
	'city'
FROM geonames_postal p
LEFT JOIN geonames_city c
	ON c.country_code = p.country_code
	AND c.city_norm = p.city_norm
	AND c.admin1_code IS NOT DISTINCT FROM NULLIF(p.admin_code_1, '')
LEFT JOIN geonames_admin1 a
	ON a.country_code = p.country_code AND a.admin1_code = COALESCE(c.admin1_code, p.admin_code_1)
WHERE p.city_norm <> ''
	AND NOT EXISTS (
		SELECT 1 FROM geonames_lookup_new l
		WHERE l.country_code = p.country_code
			AND l.city_norm = p.city_norm
			AND l.admin1_iso IS NOT DISTINCT FROM NULLIF(p.admin_code_1, '')
			AND l.zipcode IS NULL
			AND l.alias_norm IS NULL
	)
ORDER BY p.country_code, p.city_norm, COALESCE(p.admin_code_1, ''), p.accuracy DESC NULLS LAST;
`

var geoNamesLookupSwap = geoNamesSwapSpec{
	live:       "geonames_lookup",
	sequence:   "geonames_lookup_id_seq",
	pkSQL:      "ALTER TABLE %s ADD CONSTRAINT geonames_lookup_new_pkey PRIMARY KEY (id)",
	pkStgName:  "geonames_lookup_new_pkey",
	pkLiveName: "geonames_lookup_pkey",
	indexes: []geoNamesSwapIndex{
		{
			"idx_geonames_lookup_cc_zip_stg", "idx_geonames_lookup_cc_zip",
			"CREATE INDEX idx_geonames_lookup_cc_zip_stg ON geonames_lookup_new (country_code, zipcode) WHERE zipcode IS NOT NULL",
		},
		{
			"idx_geonames_lookup_cc_city_admin1_stg", "idx_geonames_lookup_cc_city_admin1",
			"CREATE INDEX idx_geonames_lookup_cc_city_admin1_stg ON geonames_lookup_new (country_code, city_norm, admin1_iso)",
		},
		{
			"idx_geonames_lookup_cc_alias_admin1_stg", "idx_geonames_lookup_cc_alias_admin1",
			"CREATE INDEX idx_geonames_lookup_cc_alias_admin1_stg ON geonames_lookup_new (country_code, alias_norm, admin1_iso)",
		},
	},
}

// RebuildGeoNamesLookup replaces geonames_lookup from the split dump tables.
func (st *Store) RebuildGeoNamesLookup(ctx context.Context) error {
	start := time.Now()
	stg := "geonames_lookup_new"
	if _, err := st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg); err != nil {
		return fmt.Errorf("drop stale %s: %w", stg, err)
	}
	if _, err := st.DB.Exec(ctx, "CREATE TABLE "+stg+" (LIKE geonames_lookup INCLUDING DEFAULTS INCLUDING COMMENTS)"); err != nil {
		return fmt.Errorf("create %s: %w", stg, err)
	}
	if err := st.execSQLStatements(ctx, RebuildGeoNamesLookupSQL); err != nil {
		_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return fmt.Errorf("rebuild geonames_lookup: %w", err)
	}

	spec := geoNamesLookupSwap
	if spec.pkSQL != "" {
		if _, err := st.DB.Exec(ctx, fmt.Sprintf(spec.pkSQL, stg)); err != nil {
			_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
			return fmt.Errorf("add pk on %s: %w", stg, err)
		}
	}
	for _, idx := range spec.indexes {
		if _, err := st.DB.Exec(ctx, idx.createSQL); err != nil {
			_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
			return fmt.Errorf("create index %s: %w", idx.stgName, err)
		}
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	old := "geonames_lookup_old"
	swapStmts := []string{
		"ALTER TABLE geonames_lookup RENAME TO " + old,
		"ALTER TABLE " + stg + " RENAME TO geonames_lookup",
		"ALTER SEQUENCE geonames_lookup_id_seq OWNED BY geonames_lookup.id",
		"DROP TABLE " + old,
		"ALTER INDEX geonames_lookup_new_pkey RENAME TO geonames_lookup_pkey",
	}
	for _, s := range swapStmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("swap geonames_lookup (%q): %w", s, err)
		}
	}
	for _, idx := range spec.indexes {
		stmt := fmt.Sprintf("ALTER INDEX %s RENAME TO %s", idx.stgName, idx.canonical)
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("rename index %s -> %s: %w", idx.stgName, idx.canonical, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	st.logger.Info("rebuilt geonames_lookup", zap.Duration("duration", time.Since(start)))
	return nil
}
