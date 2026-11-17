package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsTable is opr's bookkeeping table. The private web/API project
// keeps using schema_migrations, so the two trees can share one Postgres
// without stepping on each other's version rows.
const migrationsTable = "opr_migrations"

func RunMigrations(migrationLogger *zap.Logger, connDSN string) error {
	dsn, err := withMigrationsTable(connDSN)
	if err != nil {
		migrationLogger.Error("can't parse migration dsn", zap.Error(err))
		return err
	}

	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		migrationLogger.Error("can't create new driver from FS for embeding database migration", zap.Error(err))
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", d, dsn)

	if err != nil {
		migrationLogger.Error("can't migrate to latest schema update", zap.Error(err))
		return err
	}

	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		migrationLogger.Error("failed to migrate up to new version", zap.Error(err))
		return err
	}
	appliedNewMigrations := err == nil

	version, dirty, err := m.Version()
	if err != nil {
		migrationLogger.Error("can't return new database migration version", zap.Error(err), zap.Uint("version", version))
		return err
	}

	if appliedNewMigrations {
		migrationLogger.Info(fmt.Sprintf("applied new migrations successfully; using database schema version %d", version))
	} else {
		migrationLogger.Info(fmt.Sprintf("already at latest migration version; using database schema version %d", version))
	}
	if dirty {
		migrationLogger.Warn("database migration is marked dirty")
	}

	errSource, errDatabase := m.Close()
	if errSource != nil {
		migrationLogger.Error("can't close migration database connection", zap.Error(errSource))
	}
	if errDatabase != nil {
		migrationLogger.Error("can't close migration database connection", zap.Error(errDatabase))
	}

	return nil
}

// LatestVersion is the schema version a fully migrated Postgres reports.
func LatestVersion() uint {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return 0
	}
	var latest uint
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version, ok := migrationFileVersion(entry.Name())
		if ok && version > latest {
			latest = version
		}
	}
	return latest
}

// SchemaVersion reports the applied opr_migrations version and dirty flag.
// It does not migrate and does not create the bookkeeping table. A database
// with no opr_migrations table (or an empty one) reports version 0.
func SchemaVersion(ctx context.Context, connDSN string) (version uint, dirty bool, err error) {
	connectDSN, table, err := schemaVersionTarget(connDSN)
	if err != nil {
		return 0, false, err
	}
	conn, err := pgx.Connect(ctx, connectDSN)
	if err != nil {
		return 0, false, fmt.Errorf("postgres schema version: %w", err)
	}
	defer conn.Close(context.Background())

	query := `SELECT version, dirty FROM ` + pgx.Identifier{table}.Sanitize() + ` LIMIT 1`
	var v int64
	err = conn.QueryRow(ctx, query).Scan(&v, &dirty)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UndefinedTable {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("postgres schema version: %w", err)
	}
	if v < 0 {
		return 0, dirty, nil
	}
	return uint(v), dirty, nil
}

// schemaVersionTarget splits a postgres URL into a driver DSN and the
// bookkeeping table. golang-migrate's x-* query params are not libpq settings;
// they stay off the connection string. An explicit x-migrations-table wins,
// matching withMigrationsTable.
func schemaVersionTarget(dsn string) (connectDSN, table string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", fmt.Errorf("postgres schema version: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", "", fmt.Errorf("postgres schema version: want a postgres URL, got %q", u.Scheme)
	}
	q := u.Query()
	table = q.Get("x-migrations-table")
	if table == "" {
		table = migrationsTable
	}
	for key := range q {
		if strings.HasPrefix(key, "x-") {
			q.Del(key)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), table, nil
}

// migrationFileVersion reads the leading version from a golang-migrate
// filename such as 0001_initial.up.sql.
func migrationFileVersion(filename string) (uint, bool) {
	if !strings.HasSuffix(filename, ".sql") {
		return 0, false
	}
	stem := strings.TrimSuffix(filename, ".sql")
	dot := strings.LastIndex(stem, ".")
	if dot <= 0 {
		return 0, false
	}
	switch stem[dot+1:] {
	case "up", "down":
	default:
		return 0, false
	}
	rest := stem[:dot]
	under := strings.IndexByte(rest, '_')
	if under <= 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(rest[:under], 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}

// withMigrationsTable points golang-migrate at opr_migrations and turns on
// multi-statement mode. The squashed baseline is one file of many
// statements, and the lib/pq driver behind golang-migrate rejects that
// unless x-multi-statement is set. Callers pass the plain DSN.
func withMigrationsTable(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("migration dsn: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", fmt.Errorf("migration dsn: want a postgres URL, got %q", u.Scheme)
	}
	q := u.Query()
	if q.Get("x-migrations-table") == "" {
		q.Set("x-migrations-table", migrationsTable)
	}
	if q.Get("x-multi-statement") == "" {
		q.Set("x-multi-statement", "true")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
