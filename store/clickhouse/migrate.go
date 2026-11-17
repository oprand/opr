package clickhouse

import (
	"context"
	"embed"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const migrationsDir = "migrations"

// schemaMigrationsTable mirrors golang-migrate's bookkeeping table so swapping
// in the real thing later is mechanical. applied_at is millisecond-resolution
// because the dirty and clean rows for one version are seconds apart at most.
const schemaMigrationsTable = "schema_migrations"

const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations
(
    version    UInt32,
    dirty      UInt8,
    applied_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(applied_at)
ORDER BY version`

// Migration is one numbered file pair under migrations/.
type Migration struct {
	Version uint
	Name    string
	Up      string
	Down    string
}

// Migrations returns the embedded migrations in version order. Versions must be
// unique and gapless from 1, and every up file needs a matching down file.
func Migrations() ([]Migration, error) {
	entries, err := migrationsFS.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("clickhouse migrations: %w", err)
	}
	byVersion := map[uint]*Migration{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version, name, direction, err := ParseMigrationFilename(entry.Name())
		if err != nil {
			return nil, err
		}
		body, err := migrationsFS.ReadFile(path.Join(migrationsDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("clickhouse migrations: %w", err)
		}
		m := byVersion[version]
		if m == nil {
			m = &Migration{Version: version, Name: name}
			byVersion[version] = m
		}
		if m.Name != name {
			return nil, fmt.Errorf("clickhouse migrations: version %d has two names (%s, %s)", version, m.Name, name)
		}
		sql := strings.TrimSpace(string(body))
		switch direction {
		case "up":
			if m.Up != "" {
				return nil, fmt.Errorf("clickhouse migrations: duplicate up file for version %d", version)
			}
			m.Up = sql
		case "down":
			if m.Down != "" {
				return nil, fmt.Errorf("clickhouse migrations: duplicate down file for version %d", version)
			}
			m.Down = sql
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != uint(i+1) {
			return nil, fmt.Errorf("clickhouse migrations: version %d is out of sequence (want %d)", m.Version, i+1)
		}
		if m.Up == "" {
			return nil, fmt.Errorf("clickhouse migrations: version %d has no up file", m.Version)
		}
		if m.Down == "" {
			return nil, fmt.Errorf("clickhouse migrations: version %d has no down file", m.Version)
		}
	}
	return out, nil
}

// ParseMigrationFilename splits the golang-migrate style NNNN_name.up.sql.
func ParseMigrationFilename(filename string) (version uint, name, direction string, err error) {
	rest, ok := strings.CutSuffix(filename, ".sql")
	if !ok {
		return 0, "", "", fmt.Errorf("clickhouse migrations: %s is not a .sql file", filename)
	}
	rest, direction, ok = cutLast(rest, ".")
	if !ok || (direction != "up" && direction != "down") {
		return 0, "", "", fmt.Errorf("clickhouse migrations: %s has no .up/.down suffix", filename)
	}
	digits, name, ok := strings.Cut(rest, "_")
	if !ok || name == "" {
		return 0, "", "", fmt.Errorf("clickhouse migrations: %s is not NNNN_name.%s.sql", filename, direction)
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || n == 0 {
		return 0, "", "", fmt.Errorf("clickhouse migrations: %s has no leading version number", filename)
	}
	return uint(n), name, direction, nil
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// LatestVersion is the schema version a fully migrated ClickHouse reports.
func LatestVersion() uint {
	all, err := Migrations()
	if err != nil || len(all) == 0 {
		return 0
	}
	return all[len(all)-1].Version
}

// SchemaVersion reports the highest applied migration version and whether it is
// marked dirty. A ClickHouse with no schema_migrations table reports 0.
func (c *Client) SchemaVersion(ctx context.Context) (version uint, dirty bool, err error) {
	exists, err := c.Scalar(ctx, "EXISTS TABLE "+schemaMigrationsTable)
	if err != nil {
		return 0, false, fmt.Errorf("clickhouse schema version: %w", err)
	}
	if strings.TrimSpace(exists) != "1" {
		return 0, false, nil
	}
	row, err := c.Scalar(ctx, "SELECT version, dirty FROM "+schemaMigrationsTable+" FINAL ORDER BY version DESC LIMIT 1")
	if err != nil {
		return 0, false, fmt.Errorf("clickhouse schema version: %w", err)
	}
	row = strings.TrimSpace(row)
	if row == "" {
		return 0, false, nil
	}
	rawVersion, rawDirty, ok := strings.Cut(row, "\t")
	if !ok {
		return 0, false, fmt.Errorf("clickhouse schema version: unexpected row %q", row)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(rawVersion), 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("clickhouse schema version: unexpected version %q", rawVersion)
	}
	return uint(n), strings.TrimSpace(rawDirty) == "1", nil
}

// PendingMigrations lists the migrations newer than the applied version.
func (c *Client) PendingMigrations(ctx context.Context) ([]Migration, error) {
	current, dirty, err := c.SchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := pendingFrom(current)
	if err != nil {
		return nil, err
	}
	if dirty {
		return nil, c.dirtyError(current)
	}
	return pending, nil
}

// sqlStatements splits a migration file on semicolons. ClickHouse runs one
// statement per request. A squashed baseline may hold several idempotent
// statements; they run in order. A failure marks the version dirty, and the
// next migrate refuses until that version is deleted, so a retry re-runs the
// file. Statements are IF NOT EXISTS / IF EXISTS, so the re-run is safe.
func sqlStatements(sql string) []string {
	var out []string
	for _, part := range strings.Split(sql, ";") {
		stmt := strings.TrimSpace(part)
		if stmt == "" {
			continue
		}
		out = append(out, stmt)
	}
	return out
}

// Migrate applies every pending migration in version order. ClickHouse has no
// transactional DDL. Each statement must be idempotent so a retry after a
// half-applied migration can succeed on its own.
func (c *Client) Migrate(ctx context.Context, log *zap.Logger) error {
	if log == nil {
		log = zap.NewNop()
	}
	if err := c.Exec(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("clickhouse migrate: schema_migrations: %w", err)
	}
	current, dirty, err := c.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("clickhouse migrate: %w", err)
	}
	pending, err := pendingFrom(current)
	if err != nil {
		return err
	}
	// Dirty is never success: the version was not fully applied, and marking
	// it clean in place would skip it forever. pendingFrom already rejected a
	// database version this binary does not know.
	if dirty {
		return c.dirtyError(current)
	}
	if len(pending) == 0 {
		log.Info("clickhouse already at latest migration version", zap.Uint("version", current))
		return nil
	}

	for _, m := range pending {
		start := time.Now()
		for _, stmt := range sqlStatements(m.Up) {
			if err := c.Exec(ctx, stmt); err != nil {
				if markErr := c.markVersion(ctx, m.Version, true); markErr != nil {
					log.Error("clickhouse could not mark migration dirty",
						zap.Uint("version", m.Version), zap.Error(markErr))
				}
				return fmt.Errorf("clickhouse migrate %04d_%s: %w", m.Version, m.Name, err)
			}
		}
		if err := c.markVersion(ctx, m.Version, false); err != nil {
			return fmt.Errorf("clickhouse migrate %04d_%s: record version: %w", m.Version, m.Name, err)
		}
		log.Info("clickhouse migration applied",
			zap.Uint("version", m.Version),
			zap.String("name", m.Name),
			zap.String("elapsed", time.Since(start).Round(time.Millisecond).String()))
	}
	log.Info("clickhouse migrations applied",
		zap.Int("applied", len(pending)),
		zap.Uint("version", pending[len(pending)-1].Version))
	return nil
}

func (c *Client) markVersion(ctx context.Context, version uint, dirty bool) error {
	flag := 0
	if dirty {
		flag = 1
	}
	return c.Exec(ctx, fmt.Sprintf("INSERT INTO %s (version, dirty) VALUES (%d, %d)",
		schemaMigrationsTable, version, flag))
}

// dirtyError tells the operator the version was not applied. Deleting the row
// makes the next migrate re-run it. Inserting a clean row for the same version
// would record it as applied and skip it forever; ReplacingMergeTree keeps the
// highest version, so a clean insert does not rewind.
func (c *Client) dirtyError(version uint) error {
	database := strings.TrimSpace(c.Database)
	if database == "" {
		database = DefaultDatabase
	}
	return fmt.Errorf("clickhouse migrate: schema_migrations is dirty at version %d; "+
		"this version was not fully applied, so migrate will not continue or report success. "+
		"Inspect the schema, then delete that version so the next migrate re-runs it "+
		"(do not insert a clean row for version %d; that records it as applied and skips it): "+
		"ALTER TABLE %s.%s DELETE WHERE version = %d",
		version, version, database, schemaMigrationsTable, version)
}

func pendingFrom(current uint) ([]Migration, error) {
	all, err := Migrations()
	if err != nil {
		return nil, err
	}
	var latest uint
	if len(all) > 0 {
		latest = all[len(all)-1].Version
	}
	if current > latest {
		return nil, fmt.Errorf("clickhouse migrate: database migration version %d is ahead of this binary (embedded migrations go to %d)",
			current, latest)
	}
	var pending []Migration
	for _, m := range all {
		if m.Version > current {
			pending = append(pending, m)
		}
	}
	return pending, nil
}
