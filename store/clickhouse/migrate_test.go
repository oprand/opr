package clickhouse

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEmbeddedMigrationFilenamesAreUniqueAndGapless(t *testing.T) {
	t.Parallel()
	entries, err := migrationsFS.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded migrations")
	}
	ups := map[uint]string{}
	downs := map[uint]string{}
	for _, entry := range entries {
		version, name, direction, err := ParseMigrationFilename(entry.Name())
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		seen := ups
		if direction == "down" {
			seen = downs
		}
		if prev, dup := seen[version]; dup {
			t.Fatalf("version %d has two %s files (%s, %s)", version, direction, prev, name)
		}
		seen[version] = name
	}
	for v := uint(1); v <= uint(len(ups)); v++ {
		if _, ok := ups[v]; !ok {
			t.Fatalf("version %d is missing; the sequence must be gapless from 1", v)
		}
		if ups[v] != downs[v] {
			t.Fatalf("version %d up/down names differ: %q vs %q", v, ups[v], downs[v])
		}
	}
	if len(downs) != len(ups) {
		t.Fatalf("%d up files but %d down files", len(ups), len(downs))
	}
	if got := LatestVersion(); got != uint(len(ups)) {
		t.Fatalf("LatestVersion=%d, want %d", got, len(ups))
	}
}

func TestMigrationsAreSingleIdempotentStatements(t *testing.T) {
	t.Parallel()
	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		up := sqlStatements(m.Up)
		down := sqlStatements(m.Down)
		if len(up) == 0 || len(down) == 0 {
			t.Errorf("%04d_%s: up and down must each contain a statement", m.Version, m.Name)
		}
		for _, sql := range append(append([]string{}, up...), down...) {
			if strings.Contains(sql, "ON CLUSTER") {
				t.Errorf("%04d_%s: single node, no ON CLUSTER", m.Version, m.Name)
			}
			if strings.Contains(sql, "ALTER TABLE") && (strings.Contains(sql, " UPDATE ") || strings.Contains(sql, " DELETE ")) {
				t.Errorf("%04d_%s: mutations must not run in a migration", m.Version, m.Name)
			}
		}
		for _, sql := range up {
			if !strings.Contains(sql, "IF NOT EXISTS") {
				t.Errorf("%04d_%s: up must be idempotent:\n%s", m.Version, m.Name, sql)
			}
		}
		for _, sql := range down {
			if !strings.Contains(sql, "IF EXISTS") {
				t.Errorf("%04d_%s: down must be idempotent:\n%s", m.Version, m.Name, sql)
			}
		}
	}
}

func TestMigrateAppliesPendingInVersionOrder(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	if err := fake.client().Migrate(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, m := range all {
		want = append(want, sqlStatements(m.Up)...)
	}
	applied := fake.applied()
	if len(applied) != len(want) {
		t.Fatalf("applied %d statements, want %d", len(applied), len(want))
	}
	for i := range want {
		if applied[i] != want[i] {
			t.Fatalf("statement %d:\n got: %s\nwant: %s", i, applied[i], want[i])
		}
	}
	version, dirty, err := fake.client().SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != LatestVersion() || dirty {
		t.Fatalf("version=%d dirty=%v, want %d clean", version, dirty, LatestVersion())
	}
}

func TestMigrateRerunIsNoOp(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	c := fake.client()
	if err := c.Migrate(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	first := len(fake.applied())
	if err := c.Migrate(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.applied()); got != first {
		t.Fatalf("second Migrate applied %d more statements", got-first)
	}
	pending, err := c.PendingMigrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending=%d after a full run", len(pending))
	}
}

func TestMigrateFailureMarksDirtyAndNextRunRefuses(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	fake.failOn = func(query string) error {
		if strings.Contains(query, "fdns_cc_host_load") {
			return fmt.Errorf("Code: 57. DB::Exception: table already exists")
		}
		return nil
	}
	c := fake.client()
	err := c.Migrate(context.Background(), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "0001_initial") {
		t.Fatalf("err=%v, want the failing migration named", err)
	}
	version, dirty, err := c.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || !dirty {
		t.Fatalf("version=%d dirty=%v, want 1 dirty", version, dirty)
	}

	fake.failOn = nil
	err = c.Migrate(context.Background(), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("err=%v, want a refusal while dirty", err)
	}
	if !strings.Contains(err.Error(), "ALTER TABLE netlib.schema_migrations DELETE WHERE version = 1") {
		t.Fatalf("err=%v, want the re-run recovery statement spelled out", err)
	}
	if strings.Contains(err.Error(), "VALUES (1, 0)") {
		t.Fatalf("err=%v, recovery must not mark the dirty version clean; that skips it", err)
	}
	if got := len(fake.applied()); got != 1 {
		t.Fatalf("dirty retry applied %d statements, want only the one that succeeded before the failure", got)
	}
	if _, err := c.PendingMigrations(context.Background()); err == nil {
		t.Fatal("PendingMigrations must also refuse while dirty")
	}
}

func TestMigrateAtLatestAppliesNothing(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	fake.hasTable = true
	fake.setVersion(LatestVersion(), false)

	c := fake.client()
	pending, err := c.PendingMigrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending=%+v, want none at the latest version", pending)
	}
	if err := c.Migrate(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.applied()); got != 0 {
		t.Fatalf("applied %d statements, want 0", got)
	}
}

func TestMigrateDirtyIsNotSuccess(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	fake.hasTable = true
	fake.setVersion(1, true)

	err := fake.client().Migrate(context.Background(), zap.NewNop())
	if err == nil {
		t.Fatal("a dirty schema must not report migrate success")
	}
	if !strings.Contains(err.Error(), "dirty at version 1") || !strings.Contains(err.Error(), "will not continue") {
		t.Fatalf("err=%v, want a dirty-version error", err)
	}
	if len(fake.applied()) != 0 {
		t.Fatalf("dirty migrate applied %v", fake.applied())
	}
}

func TestMigrateRefusesDatabaseAheadOfBinary(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	fake.hasTable = true
	fake.setVersion(LatestVersion()+5, false)

	c := fake.client()
	err := c.Migrate(context.Background(), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "ahead of this binary") {
		t.Fatalf("err=%v, want database version ahead of the binary", err)
	}
	if len(fake.applied()) != 0 {
		t.Fatalf("ahead migrate applied %v", fake.applied())
	}
	if _, err := c.PendingMigrations(context.Background()); err == nil || !strings.Contains(err.Error(), "ahead of this binary") {
		t.Fatalf("PendingMigrations err=%v, want the same ahead error", err)
	}
}

func TestSchemaVersionWithoutTableIsZero(t *testing.T) {
	t.Parallel()
	fake := newFakeClickHouse(t)
	version, dirty, err := fake.client().SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 || dirty {
		t.Fatalf("version=%d dirty=%v on a fresh server", version, dirty)
	}
}

func TestParseMigrationFilenameRejectsJunk(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"0001_fdns_cc_host.sql",
		"fdns_cc_host.up.sql",
		"0001_fdns_cc_host.up.txt",
		"0000_zero.up.sql",
		"0001.up.sql",
		"0001_x.sideways.sql",
	} {
		if _, _, _, err := ParseMigrationFilename(name); err == nil {
			t.Errorf("%s must not parse", name)
		}
	}
	version, label, direction, err := ParseMigrationFilename("0042_fdns_cc_host.down.sql")
	if err != nil || version != 42 || label != "fdns_cc_host" || direction != "down" {
		t.Fatalf("version=%d label=%q direction=%q err=%v", version, label, direction, err)
	}
}

// fakeClickHouse answers just enough of the HTTP interface to drive the
// migration runner: EXISTS TABLE, the schema_migrations read and write, and
// whatever DDL a migration sends.
type fakeClickHouse struct {
	srv      *httptest.Server
	mu       sync.Mutex
	ddl      []string
	version  uint
	dirty    bool
	recorded bool
	hasTable bool
	failOn   func(query string) error
}

func newFakeClickHouse(t *testing.T) *fakeClickHouse {
	t.Helper()
	f := &fakeClickHouse{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClickHouse) client() *Client {
	c := New(f.srv.URL, "netlib", "", "", 10*time.Second)
	return c
}

func (f *fakeClickHouse) applied() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ddl...)
}

func (f *fakeClickHouse) setVersion(version uint, dirty bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.dirty, f.recorded = version, dirty, true
}

func (f *fakeClickHouse) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	query := strings.TrimSpace(string(body))
	if query == "" {
		query = r.URL.Query().Get("query")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasPrefix(query, "EXISTS TABLE schema_migrations"):
		if f.hasTable {
			_, _ = io.WriteString(w, "1\n")
			return
		}
		_, _ = io.WriteString(w, "0\n")
	case strings.HasPrefix(query, "SELECT version, dirty FROM schema_migrations"):
		if !f.recorded {
			return
		}
		dirty := 0
		if f.dirty {
			dirty = 1
		}
		fmt.Fprintf(w, "%d\t%d\n", f.version, dirty)
	case strings.HasPrefix(query, "CREATE TABLE IF NOT EXISTS schema_migrations"):
		f.hasTable = true
	case strings.HasPrefix(query, "INSERT INTO schema_migrations"):
		var version, dirty uint
		if _, err := fmt.Sscanf(query[strings.Index(query, "VALUES"):], "VALUES (%d, %d)", &version, &dirty); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "Code: 62. DB::Exception: cannot parse "+query)
			return
		}
		f.version, f.dirty, f.recorded = version, dirty == 1, true
	default:
		if f.failOn != nil {
			if err := f.failOn(query); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, err.Error())
				return
			}
		}
		f.ddl = append(f.ddl, query)
	}
}
