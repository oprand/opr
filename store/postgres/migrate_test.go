package postgres

import (
	"net/url"
	"testing"
)

func TestWithMigrationsTableAppendsBookkeepingParam(t *testing.T) {
	t.Parallel()
	in := "postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	got, err := withMigrationsTable(in)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("x-migrations-table") != "opr_migrations" {
		t.Fatalf("x-migrations-table=%q", u.Query().Get("x-migrations-table"))
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Fatalf("sslmode=%q", u.Query().Get("sslmode"))
	}
	if u.Query().Get("x-multi-statement") != "true" {
		t.Fatalf("x-multi-statement=%q", u.Query().Get("x-multi-statement"))
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user != "opr" || pass != "opr" || u.Host != "127.0.0.1:5432" || u.Path != "/opr" {
		t.Fatalf("url rewritten unexpectedly: %s", got)
	}

	already := "postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable&x-migrations-table=custom&x-multi-statement=false"
	got, err = withMigrationsTable(already)
	if err != nil {
		t.Fatal(err)
	}
	u, err = url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("x-migrations-table") != "custom" {
		t.Fatalf("existing table param overwritten: %q", u.Query().Get("x-migrations-table"))
	}
	if u.Query().Get("x-multi-statement") != "false" {
		t.Fatalf("existing multi-statement param overwritten: %q", u.Query().Get("x-multi-statement"))
	}
}

func TestWithMigrationsTableAcceptsPostgresScheme(t *testing.T) {
	t.Parallel()
	in := "postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	got, err := withMigrationsTable(in)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "postgres" {
		t.Fatalf("scheme=%q, want postgres", u.Scheme)
	}
	if u.Query().Get("sslmode") != "disable" || u.Query().Get("x-migrations-table") != "opr_migrations" {
		t.Fatalf("query=%s", u.RawQuery)
	}

	connectDSN, table, err := schemaVersionTarget(in)
	if err != nil {
		t.Fatal(err)
	}
	if table != "opr_migrations" {
		t.Fatalf("table=%q", table)
	}
	u, err = url.Parse(connectDSN)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "postgres" {
		t.Fatalf("connect scheme=%q, want postgres", u.Scheme)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Fatalf("sslmode=%q", u.Query().Get("sslmode"))
	}
}

func TestLatestVersionMatchesEmbeddedMigrations(t *testing.T) {
	t.Parallel()
	if got := LatestVersion(); got != 1 {
		t.Fatalf("LatestVersion=%d, want 1", got)
	}
	for _, name := range []string{"0001_initial.up.sql", "0001_initial.down.sql"} {
		ver, ok := migrationFileVersion(name)
		if !ok || ver != 1 {
			t.Fatalf("%s → %d ok=%t", name, ver, ok)
		}
	}
	if _, ok := migrationFileVersion("README.md"); ok {
		t.Fatal("non-migration name parsed as a version")
	}
}

func TestSchemaVersionTargetStripsMigrateParams(t *testing.T) {
	t.Parallel()
	in := "postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	connectDSN, table, err := schemaVersionTarget(in)
	if err != nil {
		t.Fatal(err)
	}
	if table != "opr_migrations" {
		t.Fatalf("table=%q", table)
	}
	u, err := url.Parse(connectDSN)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Fatalf("sslmode=%q", u.Query().Get("sslmode"))
	}
	if u.Query().Get("x-migrations-table") != "" || u.Query().Get("x-multi-statement") != "" {
		t.Fatalf("migrate params leaked into connect dsn: %s", connectDSN)
	}

	custom := in + "&x-migrations-table=custom&x-multi-statement=true"
	connectDSN, table, err = schemaVersionTarget(custom)
	if err != nil {
		t.Fatal(err)
	}
	if table != "custom" {
		t.Fatalf("table=%q", table)
	}
	u, err = url.Parse(connectDSN)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("x-migrations-table") != "" || u.Query().Get("x-multi-statement") != "" {
		t.Fatalf("migrate params leaked into connect dsn: %s", connectDSN)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Fatalf("sslmode=%q", u.Query().Get("sslmode"))
	}
}
