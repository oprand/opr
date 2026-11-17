package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestReplaceAnycastBySourceURLSQLScopedToURL(t *testing.T) {
	t.Parallel()
	stale := strings.ToLower(replaceAnycastDeleteStaleSQL)
	if !strings.Contains(stale, "delete from anycast_prefix") {
		t.Fatal("expected DELETE FROM anycast_prefix")
	}
	if !strings.Contains(stale, "source_url = $1") {
		t.Fatal("replace must filter source_url = $1 so the other dump is kept")
	}
	if !strings.Contains(stale, "anycast_prefix_stg") {
		t.Fatal("stale delete must use the COPY temp set")
	}

	all := strings.ToLower(replaceAnycastDeleteAllSQL)
	if !strings.Contains(all, "delete from anycast_prefix") {
		t.Fatal("empty parse must DELETE FROM anycast_prefix")
	}
	if !strings.Contains(all, "source_url = $1") {
		t.Fatal("empty parse must still scope to source_url")
	}
}

func TestCountAnycastBySourceURLSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(countAnycastBySourceURLSQL)
	if !strings.Contains(sql, "select count(*) from anycast_prefix") {
		t.Fatal("expected SELECT COUNT(*) FROM anycast_prefix")
	}
	if !strings.Contains(sql, "source_url = $1") {
		t.Fatal("count must filter source_url = $1")
	}
}

func TestCountAnycastBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.CountAnycastBySourceURL(context.Background(), ""); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestReplaceAnycastBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.ReplaceAnycastBySourceURL(context.Background(), "", nil); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestAnycastUpsertOnConflictNetblock(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(anycastUpsert.insertSQL())
	if !strings.Contains(sql, "on conflict (netblock)") {
		t.Fatal("expected ON CONFLICT (netblock)")
	}
	dummy := anycastCopyRow(&AnycastPrefix{Netblock: "192.0.2.0/24", SourceURL: AnycastV4DumpURL})
	if len(dummy) != len(anycastUpsert.columns) {
		t.Fatalf("copy row len %d != columns %d", len(dummy), len(anycastUpsert.columns))
	}
}

func TestAnycastStatusByURLSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(anycastStatusByURLSQL)
	if !strings.Contains(sql, "from anycast_prefix") {
		t.Fatal("status clocks count anycast_prefix, not geoip")
	}
	if !strings.Contains(sql, "group by source_url") {
		t.Fatal("expected GROUP BY source_url")
	}
	if !strings.Contains(sql, "max(meta_added_at)") {
		t.Fatal("expected MAX(meta_added_at)")
	}
}

func TestAnycastCopyRowExampleHostNotPointer(t *testing.T) {
	t.Parallel()
	host := "192.0.2.1"
	row := anycastCopyRow(&AnycastPrefix{
		Netblock:    "192.0.2.0/24",
		ExampleHost: &host,
		SourceURL:   AnycastV4DumpURL,
	})
	if len(row) != len(anycastUpsert.columns) {
		t.Fatalf("copy row len %d != columns %d", len(row), len(anycastUpsert.columns))
	}
	got, ok := row[1].(string)
	if !ok {
		t.Fatalf("example_host slot type %T, want string (pgx cannot encode *string → inet)", row[1])
	}
	if got != host {
		t.Fatalf("example_host = %q, want %q", got, host)
	}
}

func TestAnycastCopyRowNilExampleHost(t *testing.T) {
	t.Parallel()
	row := anycastCopyRow(&AnycastPrefix{
		Netblock:  "192.0.2.0/24",
		SourceURL: AnycastV4DumpURL,
	})
	if len(row) != len(anycastUpsert.columns) {
		t.Fatalf("copy row len %d != columns %d", len(row), len(anycastUpsert.columns))
	}
	if row[1] != nil {
		t.Fatalf("nil ExampleHost must COPY as nil (SQL NULL), got %T %v", row[1], row[1])
	}
}

func TestDedupAnycastPrefixesLastWinsPerNetblock(t *testing.T) {
	t.Parallel()
	hostA := "192.0.2.1"
	hostB := "192.0.2.2"
	items := dedupAnycastPrefixes([]*AnycastPrefix{
		{Netblock: "192.0.2.0/24", ExampleHost: &hostA, SourceURL: AnycastV4DumpURL},
		{Netblock: "192.0.2.0/24", ExampleHost: &hostB, SourceURL: AnycastV4DumpURL},
		{Netblock: "198.51.100.0/24", SourceURL: AnycastV4DumpURL},
		{Netblock: "", SourceURL: AnycastV4DumpURL},
		nil,
	})
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	got := map[string]string{}
	for _, it := range items {
		h := ""
		if it.ExampleHost != nil {
			h = *it.ExampleHost
		}
		got[it.Netblock] = h
	}
	if got["192.0.2.0/24"] != hostB {
		t.Fatalf("last-wins host = %q, want %q", got["192.0.2.0/24"], hostB)
	}
}
