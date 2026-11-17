package fdns

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

	"github.com/oprand/opr/store/clickhouse"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestSeedFilterSQLKeyOrderAndFilters(t *testing.T) {
	t.Parallel()
	sql, err := (SeedFilter{
		MinFetch200: 10,
		MinHCRank10: 0.5,
		MinPRank10:  0.25,
		TLDs:        []string{"com", "uk", "com"},
		Crawl:       "CC-MAIN-2025-18",
		Limit:       100,
		Order:       "key",
		CursorTLD:   "com",
		CursorHost:  "example.com",
	}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SELECT url_host_tld, host_name FROM " + CCHostTable,
		"fetch_200 >= 10",
		"hcrank10 >= 0.5",
		"prank10 >= 0.25",
		"crawl = " + clickhouse.QuoteString("CC-MAIN-2025-18"),
		"url_host_tld IN (" + clickhouse.QuoteString("com") + ", " + clickhouse.QuoteString("uk") + ")",
		"(url_host_tld, host_name) > (" + clickhouse.QuoteString("com") + ", " + clickhouse.QuoteString("example.com") + ")",
		"ORDER BY url_host_tld, host_name",
		"LIMIT 100",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "hcrank10 DESC") {
		t.Fatal("--order key must not sort by rank")
	}
	if strings.Contains(sql, "FORMAT") {
		t.Fatal("QueryTSV sets FORMAT; the SELECT must not")
	}
	if strings.Contains(sql, "CC-MAIN-2025-18") && !strings.Contains(sql, clickhouse.QuoteString("CC-MAIN-2025-18")) {
		t.Fatal("crawl must be QuoteString-quoted")
	}
}

func TestSeedFilterSQLRankOrderNoCursor(t *testing.T) {
	t.Parallel()
	sql, err := (SeedFilter{
		Limit:      50,
		Order:      "rank",
		CursorTLD:  "com",
		CursorHost: "example.com",
	}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "SELECT url_host_tld, host_name, hcrank10, prank10 FROM "+CCHostTable) {
		t.Fatalf("rank order must project rank cols:\n%s", sql)
	}
	if !strings.Contains(sql, "ORDER BY hcrank10 DESC, prank10 DESC, url_host_tld, host_name") {
		t.Fatalf("rank order:\n%s", sql)
	}
	if strings.Contains(sql, "(url_host_tld, host_name) >") {
		t.Fatal("--order rank is one-shot; no cursor predicate")
	}
	if strings.Contains(sql, "OFFSET") {
		t.Fatal("OFFSET 0 must be omitted")
	}
}

func TestSeedFilterSQLRankOrderOffset(t *testing.T) {
	t.Parallel()
	sql, err := (SeedFilter{Limit: 50, Offset: 100, Order: "rank"}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "LIMIT 50 OFFSET 100") {
		t.Fatalf("rank pages with OFFSET:\n%s", sql)
	}
	sql, err = (SeedFilter{Limit: 50, Offset: 100, Order: "key"}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "OFFSET") {
		t.Fatal("--order key pages with a cursor, not OFFSET")
	}
}

func TestSeedFilterSQLOmitsEmptyFilters(t *testing.T) {
	t.Parallel()
	sql, err := (SeedFilter{Limit: 3, Order: "key"}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "WHERE") {
		t.Fatalf("no filters must omit WHERE:\n%s", sql)
	}
	if strings.Contains(sql, "crawl") {
		t.Fatal("empty --crawl must not filter crawl")
	}
}

func TestSeedFilterSQLQuotesInjection(t *testing.T) {
	t.Parallel()
	sql, err := (SeedFilter{
		Crawl: "x'; DROP TABLE fdns_cc_host --",
		TLDs:  []string{"com'or'1"},
		Limit: 1,
	}).SQL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, clickhouse.QuoteString("x'; DROP TABLE fdns_cc_host --")) {
		t.Fatalf("crawl must be quoted:\n%s", sql)
	}
	if !strings.Contains(sql, clickhouse.QuoteString("com'or'1")) {
		t.Fatalf("tld must be quoted:\n%s", sql)
	}
}

func TestParseSeedOrder(t *testing.T) {
	t.Parallel()
	got, err := parseSeedOrder("")
	if err != nil || got != seedQueueOrderKey {
		t.Fatalf("empty=%q %v", got, err)
	}
	got, err = parseSeedOrder("RANK")
	if err != nil || got != seedQueueOrderRank {
		t.Fatalf("rank=%q %v", got, err)
	}
	if _, err := parseSeedOrder("random"); err == nil {
		t.Fatal("unknown order must error")
	}
}

func TestReadSeedPageNormalizesAndDrops(t *testing.T) {
	t.Parallel()
	body := strings.NewReader(strings.Join([]string{
		"com\tExample.COM.",
		"com\tnot a host",
		"uk\tbbc.co.uk",
		"com\texample.com",
		"org\t192.0.2.1",
	}, "\n") + "\n")
	n, names, tld, host, err := readSeedPage(body)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("chRows=%d, want 5", n)
	}
	if tld != "org" || host != "192.0.2.1" {
		t.Fatalf("cursor=%s/%s (must be last CH row, including dropped)", tld, host)
	}
	if len(names) != 2 || names[0] != "example.com" || names[1] != "bbc.co.uk" {
		t.Fatalf("names=%v (NormalizeHostname, drop invalid, dedup)", names)
	}
}

func TestQueueSeederAssertsSchemaVersion(t *testing.T) {
	t.Parallel()
	// 0 is always behind the squashed 0001_initial schema (LatestVersion == 1).
	ch := &fakeSeedCH{version: 0, dirty: false}
	s := NewQueueSeeder(zap.NewNop(), newMemSeedStore(), ch)
	err := s.Seed(context.Background())
	if err == nil || !strings.Contains(err.Error(), "opr clickhouse migrate") {
		t.Fatalf("err=%v, want migrate hint", err)
	}
	ch.version = clickhouse.LatestVersion()
	ch.dirty = true
	err = s.Seed(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dirty=true") {
		t.Fatalf("dirty err=%v", err)
	}
}

func TestQueueSeederHighWaterSkips(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	st.queueN = 10
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), tsv: "com\texample.com\n"}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.QueueHighWater = 10
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ch.queries) != 0 {
		t.Fatalf("high water must not query ClickHouse: %v", ch.queries)
	}
	if st.upsertN != 0 {
		t.Fatal("high water must not upsert")
	}
}

func TestQueueSeederHighWaterCapsRemaining(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	st.queueN = 8
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), tsv: strings.Join([]string{
		"com\ta.example",
		"com\tb.example",
		"com\tc.example",
		"com\td.example",
		"com\te.example",
	}, "\n") + "\n"}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.QueueHighWater = 10
	s.Limit = 100
	s.CopyBatch = 50
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 2 {
		t.Fatalf("remaining capacity 2, upserted %d rows: %+v", len(st.rows), st.rows)
	}
	if !strings.Contains(ch.queries[0], "LIMIT 2") {
		t.Fatalf("CH page must be capped to remaining: %s", ch.queries[0])
	}
}

func TestQueueSeederStaleAfterHonorsZero(t *testing.T) {
	t.Parallel()
	s := NewQueueSeeder(zap.NewNop(), newMemSeedStore(), &fakeSeedCH{})
	if s.staleAfter() != DefaultResolveStaleAfter {
		t.Fatalf("NewQueueSeeder default staleAfter=%s", s.staleAfter())
	}
	s.StaleAfter = 0
	if s.staleAfter() != 0 {
		t.Fatalf("--stale-after 0 must mean never-resolved, got %s", s.staleAfter())
	}
	s.StaleAfter = -time.Hour
	if s.staleAfter() != 0 {
		t.Fatalf("negative stale-after must mean never-resolved, got %s", s.staleAfter())
	}
	s.StaleAfter = time.Hour
	if s.staleAfter() != time.Hour {
		t.Fatalf("explicit window=%s", s.staleAfter())
	}
}

func TestQueueSeederPassesStaleAfterZeroToStore(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), tsv: "com\texample.com\n"}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.StaleAfter = 0
	s.Limit = 1
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.stale != 0 {
		t.Fatalf("upsert staleAfter=%s, want 0", st.stale)
	}
}

func TestQueueSeederDryRunNoWrites(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), tsv: "com\tWWW.Example.com\nuk\tbbc.co.uk\n"}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.DryRun = true
	s.Limit = 10
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.upsertN != 0 || st.saveMetaN != 0 {
		t.Fatalf("dry-run wrote pg: upsert=%d meta=%d", st.upsertN, st.saveMetaN)
	}
	if len(ch.queries) == 0 {
		t.Fatal("dry-run must still query ClickHouse")
	}
}

func TestQueueSeederUpsertsCCAndPagesCursor(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), pages: []string{
		"com\texample.com\ncom\twww.example.com\n",
		"",
	}}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.CopyBatch = 2
	s.Limit = 10
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.upsertN != 1 {
		t.Fatalf("upsertN=%d, want 1 page with names", st.upsertN)
	}
	if len(st.rows) != 2 || st.rows[0].Source[0] != postgres.HostNameSourceCC {
		t.Fatalf("rows=%+v", st.rows)
	}
	if st.rows[0].Name != "example.com" || st.rows[1].Name != "www.example.com" {
		t.Fatalf("normalized names=%+v", st.rows)
	}
	got := st.meta[postgres.FDNSCCSeedCursorURL]
	if got == nil || got.Charset == nil || *got.Charset != "" {
		t.Fatalf("end of catalog must reset cursor, got %+v", got)
	}
	if len(ch.queries) < 2 {
		t.Fatalf("expected a follow-up page, queries=%d", len(ch.queries))
	}
	if !strings.Contains(ch.queries[1], "(url_host_tld, host_name) >") {
		t.Fatalf("page 2 must use cursor: %s", ch.queries[1])
	}
}

func TestQueueSeederRankPagesOffset(t *testing.T) {
	t.Parallel()
	st := newMemSeedStore()
	ch := &fakeSeedCH{version: clickhouse.LatestVersion(), pages: []string{
		"com\ta.example\t3\t3\ncom\tb.example\t2\t2\n",
		"com\tc.example\t1\t1\ncom\td.example\t0.5\t0.5\n",
		"com\te.example\t0.1\t0.1\n",
	}}
	s := NewQueueSeeder(zap.NewNop(), st, ch)
	s.Order = seedQueueOrderRank
	s.CopyBatch = 2
	s.Limit = 5
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.upsertN != 3 {
		t.Fatalf("upsertN=%d, want 3 pages", st.upsertN)
	}
	if len(st.rows) != 5 {
		t.Fatalf("rows=%d, want 5 (paged, not one 5M load)", len(st.rows))
	}
	if len(ch.queries) != 3 {
		t.Fatalf("queries=%d, want 3 pages", len(ch.queries))
	}
	if !strings.Contains(ch.queries[0], "LIMIT 2") || strings.Contains(ch.queries[0], "OFFSET") {
		t.Fatalf("page 1: %s", ch.queries[0])
	}
	if !strings.Contains(ch.queries[1], "LIMIT 2 OFFSET 2") {
		t.Fatalf("page 2 must OFFSET: %s", ch.queries[1])
	}
	if !strings.Contains(ch.queries[2], "LIMIT 1 OFFSET 4") {
		t.Fatalf("last page remainder: %s", ch.queries[2])
	}
	if strings.Contains(ch.queries[0], "(url_host_tld, host_name) >") {
		t.Fatal("--order rank must not use a key cursor")
	}
}

func TestQueueSeederClickHouseHTTP(t *testing.T) {
	t.Parallel()
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := r.URL.Query().Get("query")
		if q == "" {
			q = string(body)
		}
		gotQuery = q
		if strings.Contains(q, "EXISTS TABLE") {
			_, _ = io.WriteString(w, "1\n")
			return
		}
		if strings.Contains(q, "schema_migrations") {
			fmt.Fprintf(w, "%d\t0\n", clickhouse.LatestVersion())
			return
		}
		if r.URL.Query().Get("default_format") != "TabSeparated" && !strings.Contains(q, "EXISTS") && !strings.Contains(q, "schema_migrations") {
			// QueryTSV sets default_format; Scalar also uses QueryTSV.
		}
		_, _ = io.WriteString(w, "com\tExample.COM\ncom\tbad_host\n")
	}))
	t.Cleanup(srv.Close)

	client := clickhouse.New(srv.URL, "netlib", "", "", time.Minute)
	st := newMemSeedStore()
	s := NewQueueSeeder(zap.NewNop(), st, client)
	s.Limit = 10
	s.MinFetch200 = 5
	s.TLDs = []string{"com"}
	s.DryRun = true
	if err := s.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "fetch_200 >= 5") {
		t.Fatalf("query=%q", gotQuery)
	}
	if !strings.Contains(gotQuery, "url_host_tld IN ("+clickhouse.QuoteString("com")+")") {
		t.Fatalf("tld filter missing: %s", gotQuery)
	}
}

type memSeedStore struct {
	mu        sync.Mutex
	meta      map[string]*postgres.ResponseMetadataItem
	rows      []postgres.HostName
	queueN    int64
	upsertN   int
	saveMetaN int
	stale     time.Duration
}

func newMemSeedStore() *memSeedStore {
	return &memSeedStore{meta: map[string]*postgres.ResponseMetadataItem{}}
}

func (m *memSeedStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memSeedStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memSeedStore) UpsertHostNamesAndEnqueue(_ context.Context, rows []postgres.HostName, staleAfter time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertN++
	m.stale = staleAfter
	m.rows = append(m.rows, rows...)
	return int64(len(rows)), nil
}

func (m *memSeedStore) CountResolveQueue(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queueN, nil
}

type fakeSeedCH struct {
	mu      sync.Mutex
	version uint
	dirty   bool
	tsv     string
	pages   []string
	pageN   int
	queries []string
}

func (f *fakeSeedCH) SchemaVersion(context.Context) (uint, bool, error) {
	return f.version, f.dirty, nil
}

func (f *fakeSeedCH) QueryTSV(_ context.Context, query string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	body := f.tsv
	if len(f.pages) > 0 {
		if f.pageN >= len(f.pages) {
			body = ""
		} else {
			body = f.pages[f.pageN]
			f.pageN++
		}
	}
	return io.NopCloser(strings.NewReader(body)), nil
}
