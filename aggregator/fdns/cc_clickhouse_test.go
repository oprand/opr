package fdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/oprand/opr/store/clickhouse"

	"go.uber.org/zap"
)

func TestCCInsertSQLCoversEveryHostIndexColumn(t *testing.T) {
	t.Parallel()
	if len(ccHostIndexColumns) != 42 {
		t.Fatalf("Host Index Parquet has 42 physical columns, ccHostIndexColumns has %d", len(ccHostIndexColumns))
	}
	for _, col := range ccHostIndexColumns {
		if col.Name == "crawl" {
			t.Fatal("crawl is a hive path segment, not an input() column")
		}
	}
	const crawl = "CC-MAIN-2025-18"
	sql := ccInsertSQL(crawl)
	structure := ccInputStructure(t, sql)
	if strings.Contains(structure, "crawl") {
		t.Fatalf("input() structure must not mention crawl:\n%s", structure)
	}
	if got := len(strings.Split(structure, ", ")); got != 42 {
		t.Fatalf("input() structure has %d columns, want 42: %s", got, structure)
	}
	for _, col := range ccHostIndexColumns {
		if !strings.Contains(structure, ccQuoteIdent(col.Name)+" "+col.Type) {
			t.Errorf("input() structure missing %s %s", col.Name, col.Type)
		}
	}
	wantCrawl := clickhouse.QuoteString(crawl) + " AS crawl"
	if !strings.Contains(sql, wantCrawl) {
		t.Fatalf("crawl must be injected as a literal %s\n%s", wantCrawl, sql)
	}
	if !strings.Contains(sql, "host_name, surt_host_name, crawl,") {
		t.Fatalf("crawl literal must land in the insert column list after surt_host_name:\n%s", sql)
	}
	if !strings.Contains(sql, "`robots_redirPerm` Int64") || !strings.Contains(sql, "`nutch_numRecords` Int64") {
		t.Error("camelCase columns must be backtick-quoted")
	}
	if strings.Contains(sql, "`fetch_200`") {
		t.Error("plain lowercase columns must not be quoted")
	}
	if !strings.Contains(sql, ccHostNameExpr+" AS host_name") {
		t.Error("host_name must be un-SURTed in the projection")
	}
	if !strings.Contains(sql, "INSERT INTO "+CCHostLoadTable+" (host_name, surt_host_name,") {
		t.Errorf("insert must target the load table with an explicit column list:\n%s", sql)
	}
	if !strings.HasSuffix(sql, "FORMAT Parquet") {
		t.Error("FORMAT must be the last clause so the body is the Parquet file")
	}
	for _, want := range []string{
		"WHERE surt_host_name != ''",
		"AND length(host_name) <= 253",
		`match(host_name, '` + ccValidDNSNameRegex + `')`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing predicate %q", want)
		}
	}
	// ClickHouse collapses \\. in a string literal to the \. RE2 needs.
	if !strings.Contains(ccValidDNSNameRegex, `\\.`) {
		t.Error("the label separator must stay escaped through the SQL literal")
	}
}

// TestCCInsertColumnsMatchMigrationDDL keeps the Go column table and the
// embedded CREATE TABLE from drifting apart: a mismatch only shows up as a
// confusing insert error against a live ClickHouse.
func TestCCInsertColumnsMatchMigrationDDL(t *testing.T) {
	t.Parallel()
	all, err := clickhouse.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var up string
	for _, m := range all {
		if m.Name == "initial" {
			up = m.Up
			break
		}
	}
	if up == "" {
		t.Fatal("no initial migration")
	}
	ddl := createTableDDL(up, "fdns_cc_host")
	if ddl == "" {
		t.Fatal("no fdns_cc_host CREATE TABLE in initial migration")
	}

	declared := ddlColumnNames(t, ddl)
	want := []string{"host_name"}
	injectedCrawl := false
	for _, col := range ccHostIndexColumns {
		want = append(want, col.Name)
		if col.Name == "surt_host_name" {
			want = append(want, "crawl")
			injectedCrawl = true
		}
	}
	if !injectedCrawl {
		t.Fatal("crawl must be injected into the table column list after surt_host_name")
	}
	want = append(want, "ingested_at")
	if len(declared) != len(want) {
		t.Fatalf("DDL declares %d columns, Go expects %d", len(declared), len(want))
	}
	for i := range want {
		if declared[i] != want[i] {
			t.Fatalf("column %d: DDL has %q, Go has %q (order must match)", i, declared[i], want[i])
		}
	}
	for _, col := range ccHostIndexColumns {
		if strings.ToLower(col.Name) != col.Name && !strings.Contains(ddl, "`"+col.Name+"`") {
			t.Errorf("DDL must backtick-quote %s", col.Name)
		}
	}
}

// createTableDDL returns the CREATE TABLE statement for table from a
// (possibly multi-statement) migration body such as 0001_initial.up.sql.
func createTableDDL(sql, table string) string {
	needle := "CREATE TABLE IF NOT EXISTS " + table + "\n"
	i := strings.Index(sql, needle)
	if i < 0 {
		return ""
	}
	rest := sql[i:]
	j := strings.Index(rest, ";")
	if j < 0 {
		return ""
	}
	return rest[:j+1]
}

// ddlColumnNames pulls the column identifiers out of a CREATE TABLE body.
func ddlColumnNames(t *testing.T, ddl string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(ddl, "\n") {
		if !strings.HasPrefix(line, "    ") {
			continue
		}
		name, _, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		out = append(out, strings.Trim(name, "`"))
	}
	return out
}

func ccInputStructure(t *testing.T, sql string) string {
	t.Helper()
	const marker = "FROM input('"
	i := strings.Index(sql, marker)
	if i < 0 {
		t.Fatalf("no input() structure in:\n%s", sql)
	}
	rest := sql[i+len(marker):]
	j := strings.Index(rest, "')")
	if j < 0 {
		t.Fatalf("unterminated input() structure in:\n%s", sql)
	}
	return rest[:j]
}

func TestLoadClickHouseTruncatesLoadsAndSwaps(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet", "part-1.parquet")
	rows, err := in.loadClickHouse(context.Background(), man)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2*ch.rowsPerPart {
		t.Fatalf("rows=%d, want %d", rows, 2*ch.rowsPerPart)
	}
	if got := len(ch.insertedPaths()); got != 2 {
		t.Fatalf("inserted %d parts, want 2", got)
	}

	stmts := ch.execStatements()
	wantOrder := []string{
		"TRUNCATE TABLE " + CCHostLoadTable,
		"INSERT INTO " + CCLoadPartTable,
		"INSERT INTO " + CCLoadPartTable,
		"EXCHANGE TABLES " + CCHostTable + " AND " + CCHostLoadTable,
		"INSERT INTO " + CCLoadPartTable,
		"TRUNCATE TABLE " + CCHostLoadTable,
		"TRUNCATE TABLE " + CCLoadPartTable,
	}
	if len(stmts) != len(wantOrder) {
		t.Fatalf("statements=%v", stmts)
	}
	for i, want := range wantOrder {
		if !strings.HasPrefix(stmts[i], want) {
			t.Fatalf("statement %d = %q, want prefix %q", i, stmts[i], want)
		}
	}
	if !strings.Contains(stmts[1], clickhouse.QuoteString(man.ID)) {
		t.Fatalf("ledger row must carry the crawl id: %s", stmts[1])
	}
	if !strings.Contains(stmts[4], clickhouse.QuoteString(ccSwapMarkerPath)) {
		t.Fatalf("swap marker must be recorded before the post-swap truncates: %s", stmts[4])
	}
	inserted := ch.insertQueries()
	if len(inserted) != 2 {
		t.Fatalf("insert queries=%d", len(inserted))
	}
	if !strings.Contains(inserted[0], clickhouse.QuoteString(man.ID)+" AS crawl") {
		t.Fatalf("insert must inject crawl from the manifest:\n%s", inserted[0])
	}
	if strings.Contains(ccInputStructure(t, inserted[0]), "crawl") {
		t.Fatal("insert input() structure must not read crawl from Parquet")
	}
	for _, stmt := range stmts {
		if !strings.HasPrefix(stmt, "INSERT INTO "+CCLoadPartTable) {
			continue
		}
		values := sqlStringLiterals(stmt)
		if len(values) != 2 || values[1] == ccSwapMarkerPath {
			continue
		}
		if !filepath.IsAbs(values[1]) {
			t.Fatalf("ledger path %q is not absolute", values[1])
		}
	}
}

func TestLoadClickHouseResumeSkipsLoadedParts(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet", "part-1.parquet")
	_, firstDest, err := in.localParquet(man.Paths[0])
	if err != nil {
		t.Fatal(err)
	}
	ch.ledger = []string{firstDest}
	ch.rows = ch.rowsPerPart

	if _, err := in.loadClickHouse(context.Background(), man); err != nil {
		t.Fatal(err)
	}
	inserted := ch.insertedPaths()
	if len(inserted) != 1 || filepath.Base(inserted[0]) != "part-1.parquet" {
		t.Fatalf("inserted=%v, want only part-1", inserted)
	}
	// Truncating the load table before the swap would throw away the resume.
	if strings.HasPrefix(ch.execStatements()[0], "TRUNCATE TABLE "+CCHostLoadTable) {
		t.Fatal("a resume must not truncate the load table")
	}
}

func TestLoadClickHouseEmptyLoadDoesNotSwap(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet")
	ch.rowsPerPart = 0

	_, err := in.loadClickHouse(context.Background(), man)
	if err == nil || !strings.Contains(err.Error(), "is empty after") {
		t.Fatalf("err=%v, want a refusal to swap an empty table", err)
	}
	for _, stmt := range ch.execStatements() {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			t.Fatal("empty load must not swap")
		}
	}
}

func TestLoadClickHouseInsertFailureDoesNotSwap(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet", "part-1.parquet")
	ch.insertErrAfter = 1

	_, err := in.loadClickHouse(context.Background(), man)
	if err == nil || !strings.Contains(err.Error(), "part-1.parquet") {
		t.Fatalf("err=%v, want the failing part named", err)
	}
	for _, stmt := range ch.execStatements() {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			t.Fatal("a failed part must abort before the swap")
		}
	}
	// The part that did land stays in the ledger so the retry skips it.
	if len(ch.ledger) != 1 {
		t.Fatalf("ledger=%v, want the one part that landed", ch.ledger)
	}
	if !filepath.IsAbs(ch.ledger[0]) {
		t.Fatalf("ledger path %q is not absolute", ch.ledger[0])
	}
}

func TestLoadClickHouseResumeAfterSwapDoesNotReinsert(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet", "part-1.parquet")
	for _, rel := range man.Paths {
		_, dest, err := in.localParquet(rel)
		if err != nil {
			t.Fatal(err)
		}
		abs, err := ccLedgerPath(dest)
		if err != nil {
			t.Fatal(err)
		}
		ch.ledger = append(ch.ledger, abs)
	}
	// Exchange already happened: the live table holds this crawl and the load
	// table holds the previous snapshot. Cleanup must not insert or swap back.
	ch.hostRows = 14
	ch.rows = 3
	ch.hostIngested = "2026-06-01 00:00:01"
	ch.loadIngested = "2020-01-01 00:00:00"

	rows, err := in.loadClickHouse(context.Background(), man)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 14 {
		t.Fatalf("rows=%d, want the live table count", rows)
	}
	if got := ch.insertedPaths(); len(got) != 0 {
		t.Fatalf("inserted=%v, want no re-insert after swap", got)
	}
	for _, stmt := range ch.execStatements() {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			t.Fatal("resume after swap must not exchange again")
		}
	}
}

func TestLoadClickHouseSwapMarkerFinishesCleanup(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet")
	ch.ledger = []string{ccSwapMarkerPath}
	ch.hostRows = 9

	rows, err := in.loadClickHouse(context.Background(), man)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 9 {
		t.Fatalf("rows=%d, want 9", rows)
	}
	if len(ch.insertedPaths()) != 0 {
		t.Fatalf("inserted=%v, want none", ch.insertedPaths())
	}
	stmts := ch.execStatements()
	var truncatedLoad, truncatedLedger bool
	for _, stmt := range stmts {
		if strings.HasPrefix(stmt, "TRUNCATE TABLE "+CCHostLoadTable) {
			truncatedLoad = true
		}
		if strings.HasPrefix(stmt, "TRUNCATE TABLE "+CCLoadPartTable) {
			truncatedLedger = true
		}
	}
	if !truncatedLoad || !truncatedLedger || !strings.HasPrefix(stmts[len(stmts)-1], "TRUNCATE TABLE "+CCLoadPartTable) {
		t.Fatalf("cleanup statements=%v", stmts)
	}
	for _, stmt := range stmts {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			t.Fatal("marker resume must not exchange")
		}
	}
}

func TestLoadClickHouseTruncateFailureAfterSwapResumesCleanup(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet", "part-1.parquet")
	var truncates int
	ch.execErr = func(query string) error {
		if strings.HasPrefix(query, "TRUNCATE TABLE "+CCHostLoadTable) {
			truncates++
			if truncates == 2 {
				return errors.New("truncate load failed")
			}
		}
		return nil
	}

	_, err := in.loadClickHouse(context.Background(), man)
	if err == nil || !strings.Contains(err.Error(), "truncate load failed") {
		t.Fatalf("err=%v, want the post-swap truncate failure", err)
	}
	if len(ch.insertedPaths()) != 2 {
		t.Fatalf("inserted=%v, want both parts before the failed cleanup", ch.insertedPaths())
	}
	foundMarker := false
	for _, path := range ch.ledger {
		if path == ccSwapMarkerPath {
			foundMarker = true
		}
	}
	if !foundMarker {
		t.Fatalf("ledger=%v, want the swap marker kept when cleanup fails", ch.ledger)
	}

	ch.execErr = nil
	insertedBefore := len(ch.insertedPaths())
	if _, err := in.loadClickHouse(context.Background(), man); err != nil {
		t.Fatal(err)
	}
	if got := len(ch.insertedPaths()); got != insertedBefore {
		t.Fatalf("resume inserted %d more parts", got-insertedBefore)
	}
	for _, stmt := range ch.execStatements()[len(ch.execStatements())-3:] {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			t.Fatal("cleanup resume must not exchange again")
		}
	}
}

func TestLoadClickHouseReloadStillSwapsWhenLoadIsNewer(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet")
	ch.hostRows = 100
	ch.hostIngested = "2020-01-01 00:00:00"

	if _, err := in.loadClickHouse(context.Background(), man); err != nil {
		t.Fatal(err)
	}
	sawExchange := false
	for _, stmt := range ch.execStatements() {
		if strings.HasPrefix(stmt, "EXCHANGE TABLES") {
			sawExchange = true
		}
	}
	if !sawExchange {
		t.Fatal("a newer load must still swap when the live table already holds this crawl")
	}
	if len(ch.insertedPaths()) != 1 {
		t.Fatalf("inserted=%v, want the new part", ch.insertedPaths())
	}
}

func TestLoadClickHouseRecordsAbsoluteLedgerPath(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relDir, err := filepath.Rel(wd, in.ParquetDir)
	if err != nil {
		t.Fatal(err)
	}
	in.ParquetDir = relDir

	if _, err := in.loadClickHouse(context.Background(), man); err != nil {
		t.Fatal(err)
	}
	var recorded string
	for _, stmt := range ch.execStatements() {
		if !strings.HasPrefix(stmt, "INSERT INTO "+CCLoadPartTable) {
			continue
		}
		values := sqlStringLiterals(stmt)
		if len(values) == 2 && values[1] != ccSwapMarkerPath {
			recorded = values[1]
			break
		}
	}
	want, err := filepath.Abs(filepath.Join(relDir, man.Paths[0]))
	if err != nil {
		t.Fatal(err)
	}
	if recorded != want {
		t.Fatalf("ledger path %q, want absolute %q", recorded, want)
	}
}

func TestLoadClickHouseRequiresExpectedSchemaVersion(t *testing.T) {
	t.Parallel()
	in, ch, man := ccLoaderFixture(t, "part-0.parquet")
	ch.version = clickhouse.LatestVersion() - 1

	_, err := in.loadClickHouse(context.Background(), man)
	if err == nil || !strings.Contains(err.Error(), "opr clickhouse migrate") {
		t.Fatalf("err=%v, want a pointer at the migrate command", err)
	}
	if len(ch.execStatements()) != 0 {
		t.Fatalf("version mismatch must touch nothing, got %v", ch.execStatements())
	}

	ch.version = clickhouse.LatestVersion()
	ch.dirty = true
	if _, err := in.loadClickHouse(context.Background(), man); err == nil {
		t.Fatal("a dirty schema must not load")
	}
}

func TestLoadClickHouseRequiresEveryManifestPart(t *testing.T) {
	t.Parallel()
	in, _, man := ccLoaderFixture(t, "part-0.parquet")
	man.Paths = append(man.Paths, "projects/host-index-testing/v2/crawl=CC-MAIN-2025-18/missing.parquet")

	if _, err := in.loadClickHouse(context.Background(), man); err == nil ||
		!strings.Contains(err.Error(), "missing verified parquet") {
		t.Fatalf("err=%v, want a missing-part error", err)
	}
}

func ccLoaderFixture(t *testing.T, parts ...string) (*CCIngestor, *fakeCCClickHouse, CCManifest) {
	t.Helper()
	dir := t.TempDir()
	crawl := "CC-MAIN-2025-18"
	rel := "projects/host-index-testing/v2/crawl=" + crawl
	if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
		t.Fatal(err)
	}
	man := CCManifest{ID: crawl}
	for _, part := range parts {
		if err := os.WriteFile(filepath.Join(dir, rel, part), []byte("PARQUET"), 0o644); err != nil {
			t.Fatal(err)
		}
		man.Paths = append(man.Paths, rel+"/"+part)
	}
	ch := newFakeCCClickHouse()
	in := NewCCIngestor(zap.NewNop(), newMemFDNSStore(), nil)
	in.ParquetDir = dir
	in.CH = ch
	return in, ch, man
}

// fakeCCClickHouse records what the loader sends and keeps a ledger the way
// fdns_cc_load_part would.
type fakeCCClickHouse struct {
	mu         sync.Mutex
	statements []string
	inserted   []string
	queries    []string
	ledger     []string

	version        uint
	dirty          bool
	rows           int64
	hostRows       int64
	loadIngested   string
	hostIngested   string
	rowsPerPart    int64
	insertErrAfter int
	execErr        func(query string) error
}

func newFakeCCClickHouse() *fakeCCClickHouse {
	return &fakeCCClickHouse{version: clickhouse.LatestVersion(), rowsPerPart: 7}
}

func (f *fakeCCClickHouse) SchemaVersion(context.Context) (uint, bool, error) {
	return f.version, f.dirty, nil
}

func (f *fakeCCClickHouse) Exec(_ context.Context, query string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statements = append(f.statements, query)
	if f.execErr != nil {
		if err := f.execErr(query); err != nil {
			return err
		}
	}
	switch {
	case strings.HasPrefix(query, "TRUNCATE TABLE "+CCHostLoadTable):
		f.rows = 0
		f.loadIngested = ""
	case strings.HasPrefix(query, "TRUNCATE TABLE "+CCLoadPartTable):
		f.ledger = nil
	case strings.HasPrefix(query, "EXCHANGE TABLES"):
		f.rows, f.hostRows = f.hostRows, f.rows
		f.loadIngested, f.hostIngested = f.hostIngested, f.loadIngested
	case strings.HasPrefix(query, "INSERT INTO "+CCLoadPartTable):
		values := sqlStringLiterals(query)
		if len(values) != 2 {
			return fmt.Errorf("unexpected ledger insert %q", query)
		}
		f.ledger = append(f.ledger, values[1])
	}
	return nil
}

// sqlStringLiterals returns the single-quoted values in a statement. Test
// fixtures never contain escaped quotes.
func sqlStringLiterals(query string) []string {
	parts := strings.Split(query, "'")
	var out []string
	for i := 1; i < len(parts); i += 2 {
		out = append(out, parts[i])
	}
	return out
}

func (f *fakeCCClickHouse) QueryTSV(_ context.Context, query string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(query, CCLoadPartTable) {
		return nil, fmt.Errorf("unexpected query %q", query)
	}
	return io.NopCloser(strings.NewReader(strings.Join(f.ledger, "\n"))), nil
}

func (f *fakeCCClickHouse) Scalar(_ context.Context, query string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(query, "max(ingested_at)"):
		if strings.Contains(query, CCHostLoadTable) {
			return f.loadIngested, nil
		}
		return f.hostIngested, nil
	case strings.Contains(query, "count()"):
		// fdns_cc_host is a prefix of fdns_cc_host_load; match the load table first.
		if strings.Contains(query, CCHostLoadTable) {
			return strconv.FormatInt(f.rows, 10), nil
		}
		if strings.Contains(query, CCHostTable) {
			return strconv.FormatInt(f.hostRows, 10), nil
		}
	}
	return "", fmt.Errorf("unexpected query %q", query)
}

func (f *fakeCCClickHouse) InsertFile(_ context.Context, query, path string) (int64, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(query, "INSERT INTO "+CCHostLoadTable) {
		return 0, 0, fmt.Errorf("unexpected insert %q", query)
	}
	if f.insertErrAfter > 0 && len(f.inserted) >= f.insertErrAfter {
		return 0, 0, errors.New("simulated clickhouse insert failure")
	}
	f.inserted = append(f.inserted, path)
	f.queries = append(f.queries, query)
	f.rows += f.rowsPerPart
	f.loadIngested = "2026-06-01 00:00:01"
	return f.rowsPerPart, int64(len("PARQUET")), nil
}

func (f *fakeCCClickHouse) execStatements() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.statements...)
}

func (f *fakeCCClickHouse) insertedPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.inserted...)
}

func (f *fakeCCClickHouse) insertQueries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// TestCCValidDNSNameRegexMatchesGo checks the one piece of the insert that can
// silently diverge: the RE2 port of validDNSName, including the backslash the
// ClickHouse string literal eats before RE2 sees it.
func TestCCValidDNSNameRegexMatchesGo(t *testing.T) {
	t.Parallel()
	// ClickHouse collapses \\ to \ when it parses the string literal.
	re, err := regexp.Compile(strings.ReplaceAll(ccValidDNSNameRegex, `\\`, `\`))
	if err != nil {
		t.Fatalf("regex does not compile after literal unescaping: %v", err)
	}

	hosts := []string{
		"example.com",
		"bbc.co.uk",
		"xn--80ak6aa92e.com",
		"a.b",
		"localhost",
		"",
		".co.uk",
		"co..uk",
		"-example.com",
		"example-.com",
		"exa_mple.com",
		"192.0.2.1",
		"ex ample.com",
		"example.com.",
		"EXAMPLE.com",
		strings.Repeat("a", 63) + ".com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, host := range hosts {
		want := validDNSName(host)
		got := len(host) <= 253 && re.MatchString(host)
		if got != want {
			t.Errorf("%q: regex=%v validDNSName=%v", host, got, want)
		}
	}
}

// TestCCHostNameExprMatchesUnSURT pins the un-SURT expression's contract: it is
// a reverse-and-join, and the labels Go rejects are the ones the regex rejects.
func TestCCHostNameExprMatchesUnSURT(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(strings.ReplaceAll(ccValidDNSNameRegex, `\\`, `\`))
	for surt, want := range map[string]string{
		"com,example":   "example.com",
		"uk,co,bbc":     "bbc.co.uk",
		"com,example,":  "",
		"org,commoncra": "",
	} {
		sqlHost := unSURTLikeClickHouse(surt)
		goHost, ok := UnSURTHostName(surt)
		if !ok {
			// Go refuses empty labels; the regex must refuse the joined form too.
			if re.MatchString(sqlHost) {
				t.Errorf("%q: Go rejects %q but the regex accepts it", surt, sqlHost)
			}
			continue
		}
		if sqlHost != goHost {
			t.Errorf("%q: SQL would build %q, Go builds %q", surt, sqlHost, goHost)
		}
		if want != "" && goHost != want {
			t.Errorf("%q → %q, want %q", surt, goHost, want)
		}
	}
}

// unSURTLikeClickHouse mirrors arrayStringConcat(arrayReverse(splitByChar(...))).
func unSURTLikeClickHouse(surt string) string {
	parts := strings.Split(surt, ",")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}
