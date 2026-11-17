package clickhouse

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecSendsQueryInBodyWithDatabaseAndSettings(t *testing.T) {
	t.Parallel()
	var gotBody, gotDatabase, gotNullAsDefault, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotMethod = r.Method
		gotDatabase = r.URL.Query().Get("database")
		gotNullAsDefault = r.URL.Query().Get("input_format_null_as_default")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	if err := c.Exec(context.Background(), "TRUNCATE TABLE fdns_cc_host_load"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method=%s, want POST", gotMethod)
	}
	if gotBody != "TRUNCATE TABLE fdns_cc_host_load" {
		t.Fatalf("body=%q", gotBody)
	}
	if gotDatabase != "netlib" {
		t.Fatalf("database=%q", gotDatabase)
	}
	if gotNullAsDefault != "1" {
		t.Fatalf("input_format_null_as_default=%q, want 1", gotNullAsDefault)
	}
}

func TestAuthHeadersOnlyWhenUserSet(t *testing.T) {
	t.Parallel()
	var gotUser, gotKey string
	var hadUserHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadUserHeader = r.Header["X-Clickhouse-User"]
		gotUser = r.Header.Get("X-ClickHouse-User")
		gotKey = r.Header.Get("X-ClickHouse-Key")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "opr", "s3cret", time.Minute)
	if err := c.Exec(context.Background(), "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if gotUser != "opr" || gotKey != "s3cret" {
		t.Fatalf("user=%q key=%q", gotUser, gotKey)
	}

	anon := New(srv.URL, "netlib", "", "", time.Minute)
	if err := anon.Exec(context.Background(), "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if hadUserHeader {
		t.Fatal("empty user must not send X-ClickHouse-User")
	}
}

func TestErrorBodyIsSurfaced(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "Code: 60. DB::Exception: Table netlib.nope does not exist.\n")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	err := c.Exec(context.Background(), "SELECT 1 FROM nope")
	if err == nil {
		t.Fatal("non-200 must error")
	}
	if !strings.Contains(err.Error(), "DB::Exception: Table netlib.nope does not exist.") {
		t.Fatalf("err=%v, want the ClickHouse message", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("err=%v, want the status", err)
	}
}

func TestScalarTrimsTrailingNewline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "309118989\n")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	got, err := c.Scalar(context.Background(), "SELECT count() FROM fdns_cc_host")
	if err != nil {
		t.Fatal(err)
	}
	if got != "309118989" {
		t.Fatalf("scalar=%q", got)
	}
}

func TestQueryTSVStreamsRows(t *testing.T) {
	t.Parallel()
	var gotFormat string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFormat = r.URL.Query().Get("default_format")
		_, _ = io.WriteString(w, "a.parquet\nb.parquet\n")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	body, err := c.QueryTSV(context.Background(), "SELECT path FROM fdns_cc_load_part")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if gotFormat != "TabSeparated" {
		t.Fatalf("default_format=%q", gotFormat)
	}
	if string(out) != "a.parquet\nb.parquet\n" {
		t.Fatalf("body=%q", out)
	}
}

func TestInsertFileStreamsBodyAndReportsWrittenRows(t *testing.T) {
	t.Parallel()
	payload := []byte("PAR1-not-really-parquet-but-bytes-are-bytes")
	path := filepath.Join(t.TempDir(), "part-00000.parquet")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	var gotQuery, gotWait string
	var gotBody []byte
	var gotContentLength int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotWait = r.URL.Query().Get("wait_end_of_query")
		gotContentLength = r.ContentLength
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"12","written_rows":"7","written_bytes":"512"}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	rows, bytes, err := c.InsertFile(context.Background(), "INSERT INTO fdns_cc_host_load FORMAT Parquet", path)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 7 {
		t.Fatalf("rows=%d, want 7 from X-ClickHouse-Summary", rows)
	}
	if bytes != int64(len(payload)) {
		t.Fatalf("bytes=%d, want %d", bytes, len(payload))
	}
	if gotQuery != "INSERT INTO fdns_cc_host_load FORMAT Parquet" {
		t.Fatalf("query param=%q", gotQuery)
	}
	if gotWait != "1" {
		t.Fatalf("wait_end_of_query=%q, want 1 (summary must arrive as a header)", gotWait)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body=%q", gotBody)
	}
	if gotContentLength != int64(len(payload)) {
		t.Fatalf("Content-Length=%d, want %d (no chunking)", gotContentLength, len(payload))
	}
}

func TestInsertFileMissingSummaryReportsZeroRows(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "part.parquet")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	rows, bytes, err := c.InsertFile(context.Background(), "INSERT INTO t FORMAT Parquet", path)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 || bytes != 1 {
		t.Fatalf("rows=%d bytes=%d", rows, bytes)
	}
}

func TestInsertFileSurfacesServerError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "part.parquet")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Code: 27. DB::ParsingException: Cannot parse input")
	}))
	defer srv.Close()

	c := New(srv.URL, "netlib", "", "", time.Minute)
	if _, _, err := c.InsertFile(context.Background(), "INSERT INTO t FORMAT Parquet", path); err == nil ||
		!strings.Contains(err.Error(), "DB::ParsingException") {
		t.Fatalf("err=%v, want the ClickHouse parse error", err)
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()
	c := New("  ", "", "", "", 0)
	if DefaultDatabase != "opr" {
		t.Fatalf("DefaultDatabase=%q, want opr", DefaultDatabase)
	}
	if c.URL != DefaultURL || c.Database != DefaultDatabase {
		t.Fatalf("url=%q database=%q, want opr", c.URL, c.Database)
	}
	if c.HTTP == nil || c.HTTP.Timeout != DefaultTimeout {
		t.Fatalf("http client=%+v", c.HTTP)
	}
	trailing := New("http://ch.test:8123/", "netlib", "", "", time.Minute)
	if trailing.URL != "http://ch.test:8123" {
		t.Fatalf("url=%q, want the trailing slash trimmed", trailing.URL)
	}
}

func TestRedirectStripsCredentialsOnHostChange(t *testing.T) {
	t.Parallel()
	orig, err := http.NewRequest(http.MethodPost, "http://ch.internal:8123/?query=SELECT", nil)
	if err != nil {
		t.Fatal(err)
	}
	orig.Header.Set("Authorization", "Basic aaa")
	orig.Header.Set("Proxy-Authorization", "Basic bbb")
	orig.Header.Set("X-ClickHouse-Key", "s3cret")
	orig.Header.Set("X-ClickHouse-User", "opr")

	next, err := http.NewRequest(http.MethodPost, "http://evil.example/stolen", nil)
	if err != nil {
		t.Fatal(err)
	}
	next.Header = orig.Header.Clone()
	if err := clickHouseRedirect(next, []*http.Request{orig}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"Authorization", "Proxy-Authorization", "X-ClickHouse-Key", "X-ClickHouse-User"} {
		if got := next.Header.Get(h); got != "" {
			t.Errorf("%s leaked to %s: %q", h, next.URL.Host, got)
		}
	}
}

func TestRedirectKeepsCredentialsOnSameHost(t *testing.T) {
	t.Parallel()
	orig, err := http.NewRequest(http.MethodPost, "http://ch.internal:8123/", nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := http.NewRequest(http.MethodPost, "https://ch.internal:8443/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	next.Header.Set("X-ClickHouse-Key", "s3cret")
	next.Header.Set("Authorization", "Basic aaa")
	if err := clickHouseRedirect(next, []*http.Request{orig}); err != nil {
		t.Fatal(err)
	}
	if next.Header.Get("X-ClickHouse-Key") != "s3cret" || next.Header.Get("Authorization") != "Basic aaa" {
		t.Fatalf("same host must keep credentials, got %v", next.Header)
	}
}

func TestClientStripsKeyWhenRedirectedToAnotherHost(t *testing.T) {
	t.Parallel()
	var gotKey, gotUser string
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-ClickHouse-Key")
		gotUser = r.Header.Get("X-ClickHouse-User")
	}))
	defer dest.Close()

	destURL, err := http.NewRequest(http.MethodGet, dest.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// localhost and 127.0.0.1 are different hostnames that both reach the dest listener.
	redirectTo := "http://localhost:" + destURL.URL.Port() + "/query"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := New(origin.URL, "netlib", "opr", "s3cret", time.Minute)
	if err := c.Exec(context.Background(), "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "" || gotUser != "" {
		t.Fatalf("key=%q user=%q leaked across hosts", gotKey, gotUser)
	}
}

func TestQuoteString(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"CC-MAIN-2025-18": `'CC-MAIN-2025-18'`,
		`o'brien`:         `'o\'brien'`,
		`back\slash`:      `'back\\slash'`,
	} {
		if got := QuoteString(in); got != want {
			t.Errorf("QuoteString(%q)=%s, want %s", in, got, want)
		}
	}
}
