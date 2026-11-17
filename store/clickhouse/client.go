// Package clickhouse is a client for the ClickHouse HTTP interface plus the
// opr ClickHouse schema and its migration runner. It is a separate package
// from github.com/oprand/opr/store/postgres so the ClickHouse code does not compile into every
// Postgres consumer and its tests run without a database.
package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultURL is the ClickHouse HTTP interface on the local node.
	DefaultURL = "http://127.0.0.1:8123"
	// DefaultDatabase is the on-disk ClickHouse database name.
	DefaultDatabase = "opr"
	// DefaultUser is the account a stock ClickHouse server ships with.
	DefaultUser = "default"
	// DefaultTimeout bounds one HTTP request. A Parquet part POST runs for minutes.
	DefaultTimeout = 30 * time.Minute

	// maxErrorBody caps how much of a ClickHouse error response is kept in the error.
	maxErrorBody = 8 << 10
	// maxScalarBody caps a Scalar result; anything larger belongs in QueryTSV.
	maxScalarBody = 1 << 20
)

// Client talks to ClickHouse over HTTP rather than the native protocol so a
// Parquet file can be streamed straight from disk as the request body.
type Client struct {
	URL      string
	Database string
	User     string
	Password string
	// Settings are ClickHouse settings sent as URL parameters on every request.
	Settings map[string]string
	HTTP     *http.Client
}

// New builds a client. input_format_null_as_default is on because every opr
// ClickHouse column is non-Nullable: a NULL in Parquet loads as zero or the
// empty string.
func New(rawURL, database, user, password string, timeout time.Duration) *Client {
	if strings.TrimSpace(rawURL) == "" {
		rawURL = DefaultURL
	}
	if strings.TrimSpace(database) == "" {
		database = DefaultDatabase
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		URL:      strings.TrimRight(strings.TrimSpace(rawURL), "/"),
		Database: strings.TrimSpace(database),
		User:     strings.TrimSpace(user),
		Password: password,
		Settings: map[string]string{"input_format_null_as_default": "1"},
		HTTP: &http.Client{
			Timeout:       timeout,
			CheckRedirect: clickHouseRedirect,
		},
	}
}

// Exec runs one statement and discards its output.
func (c *Client) Exec(ctx context.Context, query string) error {
	resp, err := c.post(ctx, nil, strings.NewReader(query), int64(len(query)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// QueryTSV runs a query and returns its TabSeparated body. The caller closes it.
func (c *Client) QueryTSV(ctx context.Context, query string) (io.ReadCloser, error) {
	resp, err := c.post(ctx, url.Values{"default_format": {"TabSeparated"}},
		strings.NewReader(query), int64(len(query)))
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Scalar runs a query expected to return one row and returns it without the
// trailing newline. Multi-column rows come back tab-separated.
func (c *Client) Scalar(ctx context.Context, query string) (string, error) {
	body, err := c.QueryTSV(ctx, query)
	if err != nil {
		return "", err
	}
	defer body.Close()
	out, err := io.ReadAll(io.LimitReader(body, maxScalarBody))
	if err != nil {
		return "", fmt.Errorf("clickhouse scalar: %w", err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// InsertFile POSTs path as the body of query, an INSERT whose last clause is
// the FORMAT of the file. It reports the rows ClickHouse wrote and the bytes
// sent. Written rows come from X-ClickHouse-Summary and are 0 when the server
// does not send one.
func (c *Client) InsertFile(ctx context.Context, query, path string) (rows, bytes int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("clickhouse insert: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, fmt.Errorf("clickhouse insert: %w", err)
	}
	// LimitReader keeps the body exactly as long as the Content-Length taken
	// from Stat, and hides the *os.File so net/http streams it rather than
	// reaching for sendfile (unavailable in some sandboxes).
	resp, err := c.post(ctx, url.Values{"query": {query}, "wait_end_of_query": {"1"}},
		io.LimitReader(f, fi.Size()), fi.Size())
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return summaryWrittenRows(resp), fi.Size(), nil
}

func (c *Client) post(ctx context.Context, params url.Values, body io.Reader, contentLength int64) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	q := url.Values{}
	if db := strings.TrimSpace(c.Database); db != "" {
		q.Set("database", db)
	}
	for k, v := range c.Settings {
		q.Set(k, v)
	}
	for k, v := range params {
		q[k] = v
	}

	base := strings.TrimRight(strings.TrimSpace(c.URL), "/")
	if base == "" {
		base = DefaultURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/?"+q.Encode(), body)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request: %w", err)
	}
	req.ContentLength = contentLength
	if user := strings.TrimSpace(c.User); user != "" {
		req.Header.Set("X-ClickHouse-User", user)
		req.Header.Set("X-ClickHouse-Key", c.Password)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// httpClient returns the configured client, installing the redirect policy
// when a caller replaced HTTP and left CheckRedirect unset.
func (c *Client) httpClient() *http.Client {
	if c == nil || c.HTTP == nil {
		return &http.Client{Timeout: DefaultTimeout, CheckRedirect: clickHouseRedirect}
	}
	if c.HTTP.CheckRedirect == nil {
		c.HTTP.CheckRedirect = clickHouseRedirect
	}
	return c.HTTP
}

// clickHouseRedirect is the HTTP redirect policy. Go already drops
// Authorization on a cross-host redirect, but it copies every other header,
// including X-ClickHouse-Key. Strip credential headers whenever the next host
// is not the host the request started on.
func clickHouseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("clickhouse: stopped after 10 redirects")
	}
	if len(via) == 0 || via[0] == nil || via[0].URL == nil || req == nil || req.URL == nil {
		return nil
	}
	if strings.EqualFold(via[0].URL.Hostname(), req.URL.Hostname()) {
		return nil
	}
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("X-ClickHouse-Key")
	req.Header.Del("X-ClickHouse-User")
	return nil
}

// QuoteString renders s as a ClickHouse string literal.
func QuoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// summaryWrittenRows reads written_rows out of X-ClickHouse-Summary, which
// arrives as a header when wait_end_of_query is set and as a trailer otherwise.
// The caller must have drained the body before trailers are readable.
func summaryWrittenRows(resp *http.Response) int64 {
	raw := resp.Header.Get("X-ClickHouse-Summary")
	if raw == "" {
		raw = resp.Trailer.Get("X-ClickHouse-Summary")
	}
	if raw == "" {
		return 0
	}
	var summary struct {
		WrittenRows string `json:"written_rows"`
	}
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		return 0
	}
	n, err := strconv.ParseInt(summary.WrittenRows, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
