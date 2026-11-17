package fdns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oprand/opr/store/clickhouse"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	ccUserAgent = "opr-fdns"
	// DefaultCCDownloadConcurrency is the parquet GET worker cap (CDN resets unbounded clients).
	DefaultCCDownloadConcurrency = 6
	CCDownloadStatsInterval      = 30 * time.Second

	maxHostIndexPathsBytes = 16 << 20
)

// ErrNoEligibleCrawl is Host Index v2.paths.gz with no CC-MAIN crawl partitions.
var ErrNoEligibleCrawl = errors.New("fdns ingest-cc: no crawl partitions in Host Index paths")

// ErrSkipDownloadIncomplete is --skip-download when local parquet is missing or size-mismatched.
var ErrSkipDownloadIncomplete = errors.New("fdns ingest-cc: --skip-download but parquet files are not verified")

type ccStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	TouchRemoteFileMetadata(ctx context.Context, url string) error
}

var _ ccStore = (*postgres.Store)(nil)

// ccClickHouse is the slice of the ClickHouse HTTP client the Host Index load uses.
type ccClickHouse interface {
	SchemaVersion(ctx context.Context) (version uint, dirty bool, err error)
	Exec(ctx context.Context, query string) error
	QueryTSV(ctx context.Context, query string) (io.ReadCloser, error)
	Scalar(ctx context.Context, query string) (string, error)
	InsertFile(ctx context.Context, query, path string) (rows, bytes int64, err error)
}

var _ ccClickHouse = (*clickhouse.Client)(nil)

// CCIngestor discovers a Host Index crawl, downloads Parquet with ETag resume,
// and POSTs every part at ClickHouse, which un-SURTs and validates host names
// during the insert. Postgres only holds the crawl id in remote_files_metadata.
type CCIngestor struct {
	Store  ccStore
	CH     ccClickHouse
	Client *http.Client
	Logger *zap.Logger

	// HostIndexPathsURL is the gzip path list. Empty means DefaultHostIndexPathsURL.
	HostIndexPathsURL string
	// DataBaseURL is https://data.commoncrawl.org (no trailing slash). Tests inject httptest.
	DataBaseURL string
	// Crawl is --crawl. Empty means latest crawl id present in the Host Index paths.
	Crawl string
	// ParquetDir is --parquet-dir (required at CLI; DefaultParquetDir when empty here).
	ParquetDir   string
	Force        bool
	SkipDownload bool
	Concurrency  int
	KeepParquet  bool

	StatsInterval time.Duration
}

// CCManifest is one Host Index crawl's parquet paths (relative to DataBaseURL).
type CCManifest struct {
	ID    string
	Paths []string
}

// NewCCIngestor builds a discover+download+ClickHouse load job. client nil uses
// an HTTP client with no overall timeout (parquet files are hundreds of MB;
// cancel via ctx).
func NewCCIngestor(logger *zap.Logger, st ccStore, client *http.Client) *CCIngestor {
	if client == nil {
		client = &http.Client{}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CCIngestor{
		Store:       st,
		Client:      client,
		Logger:      logger,
		KeepParquet: true,
	}
}

// DefaultParquetDir is the cache path used when --parquet-dir is omitted:
// UserCacheDir()/opr/cc-host-index, else os.TempDir()/opr/cc-host-index.
// Separate from the retired URL-index cache (opr/cc-index).
func DefaultParquetDir() string {
	if dir, err := os.UserCacheDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "opr", "cc-host-index")
	}
	return filepath.Join(os.TempDir(), "opr", "cc-host-index")
}

// HostIndexPathsManifestURL is the absolute URL of the Host Index v2 path list.
func HostIndexPathsManifestURL(dataBase string) string {
	base := strings.TrimRight(dataBase, "/")
	if base == "" || base == strings.TrimRight(DefaultCCDataURL, "/") {
		return DefaultHostIndexPathsURL
	}
	return base + "/projects/host-index-testing/v2.paths.gz"
}

// Ingest discovers the crawl, downloads (or verifies) Host Index parquet, and
// loads every part into ClickHouse, swapping the result into fdns_cc_host with
// EXCHANGE TABLES. The ClickHouse schema must already be at the version this
// binary embeds (opr clickhouse migrate); a failed part aborts before the
// swap, leaving the live table on its previous snapshot and the parquet on
// disk even when KeepParquet is false.
func (in *CCIngestor) Ingest(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if in.Force && in.SkipDownload {
		return fmt.Errorf("fdns ingest-cc: --force and --skip-download cannot be combined")
	}
	in.fillDefaults()

	man, err := in.Discover(ctx)
	if err != nil {
		return err
	}
	if err := in.Download(ctx, man); err != nil {
		return err
	}

	rows, err := in.loadClickHouse(ctx, man)
	if err != nil {
		return err
	}
	if err := in.maybeDeleteParquet(ctx, man); err != nil {
		return fmt.Errorf("fdns ingest-cc delete parquet: %w", err)
	}
	in.Logger.Info("fdns ingest-cc finished",
		zap.String("crawl", man.ID),
		zap.Int("files", len(man.Paths)),
		zap.Int64("rows", rows),
		zap.String("parquet_dir", in.ParquetDir))
	return nil
}

// maybeDeleteParquet removes verified Host Index parts after a successful load
// when --keep-parquet is false. Empty/failed loads never reach this: Ingest
// returns before calling it.
func (in *CCIngestor) maybeDeleteParquet(_ context.Context, man CCManifest) error {
	if in.KeepParquet {
		return nil
	}
	var errs []error
	for _, rel := range man.Paths {
		_, dest, err := in.localParquet(rel)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// verifiedLocalParquet maps man.Paths to local dest files, erroring unless
// every part is present and non-empty. Loading from this allowlist rather than
// a crawl-dir glob keeps orphan and stale parts out.
func (in *CCIngestor) verifiedLocalParquet(man CCManifest) ([]string, error) {
	if len(man.Paths) == 0 {
		return nil, fmt.Errorf("fdns ingest-cc: empty Host Index manifest")
	}
	out := make([]string, 0, len(man.Paths))
	for _, rel := range man.Paths {
		_, dest, err := in.localParquet(rel)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(dest)
		if err != nil || fi.Size() == 0 {
			return nil, fmt.Errorf("fdns ingest-cc: missing verified parquet: %s", rel)
		}
		out = append(out, dest)
	}
	return out, nil
}

func (in *CCIngestor) fillDefaults() {
	if strings.TrimSpace(in.DataBaseURL) == "" {
		in.DataBaseURL = DefaultCCDataURL
	}
	in.DataBaseURL = strings.TrimRight(in.DataBaseURL, "/")
	if strings.TrimSpace(in.HostIndexPathsURL) == "" {
		in.HostIndexPathsURL = HostIndexPathsManifestURL(in.DataBaseURL)
	}
	if strings.TrimSpace(in.ParquetDir) == "" {
		in.ParquetDir = DefaultParquetDir()
	}
	if in.Concurrency <= 0 {
		in.Concurrency = DefaultCCDownloadConcurrency
	}
	if in.Concurrency > 8 {
		in.Concurrency = 8
	}
	if in.StatsInterval <= 0 {
		in.StatsInterval = CCDownloadStatsInterval
	}
}

// Discover resolves a Host Index crawl id and its parquet path list from
// v2.paths.gz. --crawl pins an id; otherwise the latest crawl id in the
// manifest is used. The chosen id is stored in remote_files_metadata.
func (in *CCIngestor) Discover(ctx context.Context) (CCManifest, error) {
	in.fillDefaults()
	lines, hdr, err := in.fetchHostIndexPaths(ctx)
	if err != nil {
		return CCManifest{}, err
	}
	if in.Store != nil {
		in.Store.SaveResponseMetadata(metadataFromHeader(in.HostIndexPathsURL, hdr))
	}

	id := strings.TrimSpace(in.Crawl)
	if id == "" {
		id, err = LatestCrawlFromPaths(lines)
		if err != nil {
			return CCManifest{}, err
		}
	} else {
		id, err = NormalizeCrawlID(id)
		if err != nil {
			return CCManifest{}, err
		}
	}

	paths := FilterHostIndexPaths(lines, id)
	if len(paths) == 0 {
		return CCManifest{}, fmt.Errorf("fdns ingest-cc: crawl %s has no Host Index parquet parts", id)
	}
	man := CCManifest{ID: id, Paths: paths}
	in.saveCrawlID(man.ID)
	if strings.TrimSpace(in.Crawl) != "" {
		in.Logger.Info("fdns ingest-cc using --crawl",
			zap.String("crawl", man.ID), zap.Int("parts", len(man.Paths)))
	} else {
		in.Logger.Info("fdns ingest-cc discovered crawl",
			zap.String("crawl", man.ID), zap.Int("parts", len(man.Paths)))
	}
	return man, nil
}

func (in *CCIngestor) saveCrawlID(id string) {
	if in.Store == nil {
		return
	}
	now := time.Now().UTC()
	charset := id
	in.Store.SaveResponseMetadata(&postgres.ResponseMetadataItem{
		Url:         postgres.FDNSCCCrawlMetadataURL,
		Charset:     &charset,
		MetaAddedAt: &now,
	})
}

func (in *CCIngestor) fetchHostIndexPaths(ctx context.Context) ([]string, http.Header, error) {
	body, hdr, err := in.getLimited(ctx, in.HostIndexPathsURL, maxHostIndexPathsBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("fdns ingest-cc Host Index paths: %w", err)
	}
	lines, err := decodePathsBody(body)
	if err != nil {
		return nil, nil, fmt.Errorf("fdns ingest-cc Host Index paths: %w", err)
	}
	if len(lines) == 0 {
		return nil, nil, ErrNoEligibleCrawl
	}
	return lines, hdr, nil
}

// Download GETs each Host Index parquet into ParquetDir (path-relative).
// Matching stored ETag + Content-Length (>0) + local size skips unless Force.
// SkipDownload verifies only. Incomplete downloads return an error (no ClickHouse load).
func (in *CCIngestor) Download(ctx context.Context, man CCManifest) error {
	in.fillDefaults()
	if man.ID == "" || len(man.Paths) == 0 {
		return fmt.Errorf("fdns ingest-cc: empty Host Index manifest")
	}
	if err := os.MkdirAll(in.ParquetDir, 0o755); err != nil {
		return fmt.Errorf("fdns ingest-cc parquet-dir: %w", err)
	}

	jobs := make([]ccFileJob, 0, len(man.Paths))
	for _, rel := range man.Paths {
		fileURL, dest, err := in.localParquet(rel)
		if err != nil {
			return err
		}
		jobs = append(jobs, ccFileJob{URL: fileURL, Dest: dest, Rel: rel})
	}

	if in.SkipDownload {
		var missing []string
		for _, job := range jobs {
			prev := in.meta(job.URL)
			if !fileUnchanged(job.Dest, prev, false) {
				missing = append(missing, job.Rel)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("%w: %d of %d files (e.g. %s)",
				ErrSkipDownloadIncomplete, len(missing), len(jobs), missing[0])
		}
		in.Logger.Info("fdns ingest-cc skip-download: all Host Index parquet files verified",
			zap.String("crawl", man.ID),
			zap.Int("files", len(jobs)),
			zap.String("parquet_dir", in.ParquetDir))
		return nil
	}

	start := time.Now()
	var done atomic.Int64
	var bytesDone atomic.Int64
	var skipped atomic.Int64
	total := int64(len(jobs))

	stopStats := in.startDownloadStats(ctx, start, &done, &bytesDone, total)
	defer stopStats()

	workers := in.Concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}
	ch := make(chan ccFileJob)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range ch {
				if ctx.Err() != nil {
					return
				}
				n, skip, err := in.downloadOne(ctx, job)
				if skip {
					skipped.Add(1)
				}
				if n > 0 {
					bytesDone.Add(n)
				}
				done.Add(1)
				if err != nil {
					in.Logger.Error("fdns ingest-cc parquet GET failed",
						zap.String("url", job.URL), zap.Error(err))
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: %w", job.Rel, err))
					mu.Unlock()
				}
			}
		}()
	}

	for _, job := range jobs {
		select {
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return ctx.Err()
		case ch <- job:
		}
	}
	close(ch)
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("fdns ingest-cc: download incomplete (%d errors); not starting ClickHouse load: %w", len(errs), err)
	}
	elapsed := time.Since(start)
	in.Logger.Info("fdns ingest-cc parquet finished",
		zap.String("crawl", man.ID),
		zap.Int64("files_done", done.Load()),
		zap.Int64("files_total", total),
		zap.Int64("skipped", skipped.Load()),
		zap.String("bytes", formatLogBytes(bytesDone.Load())),
		elapsedField(elapsed),
		etaField(elapsed, done.Load(), total))
	return nil
}

type ccFileJob struct {
	URL  string
	Dest string
	Rel  string
}

func (in *CCIngestor) downloadOne(ctx context.Context, job ccFileJob) (written int64, skipped bool, err error) {
	prev := in.meta(job.URL)
	if !in.Force && fileUnchanged(job.Dest, prev, false) {
		in.Logger.Debug("fdns ingest-cc parquet unchanged", zap.String("url", job.URL))
		if prev != nil && prev.ContentLength != nil {
			return *prev.ContentLength, true, nil
		}
		if fi, statErr := os.Stat(job.Dest); statErr == nil {
			return fi.Size(), true, nil
		}
		return 0, true, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.URL, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("User-Agent", ccUserAgent)
	// Only conditional-GET when we can verify local size against stored Content-Length.
	if !in.Force && metaETag(prev) != "" && contentLengthOK(prev) {
		if _, statErr := os.Stat(job.Dest); statErr == nil {
			req.Header.Set("If-None-Match", metaETag(prev))
		}
	}

	resp, err := in.Client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if !contentLengthOK(prev) {
			return 0, false, fmt.Errorf("304 Not Modified without stored Content-Length > 0; cannot verify size")
		}
		fi, statErr := os.Stat(job.Dest)
		if statErr != nil || fi.Size() != *prev.ContentLength {
			return 0, false, fmt.Errorf("304 Not Modified but local size does not match Content-Length")
		}
		if in.Store != nil {
			if err := in.Store.TouchRemoteFileMetadata(ctx, job.URL); err != nil {
				return 0, false, err
			}
		}
		return fi.Size(), true, nil
	case http.StatusOK:
		// continue
	default:
		return 0, false, fmt.Errorf("status %s", resp.Status)
	}

	want, err := requireContentLength(resp.Header)
	if err != nil {
		io.Copy(io.Discard, resp.Body)
		return 0, false, err
	}

	if err := os.MkdirAll(filepath.Dir(job.Dest), 0o755); err != nil {
		return 0, false, err
	}
	tmp := job.Dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, false, err
	}
	n, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return n, false, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return n, false, closeErr
	}
	if n != want {
		_ = os.Remove(tmp)
		return n, false, fmt.Errorf("short write: got %d bytes, Content-Length %d", n, want)
	}
	if err := os.Rename(tmp, job.Dest); err != nil {
		_ = os.Remove(tmp)
		return n, false, err
	}
	if in.Store != nil {
		in.Store.SaveResponseMetadata(metadataFromHeader(job.URL, resp.Header))
	}
	return n, false, nil
}

func (in *CCIngestor) localParquet(rel string) (fileURL, dest string, err error) {
	rel = normalizeIndexPath(rel)
	if rel == "" || strings.Contains(rel, "..") {
		return "", "", fmt.Errorf("fdns ingest-cc: unsafe parquet path %q", rel)
	}
	fileURL = in.DataBaseURL + "/" + rel
	dest = filepath.Join(in.ParquetDir, filepath.FromSlash(rel))
	absDir, err := filepath.Abs(in.ParquetDir)
	if err != nil {
		return "", "", err
	}
	absFile, err := filepath.Abs(dest)
	if err != nil {
		return "", "", err
	}
	sep := string(os.PathSeparator)
	if absFile != absDir && !strings.HasPrefix(absFile, absDir+sep) {
		return "", "", fmt.Errorf("fdns ingest-cc: path escapes parquet-dir: %s", rel)
	}
	return fileURL, dest, nil
}

func (in *CCIngestor) meta(rawURL string) *postgres.ResponseMetadataItem {
	if in.Store == nil {
		return nil
	}
	m := in.Store.GetResponseMetadata(rawURL)
	if m == nil || m.Url == "" {
		return m
	}
	return m
}

func (in *CCIngestor) getLimited(ctx context.Context, rawURL string, max int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", ccUserAgent)
	resp, err := in.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > max {
		return nil, nil, fmt.Errorf("body exceeds %d bytes", max)
	}
	return body, resp.Header, nil
}

func (in *CCIngestor) startDownloadStats(ctx context.Context, start time.Time, done, bytesDone *atomic.Int64, total int64) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(in.StatsInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				elapsed := time.Since(start)
				d := done.Load()
				in.Logger.Info("fdns ingest-cc download progress",
					zap.Int64("files_done", d),
					zap.Int64("files_total", total),
					zap.String("bytes", formatLogBytes(bytesDone.Load())),
					elapsedField(elapsed),
					etaField(elapsed, d, total))
			}
		}
	}()
	return func() { close(stop) }
}

// fileUnchanged is true only when stored ETag is present, Content-Length > 0,
// and the local file size matches. Missing/zero Content-Length never skips
// (truncated parquet + ETag alone must not be treated as complete).
func fileUnchanged(dest string, prev *postgres.ResponseMetadataItem, force bool) bool {
	if force || metaETag(prev) == "" || !contentLengthOK(prev) {
		return false
	}
	fi, err := os.Stat(dest)
	if err != nil {
		return false
	}
	return fi.Size() == *prev.ContentLength
}

func contentLengthOK(m *postgres.ResponseMetadataItem) bool {
	return m != nil && m.ContentLength != nil && *m.ContentLength > 0
}

// requireContentLength parses Content-Length from a parquet GET response.
// Missing or non-positive values are rejected so size cannot be verified later.
func requireContentLength(h http.Header) (int64, error) {
	cl := strings.TrimSpace(h.Get("Content-Length"))
	if cl == "" {
		return 0, fmt.Errorf("missing Content-Length")
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid Content-Length %q", cl)
	}
	return n, nil
}

func metaETag(m *postgres.ResponseMetadataItem) string {
	if m == nil || m.Etag == nil {
		return ""
	}
	return strings.TrimSpace(*m.Etag)
}

func etaField(elapsed time.Duration, done, total int64) zap.Field {
	if done <= 0 || total <= done {
		return zap.String("eta", "0s")
	}
	rem := time.Duration(float64(elapsed) / float64(done) * float64(total-done))
	return zap.String("eta", rem.Round(time.Second).String())
}

// NormalizeCrawlID accepts CC-MAIN-YYYY-NN (optional whitespace).
func NormalizeCrawlID(raw string) (string, error) {
	id := strings.ToUpper(strings.TrimSpace(raw))
	if _, _, ok := ParseCrawlID(id); !ok {
		return "", fmt.Errorf("fdns ingest-cc: invalid crawl id %q (want CC-MAIN-YYYY-NN)", raw)
	}
	return id, nil
}

// ParseCrawlID splits CC-MAIN-YYYY-NN. Week is the two-digit crawl number, not a calendar month.
func ParseCrawlID(id string) (year, week int, ok bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	var y, w int
	if _, err := fmt.Sscanf(id, "CC-MAIN-%d-%d", &y, &w); err != nil {
		return 0, 0, false
	}
	if y < 2008 || y > 2100 || w < 1 || w > 53 {
		return 0, 0, false
	}
	// Require zero-padded week in the canonical form (CC-MAIN-2026-08 not CC-MAIN-2026-8).
	want := fmt.Sprintf("CC-MAIN-%04d-%02d", y, w)
	if id != want {
		return 0, 0, false
	}
	return y, w, true
}

func crawlIDKey(id string) int {
	y, w, ok := ParseCrawlID(id)
	if !ok {
		return 0
	}
	return y*100 + w
}

// CrawlIDAtLeast reports whether id is the same crawl as min or newer.
func CrawlIDAtLeast(id, min string) bool {
	return crawlIDKey(id) >= crawlIDKey(min)
}

func decodePathsBody(body []byte) ([]string, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty paths body")
	}
	raw := body
	if unzipped, err := gunzip(body); err == nil {
		raw = unzipped
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func normalizeIndexPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "s3://commoncrawl/")
	p = strings.TrimPrefix(p, "https://data.commoncrawl.org/")
	p = strings.TrimPrefix(p, "http://data.commoncrawl.org/")
	p = strings.TrimPrefix(p, "/")
	return p
}

// crawlIDFromHostIndexPath extracts CC-MAIN-YYYY-NN from a Host Index relative path.
func crawlIDFromHostIndexPath(p string) (string, bool) {
	p = normalizeIndexPath(p)
	const marker = "crawl="
	i := strings.Index(p, marker)
	if i < 0 {
		return "", false
	}
	rest := p[i+len(marker):]
	end := strings.IndexByte(rest, '/')
	if end < 0 {
		end = len(rest)
	}
	id, err := NormalizeCrawlID(rest[:end])
	if err != nil {
		return "", false
	}
	return id, true
}

// LatestCrawlFromPaths returns the newest CC-MAIN id present in Host Index path lines.
func LatestCrawlFromPaths(lines []string) (string, error) {
	var best string
	bestKey := 0
	for _, line := range lines {
		id, ok := crawlIDFromHostIndexPath(line)
		if !ok {
			continue
		}
		if k := crawlIDKey(id); k > bestKey {
			bestKey = k
			best = id
		}
	}
	if best == "" {
		return "", ErrNoEligibleCrawl
	}
	return best, nil
}

// FilterHostIndexPaths keeps parquet keys for crawl=<id> under the Host Index v2 prefix.
func FilterHostIndexPaths(lines []string, crawlID string) []string {
	needle := "crawl=" + crawlID + "/"
	var out []string
	seen := map[string]bool{}
	for _, line := range lines {
		p := normalizeIndexPath(line)
		if p == "" || strings.Contains(p, "..") {
			continue
		}
		if !strings.Contains(p, "projects/host-index-testing/v2/") {
			continue
		}
		if !strings.Contains(p, needle) {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(p), ".parquet") {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
