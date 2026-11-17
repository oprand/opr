package whoisdb

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/opnet"
	"github.com/oprand/opr/store/postgres"

	"github.com/jlaffaye/ftp"
	"go.uber.org/zap"
)

// DefaultPrefetchDepth is how many sources are fetched ahead of the parse loop.
// It bounds concurrent downloads and, because each fetch lands in its own temp
// file that the parse loop deletes after use, also bounds temp files on disk.
const DefaultPrefetchDepth = 3

// downloadRetries matches the retry count the sequential downloader used.
const downloadRetries = 3

// prefetchJob is one source paired with the object types this pass wants from
// it. The same URL can appear in two jobs with disjoint types.
type prefetchJob struct {
	src      whoisDBSource
	accepted []opconst.RecordType
	// forceDownload skips the ETag check. Needed when an earlier pass in this
	// same run already fetched this URL and committed its new ETag, which would
	// otherwise make this job look unchanged and get skipped.
	forceDownload bool
}

// prefetchResult is a finished fetch handed to the parse loop. Exactly one of
// path / unchanged / err is meaningful.
type prefetchResult struct {
	job       prefetchJob
	status    *WhoisDBURLStatus
	path      string
	metadata  *postgres.ResponseMetadataItem
	charset   string
	unchanged bool
	err       error
}

// cleanup removes the temp file. Safe to call more than once and on a
// zero-value result, so every exit path can call it unconditionally.
func (r *prefetchResult) cleanup() {
	if r == nil || r.path == "" {
		return
	}
	os.Remove(r.path)
	r.path = ""
}

// statusKey identifies one job in StatusMetadata.URLs. Keying on the URL alone
// lets the pass-2 job for a mixed dump overwrite the pass-1 entry, losing the
// pass-1 parse counts and health verdict for that file.
func statusKey(u string, accepted []opconst.RecordType) string {
	parts := make([]string, len(accepted))
	for i, t := range accepted {
		parts[i] = string(t)
	}
	return u + "|" + strings.Join(parts, ",")
}

// forceRefetchDuplicates marks every later job whose URL an earlier pass in this
// run already covers, so the later pass downloads the file instead of trusting
// the ETag check.
//
// remote_files_metadata is UNIQUE(url), so one URL has exactly one stored ETag no
// matter how many object-type passes read it. That breaks a duplicated URL two
// different ways, and both end with the later pass parsing nothing:
//
//   - the earlier pass downloaded the file and committed the current ETag, so
//     the later pass compares against an ETag from minutes ago and sees no
//     change;
//   - the server sends no ETag at all, so the stored value is "" and matches ""
//     forever, and neither pass ever downloads again.
//
// The second case is why this is unconditional rather than keyed on whether the
// earlier pass actually downloaded: skipping on that evidence would leave ARIN
// and AFRINIC route objects permanently unfetched for any source without ETag
// headers, which is the exact gap pass 2 exists to close. The cost is one extra
// download per duplicated URL per run.
func forceRefetchDuplicates(earlier, later []prefetchJob) {
	seen := make(map[string]struct{}, len(earlier))
	for _, j := range earlier {
		seen[j.src.url] = struct{}{}
	}
	for i := range later {
		if _, dup := seen[later[i].src.url]; dup {
			later[i].forceDownload = true
		}
	}
}

// runPass downloads every job with up to PrefetchDepth fetches in flight and
// parses them strictly in list order.
//
// Only downloads are concurrent. Parsing and saving stay single-owner exactly as
// before: one parser at a time, one unbuffered RecordChan, one SaveWhoisRecords
// goroutine owning every buffer. Nothing on the parse path needs a lock, and the
// status entries are registered here - sequentially, before any fetch starts - so
// the fetch goroutines only ever write to their own WhoisDBURLStatus and never
// to the map itself.
func (wdb *WhoisDBAggregator) runPass(ctx context.Context, jobs []prefetchJob) {
	if len(jobs) == 0 || ctx.Err() != nil {
		return
	}

	// Registered here, sequentially, before any fetch starts.
	statuses := make([]*WhoisDBURLStatus, len(jobs))
	for i, job := range jobs {
		statuses[i] = wdb.registerStatus(job)
	}

	prefetchPipeline(ctx, len(jobs), wdb.PrefetchDepth,
		func(ctx context.Context, i int) *prefetchResult {
			return wdb.fetchSource(ctx, jobs[i], statuses[i])
		},
		func(res *prefetchResult) {
			wdb.parsePrefetched(ctx, res)
		},
	)
}

// prefetchPipeline runs n fetches with at most depth in flight and hands each
// result to consume strictly in index order. consume is never called
// concurrently with itself, which is what keeps the parse path single-owner.
//
// A slot is held from before a fetch starts until after consume has returned and
// the temp file is gone, so at most depth temp files exist at any time. The
// spawner takes slots in index order, so job i always holds one before job i+1
// asks: the in-order consumer can never end up waiting on a job that has not
// been given a slot.
func prefetchPipeline(
	ctx context.Context,
	n, depth int,
	fetch func(context.Context, int) *prefetchResult,
	consume func(*prefetchResult),
) {
	if n == 0 {
		return
	}
	if depth < 1 {
		depth = 1
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]chan *prefetchResult, n)
	for i := range results {
		results[i] = make(chan *prefetchResult, 1)
	}
	slots := make(chan struct{}, depth)

	// The spawner deliberately does not bail out on cancellation: the consumer
	// below waits on every index, so a job that was never spawned would hang it.
	// On cancellation each fetch fails fast instead, and the consumer drains and
	// cleans up the rest.
	go func() {
		for i := 0; i < n; i++ {
			slots <- struct{}{}
			go func(i int) {
				results[i] <- fetch(ctx, i)
			}(i)
		}
	}()

	for i := 0; i < n; i++ {
		res := <-results[i]
		if ctx.Err() == nil {
			consume(res)
		}
		// Delete before releasing the slot so the slot count really does bound
		// temp files on disk, and so nothing is left behind on an early exit.
		res.cleanup()
		<-slots
	}
}

// registerStatus creates the status entry for a job. Called sequentially from
// runPass before any fetch goroutine starts.
func (wdb *WhoisDBAggregator) registerStatus(job prefetchJob) *WhoisDBURLStatus {
	types := make([]string, len(job.accepted))
	for i, t := range job.accepted {
		types[i] = string(t)
	}
	st := &WhoisDBURLStatus{
		URL:             job.src.url,
		RecordTypes:     types,
		Source:          job.src.source,
		IsAuthoritative: job.src.isAuthoritative,
		StartTime:       time.Now(),
		IsRunning:       true,
		HasChanged:      true,
	}
	wdb.StatusMetadata.URLs[statusKey(job.src.url, job.accepted)] = st
	return st
}

// fetchSource resolves the ETag and, if needed, streams the body into a temp
// file. It never parses and never touches a buffer, so several of these run
// concurrently. A failure here is returned, not fatal: the parse loop logs it
// and moves to the next source, matching the old behaviour on download failure.
func (wdb *WhoisDBAggregator) fetchSource(ctx context.Context, job prefetchJob, status *WhoisDBURLStatus) *prefetchResult {
	logger := wdb.Logger.With(zap.String("url", job.src.url))
	res := &prefetchResult{job: job, status: status}
	if err := ctx.Err(); err != nil {
		res.err = err
		return res
	}
	// Reset now that this job is actually starting, so JobDuration measures
	// fetch-plus-parse rather than time spent queued behind the parse loop.
	status.StartTime = time.Now()

	// 1. Has the remote file changed since last run?
	newMetadata, changed := opnet.HasFileChanged(wdb.Store, wdb.HTTPClient, job.src.url)
	res.metadata = newMetadata
	switch {
	case newMetadata == nil:
		logger.Warn("unable to get new metadata for whoisdb file, downloading anyway")
		status.HasChanged = true
	case job.forceDownload && !changed:
		// Same file, second pass of this run, for a different object type set.
		logger.Info("re-downloading whoisdb file for a second object type pass",
			zap.Strings("record_types", status.RecordTypes))
		status.HasChanged = true
	case !changed:
		logger.Info("whoisdb file not changed", zap.String("etag", etagOf(newMetadata)))
		status.HasChanged = false
		res.unchanged = true
		return res
	default:
		logger.Info("downloading whoisdb file", zap.String("etag", etagOf(newMetadata)))
	}

	// 2. Resolve the charset once, from the source override or what the server
	//    declared in Content-Type.
	res.charset = resolveCharset(job.src, newMetadata)
	status.Charset = res.charset

	// 3. Stream to a temp file. Keeping the body out of RAM is the whole point:
	//    with a prefetch depth of k the cost is O(k x filesize) on disk and
	//    O(1) in memory, instead of O(k x filesize) resident.
	startDownloadTime := time.Now()
	for attempt := 0; attempt < downloadRetries; attempt++ {
		path, err := wdb.downloadToTempFile(ctx, job.src.url, status)
		if err == nil {
			res.path = path
			status.FetchError = ""
			logger.Info("downloaded whoisdb file to temp file",
				zap.String("duration", time.Since(startDownloadTime).String()),
				zap.String("path", path),
			)
			return res
		}
		if ctx.Err() != nil {
			res.err = ctx.Err()
			return res
		}
		logger.Error("error downloading whoisdb file", zap.Error(err), zap.Int("attempt", attempt+1))
		status.FetchError = err.Error()
		res.err = err
	}
	logger.Error("giving up downloading whoisdb file", zap.Int("retries", downloadRetries))
	return res
}

// downloadToTempFile copies one source into a fresh temp file and returns its
// path. The file is removed here on any failure so a retry cannot leak it; on
// success the parse loop owns it.
func (wdb *WhoisDBAggregator) downloadToTempFile(ctx context.Context, srcURL string, status *WhoisDBURLStatus) (string, error) {
	body, closeBody, err := wdb.openSource(ctx, srcURL, status)
	if err != nil {
		return "", err
	}
	defer closeBody()

	f, err := os.CreateTemp("", "opr-whoisdb-*.gz")
	if err != nil {
		return "", fmt.Errorf("create temp file for %s: %w", srcURL, err)
	}
	path := f.Name()

	n, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(path)
		return "", fmt.Errorf("download %s: %w", srcURL, copyErr)
	}
	if closeErr != nil {
		os.Remove(path)
		return "", fmt.Errorf("close temp file for %s: %w", srcURL, closeErr)
	}
	if n == 0 {
		os.Remove(path)
		return "", fmt.Errorf("download %s: empty body", srcURL)
	}
	return path, nil
}

// openSource dials one source and returns its body. Both http(s) and ftp are
// supported, as in the sequential downloader this replaced.
func (wdb *WhoisDBAggregator) openSource(ctx context.Context, srcURL string, status *WhoisDBURLStatus) (io.Reader, func(), error) {
	switch {
	case strings.HasPrefix(srcURL, "http"):
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
		if err != nil {
			return nil, nil, err
		}
		resp, err := wdb.HTTPClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		if resp == nil {
			return nil, nil, fmt.Errorf("nil response for %s", srcURL)
		}
		status.HTTPStatus = resp.Status
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, nil, fmt.Errorf("bad status code %d for %s", resp.StatusCode, srcURL)
		}
		return resp.Body, func() { resp.Body.Close() }, nil

	case strings.HasPrefix(srcURL, "ftp://"):
		return wdb.openFTP(ctx, srcURL)

	default:
		return nil, nil, fmt.Errorf("unsupported url scheme: %s", srcURL)
	}
}

// ftpDialTimeout is how long an FTP control connection may take to come up.
// Cancel closes the socket instead of waiting this out.
const ftpDialTimeout = 20 * time.Minute

// openFTP dials and retrieves in a goroutine. ctx.Done closes the control
// connection (and the raw socket, if Dial has not returned a client yet) and
// returns ctx.Err() so a cancelled bulk job does not sit in ftp.Dial or Retr.
func (wdb *WhoisDBAggregator) openFTP(ctx context.Context, srcURL string) (io.Reader, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ftpURL, err := url.Parse(srcURL)
	if err != nil {
		return nil, nil, err
	}

	type ftpResult struct {
		resp   *ftp.Response
		client *ftp.ServerConn
		err    error
	}
	done := make(chan ftpResult, 1)

	var mu sync.Mutex
	var rawConn net.Conn
	var client *ftp.ServerConn
	stopped := false

	// stop unblocks Dial or Retr. Only one caller Quits the client; a second
	// call sees a nil client. The library client is not safe to use concurrently.
	stop := func() {
		mu.Lock()
		stopped = true
		c := client
		raw := rawConn
		client = nil
		rawConn = nil
		mu.Unlock()
		if c != nil {
			c.Quit()
			return
		}
		if raw != nil {
			raw.Close()
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				err := ctx.Err()
				if err == nil {
					err = fmt.Errorf("ftp: %v", r)
				}
				select {
				case done <- ftpResult{err: err}:
				default:
				}
			}
		}()
		c, dialErr := ftp.Dial(ftpURL.Host,
			ftp.DialWithTimeout(ftpDialTimeout),
			ftp.DialWithDialFunc(func(network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: ftpDialTimeout}
				conn, err := d.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				defer mu.Unlock()
				if stopped || ctx.Err() != nil {
					conn.Close()
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return nil, net.ErrClosed
				}
				rawConn = conn
				return conn, nil
			}),
		)
		if dialErr != nil {
			if ctx.Err() != nil {
				dialErr = ctx.Err()
			}
			done <- ftpResult{err: dialErr}
			return
		}
		mu.Lock()
		if stopped || ctx.Err() != nil {
			mu.Unlock()
			c.Quit()
			done <- ftpResult{err: ctx.Err()}
			return
		}
		client = c
		mu.Unlock()

		if err := c.Login("anonymous", "anonymous"); err != nil {
			stop()
			done <- ftpResult{err: err}
			return
		}
		resp, err := c.Retr(ftpURL.Path)
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			stop()
			done <- ftpResult{err: err}
			return
		}
		if ctx.Err() != nil {
			resp.Close()
			stop()
			done <- ftpResult{err: ctx.Err()}
			return
		}
		done <- ftpResult{resp: resp, client: c}
	}()

	select {
	case <-ctx.Done():
		stop()
		// The dial goroutine may still finish after we return. Drain it so a
		// response that won the race is closed, and so the send cannot block.
		go func() {
			res := <-done
			if res.resp != nil {
				res.resp.Close()
			}
		}()
		return nil, nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, nil, res.err
		}
		return res.resp, func() {
			res.resp.Close()
			res.client.Quit()
		}, nil
	}
}

// etagOf is nil-safe. HasFileChanged has a branch that returns an entry with no
// ETag, unreachable today only because GetResponseMetadata returns a zero struct
// rather than nil on no rows.
func etagOf(meta *postgres.ResponseMetadataItem) string {
	if meta == nil || meta.Etag == nil {
		return ""
	}
	return *meta.Etag
}

// resolveCharset picks the decoder for one file: an explicit per-source override
// first, then what the server declared in Content-Type (the same signal the
// geofeed parser uses), then per-line autodetection.
func resolveCharset(src whoisDBSource, meta *postgres.ResponseMetadataItem) string {
	if src.charset != "" {
		return src.charset
	}
	if meta != nil && meta.Charset != nil {
		if declared := strings.ToLower(strings.TrimSpace(*meta.Charset)); declared != "" {
			switch declared {
			case "iso-8859-1", "latin1", "latin-1", "iso8859-1":
				return CharsetISO8859
			case "utf-8", "utf8":
				return CharsetUTF8
			}
		}
	}
	return CharsetAuto
}
