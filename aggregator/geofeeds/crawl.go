package geofeeds

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	DefaultRefreshOlderThan = 168 * time.Hour
	DefaultWorkerCount      = 10
	DefaultQuarantine       = 24 * time.Hour
	DefaultHTTPTimeout      = 90 * time.Second
	// DefaultClaimLease matches aggregator/crawl defaultLease: longer than
	// DefaultHTTPTimeout so a live GET is not reclaimed mid-request.
	DefaultClaimLease = 2 * time.Minute
	defaultClaimBatch = 64
)

var _ CrawlerStore = (*postgres.Store)(nil)

// CrawlerStore is the catalog + derived-row surface the crawler needs.
type CrawlerStore interface {
	ClaimDueGeofeeds(ctx context.Context, batch int, refreshOlderThan, lease time.Duration) ([]postgres.GeofeedRow, error)
	StampGeofeed(ctx context.Context, stamp postgres.GeofeedStamp) error
	ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*postgres.GeoIPItem) error
}

// Crawler fetches unique geofeeds catalog URLs with one conditional GET each.
type Crawler struct {
	Store      CrawlerStore
	HTTPClient *http.Client
	Logger     *zap.Logger
	Workers    int
	Refresh    time.Duration
	Force      bool
	Once       bool
	ClaimBatch int
	Lease      time.Duration
	Timeout    time.Duration
	Quarantine time.Duration
	now        func() time.Time
}

func (c *Crawler) logger() *zap.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return zap.NewNop()
}

func (c *Crawler) nowFn() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Crawler) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: c.timeout()}
}

func (c *Crawler) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultHTTPTimeout
}

func (c *Crawler) workers() int {
	if c.Workers > 0 {
		return c.Workers
	}
	return DefaultWorkerCount
}

func (c *Crawler) refresh() time.Duration {
	if c.Refresh > 0 {
		return c.Refresh
	}
	return DefaultRefreshOlderThan
}

func (c *Crawler) quarantine() time.Duration {
	if c.Quarantine > 0 {
		return c.Quarantine
	}
	return DefaultQuarantine
}

func (c *Crawler) claimBatch() int {
	if c.ClaimBatch > 0 {
		return c.ClaimBatch
	}
	n := c.workers() * 4
	if n < defaultClaimBatch {
		return defaultClaimBatch
	}
	return n
}

func (c *Crawler) lease() time.Duration {
	if c.Lease > 0 {
		return c.Lease
	}
	return DefaultClaimLease
}

// Run claims due catalog URLs and fetches them. Without --once it drains
// currently due URLs (not a daemon loop). --force skips If-None-Match /
// If-Modified-Since. ClaimDueGeofeeds takes a SKIP LOCKED locked_at lease.
func (c *Crawler) Run(ctx context.Context) error {
	if c.Store == nil {
		return fmt.Errorf("geofeed crawl: nil store")
	}
	seen := make(map[string]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		refresh := c.refresh()
		if c.Force {
			refresh = time.Nanosecond
		}
		due, err := c.Store.ClaimDueGeofeeds(ctx, c.claimBatch(), refresh, c.lease())
		if err != nil {
			return fmt.Errorf("geofeed crawl: claim: %w", err)
		}
		jobs := make([]postgres.GeofeedRow, 0, len(due))
		for _, row := range due {
			if row.URL == "" {
				continue
			}
			if _, ok := seen[row.URL]; ok {
				continue
			}
			seen[row.URL] = struct{}{}
			jobs = append(jobs, row)
		}
		if len(jobs) == 0 {
			return nil
		}
		c.runWorkers(ctx, jobs)
		if c.Once {
			return nil
		}
	}
}

func (c *Crawler) runWorkers(ctx context.Context, jobs []postgres.GeofeedRow) {
	ch := make(chan postgres.GeofeedRow)
	var wg sync.WaitGroup
	n := c.workers()
	if n > len(jobs) {
		n = len(jobs)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for row := range ch {
				if err := ctx.Err(); err != nil {
					return
				}
				c.fetchOne(ctx, row)
			}
		}()
	}
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return
		case ch <- job:
		}
	}
	close(ch)
	wg.Wait()
}

func (c *Crawler) fetchOne(ctx context.Context, row postgres.GeofeedRow) {
	logger := c.logger().With(zap.String("url", row.URL))
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, row.URL, nil)
	if err != nil {
		logger.Error("geofeed request", zap.Error(err))
		return
	}
	req.Header.Set("User-Agent", "opr-geofeed")
	req.Header.Set("Accept", "text/csv, text/plain, application/geofeed+csv, */*")
	if !c.Force {
		if row.ETag != nil && strings.TrimSpace(*row.ETag) != "" {
			req.Header.Set("If-None-Match", strings.TrimSpace(*row.ETag))
		}
		if row.LastModified != nil && strings.TrimSpace(*row.LastModified) != "" {
			req.Header.Set("If-Modified-Since", strings.TrimSpace(*row.LastModified))
		}
	}

	resp, err := c.client().Do(req)
	if err != nil {
		logger.Error("geofeed GET", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	switch {
	case status == http.StatusNotModified:
		if err := c.Store.StampGeofeed(ctx, notModifiedStamp(row.URL, resp.Header, c.nowFn())); err != nil {
			logger.Error("stamp 304", zap.Error(err))
		}
		logger.Info("geofeed not modified")
		return
	case status == http.StatusOK:
		c.handleOK(ctx, logger, row, resp)
		return
	case status == http.StatusNotFound || status == http.StatusGone:
		c.quarantineURL(ctx, logger, row.URL, intPtr(status), fmt.Errorf("http %d", status))
		return
	default:
		c.quarantineURL(ctx, logger, row.URL, intPtr(status), fmt.Errorf("http %d", status))
		return
	}
}

func (c *Crawler) handleOK(ctx context.Context, logger *zap.Logger, row postgres.GeofeedRow, resp *http.Response) {
	items, err := parseGeofeedBody(resp.Body, row.URL, resp.Header.Get("Content-Type"))
	if err != nil {
		logger.Warn("geofeed unparseable", zap.Error(err))
		c.quarantineURL(ctx, logger, row.URL, intPtr(http.StatusOK), err)
		return
	}
	// Successful full parse, including zero rows: replace then stamp.
	if err := c.Store.ReplaceGeoIPBySourceURL(ctx, row.URL, items); err != nil {
		logger.Error("replace geoip", zap.Error(err))
		return
	}
	now := c.nowFn()
	count := len(items)
	valid := true
	stamp := postgres.GeofeedStamp{
		URL:             row.URL,
		ETag:            headerPtr(resp.Header, "ETag"),
		LastModified:    headerPtr(resp.Header, "Last-Modified"),
		CacheUntil:      cacheUntilFromHeaders(resp.Header, now),
		LastFetchedAt:   &now,
		LastHTTPStatus:  intPtr(http.StatusOK),
		ItemCount:       &count,
		IsValid:         &valid,
		ClearQuarantine: true,
	}
	if err := c.Store.StampGeofeed(ctx, stamp); err != nil {
		logger.Error("stamp 200", zap.Error(err))
	}
	logger.Info("geofeed fetched", zap.Int("item_count", count))
}

func (c *Crawler) quarantineURL(ctx context.Context, logger *zap.Logger, url string, status *int, cause error) {
	until := c.nowFn().Add(c.quarantine())
	valid := false
	stamp := postgres.GeofeedStamp{
		URL:              url,
		LastHTTPStatus:   status,
		IsValid:          &valid,
		QuarantinedUntil: &until,
	}
	if err := c.Store.StampGeofeed(ctx, stamp); err != nil {
		logger.Error("stamp quarantine", zap.Error(err), zap.NamedError("cause", cause))
		return
	}
	logger.Info("geofeed quarantined", zap.Error(cause), zap.Time("until", until))
}

func notModifiedStamp(url string, h http.Header, now time.Time) postgres.GeofeedStamp {
	status := http.StatusNotModified
	return postgres.GeofeedStamp{
		URL:            url,
		ETag:           headerPtr(h, "ETag"),
		LastModified:   headerPtr(h, "Last-Modified"),
		CacheUntil:     cacheUntilFromHeaders(h, now),
		LastHTTPStatus: &status,
	}
}

func headerPtr(h http.Header, key string) *string {
	v := strings.TrimSpace(h.Get(key))
	if v == "" {
		return nil
	}
	return &v
}

func intPtr(n int) *int { return &n }

func cacheUntilFromHeaders(h http.Header, now time.Time) *time.Time {
	if cc := h.Get("Cache-Control"); cc != "" {
		if t, ok := cacheUntilFromCacheControl(cc, now); ok {
			return t
		}
	}
	if exp := strings.TrimSpace(h.Get("Expires")); exp != "" {
		if t, err := http.ParseTime(exp); err == nil {
			return &t
		}
	}
	return nil
}

func cacheUntilFromCacheControl(cc string, now time.Time) (*time.Time, bool) {
	var maxAge, sMaxAge *int
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "no-store" || part == "no-cache" {
			t := now
			return &t, true
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || n < 0 {
			continue
		}
		switch strings.TrimSpace(name) {
		case "s-maxage":
			sMaxAge = &n
		case "max-age":
			maxAge = &n
		}
	}
	secs := 0
	switch {
	case sMaxAge != nil:
		secs = *sMaxAge
	case maxAge != nil:
		secs = *maxAge
	default:
		return nil, false
	}
	t := now.Add(time.Duration(secs) * time.Second)
	return &t, true
}
