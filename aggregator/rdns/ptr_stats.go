package rdns

import (
	"context"
	"sync"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

// PTRCrawlStats is a point-in-time snapshot for the 5-minute crawl-ptr ticker.
type PTRCrawlStats struct {
	Elapsed         time.Duration
	BlocksDone      int64
	BlocksRemaining int64
	QueuePending    int64
	QueueLeased     int64
	QueueDone       int64
	QueueFailed     int64
	PTRQueries      int64
	Upserts         int64
	Rcodes          map[string]int64
	CurrentPrefix   string
	CurrentZone     string
	CurrentNS       string
	ApproxQPS       float64
}

// ApproxPTRQPS is queries / elapsed seconds (0 if elapsed is 0).
func ApproxPTRQPS(queries int64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(queries) / elapsed.Seconds()
}

// ZapFields is the opr.rdns.crawl-ptr debug/info snapshot.
func (s PTRCrawlStats) ZapFields() []zap.Field {
	return []zap.Field{
		zap.String("elapsed", s.Elapsed.Round(time.Second).String()),
		zap.Int64("blocks_done", s.BlocksDone),
		zap.Int64("blocks_remaining", s.BlocksRemaining),
		zap.Int64("queue_pending", s.QueuePending),
		zap.Int64("queue_leased", s.QueueLeased),
		zap.Int64("queue_done", s.QueueDone),
		zap.Int64("queue_failed", s.QueueFailed),
		zap.Int64("ptr_queries", s.PTRQueries),
		zap.Int64("upserts", s.Upserts),
		zap.Any("rcodes", s.Rcodes),
		zap.String("current_prefix", s.CurrentPrefix),
		zap.String("current_zone", s.CurrentZone),
		zap.String("current_ns", s.CurrentNS),
		zap.Float64("approx_qps", s.ApproxQPS),
	}
}

type ptrRunStats struct {
	mu            sync.Mutex
	started       time.Time
	blocksDone    int64
	remaining     int64
	queuePending  int64
	queueLeased   int64
	queueDone     int64
	queueFailed   int64
	queries       int64
	upserts       int64
	rcodes        map[string]int64
	currentPrefix string
	currentZone   string
	currentNS     string
}

func newPTRRunStats() *ptrRunStats {
	return &ptrRunStats{
		started: time.Now(),
		rcodes:  make(map[string]int64),
	}
}

func (s *ptrRunStats) addQuery(rcode, ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	if rcode != "" {
		s.rcodes[rcode]++
	}
	if ns != "" {
		s.currentNS = ns
	}
}

func (s *ptrRunStats) addUpserts(n int64) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts += n
}

func (s *ptrRunStats) addBlockDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocksDone++
	if s.remaining > 0 {
		s.remaining--
	}
}

func (s *ptrRunStats) addBlockFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queueFailed++
	if s.remaining > 0 {
		s.remaining--
	}
}

func (s *ptrRunStats) setRemaining(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remaining = n
}

func (s *ptrRunStats) setCurrent(prefix, zone, ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentPrefix = prefix
	s.currentZone = zone
	if ns != "" {
		s.currentNS = ns
	}
}

func (s *ptrRunStats) setQueue(c postgres.RDNSPTRBlockCounts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queuePending = c.Pending
	s.queueLeased = c.Leased
	s.queueDone = c.Done
	s.queueFailed = c.Failed
	s.remaining = c.Pending + c.Leased
}

func (s *ptrRunStats) snapshot() PTRCrawlStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed := time.Since(s.started)
	rc := make(map[string]int64, len(s.rcodes))
	for k, v := range s.rcodes {
		rc[k] = v
	}
	return PTRCrawlStats{
		Elapsed:         elapsed,
		BlocksDone:      s.blocksDone,
		BlocksRemaining: s.remaining,
		QueuePending:    s.queuePending,
		QueueLeased:     s.queueLeased,
		QueueDone:       s.queueDone,
		QueueFailed:     s.queueFailed,
		PTRQueries:      s.queries,
		Upserts:         s.upserts,
		Rcodes:          rc,
		CurrentPrefix:   s.currentPrefix,
		CurrentZone:     s.currentZone,
		CurrentNS:       s.currentNS,
		ApproxQPS:       ApproxPTRQPS(s.queries, elapsed),
	}
}

func (c *PTRCrawler) startPTRStats(ctx context.Context, st *ptrRunStats) func() {
	c.logPTRStats(st)
	interval := c.StatsInterval
	if interval <= 0 {
		interval = PTRStatsInterval
	}
	tick := time.NewTicker(interval)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			select {
			case <-tick.C:
				c.refreshQueueCounts(ctx, st)
				c.logPTRStats(st)
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	return func() {
		once.Do(func() {
			tick.Stop()
			close(done)
		})
	}
}

func (c *PTRCrawler) logPTRStats(st *ptrRunStats) {
	if c.Logger == nil {
		return
	}
	c.Logger.Info("rdns crawl-ptr stats", st.snapshot().ZapFields()...)
}

func (c *PTRCrawler) refreshQueueCounts(ctx context.Context, st *ptrRunStats) {
	if c.Store == nil || c.scoped() {
		return
	}
	counts, err := c.Store.CountRDNSPTRBlocks(ctx)
	if err != nil {
		c.Logger.Debug("rdns crawl-ptr queue counts", zap.Error(err))
		return
	}
	st.setQueue(counts)
}
