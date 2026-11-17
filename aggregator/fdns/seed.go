package fdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oprand/opr/store/clickhouse"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	// DefaultSeedQueueLimit caps ClickHouse rows this seed-queue run reads.
	DefaultSeedQueueLimit = 5_000_000
	// seedQueueCopyBatch is one Postgres COPY/upsert page.
	seedQueueCopyBatch = 50_000
	seedQueueOrderKey  = "key"
	seedQueueOrderRank = "rank"
	seedQueueDrySample = 20
)

type seedStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	UpsertHostNamesAndEnqueue(ctx context.Context, rows []postgres.HostName, staleAfter time.Duration) (int64, error)
	// CountResolveQueue is approximate (pg_class.reltuples), not count(*).
	CountResolveQueue(ctx context.Context) (int64, error)
}

var _ seedStore = (*postgres.Store)(nil)

type seedClickHouse interface {
	SchemaVersion(ctx context.Context) (version uint, dirty bool, err error)
	QueryTSV(ctx context.Context, query string) (io.ReadCloser, error)
}

var _ seedClickHouse = (*clickhouse.Client)(nil)

// QueueSeeder copies a filtered ClickHouse Host Index slice into Postgres
// fdns_host_name (source=cc) and fdns_resolve_queue.
type QueueSeeder struct {
	Store  seedStore
	CH     seedClickHouse
	Logger *zap.Logger

	MinFetch200    int64
	MinHCRank10    float64
	MinPRank10     float64
	TLDs           []string
	Crawl          string
	Limit          int
	Order          string
	QueueHighWater int
	DryRun         bool
	StaleAfter     time.Duration
	CopyBatch      int
}

// SeedFilter is the ClickHouse WHERE/ORDER/LIMIT used by seed-queue.
type SeedFilter struct {
	MinFetch200 int64
	MinHCRank10 float64
	MinPRank10  float64
	TLDs        []string
	Crawl       string
	Limit       int
	Offset      int
	Order       string
	CursorTLD   string
	CursorHost  string
}

// NewQueueSeeder builds a seed-queue job.
func NewQueueSeeder(logger *zap.Logger, st seedStore, ch seedClickHouse) *QueueSeeder {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &QueueSeeder{
		Store:      st,
		CH:         ch,
		Logger:     logger,
		Limit:      DefaultSeedQueueLimit,
		Order:      seedQueueOrderKey,
		StaleAfter: DefaultResolveStaleAfter,
		CopyBatch:  seedQueueCopyBatch,
	}
}

// Seed streams matching ClickHouse host_name rows, re-runs NormalizeHostname
// (IDNA parity with list ingest), and upserts+enqueues in Postgres.
func (s *QueueSeeder) Seed(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CH == nil {
		return fmt.Errorf("fdns seed-queue: clickhouse client required")
	}
	if s.Store == nil {
		return fmt.Errorf("fdns seed-queue: store is nil")
	}
	if s.Logger == nil {
		s.Logger = zap.NewNop()
	}
	if err := s.assertSchemaVersion(ctx); err != nil {
		return err
	}

	order, err := parseSeedOrder(s.Order)
	if err != nil {
		return err
	}
	insertCap := -1
	if s.QueueHighWater > 0 {
		// CountResolveQueue is pg_class.reltuples (approximate; ANALYZE
		// lag; locked+unlocked; not due). High-water skip/cap uses this
		// so it does not seq-scan fdns_resolve_queue.
		approx, err := s.Store.CountResolveQueue(ctx)
		if err != nil {
			return err
		}
		if approx >= int64(s.QueueHighWater) {
			s.Logger.Info("fdns seed-queue skipped; approximate queue is at high water",
				zap.Int64("queue_approx", approx),
				zap.Int("queue_high_water", s.QueueHighWater))
			return nil
		}
		insertCap = s.QueueHighWater - int(approx)
	}

	limit := s.limit()
	batch := s.copyBatch()
	filter := SeedFilter{
		MinFetch200: s.MinFetch200,
		MinHCRank10: s.MinHCRank10,
		MinPRank10:  s.MinPRank10,
		TLDs:        append([]string(nil), s.TLDs...),
		Crawl:       strings.TrimSpace(s.Crawl),
		Limit:       limit,
		Order:       order,
	}
	if order == seedQueueOrderKey {
		filter.CursorTLD, filter.CursorHost = loadSeedCursor(s.Store)
	}

	s.Logger.Info("fdns seed-queue starting",
		zap.String("crawl", filter.Crawl),
		zap.String("order", order),
		zap.Int("limit", limit),
		zap.Int64("min_fetch_200", s.MinFetch200),
		zap.Float64("min_hcrank10", s.MinHCRank10),
		zap.Float64("min_prank10", s.MinPRank10),
		zap.Strings("tld", filter.TLDs),
		zap.String("cursor_tld", filter.CursorTLD),
		zap.String("cursor_host", filter.CursorHost),
		zap.Bool("dry_run", s.DryRun))

	var (
		pages      int
		chRows     int
		upserted   int
		queued     int64
		dropped    int
		sample     []string
		lastTLD    string
		lastHost   string
		reachedEnd bool
		remaining  = limit
		staleAfter = s.staleAfter()
	)
	for remaining > 0 {
		if insertCap == 0 {
			break
		}
		page := remaining
		if page > batch {
			page = batch
		}
		if insertCap > 0 && page > insertCap {
			page = insertCap
		}
		filter.Limit = page
		query, err := filter.SQL()
		if err != nil {
			return err
		}
		body, err := s.CH.QueryTSV(ctx, query)
		if err != nil {
			return fmt.Errorf("fdns seed-queue clickhouse: %w", err)
		}
		pageRows, names, tld, host, err := readSeedPage(body)
		body.Close()
		if err != nil {
			return err
		}
		pages++
		chRows += pageRows
		dropped += pageRows - len(names)
		if pageRows > 0 {
			lastTLD, lastHost = tld, host
		}
		if insertCap > 0 && len(names) > insertCap {
			names = names[:insertCap]
		}
		if s.DryRun {
			for _, n := range names {
				if len(sample) < seedQueueDrySample {
					sample = append(sample, n)
				}
			}
			upserted += len(names)
			if insertCap > 0 {
				insertCap -= len(names)
				if insertCap < 0 {
					insertCap = 0
				}
			}
		} else if len(names) > 0 {
			now := time.Now().UTC()
			rows := make([]postgres.HostName, len(names))
			for i, name := range names {
				rows[i] = postgres.HostName{
					Name:      name,
					Source:    []string{postgres.HostNameSourceCC},
					FirstSeen: now,
					LastSeen:  now,
				}
			}
			n, err := s.Store.UpsertHostNamesAndEnqueue(ctx, rows, staleAfter)
			if err != nil {
				return err
			}
			upserted += len(names)
			queued += n
			if insertCap > 0 {
				insertCap -= int(n)
				if insertCap < 0 {
					insertCap = 0
				}
			}
		}
		if pageRows == 0 {
			if order == seedQueueOrderKey {
				reachedEnd = true
			}
			break
		}
		if order == seedQueueOrderKey {
			filter.CursorTLD, filter.CursorHost = lastTLD, lastHost
			if !s.DryRun {
				saveSeedCursor(s.Store, lastTLD, lastHost)
			}
		} else {
			filter.Offset += pageRows
		}
		remaining -= pageRows
		if pageRows < page {
			if order == seedQueueOrderKey {
				reachedEnd = true
			}
			break
		}
	}
	if order == seedQueueOrderKey && reachedEnd && !s.DryRun {
		saveSeedCursor(s.Store, "", "")
	}

	s.Logger.Info("fdns seed-queue finished",
		zap.String("crawl", filter.Crawl),
		zap.String("order", order),
		zap.Int("pages", pages),
		zap.Int("clickhouse_rows", chRows),
		zap.Int("names_upserted", upserted),
		zap.Int64("queue_inserted", queued),
		zap.Int("dropped_normalize", dropped),
		zap.Strings("sample", sample),
		zap.String("cursor_tld", filter.CursorTLD),
		zap.String("cursor_host", filter.CursorHost),
		zap.Bool("dry_run", s.DryRun),
		zap.Bool("cursor_reset", order == seedQueueOrderKey && reachedEnd && !s.DryRun))
	return nil
}

func (s *QueueSeeder) assertSchemaVersion(ctx context.Context) error {
	want := clickhouse.LatestVersion()
	version, dirty, err := s.CH.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("fdns seed-queue clickhouse schema version: %w", err)
	}
	if version != want || dirty {
		return fmt.Errorf("fdns seed-queue: clickhouse schema is version %d (dirty=%t), want %d; run `opr clickhouse migrate`",
			version, dirty, want)
	}
	return nil
}

func (s *QueueSeeder) limit() int {
	if s.Limit > 0 {
		return s.Limit
	}
	return DefaultSeedQueueLimit
}

func (s *QueueSeeder) copyBatch() int {
	if s.CopyBatch > 0 {
		return s.CopyBatch
	}
	return seedQueueCopyBatch
}

func (s *QueueSeeder) staleAfter() time.Duration {
	// 0 and negative mean only never-resolved (SQL: $1 <= 0). Do not
	// substitute the 168h default; NewQueueSeeder / CLI flag Value set that.
	if s.StaleAfter < 0 {
		return 0
	}
	return s.StaleAfter
}

func parseSeedOrder(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", seedQueueOrderKey:
		return seedQueueOrderKey, nil
	case seedQueueOrderRank:
		return seedQueueOrderRank, nil
	default:
		return "", fmt.Errorf("fdns seed-queue: unknown --order %q (want key or rank)", s)
	}
}

// SQL is the ClickHouse SELECT for one seed-queue page. Strings are quoted
// with clickhouse.QuoteString. FORMAT is not included; QueryTSV sets it.
func (f SeedFilter) SQL() (string, error) {
	order, err := parseSeedOrder(f.Order)
	if err != nil {
		return "", err
	}
	limit := f.Limit
	if limit < 1 {
		limit = DefaultSeedQueueLimit
	}

	var where []string
	if f.MinFetch200 > 0 {
		where = append(where, fmt.Sprintf("fetch_200 >= %d", f.MinFetch200))
	}
	if f.MinHCRank10 != 0 {
		where = append(where, fmt.Sprintf("hcrank10 >= %g", f.MinHCRank10))
	}
	if f.MinPRank10 != 0 {
		where = append(where, fmt.Sprintf("prank10 >= %g", f.MinPRank10))
	}
	if crawl := strings.TrimSpace(f.Crawl); crawl != "" {
		where = append(where, "crawl = "+clickhouse.QuoteString(crawl))
	}
	if tlds := uniqNonEmpty(f.TLDs); len(tlds) > 0 {
		quoted := make([]string, len(tlds))
		for i, tld := range tlds {
			quoted[i] = clickhouse.QuoteString(tld)
		}
		where = append(where, "url_host_tld IN ("+strings.Join(quoted, ", ")+")")
	}
	if order == seedQueueOrderKey && (f.CursorTLD != "" || f.CursorHost != "") {
		where = append(where, fmt.Sprintf("(url_host_tld, host_name) > (%s, %s)",
			clickhouse.QuoteString(f.CursorTLD), clickhouse.QuoteString(f.CursorHost)))
	}

	cols := "url_host_tld, host_name"
	orderBy := "url_host_tld, host_name"
	if order == seedQueueOrderRank {
		cols = "url_host_tld, host_name, hcrank10, prank10"
		orderBy = "hcrank10 DESC, prank10 DESC, url_host_tld, host_name"
	}

	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(cols)
	b.WriteString(" FROM ")
	b.WriteString(CCHostTable)
	if len(where) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(where, " AND "))
	}
	b.WriteString(" ORDER BY ")
	b.WriteString(orderBy)
	fmt.Fprintf(&b, " LIMIT %d", limit)
	if order == seedQueueOrderRank && f.Offset > 0 {
		fmt.Fprintf(&b, " OFFSET %d", f.Offset)
	}
	return b.String(), nil
}

func loadSeedCursor(st seedStore) (tld, host string) {
	if st == nil {
		return "", ""
	}
	meta := st.GetResponseMetadata(postgres.FDNSCCSeedCursorURL)
	if meta == nil || meta.Charset == nil {
		return "", ""
	}
	raw := strings.TrimSpace(*meta.Charset)
	if raw == "" {
		return "", ""
	}
	tld, host, _ = strings.Cut(raw, "\t")
	return tld, host
}

func saveSeedCursor(st seedStore, tld, host string) {
	if st == nil {
		return
	}
	now := time.Now().UTC()
	charset := tld + "\t" + host
	if tld == "" && host == "" {
		charset = ""
	}
	st.SaveResponseMetadata(&postgres.ResponseMetadataItem{
		Url:         postgres.FDNSCCSeedCursorURL,
		Charset:     &charset,
		MetaAddedAt: &now,
	})
}

func readSeedPage(r io.Reader) (chRows int, names []string, lastTLD, lastHost string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := map[string]struct{}{}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		tld, host, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		// Rank order projects extra columns; host_name is still field 1.
		if rest, _, cut := strings.Cut(host, "\t"); cut {
			host = rest
		}
		lastTLD, lastHost = tld, host
		chRows++
		name, ok := NormalizeHostname(host)
		if !ok {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return 0, nil, "", "", fmt.Errorf("fdns seed-queue read: %w", err)
	}
	return chRows, names, lastTLD, lastHost, nil
}

func uniqNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
