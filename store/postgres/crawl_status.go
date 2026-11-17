package postgres

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"
)

// RibSeedWatermarkURL is the remote_files_metadata sentinel written after a
// successful RouteViews RIB pass. Collector archive URLs change every two
// hours, so a stable key is what status reads. Absence means NEVER: run
// `registry-crawl seed` without --skip-ribs.
const RibSeedWatermarkURL = "registry-crawl:rib-seed"

// RDAPStaleLeaseAfter is how old an in_progress locked_at must be before
// status calls the lease stale. Matches the worker steal window operators
// already reason about (minutes, not the 48h NRO flag).
const RDAPStaleLeaseAfter = 15 * time.Minute

// DefaultNROStaleAfter flags delegated_stats as STALE when ingested_at is
// older than this. Only the NRO row uses it.
const DefaultNROStaleAfter = 48 * time.Hour

// BulkFileRef is one pass-1 WHOIS dump URL and the source it is ingested as.
// Status joins these known URLs to remote_files_metadata; a missing URL is
// never fetched, not "unchanged".
type BulkFileRef struct {
	URL      string `json:"url"`
	Source   string `json:"source"`
	Coverage bool   `json:"coverage"`
}

// CrawlStatusOptions controls FetchCrawlStatus. Zero Now/StaleAfter are
// filled with UTC now and DefaultNROStaleAfter.
type CrawlStatusOptions struct {
	Now        time.Time
	StaleAfter time.Duration
	BulkFiles  []BulkFileRef
	ASNamesURL string
}

// CrawlStatusSnapshot is the read-only registry-crawl status board. Human
// output and --json are two renderings of the same struct.
type CrawlStatusSnapshot struct {
	GeneratedAt time.Time            `json:"generated_at"`
	StaleAfter  string               `json:"stale_after"`
	NRO         NROStatus            `json:"nro"`
	Bulk        []BulkSourceStatus   `json:"bulk"`
	RIB         FileWatermark        `json:"rib"`
	ASNames     ASNamesStatus        `json:"asnames"`
	WhoisDB     []WhoisDBSourceCount `json:"whoisdb"`
	Coverage    CoverageStatus       `json:"coverage"`
	Queue       []QueueSnapshot      `json:"queue"`
	RDAP        RDAPHealth           `json:"rdap"`
}

// NROStatus is the delegated_stats snapshot. Empty or ingested_at older
// than --stale-after is Stale. NRO ingest does not write remote_files_metadata.
type NROStatus struct {
	Rows       int64      `json:"rows"`
	FileDate   *time.Time `json:"file_date"`
	IngestedAt *time.Time `json:"ingested_at"`
	Stale      bool       `json:"stale"`
	Empty      bool       `json:"empty"`
}

// BulkSourceStatus is pass-1 dump fetch state for one source, joined from
// known URLs to remote_files_metadata.
type BulkSourceStatus struct {
	Source   string     `json:"source"`
	LastSeen *time.Time `json:"last_seen"`
	Files    int        `json:"files"`
	Present  int        `json:"present"`
	Missing  bool       `json:"missing"`
	Never    bool       `json:"never"`
	Coverage bool       `json:"coverage"`
}

// FileWatermark is a remote_files_metadata timestamp, or Never if no row.
type FileWatermark struct {
	URL      string     `json:"url"`
	LastSeen *time.Time `json:"last_seen"`
	Never    bool       `json:"never"`
}

// ASNamesStatus is the asnames.txt watermark plus whoisdb_autnum rows
// stamped fetch_method=asnames.
type ASNamesStatus struct {
	FileWatermark
	Rows int64 `json:"rows"`
}

// WhoisDBSourceCount is a full-table COUNT(*) by source. Unlike
// FetchWhoisDBRecordsTypeCountBySource this has no recency window, so a dump
// that parsed 0 rows stays visible. As-set/as-block/irt stay 0 until the next
// pass-1 bulk upserts those tables.
type WhoisDBSourceCount struct {
	Source   string `json:"source"`
	Autnum   int64  `json:"autnum"`
	Inetnum  int64  `json:"inetnum"`
	Inet6num int64  `json:"inet6num"`
	AsSet    int64  `json:"as_set"`
	AsBlock  int64  `json:"as_block"`
	Irt      int64  `json:"irt"`
}

// CoverageStatus compares NRO / crawl_target / whoisdb. Autnum uses
// SUM(range_value) on allocated/assigned ASN rows. Ipnet does not use NRO
// range_value (that is an address count, not a prefix count).
type CoverageStatus struct {
	Autnum []AutnumCoverage `json:"autnum"`
	Ipnet  []IpnetCoverage  `json:"ipnet"`
}

// AutnumCoverage is one registry's ASN census.
type AutnumCoverage struct {
	Registry string `json:"registry"`
	NRO      int64  `json:"nro"`
	Target   int64  `json:"target"`
	WhoisDB  int64  `json:"whoisdb"`
}

// IpnetCoverage compares crawl_target ipnet rows to whoisdb inetnum/inet6num
// for ARIN/LACNIC (the incomplete-dump registries).
type IpnetCoverage struct {
	Registry string `json:"registry"`
	Target   int64  `json:"target"`
	Inetnum  int64  `json:"inetnum"`
	Inet6num int64  `json:"inet6num"`
}

// QueueSnapshot is per-registry state counts for one crawl kind.
type QueueSnapshot struct {
	Kind       string             `json:"kind"`
	Registries []QueueRegistryRow `json:"registries"`
}

// QueueRegistryRow is one registry's pending/in_progress/done/failed/gone
// counts. Zeros are 0, never omitted.
type QueueRegistryRow struct {
	Registry   string `json:"registry"`
	Pending    int64  `json:"pending"`
	InProgress int64  `json:"in_progress"`
	Done       int64  `json:"done"`
	Failed     int64  `json:"failed"`
	Gone       int64  `json:"gone"`
}

// QueueCount is one GROUP BY kind, registry, state row before pivoting.
type QueueCount struct {
	Kind     string
	Registry string
	State    string
	Count    int64
}

// RDAPHealth is queue-wide worker signals, not per-registry.
type RDAPHealth struct {
	Status429         int64         `json:"status_429"`
	StaleLeases       int64         `json:"stale_leases"`
	StaleLeaseAfter   string        `json:"stale_lease_after"`
	OldestPendingAt   *time.Time    `json:"oldest_pending_at"`
	OldestFailedRetry *time.Time    `json:"oldest_failed_retry_at"`
	Errors            []ErrorSample `json:"errors"`
}

// ErrorSample is one distinct last_error and how many rows share it.
type ErrorSample struct {
	Error string `json:"error"`
	Count int64  `json:"count"`
}

// RemoteFileTime is the two timestamps status uses from remote_files_metadata.
type RemoteFileTime struct {
	LastModified *time.Time
	MetaAddedAt  *time.Time
}

// statusRIROrder is the stable board order for the five RIRs, then NIRs.
var statusRIROrder = []string{
	opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE,
	opconst.JPNIC, opconst.KRNIC, opconst.TWNIC,
}

var statusIpnetCoverageOrder = []string{opconst.ARIN, opconst.LACNIC}

var statusQueueKinds = []string{CrawlKindAutnum, CrawlKindIpnet}

// TouchRemoteFileMetadata upserts url with meta_added_at=now() and leaves
// etag/last_modified alone. Used as a watermark, not an HTTP cache entry.
func (st *Store) TouchRemoteFileMetadata(ctx context.Context, url string) error {
	if url == "" {
		return fmt.Errorf("touch remote file metadata: empty url")
	}
	_, err := st.DB.Exec(ctx, `
		INSERT INTO remote_files_metadata (url, meta_added_at)
		VALUES ($1, NOW())
		ON CONFLICT (url) DO UPDATE SET meta_added_at = EXCLUDED.meta_added_at`, url)
	if err != nil {
		return fmt.Errorf("touch remote file metadata %s: %w", url, err)
	}
	return nil
}

// FetchCrawlStatus loads a read-only snapshot. It does not touch the network.
func (st *Store) FetchCrawlStatus(ctx context.Context, opts CrawlStatusOptions) (CrawlStatusSnapshot, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = DefaultNROStaleAfter
	}

	var snap CrawlStatusSnapshot
	snap.GeneratedAt = opts.Now
	snap.StaleAfter = opts.StaleAfter.String()

	nro, err := st.fetchNROStatus(ctx, opts.Now, opts.StaleAfter)
	if err != nil {
		return snap, err
	}
	snap.NRO = nro

	urls := make([]string, 0, len(opts.BulkFiles)+2)
	for _, f := range opts.BulkFiles {
		urls = append(urls, f.URL)
	}
	urls = append(urls, RibSeedWatermarkURL)
	if opts.ASNamesURL != "" {
		urls = append(urls, opts.ASNamesURL)
	}
	times, err := st.listRemoteFileTimes(ctx, urls)
	if err != nil {
		return snap, err
	}

	snap.Bulk = GroupBulkSources(opts.BulkFiles, times)
	snap.RIB = watermarkOf(RibSeedWatermarkURL, times)
	asnamesWM := watermarkOf(opts.ASNamesURL, times)
	asnamesRows, err := st.countWhoisAutnumByFetchMethod(ctx, whoisdb.FetchMethodASNames)
	if err != nil {
		return snap, err
	}
	snap.ASNames = ASNamesStatus{FileWatermark: asnamesWM, Rows: asnamesRows}

	whois, err := st.countWhoisDBBySource(ctx)
	if err != nil {
		return snap, err
	}
	snap.WhoisDB = MergeWhoisDBCounts(whois, knownBulkSources(opts.BulkFiles))

	nroASN, err := st.sumNROAllocatedASNs(ctx)
	if err != nil {
		return snap, err
	}
	queueRows, err := st.listQueueCounts(ctx)
	if err != nil {
		return snap, err
	}
	snap.Queue = PivotQueue(queueRows, statusQueueKinds, statusRIROrder[:5])

	whoisAutnum := whoisAutnumMap(snap.WhoisDB)
	targetAutnum := targetCountMap(queueRows, CrawlKindAutnum)
	targetIpnet := targetCountMap(queueRows, CrawlKindIpnet)
	snap.Coverage.Autnum = MergeAutnumCoverage(nroASN, targetAutnum, whoisAutnum, statusRIROrder[:5])
	snap.Coverage.Ipnet = MergeIpnetCoverage(targetIpnet, snap.WhoisDB, statusIpnetCoverageOrder)

	health, err := st.fetchRDAPHealth(ctx, opts.Now)
	if err != nil {
		return snap, err
	}
	snap.RDAP = health
	return snap, nil
}

func (st *Store) fetchNROStatus(ctx context.Context, now time.Time, staleAfter time.Duration) (NROStatus, error) {
	var rows int64
	var ingested, fileDate *time.Time
	err := st.DB.QueryRow(ctx, `
		SELECT COUNT(*), MAX(ingested_at), MAX(file_date)
		FROM delegated_stats`).Scan(&rows, &ingested, &fileDate)
	if err != nil {
		return NROStatus{}, fmt.Errorf("crawl status nro: %w", err)
	}
	return NROStatus{
		Rows:       rows,
		FileDate:   fileDate,
		IngestedAt: ingested,
		Empty:      rows == 0,
		Stale:      NROIsStale(rows, ingested, staleAfter, now),
	}, nil
}

func (st *Store) listRemoteFileTimes(ctx context.Context, urls []string) (map[string]RemoteFileTime, error) {
	out := make(map[string]RemoteFileTime, len(urls))
	if len(urls) == 0 {
		return out, nil
	}
	pgRows, err := st.DB.Query(ctx, `
		SELECT url, last_modified, meta_added_at
		FROM remote_files_metadata
		WHERE url = ANY($1)`, urls)
	if err != nil {
		return nil, fmt.Errorf("crawl status remote files: %w", err)
	}
	defer pgRows.Close()
	for pgRows.Next() {
		var url string
		var t RemoteFileTime
		if err := pgRows.Scan(&url, &t.LastModified, &t.MetaAddedAt); err != nil {
			return nil, fmt.Errorf("crawl status remote files: %w", err)
		}
		out[url] = t
	}
	return out, pgRows.Err()
}

func (st *Store) countWhoisAutnumByFetchMethod(ctx context.Context, method string) (int64, error) {
	var n int64
	err := st.DB.QueryRow(ctx, `
		SELECT COUNT(*) FROM whoisdb_autnum WHERE fetch_method = $1`, method).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("crawl status asnames rows: %w", err)
	}
	return n, nil
}

func (st *Store) countWhoisDBBySource(ctx context.Context) (map[string]WhoisDBSourceCount, error) {
	const q = `
		SELECT 'autnum', COALESCE(source, ''), COUNT(*) FROM whoisdb_autnum GROUP BY source
		UNION ALL
		SELECT 'inetnum', COALESCE(source, ''), COUNT(*) FROM whoisdb_inetnum GROUP BY source
		UNION ALL
		SELECT 'inet6num', COALESCE(source, ''), COUNT(*) FROM whoisdb_inet6num GROUP BY source
		UNION ALL
		SELECT 'as-set', COALESCE(source, ''), COUNT(*) FROM whoisdb_as_set GROUP BY source
		UNION ALL
		SELECT 'as-block', COALESCE(source, ''), COUNT(*) FROM whoisdb_as_block GROUP BY source
		UNION ALL
		SELECT 'irt', COALESCE(source, ''), COUNT(*) FROM whoisdb_irt GROUP BY source`
	pgRows, err := st.DB.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("crawl status whoisdb counts: %w", err)
	}
	defer pgRows.Close()

	out := make(map[string]WhoisDBSourceCount)
	for pgRows.Next() {
		var kind, source string
		var n int64
		if err := pgRows.Scan(&kind, &source, &n); err != nil {
			return nil, fmt.Errorf("crawl status whoisdb counts: %w", err)
		}
		row := out[source]
		row.Source = source
		switch kind {
		case "autnum":
			row.Autnum = n
		case "inetnum":
			row.Inetnum = n
		case "inet6num":
			row.Inet6num = n
		case string(opconst.RecordTypeAsSet):
			row.AsSet = n
		case string(opconst.RecordTypeAsBlock):
			row.AsBlock = n
		case string(opconst.RecordTypeIrt):
			row.Irt = n
		}
		out[source] = row
	}
	return out, pgRows.Err()
}

func (st *Store) sumNROAllocatedASNs(ctx context.Context) (map[string]int64, error) {
	pgRows, err := st.DB.Query(ctx, `
		SELECT registry, COALESCE(SUM(range_value), 0)::bigint
		FROM delegated_stats
		WHERE resource_type = 'asn' AND status IN ('allocated', 'assigned')
		GROUP BY registry`)
	if err != nil {
		return nil, fmt.Errorf("crawl status nro asn: %w", err)
	}
	defer pgRows.Close()

	out := make(map[string]int64)
	for pgRows.Next() {
		var registry string
		var n int64
		if err := pgRows.Scan(&registry, &n); err != nil {
			return nil, fmt.Errorf("crawl status nro asn: %w", err)
		}
		out[registry] = n
	}
	return out, pgRows.Err()
}

func (st *Store) listQueueCounts(ctx context.Context) ([]QueueCount, error) {
	pgRows, err := st.DB.Query(ctx, `
		SELECT kind, registry, state, COUNT(*)
		FROM crawl_target
		GROUP BY kind, registry, state
		ORDER BY kind, registry, state`)
	if err != nil {
		return nil, fmt.Errorf("crawl status queue: %w", err)
	}
	defer pgRows.Close()

	var out []QueueCount
	for pgRows.Next() {
		var row QueueCount
		if err := pgRows.Scan(&row.Kind, &row.Registry, &row.State, &row.Count); err != nil {
			return nil, fmt.Errorf("crawl status queue: %w", err)
		}
		out = append(out, row)
	}
	return out, pgRows.Err()
}

func (st *Store) fetchRDAPHealth(ctx context.Context, now time.Time) (RDAPHealth, error) {
	leaseCut := now.Add(-RDAPStaleLeaseAfter)
	var h RDAPHealth
	h.StaleLeaseAfter = RDAPStaleLeaseAfter.String()
	err := st.DB.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE last_status_code = 429),
			COUNT(*) FILTER (WHERE state = $1 AND locked_at IS NOT NULL AND locked_at < $2),
			MIN(created_at) FILTER (WHERE state = $3),
			MIN(next_retry_at) FILTER (WHERE state = $4)
		FROM crawl_target`,
		CrawlStateInProgress, leaseCut, CrawlStatePending, CrawlStateFailed,
	).Scan(&h.Status429, &h.StaleLeases, &h.OldestPendingAt, &h.OldestFailedRetry)
	if err != nil {
		return h, fmt.Errorf("crawl status rdap health: %w", err)
	}

	pgRows, err := st.DB.Query(ctx, `
		SELECT last_error, COUNT(*)
		FROM crawl_target
		WHERE last_error IS NOT NULL AND last_error <> ''
		GROUP BY last_error
		ORDER BY COUNT(*) DESC, last_error
		LIMIT 5`)
	if err != nil {
		return h, fmt.Errorf("crawl status rdap errors: %w", err)
	}
	defer pgRows.Close()
	for pgRows.Next() {
		var sample ErrorSample
		if err := pgRows.Scan(&sample.Error, &sample.Count); err != nil {
			return h, fmt.Errorf("crawl status rdap errors: %w", err)
		}
		h.Errors = append(h.Errors, sample)
	}
	if h.Errors == nil {
		h.Errors = []ErrorSample{}
	}
	return h, pgRows.Err()
}

// NROIsStale reports empty snapshots or ingested_at older than staleAfter.
func NROIsStale(rows int64, ingestedAt *time.Time, staleAfter time.Duration, now time.Time) bool {
	if rows == 0 || ingestedAt == nil || ingestedAt.IsZero() {
		return true
	}
	return now.Sub(*ingestedAt) > staleAfter
}

// PickFileTime prefers last_modified, then meta_added_at.
func PickFileTime(t RemoteFileTime) *time.Time {
	if t.LastModified != nil && !t.LastModified.IsZero() {
		return t.LastModified
	}
	if t.MetaAddedAt != nil && !t.MetaAddedAt.IsZero() {
		return t.MetaAddedAt
	}
	return nil
}

// GroupBulkSources joins known pass-1 URLs to metadata. Missing URL = never
// fetched. Sources keep first-seen order from files.
func GroupBulkSources(files []BulkFileRef, times map[string]RemoteFileTime) []BulkSourceStatus {
	type acc struct {
		status BulkSourceStatus
		best   *time.Time
	}
	order := make([]string, 0)
	by := make(map[string]*acc)
	for _, f := range files {
		a, ok := by[f.Source]
		if !ok {
			a = &acc{status: BulkSourceStatus{Source: f.Source, Coverage: f.Coverage}}
			by[f.Source] = a
			order = append(order, f.Source)
		}
		a.status.Files++
		a.status.Coverage = a.status.Coverage || f.Coverage
		seen := PickFileTime(times[f.URL])
		if seen != nil {
			a.status.Present++
			if a.best == nil || seen.After(*a.best) {
				cp := *seen
				a.best = &cp
			}
		}
	}
	out := make([]BulkSourceStatus, 0, len(order))
	for _, src := range order {
		a := by[src]
		a.status.LastSeen = a.best
		a.status.Never = a.status.Present == 0
		a.status.Missing = a.status.Present < a.status.Files
		out = append(out, a.status)
	}
	return out
}

func watermarkOf(url string, times map[string]RemoteFileTime) FileWatermark {
	if url == "" {
		return FileWatermark{Never: true}
	}
	seen := PickFileTime(times[url])
	return FileWatermark{URL: url, LastSeen: seen, Never: seen == nil}
}

// MergeWhoisDBCounts emits a row per known source (zeros included) plus any
// extra sources present in the table, in statusRIROrder then alpha.
func MergeWhoisDBCounts(bySource map[string]WhoisDBSourceCount, known []string) []WhoisDBSourceCount {
	names := uniqueStrings(append(slices.Clone(known), mapKeys(bySource)...))
	sortRegistries(names, statusRIROrder)
	out := make([]WhoisDBSourceCount, 0, len(names))
	for _, src := range names {
		row := bySource[src]
		row.Source = src
		out = append(out, row)
	}
	return out
}

// PivotQueue turns GROUP BY rows into a dense kind x registry table. always
// registries are present with zeros so the board keeps a fixed shape.
func PivotQueue(rows []QueueCount, kinds, always []string) []QueueSnapshot {
	type key struct{ kind, registry string }
	by := make(map[key]*QueueRegistryRow)
	have := make(map[string]map[string]struct{})
	for _, kind := range kinds {
		have[kind] = make(map[string]struct{})
		for _, r := range always {
			have[kind][r] = struct{}{}
			k := key{kind, r}
			by[k] = &QueueRegistryRow{Registry: r}
		}
	}
	for _, row := range rows {
		if have[row.Kind] == nil {
			have[row.Kind] = make(map[string]struct{})
		}
		have[row.Kind][row.Registry] = struct{}{}
		k := key{row.Kind, row.Registry}
		rec := by[k]
		if rec == nil {
			rec = &QueueRegistryRow{Registry: row.Registry}
			by[k] = rec
		}
		switch row.State {
		case CrawlStatePending:
			rec.Pending = row.Count
		case CrawlStateInProgress:
			rec.InProgress = row.Count
		case CrawlStateDone:
			rec.Done = row.Count
		case CrawlStateFailed:
			rec.Failed = row.Count
		case CrawlStateGone:
			rec.Gone = row.Count
		}
	}

	out := make([]QueueSnapshot, 0, len(kinds))
	for _, kind := range kinds {
		regs := make([]string, 0, len(have[kind]))
		for r := range have[kind] {
			regs = append(regs, r)
		}
		sortRegistries(regs, statusRIROrder)
		q := QueueSnapshot{Kind: kind, Registries: make([]QueueRegistryRow, 0, len(regs))}
		for _, r := range regs {
			if rec := by[key{kind, r}]; rec != nil {
				q.Registries = append(q.Registries, *rec)
			}
		}
		out = append(out, q)
	}
	return out
}

// MergeAutnumCoverage unions NRO / crawl_target / whoisdb ASN counts.
func MergeAutnumCoverage(nro, target, whois map[string]int64, always []string) []AutnumCoverage {
	names := uniqueStrings(append(slices.Clone(always), mapKeys(nro)...))
	names = uniqueStrings(append(names, mapKeys(target)...))
	names = uniqueStrings(append(names, mapKeys(whois)...))
	// Empty whoisdb source is asnames, not a registry census.
	names = slices.DeleteFunc(names, func(s string) bool { return s == "" })
	sortRegistries(names, statusRIROrder)
	out := make([]AutnumCoverage, 0, len(names))
	for _, r := range names {
		out = append(out, AutnumCoverage{
			Registry: r,
			NRO:      nro[r],
			Target:   target[r],
			WhoisDB:  whois[r],
		})
	}
	return out
}

// MergeIpnetCoverage compares crawl_target ipnet counts to whoisdb inet rows.
func MergeIpnetCoverage(target map[string]int64, whois []WhoisDBSourceCount, always []string) []IpnetCoverage {
	by := make(map[string]WhoisDBSourceCount, len(whois))
	for _, w := range whois {
		by[w.Source] = w
	}
	names := uniqueStrings(append(slices.Clone(always), mapKeys(target)...))
	sortRegistries(names, statusIpnetCoverageOrder)
	out := make([]IpnetCoverage, 0, len(names))
	for _, r := range names {
		w := by[r]
		out = append(out, IpnetCoverage{
			Registry: r,
			Target:   target[r],
			Inetnum:  w.Inetnum,
			Inet6num: w.Inet6num,
		})
	}
	return out
}

func knownBulkSources(files []BulkFileRef) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, f := range files {
		if _, ok := seen[f.Source]; ok {
			continue
		}
		seen[f.Source] = struct{}{}
		out = append(out, f.Source)
	}
	return out
}

func whoisAutnumMap(rows []WhoisDBSourceCount) map[string]int64 {
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Source] = r.Autnum
	}
	return out
}

func targetCountMap(rows []QueueCount, kind string) map[string]int64 {
	out := make(map[string]int64)
	for _, r := range rows {
		if r.Kind == kind {
			out[r.Registry] += r.Count
		}
	}
	return out
}

func sortRegistries(names []string, order []string) {
	rank := make(map[string]int, len(order))
	for i, n := range order {
		rank[n] = i
	}
	slices.SortStableFunc(names, func(a, b string) int {
		ra, oka := rank[a]
		rb, okb := rank[b]
		switch {
		case oka && okb:
			return ra - rb
		case oka:
			return -1
		case okb:
			return 1
		default:
			return strings.Compare(a, b)
		}
	})
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
