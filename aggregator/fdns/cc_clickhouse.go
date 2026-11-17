package fdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/store/clickhouse"

	"go.uber.org/zap"
)

const (
	// CCHostTable is the live Host Index table. CCHostLoadTable is its staging
	// twin; EXCHANGE TABLES swaps the two once a load is complete.
	CCHostTable     = "fdns_cc_host"
	CCHostLoadTable = "fdns_cc_host_load"
	// CCLoadPartTable is the per-part ledger that makes a failed load resumable.
	CCLoadPartTable = "fdns_cc_load_part"
)

// ccHostNameExpr un-SURTs surt_host_name into a dotted FQDN (uk,co,bbc → bbc.co.uk).
const ccHostNameExpr = `arrayStringConcat(arrayReverse(splitByChar(',', surt_host_name)), '.')`

// ccValidDNSNameRegex is validDNSName from parse.go as RE2: at least two
// labels, 1-63 chars each, [a-z0-9-] only, no leading or trailing hyphen. SURT
// values are already lowercase ASCII punycode, so there is nothing to case
// fold. Unlike NormalizeHostname it does not check that xn-- labels decode;
// the seeder re-runs NormalizeHostname in Go on the filtered slice.
// The doubled backslash is the ClickHouse string literal escape for \. in RE2.
const ccValidDNSNameRegex = `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`

// ccColumn is one Host Index Parquet column. Type is what input() declares;
// the table may widen it with a codec (see migration 0001).
type ccColumn struct {
	Name string
	Type string
}

// ccSwapMarkerPath is a ledger path that is not a parquet file. It is written
// only after EXCHANGE TABLES succeeds, and the ledger is truncated only after
// that marker and the load-table truncate have both succeeded. A resume that
// sees it finishes cleanup and does not insert again.
const ccSwapMarkerPath = "fdns-cc-swap-complete"

// ccHostIndexColumns are the 42 physical Host Index Parquet columns in
// migration 0001 order, minus crawl. crawl is a hive path segment
// (crawl=CC-MAIN-...), not a file column; ccInsertSQL injects it from the
// manifest id so the table's crawl column is still populated.
var ccHostIndexColumns = []ccColumn{
	{"surt_host_name", "String"},
	{"url_host_tld", "String"},
	{"url_host_registered_domain", "String"},
	{"fetch_200", "Int64"},
	{"fetch_200_lote", "Int64"},
	{"fetch_200_lote_pct", "Int8"},
	{"fetch_3xx", "Int64"},
	{"fetch_4xx", "Int64"},
	{"fetch_5xx", "Int64"},
	{"fetch_gone", "Int64"},
	{"fetch_notModified", "Int64"},
	{"fetch_other", "Int64"},
	{"fetch_redirPerm", "Int64"},
	{"fetch_redirTemp", "Int64"},
	{"nutch_fetched", "Int64"},
	{"nutch_fetched_pct", "Int8"},
	{"nutch_gone", "Int64"},
	{"nutch_gone_pct", "Int8"},
	{"nutch_notModified", "Int64"},
	{"nutch_notModified_pct", "Int8"},
	{"nutch_numRecords", "Int64"},
	{"nutch_redirPerm", "Int64"},
	{"nutch_redirPerm_pct", "Int8"},
	{"nutch_redirTemp", "Int64"},
	{"nutch_redirTemp_pct", "Int8"},
	{"nutch_unfetched", "Int64"},
	{"nutch_unfetched_pct", "Int8"},
	{"robots_200", "Int64"},
	{"robots_3xx", "Int64"},
	{"robots_4xx", "Int64"},
	{"robots_5xx", "Int64"},
	{"robots_gone", "Int64"},
	{"robots_notModified", "Int64"},
	{"robots_other", "Int64"},
	{"robots_redirPerm", "Int64"},
	{"robots_redirTemp", "Int64"},
	{"warc_record_length_av", "Int64"},
	{"warc_record_length_median", "Int64"},
	{"hcrank", "Float64"},
	{"hcrank10", "Float64"},
	{"prank", "Float64"},
	{"prank10", "Float64"},
}

// ccQuoteIdent backtick-quotes identifiers that are not plain lowercase so the
// camelCase Host Index names (robots_redirPerm, nutch_numRecords, ...) survive.
func ccQuoteIdent(name string) string {
	if strings.ToLower(name) == name {
		return name
	}
	return "`" + name + "`"
}

// ccInsertSQL un-SURTs and validates host_name while the Parquet part streams
// in, so there is no staging pass. Parquet columns are matched by name, which
// is why input() repeats the file's own column names. crawl is not one of
// those columns; it is injected as a string literal from the manifest id.
func ccInsertSQL(crawl string) string {
	crawlLiteral := clickhouse.QuoteString(crawl)
	target := make([]string, 0, len(ccHostIndexColumns)+2)
	projection := make([]string, 0, len(ccHostIndexColumns)+2)
	structure := make([]string, 0, len(ccHostIndexColumns))

	target = append(target, "host_name")
	projection = append(projection, "    "+ccHostNameExpr+" AS host_name")
	for _, col := range ccHostIndexColumns {
		ident := ccQuoteIdent(col.Name)
		target = append(target, ident)
		projection = append(projection, "    "+ident)
		structure = append(structure, ident+" "+col.Type)
		if col.Name == "surt_host_name" {
			target = append(target, "crawl")
			projection = append(projection, "    "+crawlLiteral+" AS crawl")
		}
	}

	return fmt.Sprintf(`INSERT INTO %s (%s)
SELECT
%s
FROM input('%s')
WHERE surt_host_name != ''
  AND length(host_name) <= 253
  AND match(host_name, '%s')
FORMAT Parquet`,
		CCHostLoadTable,
		strings.Join(target, ", "),
		strings.Join(projection, ",\n"),
		strings.Join(structure, ", "),
		ccValidDNSNameRegex)
}

// loadClickHouse wipes fdns_cc_host_load (unless a previous run left parts in
// the ledger), POSTs every verified Parquet part, and swaps the result into
// fdns_cc_host. A failed part aborts before the swap, so the live table keeps
// its previous snapshot and the retry skips what already landed.
func (in *CCIngestor) loadClickHouse(ctx context.Context, man CCManifest) (int64, error) {
	if in.CH == nil {
		return 0, fmt.Errorf("fdns ingest-cc: clickhouse client required")
	}
	if err := in.assertSchemaVersion(ctx); err != nil {
		return 0, err
	}

	paths, err := in.verifiedLocalParquet(man)
	if err != nil {
		return 0, err
	}
	paths, err = ccAbsPaths(paths)
	if err != nil {
		return 0, err
	}
	loaded, swapped, err := in.loadedParts(ctx, man.ID)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if swapped {
		in.Logger.Info("fdns ingest-cc clickhouse swap already recorded; finishing cleanup",
			zap.String("crawl", man.ID))
		return in.finishAlreadySwapped(ctx, man.ID, start)
	}
	if ccPartsAllLoaded(paths, loaded) {
		already, err := in.hostHoldsSwappedCrawl(ctx, man.ID)
		if err != nil {
			return 0, err
		}
		if already {
			in.Logger.Info("fdns ingest-cc clickhouse swap already applied; finishing cleanup",
				zap.String("crawl", man.ID))
			return in.finishAlreadySwapped(ctx, man.ID, start)
		}
	}
	if len(loaded) == 0 {
		if err := in.CH.Exec(ctx, "TRUNCATE TABLE "+CCHostLoadTable); err != nil {
			return 0, fmt.Errorf("fdns ingest-cc truncate %s: %w", CCHostLoadTable, err)
		}
	}

	todo := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, done := loaded[path]; !done {
			todo = append(todo, path)
		}
	}
	in.Logger.Info("fdns ingest-cc clickhouse load starting",
		zap.String("crawl", man.ID),
		zap.Int("parts_total", len(paths)),
		zap.Int("parts_todo", len(todo)),
		zap.String("table", CCHostLoadTable))

	insert := ccInsertSQL(man.ID)
	var bytesDone int64
	for i, path := range todo {
		// Gate on the same absolute key recordLoadedPart writes, so a retry
		// cannot insert a part the ledger already counts as done.
		if _, done := loaded[path]; done {
			continue
		}
		rows, n, err := in.CH.InsertFile(ctx, insert, path)
		if err != nil {
			return 0, fmt.Errorf("fdns ingest-cc clickhouse insert %s: %w", filepath.Base(path), err)
		}
		if err := in.recordLoadedPart(ctx, man.ID, path, rows); err != nil {
			return 0, err
		}
		loaded[path] = struct{}{}
		bytesDone += n
		elapsed := time.Since(start)
		in.Logger.Info("fdns ingest-cc clickhouse part loaded",
			zap.String("crawl", man.ID),
			zap.String("part", filepath.Base(path)),
			zap.Int64("rows", rows),
			zap.String("bytes", formatLogBytes(bytesDone)),
			elapsedField(elapsed),
			etaField(elapsed, int64(i+1), int64(len(todo))))
	}

	total, err := in.countLoadTable(ctx)
	if err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, fmt.Errorf("fdns ingest-cc: %s is empty after %d parts; not swapping %s",
			CCHostLoadTable, len(paths), CCHostTable)
	}
	already, err := in.hostHoldsSwappedCrawl(ctx, man.ID)
	if err != nil {
		return 0, err
	}
	if already {
		in.Logger.Info("fdns ingest-cc clickhouse swap already applied; finishing cleanup",
			zap.String("crawl", man.ID))
		return in.finishAlreadySwapped(ctx, man.ID, start)
	}

	if err := in.CH.Exec(ctx, fmt.Sprintf("EXCHANGE TABLES %s AND %s", CCHostTable, CCHostLoadTable)); err != nil {
		return 0, fmt.Errorf("fdns ingest-cc exchange tables: %w", err)
	}
	// Ledger stays until both the swap marker and the load truncate succeed,
	// so a crash here resumes into cleanup instead of inserting again.
	return in.finishAlreadySwapped(ctx, man.ID, start)
}

// finishAlreadySwapped truncates the load table, then the ledger. The ledger
// is cleared only after the load truncate succeeds, and only once a swap
// marker has been recorded, so a crash cannot look like a fresh load.
func (in *CCIngestor) finishAlreadySwapped(ctx context.Context, crawl string, start time.Time) (int64, error) {
	total, err := in.countTable(ctx, "SELECT count() FROM "+CCHostTable, CCHostTable)
	if err != nil {
		return 0, err
	}
	if err := in.recordSwapMarker(ctx, crawl); err != nil {
		return total, err
	}
	if err := in.CH.Exec(ctx, "TRUNCATE TABLE "+CCHostLoadTable); err != nil {
		return total, fmt.Errorf("fdns ingest-cc truncate %s after swap: %w", CCHostLoadTable, err)
	}
	if err := in.CH.Exec(ctx, "TRUNCATE TABLE "+CCLoadPartTable); err != nil {
		return total, fmt.Errorf("fdns ingest-cc truncate %s after swap: %w", CCLoadPartTable, err)
	}
	in.Logger.Info("fdns ingest-cc clickhouse swap done",
		zap.String("crawl", crawl),
		zap.String("table", CCHostTable),
		zap.Int64("rows", total),
		elapsedField(time.Since(start)))
	return total, nil
}

// hostHoldsSwappedCrawl reports whether EXCHANGE TABLES already moved this
// crawl into the live table. The load table then holds the previous snapshot
// (a different crawl, an older ingested_at, or nothing).
func (in *CCIngestor) hostHoldsSwappedCrawl(ctx context.Context, crawl string) (bool, error) {
	quoted := clickhouse.QuoteString(crawl)
	hostN, err := in.countTable(ctx, fmt.Sprintf("SELECT count() FROM %s WHERE crawl = %s", CCHostTable, quoted), CCHostTable)
	if err != nil || hostN == 0 {
		return false, err
	}
	loadN, err := in.countTable(ctx, fmt.Sprintf("SELECT count() FROM %s WHERE crawl = %s", CCHostLoadTable, quoted), CCHostLoadTable)
	if err != nil {
		return false, err
	}
	if loadN == 0 {
		return true, nil
	}
	hostAt, err := in.maxIngestedAt(ctx, CCHostTable, quoted)
	if err != nil {
		return false, err
	}
	loadAt, err := in.maxIngestedAt(ctx, CCHostLoadTable, quoted)
	if err != nil {
		return false, err
	}
	return hostAt > loadAt, nil
}

func (in *CCIngestor) assertSchemaVersion(ctx context.Context) error {
	want := clickhouse.LatestVersion()
	version, dirty, err := in.CH.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("fdns ingest-cc clickhouse schema version: %w", err)
	}
	if version != want || dirty {
		return fmt.Errorf("fdns ingest-cc: clickhouse schema is version %d (dirty=%t), want %d; run `opr clickhouse migrate`",
			version, dirty, want)
	}
	return nil
}

// loadedParts lists the parquet files a previous run already inserted for this
// crawl, keyed by the same absolute path recordLoadedPart stores. swapped is
// set when the post-EXCHANGE marker is present. An empty map means this is a
// fresh load, not a resume.
func (in *CCIngestor) loadedParts(ctx context.Context, crawl string) (map[string]struct{}, bool, error) {
	body, err := in.CH.QueryTSV(ctx, fmt.Sprintf("SELECT DISTINCT path FROM %s WHERE crawl = %s",
		CCLoadPartTable, clickhouse.QuoteString(crawl)))
	if err != nil {
		return nil, false, fmt.Errorf("fdns ingest-cc read %s: %w", CCLoadPartTable, err)
	}
	defer body.Close()

	out := map[string]struct{}{}
	swapped := false
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line == ccSwapMarkerPath {
			swapped = true
			continue
		}
		key, err := ccLedgerPath(line)
		if err != nil {
			return nil, false, err
		}
		out[key] = struct{}{}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, false, fmt.Errorf("fdns ingest-cc read %s: %w", CCLoadPartTable, err)
	}
	if len(out) > 0 && !swapped {
		in.Logger.Info("fdns ingest-cc resuming clickhouse load",
			zap.String("crawl", crawl), zap.Int("parts_done", len(out)))
	}
	return out, swapped, nil
}

func (in *CCIngestor) recordLoadedPart(ctx context.Context, crawl, path string, rows int64) error {
	key := path
	if path != ccSwapMarkerPath {
		var err error
		key, err = ccLedgerPath(path)
		if err != nil {
			return err
		}
	}
	query := fmt.Sprintf("INSERT INTO %s (crawl, path, rows) VALUES (%s, %s, %d)",
		CCLoadPartTable, clickhouse.QuoteString(crawl), clickhouse.QuoteString(key), rows)
	if err := in.CH.Exec(ctx, query); err != nil {
		return fmt.Errorf("fdns ingest-cc record loaded part %s: %w", filepath.Base(path), err)
	}
	return nil
}

func (in *CCIngestor) recordSwapMarker(ctx context.Context, crawl string) error {
	if err := in.recordLoadedPart(ctx, crawl, ccSwapMarkerPath, 0); err != nil {
		return fmt.Errorf("fdns ingest-cc record swap marker: %w", err)
	}
	return nil
}

// ccLedgerPath is the ledger key for a parquet part. Recording and skipping
// both use it, so a resume cannot miss a part because one side was relative.
func ccLedgerPath(path string) (string, error) {
	if path == ccSwapMarkerPath {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("fdns ingest-cc ledger path: %w", err)
	}
	return abs, nil
}

func ccAbsPaths(paths []string) ([]string, error) {
	out := make([]string, len(paths))
	for i, path := range paths {
		abs, err := ccLedgerPath(path)
		if err != nil {
			return nil, err
		}
		out[i] = abs
	}
	return out, nil
}

func ccPartsAllLoaded(paths []string, loaded map[string]struct{}) bool {
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		if _, ok := loaded[path]; !ok {
			return false
		}
	}
	return true
}

func (in *CCIngestor) countLoadTable(ctx context.Context) (int64, error) {
	return in.countTable(ctx, "SELECT count() FROM "+CCHostLoadTable, CCHostLoadTable)
}

func (in *CCIngestor) countTable(ctx context.Context, query, what string) (int64, error) {
	out, err := in.CH.Scalar(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("fdns ingest-cc count %s: %w", what, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("fdns ingest-cc count %s: unexpected result %q", what, out)
	}
	return n, nil
}

func (in *CCIngestor) maxIngestedAt(ctx context.Context, table, quotedCrawl string) (string, error) {
	out, err := in.CH.Scalar(ctx, fmt.Sprintf("SELECT toString(max(ingested_at)) FROM %s WHERE crawl = %s", table, quotedCrawl))
	if err != nil {
		return "", fmt.Errorf("fdns ingest-cc ingested_at %s: %w", table, err)
	}
	return strings.TrimSpace(out), nil
}
