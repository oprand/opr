// Package asnames backfills as_name and country_code from RIPE's asnames.txt
// for autnums that no WHOIS dump covers.
//
// This is not a coverage mark. Rows are persisted with an empty source so
// MarkAutnumCoveredFromWhoisDB (WHERE source = ANY($1) with RIR names) cannot
// treat a name string as a bulk dump object.
package asnames

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/oprand/opr/store/postgres"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

// DefaultURL is RIPE NCC's daily asnames file (~6MB, ~122k lines). Completeness
// is best-effort; RIPE does not guarantee every allocated ASN appears.
const DefaultURL = "https://ftp.ripe.net/ripe/asnames/asn.txt"

const saveBatchSize = 5000

// reservedName is skipped per the asnames.txt convention for unallocated space.
const reservedName = "-Reserved AS-"

// emptySource is persisted for asnames rows. whoisdb_autnum.source is TEXT NOT
// NULL, and SaveWhoisAutNum's dedup drops a nil Source. An empty string does
// not match coverage filters (RIR names), so it cannot fake bulk coverage.
var emptySource string

// Entry is one parsed asnames.txt line.
type Entry struct {
	ASN         uint32
	Name        string
	CountryCode string
}

// ParseLine parses `<asn> <name>, <cc>`. Names may contain commas; the country
// code is the trailing two-letter field after the last comma. Reserved and
// unparseable lines return ok=false.
func ParseLine(line string) (Entry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, reservedName) {
		return Entry{}, false
	}
	space := strings.IndexByte(line, ' ')
	if space < 0 {
		return Entry{}, false
	}
	asnStr := line[:space]
	rest := strings.TrimSpace(line[space+1:])
	comma := strings.LastIndexByte(rest, ',')
	if comma < 0 {
		return Entry{}, false
	}
	name := strings.TrimSpace(rest[:comma])
	cc := strings.ToUpper(strings.TrimSpace(rest[comma+1:]))
	if name == "" || !isCountryCode(cc) {
		return Entry{}, false
	}
	asn, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil || asn == 0 {
		return Entry{}, false
	}
	return Entry{ASN: uint32(asn), Name: name, CountryCode: cc}, true
}

func isCountryCode(cc string) bool {
	if len(cc) != 2 {
		return false
	}
	for _, r := range cc {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// SparseAutNum builds a whoisdb_autnum row with only AutNum, ASName, and
// CountryCode. Source is left nil: a RIR source here would make
// MarkAutnumCoveredFromWhoisDB treat the row as dump coverage.
func SparseAutNum(e Entry) *whoisdb.WhoisAutNum {
	cc := e.CountryCode
	rec := &whoisdb.WhoisAutNum{
		AutNum:      e.ASN,
		ASName:      e.Name,
		CountryCode: &cc,
	}
	rec.StampFetch(whoisdb.FetchMethodASNames)
	return rec
}

// prepareForSave satisfies whoisdb_autnum.source NOT NULL and
// SaveWhoisAutNum's nil-Source dedup without using a fake RIR name.
func prepareForSave(rec *whoisdb.WhoisAutNum) {
	if rec == nil {
		return
	}
	if rec.Source == nil {
		rec.Source = &emptySource
	}
}

// Collect streams asnames.txt lines and returns sparse autnums whose ASN is in
// pending. pending must be the still-uncovered crawl_target set; passing nil or
// empty yields no rows so a full 122k-line file cannot stamp dump-owned ASNs.
func Collect(r io.Reader, pending map[uint32]struct{}) ([]*whoisdb.WhoisAutNum, error) {
	if len(pending) == 0 {
		return nil, nil
	}
	scanner := bufio.NewScanner(r)
	out := make([]*whoisdb.WhoisAutNum, 0, min(len(pending), 1024))
	for scanner.Scan() {
		e, ok := ParseLine(scanner.Text())
		if !ok {
			continue
		}
		if _, want := pending[e.ASN]; !want {
			continue
		}
		out = append(out, SparseAutNum(e))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan asnames: %w", err)
	}
	return out, nil
}

func pendingSet(keys []string) map[uint32]struct{} {
	out := make(map[uint32]struct{}, len(keys))
	for _, key := range keys {
		n, err := strconv.ParseUint(strings.TrimSpace(key), 10, 32)
		if err != nil || n == 0 {
			continue
		}
		out[uint32(n)] = struct{}{}
	}
	return out
}

// Backfill downloads asnames.txt, intersects it with pending crawl_target
// autnums that no dump/RDAP row owns, and upserts sparse name+country rows.
func Backfill(ctx context.Context, logger *zap.Logger, st *postgres.Store, client *http.Client, url string) (int, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if st == nil {
		return 0, fmt.Errorf("asnames backfill: nil store")
	}
	if client == nil {
		client = http.DefaultClient
	}
	if url == "" {
		url = DefaultURL
	}

	keys, err := st.ListPendingAutnumKeys(ctx)
	if err != nil {
		return 0, err
	}
	pending := pendingSet(keys)
	if len(pending) == 0 {
		logger.Info("asnames backfill: no pending autnums")
		return 0, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("asnames request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download asnames: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download asnames: unexpected status %s", resp.Status)
	}

	recs, err := Collect(resp.Body, pending)
	if err != nil {
		return 0, err
	}

	for _, rec := range recs {
		prepareForSave(rec)
	}

	saved := 0
	for i := 0; i < len(recs); i += saveBatchSize {
		end := i + saveBatchSize
		if end > len(recs) {
			end = len(recs)
		}
		if err := st.SaveWhoisAutNum(ctx, recs[i:end]); err != nil {
			return saved, fmt.Errorf("save asnames autnums: %w", err)
		}
		saved += end - i
	}

	if err := st.TouchRemoteFileMetadata(ctx, DefaultURL); err != nil {
		return saved, fmt.Errorf("asnames watermark: %w", err)
	}
	if url != DefaultURL {
		if err := st.TouchRemoteFileMetadata(ctx, url); err != nil {
			return saved, fmt.Errorf("asnames watermark: %w", err)
		}
	}

	logger.Info("asnames backfill saved",
		zap.Int("pending", len(pending)),
		zap.Int("matched", len(recs)),
		zap.Int("saved", saved),
		zap.String("url", url),
	)
	return saved, nil
}
