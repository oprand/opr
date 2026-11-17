package nro

import (
	"bufio"
	"context"
	"fmt"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DefaultDelegatedStatsURL is the combined NRO extended delegated-stats file
// (all five RIRs + IANA), mirrored by RIPE NCC.
const DefaultDelegatedStatsURL = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"

// Aggregator downloads the NRO extended delegated-stats snapshot and loads it
// into delegated_stats via a rename-swap: COPY into an off-to-the-side staging
// table, then a short metadata-only ALTER TABLE RENAME. It is the source of
// truth for asn/prefix -> registry attribution.
type Aggregator struct {
	Logger     *zap.Logger
	Store      *postgres.Store
	httpClient *http.Client
	url        string
}

func New(logger *zap.Logger, st *postgres.Store, url string) *Aggregator {
	if url == "" {
		url = DefaultDelegatedStatsURL
	}
	return &Aggregator{
		Logger:     logger.Named("opr.nro"),
		Store:      st,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
		url:        url,
	}
}

func (a *Aggregator) Close() {
	a.Store.Close()
}

// DownloadAndLoad fetches the current NRO delegated-stats file, parses it, and
// atomically replaces delegated_stats with the new snapshot.
func (a *Aggregator) DownloadAndLoad(ctx context.Context) error {
	a.Logger.Info("downloading NRO delegated-stats", zap.String("url", a.url))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return fmt.Errorf("download nro delegated-stats: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download nro delegated-stats: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download nro delegated-stats: unexpected status %s", resp.Status)
	}

	rows, fileDate, err := ParseDelegatedStats(resp.Body)
	if err != nil {
		return fmt.Errorf("parse nro delegated-stats: %w", err)
	}
	for i := range rows {
		rows[i].FileDate = fileDate
	}

	n, err := a.Store.LoadDelegatedStats(ctx, rows)
	if err != nil {
		return fmt.Errorf("load delegated_stats: %w", err)
	}
	a.Logger.Info("loaded delegated_stats snapshot", zap.Int64("rows", n), zap.Int("parsed", len(rows)))
	return nil
}

// ParseDelegatedStats parses the NRO extended delegated-stats format. Each
// record derives asn_end / ip_end so containment lookups stay indexable without
// CIDR decomposition. Returns the parsed rows and the file's snapshot date.
//
// Record formats (fields split on '|'):
//
//	registry|cc|asn|start|count|date|status[|opaque-id]
//	registry|cc|ipv4|start-ip|addr-count|date|status[|opaque-id]
//	registry|cc|ipv6|start-ip|prefix-length|date|status[|opaque-id]
func ParseDelegatedStats(r io.Reader) ([]postgres.DelegatedStat, *time.Time, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	var out []postgres.DelegatedStat
	var fileDate *time.Time
	// Dedup on the same tuple as the delegated_stats unique index (using the
	// normalized registry, which is what gets stored). NRO conflict artifacts -
	// and especially concatenated per-RIR mirror files - can repeat a key;
	// first occurrence wins, so the later unique-index rebuild cannot fail.
	seen := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 6 {
			continue
		}

		// Version header: version|registry|serial|records|startdate|enddate|UTCoffset
		if f[0] == "2" {
			if d, err := time.Parse("20060102", f[5]); err == nil {
				fileDate = &d
			}
			continue
		}
		// Summary line: registry|*|type|*|count|summary
		if f[1] == "*" {
			continue
		}

		rec := postgres.DelegatedStat{
			Registry:     normalizeRegistry(f[0]),
			ResourceType: f[2],
			RangeStart:   f[3],
		}
		if f[1] != "" {
			cc := f[1]
			rec.CountryCode = &cc
		}
		if len(f) >= 7 && f[6] != "" {
			rec.Status = f[6]
		} else {
			rec.Status = "reserved"
		}
		if len(f) >= 8 && f[7] != "" {
			opaque := f[7]
			rec.OpaqueID = &opaque
		}
		if d, err := time.Parse("20060102", f[5]); err == nil {
			rec.AllocDate = &d
		}

		value, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			continue
		}
		rec.RangeValue = value

		switch rec.ResourceType {
		case "asn":
			start, err := strconv.ParseInt(f[3], 10, 64)
			if err != nil {
				continue
			}
			end := start + value - 1
			rec.AsnStart = &start
			rec.AsnEnd = &end
		case "ipv4":
			ip := net.ParseIP(f[3])
			if ip == nil {
				continue
			}
			rec.IPStart = ip
			rec.IPEnd = addToIP(ip, big.NewInt(value))
		case "ipv6":
			ip := net.ParseIP(f[3])
			if ip == nil {
				continue
			}
			// value is a prefix length; address count = 2^(128 - length).
			count := new(big.Int).Lsh(big.NewInt(1), uint(128-value))
			rec.IPStart = ip
			rec.IPEnd = addToIP(ip, count)
		default:
			continue
		}

		key := rec.Registry + "|" + rec.ResourceType + "|" + rec.RangeStart
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return out, fileDate, nil
}

// addToIP returns firstIP + (count - 1), preserving the address family. Used to
// derive the inclusive last address of a delegated range.
func addToIP(ip net.IP, count *big.Int) net.IP {
	var b []byte
	if v4 := ip.To4(); v4 != nil {
		b = v4
	} else {
		b = ip.To16()
	}
	start := new(big.Int).SetBytes(b)
	end := new(big.Int).Add(start, new(big.Int).Sub(count, big.NewInt(1)))

	size := len(b)
	endBytes := end.Bytes()
	if len(endBytes) > size {
		// overflow (shouldn't happen for valid delegated ranges); clamp to max.
		endBytes = endBytes[len(endBytes)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(endBytes):], endBytes)
	return net.IP(out)
}

// normalizeRegistry maps NRO registry tokens to the canonical opconst names used
// throughout the crawler (so RegistryForASN/IP return crawler-ready values).
func normalizeRegistry(nro string) string {
	switch strings.ToLower(nro) {
	case "arin":
		return opconst.ARIN
	case "ripencc":
		return opconst.RIPE
	case "apnic":
		return opconst.APNIC
	case "lacnic":
		return opconst.LACNIC
	case "afrinic":
		return opconst.AFRINIC
	default:
		return strings.ToUpper(nro)
	}
}
