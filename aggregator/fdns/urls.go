package fdns

import (
	"fmt"
	"strings"

	"github.com/oprand/opr/store/postgres"
)

// Default list dump URLs. Single source of truth is store (status board + ingest).
const (
	DefaultTrancoURL   = postgres.TrancoListURL
	DefaultUmbrellaURL = postgres.UmbrellaListURL
	DefaultCrUXURL     = postgres.CrUXListURL
)

const (
	SourceTranco   = postgres.HostNameSourceTranco
	SourceUmbrella = postgres.HostNameSourceUmbrella
	SourceCrux     = postgres.HostNameSourceCrux
	SourceCC       = postgres.HostNameSourceCC
)

const (
	DefaultCCDataURL         = postgres.CommonCrawlDataURL
	DefaultHostIndexPathsURL = postgres.HostIndexPathsURL
)

// Compression of the HTTP body (not Content-Encoding; the client already
// unwraps that). Tranco/Umbrella are zip; CrUX is gzip CSV.
type Compression int

const (
	CompressNone Compression = iota
	CompressZip
	CompressGzip
)

// Format selects how CSV rows become hostnames.
type Format int

const (
	// FormatRankedCSV is rank,hostname (Tranco apex / Umbrella FQDN).
	FormatRankedCSV Format = iota
	// FormatCrUXCSV is Chrome origin URLs, optional rank column.
	FormatCrUXCSV
)

// List is one popularity dump ingest-lists fetches.
type List struct {
	Name        string
	URL         string
	Format      Format
	Compression Compression
}

// DefaultLists is Tranco + Umbrella + CrUX. Callers may copy and override URLs.
func DefaultLists() []List {
	return []List{
		{Name: SourceTranco, URL: DefaultTrancoURL, Format: FormatRankedCSV, Compression: CompressZip},
		{Name: SourceUmbrella, URL: DefaultUmbrellaURL, Format: FormatRankedCSV, Compression: CompressZip},
		{Name: SourceCrux, URL: DefaultCrUXURL, Format: FormatCrUXCSV, Compression: CompressGzip},
	}
}

// SelectLists filters DefaultLists (or all) by --only names. Empty only returns all.
func SelectLists(all []List, only []string) ([]List, error) {
	if len(only) == 0 {
		return all, nil
	}
	valid := map[string]List{}
	for _, list := range all {
		valid[list.Name] = list
	}
	out := make([]List, 0, len(only))
	seen := map[string]bool{}
	for _, name := range only {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		list, ok := valid[name]
		if !ok {
			return nil, fmt.Errorf("unknown fdns list %q. Valid names: tranco, umbrella, crux", name)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, list)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unknown fdns list. Valid names: tranco, umbrella, crux")
	}
	return out, nil
}

func applyRank(row *postgres.HostName, source string, rank int) {
	r := rank
	switch source {
	case SourceTranco:
		row.RankTranco = &r
	case SourceUmbrella:
		row.RankUmbrella = &r
	case SourceCrux:
		row.RankCrux = &r
	}
}
