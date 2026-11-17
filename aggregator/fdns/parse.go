package fdns

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"golang.org/x/net/idna"
)

var htmlPrefixes = []string{
	"<!doctype html",
	"<html",
	"<head",
	"<body",
	"<meta",
}

// ErrUnparseable is a list body that is HTML or not CSV. Callers must not upsert.
var ErrUnparseable = errors.New("fdns: unparseable list body")

// ErrEmptyList is a successful parse with no valid hostnames. Callers must not upsert.
var ErrEmptyList = errors.New("fdns: no valid hostnames in list")

// UnSURTHostName converts a Common Crawl Host Index surt_host_name to a dotted
// FQDN: split on ',', reverse labels, join with '.' (uk,co,bbc → bbc.co.uk).
// Empty input or empty labels return "", false. Does not run NormalizeHostname.
func UnSURTHostName(surt string) (string, bool) {
	surt = strings.TrimSpace(surt)
	if surt == "" {
		return "", false
	}
	parts := strings.Split(surt, ",")
	if len(parts) == 0 {
		return "", false
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return "", false
		}
		parts[i] = p
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "."), true
}

// NormalizeHostname lowercases, strips a trailing dot, and accepts an origin
// URL (CrUX) by taking the hostname. IPs, single labels, and invalid DNS
// names are dropped.
func NormalizeHostname(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	s = strings.TrimPrefix(s, "\ufeff")
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		s = u.Hostname()
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(strings.ToLower(s), ".")
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", false
	}
	ascii = strings.Trim(strings.ToLower(ascii), ".")
	if !validDNSName(ascii) {
		return "", false
	}
	return ascii, true
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lab := range labels {
		if len(lab) == 0 || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for i := 0; i < len(lab); i++ {
			c := lab[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// ParseListCSV reads a decompressed CSV into fdns_host_name rows for one source.
func ParseListCSV(r io.Reader, list List, now time.Time) ([]postgres.HostName, error) {
	br := bufio.NewReader(r)
	peek, err := br.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if looksLikeHTML(string(peek)) {
		return nil, ErrUnparseable
	}
	switch list.Format {
	case FormatCrUXCSV:
		return parseCrUXCSV(br, list.Name, now)
	default:
		return parseRankedCSV(br, list.Name, now)
	}
}

func looksLikeHTML(peek string) bool {
	s := strings.ToLower(strings.TrimSpace(peek))
	for _, p := range htmlPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func parseRankedCSV(r io.Reader, source string, now time.Time) ([]postgres.HostName, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true

	best := map[string]int{}
	header := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("fdns parse %s: %w", source, err)
		}
		if len(rec) == 0 {
			continue
		}
		rec[0] = stripBOM(rec[0])
		if isComment(rec[0]) {
			continue
		}
		if header {
			header = false
			if isRankedHeader(rec) {
				continue
			}
		}
		if len(rec) < 2 {
			continue
		}
		rank, err := strconv.Atoi(strings.TrimSpace(rec[0]))
		if err != nil || rank < 1 {
			continue
		}
		name, ok := NormalizeHostname(rec[1])
		if !ok {
			continue
		}
		if prev, exists := best[name]; exists && prev <= rank {
			continue
		}
		best[name] = rank
	}
	return hostNamesFromRanks(best, source, now), nil
}

func parseCrUXCSV(r io.Reader, source string, now time.Time) ([]postgres.HostName, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true

	originCol, rankCol := 0, -1
	header := true
	best := map[string]int{}
	rowNum := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("fdns parse %s: %w", source, err)
		}
		if len(rec) == 0 {
			continue
		}
		rec[0] = stripBOM(rec[0])
		if isComment(rec[0]) {
			continue
		}
		if header {
			header = false
			if isCrUXHeader(rec) {
				originCol, rankCol = cruxColumns(rec)
				continue
			}
		}
		if originCol >= len(rec) {
			continue
		}
		name, ok := NormalizeHostname(rec[originCol])
		if !ok {
			continue
		}
		rowNum++
		rank := rowNum
		if rankCol >= 0 && rankCol < len(rec) {
			if n, err := strconv.Atoi(strings.TrimSpace(rec[rankCol])); err == nil && n > 0 {
				rank = n
			}
		}
		if prev, exists := best[name]; exists && prev <= rank {
			continue
		}
		best[name] = rank
	}
	return hostNamesFromRanks(best, source, now), nil
}

func hostNamesFromRanks(best map[string]int, source string, now time.Time) []postgres.HostName {
	out := make([]postgres.HostName, 0, len(best))
	for name, rank := range best {
		row := postgres.HostName{
			Name:      name,
			Source:    []string{source},
			FirstSeen: now,
			LastSeen:  now,
		}
		applyRank(&row, source, rank)
		out = append(out, row)
	}
	return out
}

func isRankedHeader(rec []string) bool {
	if len(rec) == 0 {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(rec[0]))
	if a == "rank" || a == "#rank" {
		return true
	}
	if len(rec) > 1 {
		b := strings.ToLower(strings.TrimSpace(rec[1]))
		if b == "domain" || b == "apex" || b == "fqdn" || b == "hostname" || b == "host" {
			return true
		}
	}
	return false
}

func isCrUXHeader(rec []string) bool {
	for _, f := range rec {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "origin", "rank", "host", "hostname", "url":
			return true
		}
	}
	return false
}

func cruxColumns(rec []string) (originCol, rankCol int) {
	originCol, rankCol = 0, -1
	for i, f := range rec {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "origin", "host", "hostname", "url", "domain":
			originCol = i
		case "rank":
			rankCol = i
		}
	}
	return originCol, rankCol
}

func isComment(field string) bool {
	s := strings.TrimSpace(field)
	return s == "" || strings.HasPrefix(s, "#")
}

func stripBOM(s string) string {
	return strings.TrimPrefix(s, "\ufeff")
}
