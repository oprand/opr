package rdns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

const (
	// maxGenerateExpansions is a hard cap per $GENERATE (not the 64MiB
	// source-text cap). Unbounded 0-99999999 ranges must not explode parse.
	maxGenerateExpansions = 4096
	maxParseRRs           = 100000
)

// ErrGenerateLimit is returned when a $GENERATE range expands past
// maxGenerateExpansions. Callers must not replace last good rows.
var ErrGenerateLimit = errors.New("rdns: $GENERATE expansion exceeds cap")

// ErrParseRRLimit is returned when the parser yields more RRs than maxParseRRs.
var ErrParseRRLimit = errors.New("rdns: zone file RR count exceeds cap")

var generateRangeRe = regexp.MustCompile(`(?i)^\$GENERATE\s+(\d+)\s*-\s*(\d+)(?:\s*/\s*(\d+))?`)

// ParseZoneFile reads a DNS master file and returns one aggregated
// delegation per owner with NS, DS, and/or RFC 2317 CNAME. SOA / RRSIG /
// NSEC / DNSKEY / A / AAAA are dropped before parse so noisy signatures
// cannot fail the file. origin is the filename origin (trailing-dot FQDN).
func ParseZoneFile(r io.Reader, origin, filename string) ([]parsedRR, error) {
	origin = canonicalZone(origin)
	if origin == "" {
		return nil, fmt.Errorf("rdns: empty origin for %s", filename)
	}

	filtered, err := filterDelegationMaster(r)
	if err != nil {
		return nil, fmt.Errorf("rdns: filter %s: %w", filename, err)
	}
	if strings.TrimSpace(filtered) == "" {
		return nil, nil
	}

	zp := dns.NewZoneParser(strings.NewReader(filtered), origin, filename)
	zp.SetIncludeAllowed(false)

	byOwner := make(map[string]*parsedRR)
	nRR := 0
	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		if rr == nil {
			continue
		}
		nRR++
		if nRR > maxParseRRs {
			return nil, fmt.Errorf("%w: %d", ErrParseRRLimit, nRR)
		}
		owner := canonicalZone(rr.Header().Name)
		if owner == "" {
			continue
		}
		prefix, err := ZoneToPrefix(owner)
		if err != nil {
			continue
		}
		row := byOwner[owner]
		if row == nil {
			row = &parsedRR{Zone: owner, Prefix: prefix}
			byOwner[owner] = row
		}
		switch v := rr.(type) {
		case *dns.NS:
			row.addNS(v.Ns)
		case *dns.DS:
			row.addDS(formatDS(v))
		case *dns.CNAME:
			row.setCNAME(v.Target)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("rdns: parse %s: %w", filename, err)
	}

	out := make([]parsedRR, 0, len(byOwner))
	for _, row := range byOwner {
		if len(row.Nservers) == 0 && len(row.DS) == 0 && row.CNAMETarget == nil {
			continue
		}
		sort.Strings(row.Nservers)
		sort.Strings(row.DS)
		out = append(out, *row)
	}
	return out, nil
}

type parsedRR struct {
	Zone        string
	Prefix      string
	Nservers    []string
	DS          []string
	CNAMETarget *string
	nsSeen      map[string]struct{}
	dsSeen      map[string]struct{}
}

func (p *parsedRR) addNS(ns string) {
	n := canonicalName(ns)
	if n == "" {
		return
	}
	if p.nsSeen == nil {
		p.nsSeen = make(map[string]struct{})
	}
	if _, ok := p.nsSeen[n]; ok {
		return
	}
	p.nsSeen[n] = struct{}{}
	p.Nservers = append(p.Nservers, n)
}

func (p *parsedRR) addDS(ds string) {
	ds = strings.TrimSpace(ds)
	if ds == "" {
		return
	}
	if p.dsSeen == nil {
		p.dsSeen = make(map[string]struct{})
	}
	if _, ok := p.dsSeen[ds]; ok {
		return
	}
	p.dsSeen[ds] = struct{}{}
	p.DS = append(p.DS, ds)
}

func (p *parsedRR) setCNAME(target string) {
	t := canonicalName(target)
	if t == "" {
		return
	}
	p.CNAMETarget = &t
}

func canonicalName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return ""
	}
	return n
}

func formatDS(ds *dns.DS) string {
	if ds == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest)))
}

// filterDelegationMaster keeps $ORIGIN / $TTL / $GENERATE, SOA (so blank-owner
// NS after the apex SOA still inherit @), and NS / DS / CNAME. RRSIG / NSEC /
// DNSKEY and other types are dropped so noisy signatures cannot fail the file.
func filterDelegationMaster(r io.Reader) (string, error) {
	logical, err := splitLogicalRecords(r)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, rec := range logical {
		if !keepMasterRecord(rec) {
			continue
		}
		trim := strings.TrimSpace(stripComment(rec))
		if strings.HasPrefix(strings.ToUpper(trim), "$GENERATE") {
			n, ok := generateExpansionCount(trim)
			if !ok || n > maxGenerateExpansions {
				return "", fmt.Errorf("%w: %d (cap %d)", ErrGenerateLimit, n, maxGenerateExpansions)
			}
		}
		b.WriteString(rec)
		if !strings.HasSuffix(rec, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

func generateExpansionCount(rec string) (int, bool) {
	m := generateRangeRe.FindStringSubmatch(strings.TrimSpace(stripComment(rec)))
	if m == nil {
		return 0, false
	}
	start, err1 := strconv.Atoi(m[1])
	stop, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, false
	}
	step := 1
	if m[3] != "" {
		var err error
		step, err = strconv.Atoi(m[3])
		if err != nil || step < 1 {
			return 0, false
		}
	}
	if stop < start {
		return 0, false
	}
	return (stop-start)/step + 1, true
}

func splitLogicalRecords(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
	var (
		out   []string
		cur   strings.Builder
		depth int
	)
	flush := func() {
		s := cur.String()
		cur.Reset()
		if strings.TrimSpace(stripComment(s)) != "" {
			out = append(out, s)
		}
	}
	for sc.Scan() {
		line := sc.Text()
		if cur.Len() == 0 && strings.TrimSpace(stripComment(line)) == "" {
			continue
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(line)
		depth += parenDelta(stripComment(line))
		if depth < 0 {
			depth = 0
		}
		if depth == 0 {
			flush()
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur.Len() > 0 {
		flush()
	}
	return out, nil
}

func keepMasterRecord(rec string) bool {
	trim := strings.TrimSpace(stripComment(rec))
	if trim == "" {
		return false
	}
	if strings.HasPrefix(trim, "$") {
		dir := strings.ToUpper(strings.Fields(trim)[0])
		switch dir {
		case "$ORIGIN", "$TTL", "$GENERATE":
			return true
		default:
			return false
		}
	}
	typ := rrTypeFromRecord(rec)
	switch typ {
	case "NS", "DS", "CNAME", "SOA":
		return true
	default:
		return false
	}
}

func rrTypeFromRecord(rec string) string {
	first := firstLine(rec)
	hasOwner := first != "" && !unicode.IsSpace(rune(first[0]))
	fields := strings.Fields(stripComment(first))
	if len(fields) == 0 {
		return ""
	}
	i := 0
	if hasOwner {
		i = 1
	}
	for i < len(fields) {
		f := strings.ToUpper(fields[i])
		if isTTLToken(fields[i]) {
			i++
			continue
		}
		if f == "IN" || f == "CH" || f == "HS" || f == "ANY" || strings.HasPrefix(f, "CLASS") {
			i++
			continue
		}
		return f
	}
	return ""
}

func isTTLToken(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if i == len(s) {
		return true
	}
	switch strings.ToLower(s[i:]) {
	case "s", "m", "h", "d", "w":
		return true
	default:
		return false
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return s[:i]
			}
		}
	}
	return s
}

func parenDelta(s string) int {
	inQuote := false
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				d++
			}
		case ')':
			if !inQuote {
				d--
			}
		}
	}
	return d
}
