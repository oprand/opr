package rdns

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"

	"github.com/oprand/opr/store/postgres"
)

// Leaf prefix floors. A leftover /8 or IPv6 /32 must not expand to millions
// of PTR queries. RFC 2317 classless IPv4 (/25+) is allowed because it is
// /24 or longer. IPv6 /48 is a leaf (not a /32 brute) but hosts are only
// enumerated at /120+ (256 addresses, analogue of IPv4 /24).
const (
	MinIPv4LeafBits     = 24
	MinIPv6LeafBits     = 48
	MinIPv6ExpandBits   = 120
	DefaultMaxAddresses = 256
)

// Skip reasons for status logs / tests.
const (
	SkipTooCoarse     = "too_coarse"
	SkipIPv6TooWide   = "ipv6_too_wide"
	SkipNoNservers    = "no_nservers"
	SkipNotExpandable = "not_expandable"
)

// SelectLeaves returns deepest delegated cuts from in-memory rows (tests and
// the same rules as ListRDNSLeaves + SkipCoarseLeaves). IANA is ignored.
// A /8 with a /24 child yields only the /24. Duplicate prefixes (ERX) merge
// nservers.
func SelectLeaves(rows []postgres.RDNSDelegation) []postgres.RDNSLeaf {
	type item struct {
		leaf postgres.RDNSLeaf
		net  *net.IPNet
	}
	items := make([]item, 0, len(rows))
	for _, row := range rows {
		if strings.EqualFold(row.Source, postgres.RDNSSourceIANA) {
			continue
		}
		if strings.TrimSpace(row.Prefix) == "" || len(row.Nservers) == 0 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(row.Prefix)
		if err != nil {
			continue
		}
		items = append(items, item{
			leaf: postgres.RDNSLeaf{
				Zone:     row.Zone,
				Prefix:   ipnet.String(),
				Nservers: append([]string(nil), row.Nservers...),
				Source:   row.Source,
			},
			net: ipnet,
		})
	}

	leaves := make([]item, 0, len(items))
	for i, a := range items {
		moreSpecific := false
		for j, b := range items {
			if i == j {
				continue
			}
			if containsStrict(a.net, b.net) {
				moreSpecific = true
				break
			}
		}
		if !moreSpecific {
			leaves = append(leaves, a)
		}
	}

	byPrefix := make(map[string]*postgres.RDNSLeaf)
	var order []string
	for _, it := range leaves {
		cur, ok := byPrefix[it.leaf.Prefix]
		if !ok {
			cp := it.leaf
			byPrefix[it.leaf.Prefix] = &cp
			order = append(order, it.leaf.Prefix)
			continue
		}
		cur.Nservers = unionStrings(cur.Nservers, it.leaf.Nservers)
	}
	out := make([]postgres.RDNSLeaf, 0, len(order))
	for _, p := range order {
		out = append(out, *byPrefix[p])
	}
	return out
}

// containsStrict reports whether inner is strictly more specific than outer
// (same family, inner inside outer, not equal).
func containsStrict(outer, inner *net.IPNet) bool {
	if outer == nil || inner == nil {
		return false
	}
	oOnes, oBits := outer.Mask.Size()
	iOnes, iBits := inner.Mask.Size()
	if oBits != iBits {
		return false
	}
	if iOnes <= oOnes {
		return false
	}
	return outer.Contains(inner.IP)
}

// LeafSkip is a leaf that must not be address-walked.
type LeafSkip struct {
	Leaf   postgres.RDNSLeaf
	Reason string
}

// PartitionLeaves splits leaves into expandable vs skipped (coarse /8, IPv6
// /32, IPv6 /48–/119 host expansion).
func PartitionLeaves(leaves []postgres.RDNSLeaf) (walk []postgres.RDNSLeaf, skip []LeafSkip) {
	for _, leaf := range leaves {
		if len(leaf.Nservers) == 0 {
			skip = append(skip, LeafSkip{Leaf: leaf, Reason: SkipNoNservers})
			continue
		}
		reason := SkipReason(leaf.Prefix)
		if reason != "" {
			skip = append(skip, LeafSkip{Leaf: leaf, Reason: reason})
			continue
		}
		walk = append(walk, leaf)
	}
	return walk, skip
}

// SkipReason is empty when the prefix may be enumerated for PTR. Coarse
// leftovers are skipped; IPv6 /48 is a valid leaf but not host-enumerated.
func SkipReason(cidr string) string {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return SkipNotExpandable
	}
	ones, bits := ipnet.Mask.Size()
	switch bits {
	case 32:
		if ones < MinIPv4LeafBits {
			return SkipTooCoarse
		}
		return ""
	case 128:
		if ones < MinIPv6LeafBits {
			return SkipTooCoarse
		}
		if ones < MinIPv6ExpandBits {
			return SkipIPv6TooWide
		}
		return ""
	default:
		return SkipNotExpandable
	}
}

// AddressCount is 2^(bits-ones) capped so a /8 cannot be walked by accident.
func AddressCount(ipnet *net.IPNet) int {
	if ipnet == nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	if ones < 0 || bits-ones > 16 {
		return 1 << 16
	}
	return 1 << (bits - ones)
}

// EnumerateAddresses lists IPs in cidr, network through last, up to max.
// max <= 0 means DefaultMaxAddresses. Refuses to expand more than max
// without truncating: returns an error if the prefix is larger than max
// (callers that passed --i-mean-it should set max to the cap they want and
// use EnumerateAddressesTruncating).
func EnumerateAddresses(cidr string, max int) ([]net.IP, error) {
	return enumerate(cidr, max, false)
}

// EnumerateAddressesTruncating is EnumerateAddresses but stops at max
// instead of erroring when the prefix is larger (used with --max-addresses
// on an --i-mean-it coarse prefix).
func EnumerateAddressesTruncating(cidr string, max int) ([]net.IP, error) {
	return enumerate(cidr, max, true)
}

func enumerate(cidr string, max int, truncate bool) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("rdns: prefix: %w", err)
	}
	if max <= 0 {
		max = DefaultMaxAddresses
	}
	n := AddressCount(ipnet)
	if n > max && !truncate {
		return nil, fmt.Errorf("rdns: prefix %s has %d addresses (max %d); pass --max-addresses or a narrower prefix", ipnet, n, max)
	}
	if n > max {
		n = max
	}
	out := make([]net.IP, 0, n)
	ip := append(net.IP(nil), ipnet.IP...)
	if v4 := ip.To4(); v4 != nil {
		ip = append(net.IP(nil), v4...)
	}
	for i := 0; i < n; i++ {
		if !ipnet.Contains(ip) {
			break
		}
		out = append(out, append(net.IP(nil), ip...))
		incIP(ip)
	}
	return out, nil
}

// ShuffleAddresses randomizes PTR walk order inside a block (OpenINTEL-style
// spreading). Same length and membership.
func ShuffleAddresses(addrs []net.IP) {
	if len(addrs) < 2 {
		return
	}
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
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
	sort.Strings(out)
	return out
}

// IntersectPrefix returns the CIDR to walk: user scope ∩ leaf. Empty user
// scope means the leaf prefix.
func IntersectPrefix(leafCIDR, scopeCIDR string) (string, error) {
	_, leaf, err := net.ParseCIDR(strings.TrimSpace(leafCIDR))
	if err != nil {
		return "", err
	}
	scopeCIDR = strings.TrimSpace(scopeCIDR)
	if scopeCIDR == "" {
		return leaf.String(), nil
	}
	_, scope, err := net.ParseCIDR(scopeCIDR)
	if err != nil {
		return "", fmt.Errorf("rdns: --prefix: %w", err)
	}
	lOnes, lBits := leaf.Mask.Size()
	sOnes, sBits := scope.Mask.Size()
	if lBits != sBits {
		return "", fmt.Errorf("rdns: prefix family mismatch")
	}
	switch {
	case leaf.Contains(scope.IP) && sOnes >= lOnes:
		return scope.String(), nil
	case scope.Contains(leaf.IP) && lOnes >= sOnes:
		return leaf.String(), nil
	default:
		return "", fmt.Errorf("rdns: leaf %s does not overlap %s", leaf, scope)
	}
}

// ValidateUserPrefix refuses accidental /8 walks. IPv4 shorter than /24 and
// IPv6 shorter than /120 require --i-mean-it and --max-addresses.
func ValidateUserPrefix(cidr string, iMeanIt bool, maxAddresses int) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("rdns: --prefix: %w", err)
	}
	ones, bits := ipnet.Mask.Size()
	coarse := (bits == 32 && ones < MinIPv4LeafBits) || (bits == 128 && ones < MinIPv6ExpandBits)
	if !coarse {
		return nil
	}
	if !iMeanIt {
		return fmt.Errorf("%w: %s is coarser than IPv4 /%d or IPv6 /%d; pass --i-mean-it and --max-addresses", ErrCoarsePrefix, ipnet, MinIPv4LeafBits, MinIPv6ExpandBits)
	}
	if maxAddresses <= 0 {
		return fmt.Errorf("%w: coarse prefix %s requires --max-addresses", ErrCoarsePrefix, ipnet)
	}
	return nil
}
