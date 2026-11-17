package rdns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ZoneToPrefix maps a reverse DNS name to the address prefix it covers.
// 193.in-addr.arpa → 193.0.0.0/8; nibble ip6.arpa → IPv6. RFC 2317 labels
// like 128/25.2.0.192.in-addr.arpa → 192.0.2.128/25.
func ZoneToPrefix(zone string) (string, error) {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return "", fmt.Errorf("rdns: empty zone")
	}

	switch {
	case z == "in-addr.arpa" || z == "ip6.arpa":
		return "", fmt.Errorf("rdns: parent zone %s has no prefix (IANA checklist)", z)
	case strings.HasSuffix(z, ".in-addr.arpa"):
		return inAddrToPrefix(strings.TrimSuffix(z, ".in-addr.arpa"))
	case strings.HasSuffix(z, ".ip6.arpa"):
		return ip6ArpaToPrefix(strings.TrimSuffix(z, ".ip6.arpa"))
	default:
		return "", fmt.Errorf("rdns: not a reverse zone: %s", zone)
	}
}

func inAddrToPrefix(head string) (string, error) {
	if head == "" {
		return "", fmt.Errorf("rdns: empty in-addr labels")
	}
	labels := strings.Split(head, ".")
	if len(labels) > 4 {
		return "", fmt.Errorf("rdns: too many in-addr labels: %s", head)
	}

	classlessLen := -1
	ip := make(net.IP, 4)

	for i, lab := range labels {
		octet, plen, err := parseInAddrLabel(lab)
		if err != nil {
			return "", err
		}
		if plen >= 0 {
			if i != 0 {
				return "", fmt.Errorf("rdns: RFC 2317 /len only on most-specific label: %s", head)
			}
			classlessLen = plen
		}
		// labels are LSB-first: last label is the first IPv4 octet.
		ip[len(labels)-1-i] = octet
	}

	prefixLen := 8 * len(labels)
	if classlessLen >= 0 {
		prefixLen = classlessLen
	}
	if prefixLen < 0 || prefixLen > 32 {
		return "", fmt.Errorf("rdns: invalid IPv4 prefix length %d", prefixLen)
	}
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(prefixLen, 32)}).String(), nil
}

func parseInAddrLabel(lab string) (octet byte, classlessLen int, err error) {
	classlessLen = -1
	s := lab
	if i := strings.IndexByte(lab, '/'); i >= 0 {
		s = lab[:i]
		n, convErr := strconv.Atoi(lab[i+1:])
		if convErr != nil || n < 0 || n > 32 {
			return 0, -1, fmt.Errorf("rdns: invalid RFC 2317 prefix length in %q", lab)
		}
		classlessLen = n
	}
	n, convErr := strconv.Atoi(s)
	if convErr != nil || n < 0 || n > 255 {
		return 0, -1, fmt.Errorf("rdns: invalid in-addr octet %q", lab)
	}
	return byte(n), classlessLen, nil
}

func ip6ArpaToPrefix(head string) (string, error) {
	if head == "" {
		return "", fmt.Errorf("rdns: empty ip6.arpa labels")
	}
	labels := strings.Split(head, ".")
	if len(labels) > 32 {
		return "", fmt.Errorf("rdns: too many ip6.arpa labels: %s", head)
	}
	nibbles := make([]byte, 0, 32)
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		if len(lab) != 1 {
			return "", fmt.Errorf("rdns: ip6.arpa label must be one nibble: %q", lab)
		}
		n, err := strconv.ParseUint(lab, 16, 8)
		if err != nil || n > 0xf {
			return "", fmt.Errorf("rdns: invalid ip6.arpa nibble %q", lab)
		}
		nibbles = append(nibbles, byte(n))
	}
	var addr [16]byte
	for i, n := range nibbles {
		if i%2 == 0 {
			addr[i/2] = n << 4
		} else {
			addr[i/2] |= n
		}
	}
	prefixLen := 4 * len(labels)
	ip := net.IP(addr[:])
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(prefixLen, 128)}).String(), nil
}

// PrefixToZone is the inverse of ZoneToPrefix for octet-aligned IPv4 and
// nibble-aligned IPv6. Other prefix lengths have no unique reverse zone
// (RFC 2317 is not reconstructed) and return an error.
func PrefixToZone(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", fmt.Errorf("rdns: prefix: %w", err)
	}
	ones, bits := ipnet.Mask.Size()
	switch bits {
	case 32:
		return ipv4PrefixToZone(ipnet.IP.To4(), ones)
	case 128:
		return ipv6PrefixToZone(ipnet.IP.To16(), ones)
	default:
		return "", fmt.Errorf("rdns: unknown address family bits %d", bits)
	}
}

func ipv4PrefixToZone(ip net.IP, ones int) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("rdns: not IPv4")
	}
	if ones < 0 || ones > 32 || ones%8 != 0 {
		return "", fmt.Errorf("rdns: IPv4 prefix /%d is not octet-aligned", ones)
	}
	n := ones / 8
	if n == 0 {
		return "", fmt.Errorf("rdns: IPv4 /0 has no reverse zone")
	}
	labels := make([]string, n)
	for i := 0; i < n; i++ {
		labels[i] = strconv.Itoa(int(ip[n-1-i]))
	}
	return strings.Join(labels, ".") + ".in-addr.arpa.", nil
}

func ipv6PrefixToZone(ip net.IP, ones int) (string, error) {
	if ip == nil || len(ip) < 16 {
		return "", fmt.Errorf("rdns: not IPv6")
	}
	if ones < 0 || ones > 128 || ones%4 != 0 {
		return "", fmt.Errorf("rdns: IPv6 prefix /%d is not nibble-aligned", ones)
	}
	n := ones / 4
	if n == 0 {
		return "", fmt.Errorf("rdns: IPv6 /0 has no reverse zone")
	}
	labels := make([]string, n)
	for i := 0; i < n; i++ {
		addrIdx := i / 2
		var nib byte
		if i%2 == 0 {
			nib = ip[addrIdx] >> 4
		} else {
			nib = ip[addrIdx] & 0xf
		}
		labels[n-1-i] = strconv.FormatUint(uint64(nib), 16)
	}
	return strings.Join(labels, ".") + ".ip6.arpa.", nil
}
