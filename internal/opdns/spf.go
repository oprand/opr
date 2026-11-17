package opdns

import (
	"context"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

type SpfRecord struct {
	Domain      string
	Raw         string
	Children    []*SpfRecord
	Version     int
	Ip4         []string
	Ip4Count    uint64
	Ip6         []string
	Ip6Count    uint64
	Includes    []string
	Redirect    string
	All         string
	MailServers []string
	A           bool
	Ptr         bool
}

// ParseSpf takes a domain and its related SPF record as string
// and attempt to parse it following the SPF RFC specification.
// It builds and returns a tree of SpfRecord following the chain
// of include statements.
// TODO:
//   - Need to support more syntax: https://www.rfc-editor.org/rfc/rfc7208#page-46
//   - Use an ABNF lexer
func GetSpfTree(domain string, resolver *resolve.Resolvers) *SpfRecord {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawRec, exists, err := GetSpfRecord(ctx, domain, resolver)
	if err != nil {
		panic(err)
	}
	if !exists {
		return nil
	}

	out := SpfRecord{Raw: rawRec, Domain: domain}

	tokens := strings.Split(rawRec, " ")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, "v=spf") {
			version, err := strconv.Atoi(token[len("v=spf"):])
			if err != nil {
				continue
			}
			out.Version = version
		} else if strings.HasPrefix(token, "include:") {
			out.Includes = append(out.Includes, token[len("include:"):])
		} else if strings.HasPrefix(token, "mx:") {
			out.MailServers = append(out.MailServers, token[len("mx:"):])
		} else if strings.HasPrefix(token, "redirect=") {
			out.Redirect = token[len("redirect="):]
		} else if strings.HasPrefix(token, "ip4:") {
			var ipNet string
			if strings.Contains(token[len("ip4:"):], "/") {
				_, cidrNet, err := net.ParseCIDR(token[len("ip4:"):])
				if err != nil {
					continue
				}
				ipNet = cidrNet.String()
				prefix, _ := cidrNet.Mask.Size()
				out.Ip4Count += uint64(math.Pow(2, float64(32-prefix)))
				if prefix != 31 && prefix != 32 {
					out.Ip4Count -= 2
				}
			} else {
				ip := net.ParseIP(token[len("ip4:"):])
				ipNet = ip.String()
				out.Ip4Count += 1
			}
			out.Ip4 = append(out.Ip4, ipNet)
		} else if strings.HasPrefix(token, "ip6:") {
			var ipNet string
			if strings.Contains(token[len("ip6:"):], "/") {
				_, cidrNet, err := net.ParseCIDR(token[len("ip6:"):])
				if err != nil {
					continue
				}
				ipNet = cidrNet.String()
			} else {
				ip := net.ParseIP(token[len("ip6:"):])
				ipNet = ip.String()
			}
			out.Ip6Count += 1
			out.Ip6 = append(out.Ip6, ipNet)
		} else if token == "~all" || token == "-all" || token == "+all" || token == "?all" {
			out.All = token
		} else if token == "a" {
			out.A = true
		} else if token == "ptr" {
			out.Ptr = true
		}

	}

	if out.Redirect != "" {
		child := GetSpfTree(out.Redirect, resolver)
		out.Children = append(out.Children, child)
		out.Ip4Count += child.Ip4Count
		out.Ip6Count += child.Ip6Count
	}

	// If any include do a recursive Fetch + Parse
	for _, includeDomain := range out.Includes {
		child := GetSpfTree(includeDomain, resolver)
		out.Children = append(out.Children, child)
		out.Ip4Count += child.Ip4Count
		out.Ip6Count += child.Ip6Count
	}

	return &out
}

func GetSpfRecord(ctx context.Context, domain string, resolver *resolve.Resolvers) (string, bool, error) {

	dns_txt_records, err := GetDnsRecord(ctx, domain, dns.TypeTXT, resolver)
	if err != nil {
		return "", false, err
	}

	for _, record := range dns_txt_records {
		if strings.Contains(strings.ToLower(record), "v=spf1") {
			return record, true, nil
		}
	}

	return "", false, nil

}
