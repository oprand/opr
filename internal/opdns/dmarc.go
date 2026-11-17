package opdns

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

// https://datatracker.ietf.org/doc/html/rfc7489#section-6.3
type DmarcRecord struct {
	Domain                 string
	Raw                    string
	DkimAlignment          string // adkim
	SpfAlignment           string // aspf
	Version                int    // v
	Policy                 string // p
	SubDomainPolicy        string // sp
	Percent                int    // pct
	FailureReporting       string // fo
	ReportFailureFormat    string // rf
	ReportInterval         int    // ri
	ReportAggregateAddress string // rua
	ReportFailureAddress   string // ruf
}

func NewDmarcRecord(domain string, raw string) DmarcRecord {

	return DmarcRecord{
		Domain:              domain,
		Raw:                 raw,
		DkimAlignment:       "r",
		SpfAlignment:        "r",
		Version:             1,
		Percent:             100,
		FailureReporting:    "0",
		ReportFailureFormat: "afrf",
		ReportInterval:      86400,
	}

}

func ParseDmarcRecord(domain string, dmarc string) *DmarcRecord {

	out := NewDmarcRecord(domain, dmarc)

	dmarc = strings.ToLower(dmarc)
	dmarc = strings.TrimSuffix(dmarc, ";")

	tokens := strings.Split(dmarc, "; ")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, "v=dmarc") {
			version, err := strconv.Atoi(token[len("v=dmarc"):])
			if err != nil {
				continue
			}
			out.Version = version
		} else if strings.HasPrefix(token, "p=") {
			out.Policy = token[len("p="):]
		} else if strings.HasPrefix(token, "sp=") {
			out.SubDomainPolicy = token[len("sp="):]
		} else if strings.HasPrefix(token, "pct=") {
			pct, err := strconv.Atoi(token[len("pct="):])
			if err != nil {
				continue
			}
			out.Percent = pct
		} else if strings.HasPrefix(token, "adkim=") {
			out.DkimAlignment = token[len("adkim="):]
		} else if strings.HasPrefix(token, "aspf=") {
			out.SpfAlignment = token[len("aspf="):]
		} else if strings.HasPrefix(token, "rua=") {
			out.ReportAggregateAddress = token[len("rua="):]
		} else if strings.HasPrefix(token, "ruf=") {
			out.ReportFailureAddress = token[len("ruf="):]
		} else if strings.HasPrefix(token, "ri=") {
			ri, err := strconv.Atoi(token[len("ri="):])
			if err != nil {
				continue
			}
			out.ReportInterval = ri
		} else if strings.HasPrefix(token, "fo=") {
			out.FailureReporting = token[len("fo="):]
		} else if strings.HasPrefix(token, "rf=") {
			out.ReportFailureFormat = token[len("rf="):]
		}
	}

	return &out

}

func GetDmarcRecord(ctx context.Context, domain string, resolver *resolve.Resolvers) (string, bool, error) {

	dmarcSubDomain := fmt.Sprintf("_dmarc.%s", domain)

	dns_txt_records, err := GetDnsRecord(ctx, dmarcSubDomain, dns.TypeTXT, resolver)
	if err != nil {
		return "", false, err
	}

	for _, record := range dns_txt_records {
		if strings.Contains(strings.ToLower(record), "v=dmarc") {
			return record, true, nil
		}
	}

	return "", false, nil

}
