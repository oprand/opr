// Package nro owns resource -> registry attribution derived from the NRO
// delegated-stats snapshot, plus the registry -> RDAP base URL mapping. For now
// it hosts the URL-based registry detection absorbed from aggregator/registry;
// the delegated-stats ingest and asn/prefix -> registry lookups land in a later
// phase.
package nro

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/oprand/opr/internal/opconst"
)

// FindRegistryByURL maps an RDAP/whois URL to the RIR that operates it. It is a
// best-effort substring match on the host, tolerant of redirect targets such as
// registro.br (operated under LACNIC).
func FindRegistryByURL(url string) (string, error) {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "arin"):
		return opconst.ARIN, nil
	case strings.Contains(lower, "ripe"):
		return opconst.RIPE, nil
	case strings.Contains(lower, "apnic"):
		return opconst.APNIC, nil
	case strings.Contains(lower, "lacnic"):
		return opconst.LACNIC, nil
	case strings.Contains(lower, "registro.br"):
		return opconst.LACNIC, nil
	case strings.Contains(lower, "afrinic"):
		return opconst.AFRINIC, nil
	default:
		return "", fmt.Errorf("couldn't find registry from url")
	}
}

// RDAPBaseURL returns the canonical RDAP base URL for a given RIR, or an empty
// string if the registry is unknown. Backed by opconst.RegistryRDAPEndpoints so
// request sites can set req.Server explicitly instead of relying on bootstrap.
// Country-specific NIRs (LACNIC+BR → registro.br) use RDAPBaseURLFor.
func RDAPBaseURL(registry string) string {
	return RDAPBaseURLFor(registry, "")
}

// RDAPBaseURLFor returns the RDAP base URL for a registry, optionally narrowed
// by ISO country code from the live NRO delegated_stats snapshot. LACNIC
// resources tagged BR are served by NIC.br (https://rdap.registro.br, no /rdap
// suffix). Empty or non-BR country keeps the parent RIR endpoint (lacnic.net).
// Mexico has no public IP/ASN RDAP, so MX (and every other LACNIC economy)
// stays on lacnic.net.
func RDAPBaseURLFor(registry, country string) string {
	if strings.EqualFold(registry, opconst.LACNIC) && strings.EqualFold(strings.TrimSpace(country), "BR") {
		return opconst.RegistroBRRDAPEndpoint
	}
	return opconst.RegistryRDAPEndpoints[registry]
}

// HostIsRegistroBR reports whether host (or a full URL) is NIC.br RDAP.
func HostIsRegistroBR(hostOrURL string) bool {
	return strings.Contains(strings.ToLower(rdapHostname(hostOrURL)), "registro.br")
}

func rdapHostname(hostOrURL string) string {
	s := strings.TrimSpace(hostOrURL)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	return strings.ToLower(s)
}
