package rdns

import (
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
)

// Default RIR /zones/ directory URLs. Zone files live here; checksum sidecars
// are listed alongside and skipped by IsChecksumName.
const (
	DefaultRIPEZonesURL    = "https://ftp.ripe.net/pub/zones/"
	DefaultAPNICZonesURL   = "https://ftp.apnic.net/zones/"
	DefaultARINZonesURL    = "https://ftp.arin.net/pub/zones/"
	DefaultAFRINICZonesURL = "https://ftp.afrinic.net/pub/zones/"
	DefaultLACNICZonesURL  = "https://ftp.lacnic.net/pub/zones/"
)

// InterNIC / WHOIS dump URLs. Single source of truth is store (status board
// + ingest). Aggregator aliases so CLI flags do not duplicate the strings.
const (
	DefaultIANAInAddrURL    = postgres.IANAInAddrURL
	DefaultIANAIP6URL       = postgres.IANAIP6URL
	DefaultRIPEDomainURL    = postgres.RIPEDomainDumpURL
	DefaultAPNICDomainURL   = postgres.APNICDomainDumpURL
	DefaultAFRINICWhoisURL  = postgres.AFRINICWhoisDBURL
	DefaultLACNICWhoisDBURL = postgres.LACNICWhoisDBURL
)

// WhoisDumpKind selects which RPSL objects to harvest from a dump.
type WhoisDumpKind int

const (
	WhoisDumpDomain WhoisDumpKind = iota
	WhoisDumpMixedDomain
	WhoisDumpLacnicInetnum
)

// WhoisDump is one reverse-domain or LACNIC inetnum WHOIS file.
type WhoisDump struct {
	Name string
	URL  string
	Kind WhoisDumpKind
}

// DefaultWhoisDumps is RIPE/APNIC domain-only plus AFRINIC mixed (no second
// AFRINIC download URL). ARIN/LACNIC have no domain: dump.
var DefaultWhoisDumps = []WhoisDump{
	{Name: opconst.RIPE, URL: DefaultRIPEDomainURL, Kind: WhoisDumpDomain},
	{Name: opconst.APNIC, URL: DefaultAPNICDomainURL, Kind: WhoisDumpDomain},
	{Name: opconst.AFRINIC, URL: DefaultAFRINICWhoisURL, Kind: WhoisDumpMixedDomain},
}

// Source is one RIR's zone directory.
type Source struct {
	Name    string
	ListURL string
}

// DefaultSources is ingest order for `opr rdns ingest`.
var DefaultSources = []Source{
	{Name: opconst.AFRINIC, ListURL: DefaultAFRINICZonesURL},
	{Name: opconst.APNIC, ListURL: DefaultAPNICZonesURL},
	{Name: opconst.ARIN, ListURL: DefaultARINZonesURL},
	{Name: opconst.LACNIC, ListURL: DefaultLACNICZonesURL},
	{Name: opconst.RIPE, ListURL: DefaultRIPEZonesURL},
}
