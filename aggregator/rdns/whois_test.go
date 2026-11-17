package rdns

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestParseReverseDomainSkipsForward(t *testing.T) {
	t.Parallel()
	body := `domain:         example.com
org:            ORG-FWD
nserver:        ns.example.com

domain:         0.0.193.in-addr.arpa
org:            ORG-RIEN1-RIPE
admin-c:        CREW-RIPE
tech-c:         CREW-RIPE
nserver:        ns.ripe.net
nserver:        ns3.nic.fr
mnt-by:         RIPE-NCC-MNT
source:         RIPE

domain:         0.4.2.ip6.arpa
org:            ORG-APNIC
nserver:        ns1.apnic.net
`
	rows, err := parseReverseDomains(strings.NewReader(body), opconst.RIPE, "https://example.test/ripe.db.domain.gz", CharsetUTF8)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2 (forward domain skipped): %+v", len(rows), rows)
	}
	by := map[string]postgres.RDNSDelegation{}
	for _, r := range rows {
		by[r.Zone] = r
	}
	ripe := by["0.0.193.in-addr.arpa."]
	if ripe.Org != "ORG-RIEN1-RIPE" || ripe.Prefix != "193.0.0.0/24" {
		t.Fatalf("%+v", ripe)
	}
	if len(ripe.Nservers) != 2 || ripe.Nservers[0] != "ns.ripe.net" {
		t.Fatalf("ns=%v", ripe.Nservers)
	}
	if len(ripe.AdminC) != 1 || ripe.AdminC[0] != "CREW-RIPE" {
		t.Fatalf("admin=%v", ripe.AdminC)
	}
}

func TestParseAFRINICMixedDomainOnly(t *testing.T) {
	t.Parallel()
	body := `inetnum:        41.0.0.0 - 41.255.255.255
netname:        AFRINIC
nserver:        ns.afrinic.net

domain:         41.in-addr.arpa
org:            ORG-AFNI1-AFRINIC
admin-c:        CA15-AFRINIC
nserver:        ns.afrinic.net
mnt-by:         AFRINIC-HM-MNT
`
	rows, err := parseReverseDomains(strings.NewReader(body), opconst.AFRINIC, DefaultAFRINICWhoisURL, CharsetUTF8)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Zone != "41.in-addr.arpa." {
		t.Fatalf("mixed dump must keep domain: only: %+v", rows)
	}
	if rows[0].Org != "ORG-AFNI1-AFRINIC" {
		t.Fatalf("org=%s", rows[0].Org)
	}
}

func TestParseLacnicInetnumNserver(t *testing.T) {
	t.Parallel()
	body := `inetnum:     200.7.84/24
status:      allocated
nserver:     ns.lacnic.net
nsstat:      20240101 AA
nslastaa:    20240101
org:         ORG-LACNIC
admin-c:     LAC-AR
tech-c:      LAC-AR
mnt-by:      MNT-LACNIC

inetnum:     201.0.0.0/8
status:      allocated
org:         ORG-NO-NS
`
	rows, err := parseLacnicNserver(strings.NewReader(body), opconst.LACNIC, DefaultLACNICWhoisDBURL, CharsetISO8859)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 (inetnum without nserver skipped): %+v", len(rows), rows)
	}
	if rows[0].Zone != "84.7.200.in-addr.arpa." || rows[0].Prefix != "200.7.84.0/24" {
		t.Fatalf("%+v", rows[0])
	}
	if len(rows[0].Nservers) != 1 || rows[0].Nservers[0] != "ns.lacnic.net" {
		t.Fatalf("ns=%v", rows[0].Nservers)
	}
	if rows[0].Org != "ORG-LACNIC" {
		t.Fatalf("org=%s", rows[0].Org)
	}
}

func TestIngestWhoisDomainEnrichesWithoutReplaceOnEmptyZoneListing(t *testing.T) {
	t.Parallel()
	plain := []byte(`domain:         0.0.193.in-addr.arpa
org:            ORG-RIEN1-RIPE
nserver:        ns.ripe.net
admin-c:        CREW-RIPE

`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	mem := newMemRDNSStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			w.Write(gz.Bytes())
		}
	}))
	t.Cleanup(srv.Close)

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), nil)
	in.Sources = nil
	in.WhoisDumps = []WhoisDump{{Name: opconst.RIPE, URL: srv.URL + "/ripe.db.domain.gz", Kind: WhoisDumpDomain}}
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}
	var found []postgres.RDNSDelegation
	for _, rows := range mem.replaced {
		found = append(found, rows...)
	}
	if len(found) != 1 || found[0].Org != "ORG-RIEN1-RIPE" {
		t.Fatalf("whois rows=%+v", found)
	}
	if found[0].IsPartial != true {
		t.Fatal("whois-only row must be is_partial")
	}
}

func TestWhoisNSDoesNotReplaceZoneNS(t *testing.T) {
	t.Parallel()
	mem := newMemRDNSStore()
	zoneURL := "https://ftp.ripe.net/pub/zones/193.in-addr.arpa-RIPE"
	zoneRow := postgres.RDNSDelegation{
		Zone:      "0.0.193.in-addr.arpa.",
		Prefix:    "193.0.0.0/24",
		Nservers:  []string{"ns.ripe.net", "ns3.nic.fr"},
		Source:    opconst.RIPE,
		SourceURL: zoneURL,
	}
	if err := mem.ReplaceRDNSBySourceURL(context.Background(), zoneURL, []postgres.RDNSDelegation{zoneRow}); err != nil {
		t.Fatal(err)
	}
	whois := postgres.RDNSDelegation{
		Zone:      "0.0.193.in-addr.arpa.",
		Prefix:    "193.0.0.0/24",
		Nservers:  []string{"whois-only.example.net"},
		Source:    opconst.RIPE,
		SourceURL: "https://ftp.ripe.net/ripe/dbase/split/ripe.db.domain.gz",
		Org:       "ORG-RIEN1-RIPE",
		AdminC:    []string{"CREW-RIPE"},
	}
	if err := mem.UpsertRDNSDelegations(context.Background(), []postgres.RDNSDelegation{whois}); err != nil {
		t.Fatal(err)
	}
	got := mem.replaced[zoneURL]
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if strings.Contains(strings.Join(got[0].Nservers, " "), "whois-only") {
		t.Fatalf("zone NS must win: %v", got[0].Nservers)
	}
	if got[0].Org != "ORG-RIEN1-RIPE" {
		t.Fatalf("org=%s", got[0].Org)
	}
}
