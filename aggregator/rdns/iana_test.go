package rdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestIANAZoneOrigin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		want string
	}{
		{"https://www.internic.net/zones/in-addr.arpa.zone", "in-addr.arpa."},
		{"https://www.internic.net/zones/in-addr.arpa", "in-addr.arpa."},
		{"https://www.internic.net/zones/ip6.arpa", "ip6.arpa."},
		{"https://www.internic.net/zones/ip6.arpa.zone", "ip6.arpa."},
	}
	for _, tc := range cases {
		got, ok := IANAZoneOrigin(tc.url)
		if !ok || got != tc.want {
			t.Errorf("%s: got %q ok=%v, want %s", tc.url, got, ok, tc.want)
		}
	}
}

func TestRIRFromNameserver(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ns   string
		want string
	}{
		{"ns.afrinic.net", "AFRINIC"},
		{"ns1.apnic.net", "APNIC"},
		{"ns3.lacnic.net", "LACNIC"},
		{"r.arin.net", "ARIN"},
		{"arin.authdns.ripe.net", "ARIN"},
		{"apnic.authdns.ripe.net", "APNIC"},
		{"pri.authdns.ripe.net", "RIPE"},
		{"ns.ripe.net", "RIPE"},
		{"a.in-addr-servers.arpa", ""},
		{"ns01.army.mil", ""},
	}
	for _, tc := range cases {
		if got := postgres.RIRFromNameserver(tc.ns); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.ns, got, tc.want)
		}
	}
}

func TestMajorityRIR(t *testing.T) {
	t.Parallel()
	if got := majorityRIR([]string{"r.arin.net", "u.arin.net", "arin.authdns.ripe.net"}); got != "ARIN" {
		t.Fatalf("got %s, want ARIN", got)
	}
	if got := majorityRIR([]string{"ns.afrinic.net", "ns1.apnic.net"}); got != "" {
		t.Fatalf("tie should be empty, got %s", got)
	}
}

func TestIngestIANAParentZones(t *testing.T) {
	t.Parallel()
	mem := newMemRDNSStore()
	const inaddr = `in-addr.arpa. IN SOA b.in-addr-servers.arpa. nstld.iana.org. 1 2 3 4 5
41.in-addr.arpa. IN NS ns.afrinic.net.
41.in-addr.arpa. IN NS ns-afr.afrinic.net.
1.in-addr.arpa. IN NS ns1.apnic.net.
1.in-addr.arpa. IN NS rirns.arin.net.
`
	const ip6 = `ip6.arpa. IN SOA b.ip6-servers.arpa. nstld.iana.org. 1 2 3 4 5
2.0.1.0.0.2.ip6.arpa. IN NS ns1.apnic.net.
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch {
		case strings.HasSuffix(r.URL.Path, "in-addr.arpa.zone"):
			if r.Method == http.MethodGet {
				w.Write([]byte(inaddr))
			}
		case strings.HasSuffix(r.URL.Path, "ip6.arpa"):
			if r.Method == http.MethodGet {
				w.Write([]byte(ip6))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	in := NewIngestor(zap.NewNop(), mem, srv.Client(), []Source{{Name: opconst.RIPE, ListURL: srv.URL + "/missing/"}})
	in.Sources = nil
	in.IANAInAddrURL = srv.URL + "/in-addr.arpa.zone"
	in.IANAIP6URL = srv.URL + "/ip6.arpa"
	if err := in.Ingest(context.Background()); err != nil {
		t.Fatal(err)
	}

	inaddrURL := srv.URL + "/in-addr.arpa.zone"
	got := mem.replaced[inaddrURL]
	if len(got) != 2 {
		t.Fatalf("IANA in-addr rows=%d want 2: %+v", len(got), got)
	}
	byZone := map[string]postgres.RDNSDelegation{}
	for _, row := range got {
		if row.Source != postgres.RDNSSourceIANA {
			t.Fatalf("source=%s", row.Source)
		}
		byZone[row.Zone] = row
	}
	afr := byZone["41.in-addr.arpa."]
	if afr.DelegatedRIR != opconst.AFRINIC || afr.Prefix != "41.0.0.0/8" {
		t.Fatalf("41.in-addr: %+v", afr)
	}
	if mem.replaceN < 1 {
		t.Fatalf("replaceN=%d", mem.replaceN)
	}
}
