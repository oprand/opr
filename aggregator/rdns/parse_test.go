package rdns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseZoneFileFixture(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("testdata", "193.in-addr.arpa-RIPE"))
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := filterDelegationMaster(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filtered, "ns.ripe.net") {
		t.Fatalf("apex NS dropped from filter:\n%s", filtered)
	}

	rows, err := ParseZoneFile(strings.NewReader(string(b)), "193.in-addr.arpa.", "193.in-addr.arpa-RIPE")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]parsedRR{}
	for _, r := range rows {
		by[r.Zone] = r
	}

	apex := by["193.in-addr.arpa."]
	if apex.Prefix != "193.0.0.0/8" {
		t.Fatalf("apex prefix=%s keys=%v", apex.Prefix, keys(by))
	}
	if len(apex.Nservers) != 2 {
		t.Fatalf("apex ns=%v", apex.Nservers)
	}

	child := by["0.0.193.in-addr.arpa."]
	if child.Prefix != "193.0.0.0/24" {
		t.Fatalf("child prefix=%s", child.Prefix)
	}
	if len(child.Nservers) != 2 {
		t.Fatalf("child ns=%v", child.Nservers)
	}
	if len(child.DS) != 1 || !strings.Contains(child.DS[0], "12345 8 2") {
		t.Fatalf("child ds=%v", child.DS)
	}

	rfc2317 := by["128/25.1.0.193.in-addr.arpa."]
	if rfc2317.Prefix != "193.0.1.128/25" {
		t.Fatalf("rfc2317 prefix=%s", rfc2317.Prefix)
	}
	if rfc2317.CNAMETarget == nil || *rfc2317.CNAMETarget != "128.1.0.193.in-addr.arpa.customer.example.net" {
		t.Fatalf("cname=%v", rfc2317.CNAMETarget)
	}

	for _, r := range rows {
		if strings.Contains(strings.ToLower(strings.Join(r.Nservers, " ")), "rrsig") {
			t.Fatal("RRSIG must not become an NS")
		}
	}
}

func keys(m map[string]parsedRR) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseZoneFileEmptySOAOnly(t *testing.T) {
	t.Parallel()
	body := `$ORIGIN 193.in-addr.arpa.
@ IN SOA ns.ripe.net. dns.ripe.net. 1 2 3 4 5
`
	rows, err := ParseZoneFile(strings.NewReader(body), "193.in-addr.arpa.", "empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows", len(rows))
	}
}

func TestParseZoneFileGenerateSmall(t *testing.T) {
	t.Parallel()
	body := `$ORIGIN 193.in-addr.arpa.
$GENERATE 0-2 $.0 NS ns.example.net.
`
	rows, err := ParseZoneFile(strings.NewReader(body), "193.in-addr.arpa.", "gen")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%d want 3: %+v", len(rows), rows)
	}
}

func TestParseZoneFileGenerateCapped(t *testing.T) {
	t.Parallel()
	body := `$ORIGIN 193.in-addr.arpa.
$GENERATE 0-99999 $ NS ns.example.net.
`
	_, err := ParseZoneFile(strings.NewReader(body), "193.in-addr.arpa.", "bomb")
	if !errors.Is(err, ErrGenerateLimit) {
		t.Fatalf("err=%v, want ErrGenerateLimit", err)
	}
}
