package main

import (
	"strings"
	"testing"

	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/opconst"
)

func TestResolveBulkCoverageRegistries(t *testing.T) {
	t.Parallel()
	got, err := resolveBulkCoverageRegistries(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := whoisdb.BulkDumpCoverageRegistries()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("default = %v, want %v", got, want)
	}

	got, err = resolveBulkCoverageRegistries([]string{opconst.RIPE})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != opconst.RIPE {
		t.Fatalf("only RIPE = %v", got)
	}

	if _, err := resolveBulkCoverageRegistries([]string{opconst.ARIN}); err == nil {
		t.Fatal("ARIN must be rejected")
	}
	if _, err := resolveBulkCoverageRegistries([]string{"NOT_A_RIR"}); err == nil {
		t.Fatal("unknown registry must be rejected")
	}
}

func TestCanonicalCIDRArgs(t *testing.T) {
	t.Parallel()
	got, err := canonicalCIDRArgs([]string{"192.0.2.1/24", "2001:db8::1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "192.0.2.0/24" || got[1] != "2001:db8::/32" {
		t.Fatalf("got %v", got)
	}
	if _, err := canonicalCIDRArgs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid CIDR must error")
	}
	if _, err := canonicalCIDRArgs([]string{"", "  "}); err == nil {
		t.Fatal("empty CIDRs must error")
	}
}
