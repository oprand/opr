package postgres

import (
	"reflect"
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestIPv4RangeToCIDRs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		start string
		count int64
		want  []string
	}{
		{
			// The NRO ipv4 address count is frequently not a power of two, so
			// one delegated row becomes several prefixes.
			name:  "non power of two count",
			start: "100.64.0.0",
			count: 196608,
			want:  []string{"100.64.0.0/15", "100.66.0.0/16"},
		},
		{
			name:  "single address",
			start: "192.0.2.5",
			count: 1,
			want:  []string{"192.0.2.5/32"},
		},
		{
			// Alignment, not the count, caps the first block here: a /24 worth
			// of addresses starting mid-block needs two /25s.
			name:  "unaligned start",
			start: "192.0.2.128",
			count: 256,
			want:  []string{"192.0.2.128/25", "192.0.3.0/25"},
		},
		{
			name:  "already /24 aligned",
			start: "203.0.113.0",
			count: 256,
			want:  []string{"203.0.113.0/24"},
		},
		{
			// End of the address space: the walk must not wrap past 2^32-1.
			name:  "last block",
			start: "255.255.255.252",
			count: 4,
			want:  []string{"255.255.255.252/30"},
		},
		{
			name:  "whole space",
			start: "0.0.0.0",
			count: 1 << 32,
			want:  []string{"0.0.0.0/0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start, ok := ipv4ToUint32(tc.start)
			if !ok {
				t.Fatalf("bad start %q", tc.start)
			}
			end := uint32(uint64(start) + uint64(tc.count) - 1)
			got := ipv4RangeToCIDRs(start, end)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestIPv4RangeToCIDRsRejectsInvertedRange(t *testing.T) {
	t.Parallel()
	if got := ipv4RangeToCIDRs(100, 99); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
}

func TestDelegatedRowCIDRs(t *testing.T) {
	t.Parallel()

	// ipv6 rows carry a prefix length in range_value, not an address count.
	got := delegatedRowCIDRs("ipv6", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 32)
	if want := []string{"2001:db8::/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ipv6 row: got %#v, want %#v", got, want)
	}

	// Keys must be canonical even if the published start address is not the
	// network address of the prefix length.
	got = delegatedRowCIDRs("ipv6", "2001:db8:1::", "", 32)
	if want := []string{"2001:db8::/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("non canonical ipv6 row: got %#v, want %#v", got, want)
	}

	got = delegatedRowCIDRs("ipv4", "100.64.0.0", "100.66.255.255", 196608)
	if want := []string{"100.64.0.0/15", "100.66.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ipv4 row: got %#v, want %#v", got, want)
	}

	if got := delegatedRowCIDRs("asn", "1", "10", 10); got != nil {
		t.Fatalf("asn row: got %#v, want nil", got)
	}
	if got := delegatedRowCIDRs("ipv4", "not-an-ip", "100.66.255.255", 10); got != nil {
		t.Fatalf("unparseable start: got %#v, want nil", got)
	}
	if got := delegatedRowCIDRs("ipv6", "2001:db8::", "", 129); got != nil {
		t.Fatalf("out of range prefix length: got %#v, want nil", got)
	}
}

func TestDelegatedRowCIDRsDropsDefaultRoutes(t *testing.T) {
	t.Parallel()

	if got := delegatedRowCIDRs("ipv6", "::", "", 0); len(got) != 0 {
		t.Fatalf("::/0 must be dropped, got %#v", got)
	}
	if got := delegatedRowCIDRs("ipv4", "0.0.0.0", "255.255.255.255", 1<<32); len(got) != 0 {
		t.Fatalf("0.0.0.0/0 must be dropped, got %#v", got)
	}
}

func TestIpnetSeedRegistriesFor(t *testing.T) {
	t.Parallel()

	if got, want := IpnetSeedRegistriesFor(nil), []string{opconst.ARIN, opconst.LACNIC}; !reflect.DeepEqual(got, want) {
		t.Fatalf("no filter: got %#v, want %#v", got, want)
	}
	if got, want := IpnetSeedRegistriesFor([]string{}), []string{opconst.ARIN, opconst.LACNIC}; !reflect.DeepEqual(got, want) {
		t.Fatalf("empty filter: got %#v, want %#v", got, want)
	}
	if got, want := IpnetSeedRegistriesFor([]string{opconst.ARIN}), []string{opconst.ARIN}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ARIN only: got %#v, want %#v", got, want)
	}
	// The other three RIRs have complete bulk dumps, so a RIPE-only filter has
	// nothing to seed rather than falling back to all.
	if got := IpnetSeedRegistriesFor([]string{opconst.RIPE}); got != nil {
		t.Fatalf("RIPE only: got %#v, want nil", got)
	}
	if got, want := IpnetSeedRegistriesFor([]string{opconst.RIPE, opconst.LACNIC, opconst.ARIN}),
		[]string{opconst.ARIN, opconst.LACNIC}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed filter: got %#v, want %#v", got, want)
	}

	// Mutating the returned slice must not corrupt the package-level default.
	got := IpnetSeedRegistriesFor(nil)
	got[0] = "MUTATED"
	if IpnetSeedRegistries[0] != opconst.ARIN {
		t.Fatalf("IpnetSeedRegistries was mutated: %#v", IpnetSeedRegistries)
	}
}

func TestCanonicalIpnetTargets(t *testing.T) {
	t.Parallel()

	got, invalid := canonicalIpnetTargets([]string{
		"0.0.0.0/0",
		"::/0",
		"192.0.2.5/24",
		"192.0.2.0/24",
		"not-a-cidr",
		"2001:db8:1::/48",
	})
	if invalid != 1 {
		t.Fatalf("invalid = %d, want 1", invalid)
	}
	want := []ipnetTarget{
		{cidr: "192.0.2.0/24", addr: "192.0.2.0"},
		{cidr: "2001:db8:1::/48", addr: "2001:db8:1::"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestDedupIpnetTargets(t *testing.T) {
	t.Parallel()

	if got := dedupIpnetTargets(nil); got != nil {
		t.Fatalf("nil input: got %#v, want nil", got)
	}
	got := dedupIpnetTargets([]ipnetTarget{
		{cidr: "192.0.2.0/24", registry: opconst.ARIN},
		{cidr: "192.0.2.0/24", registry: opconst.ARIN},
		// Same key under a different registry is a distinct crawl_target row.
		{cidr: "192.0.2.0/24", registry: opconst.LACNIC},
	})
	want := []ipnetTarget{
		{cidr: "192.0.2.0/24", registry: opconst.ARIN},
		{cidr: "192.0.2.0/24", registry: opconst.LACNIC},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
