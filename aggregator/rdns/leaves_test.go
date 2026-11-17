package rdns

import (
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
)

func TestSelectLeavesSkipsParentWhenChildExists(t *testing.T) {
	t.Parallel()
	rows := []postgres.RDNSDelegation{
		{Zone: "193.in-addr.arpa.", Prefix: "193.0.0.0/8", Nservers: []string{"ns.ripe.net"}, Source: opconst.RIPE},
		{Zone: "0.0.193.in-addr.arpa.", Prefix: "193.0.0.0/24", Nservers: []string{"ns.example.net"}, Source: opconst.RIPE},
		{Zone: "1.in-addr.arpa.", Prefix: "1.0.0.0/8", Nservers: []string{"ns.apnic.net"}, Source: postgres.RDNSSourceIANA},
	}
	leaves := SelectLeaves(rows)
	if len(leaves) != 1 || leaves[0].Prefix != "193.0.0.0/24" {
		t.Fatalf("leaves=%+v, want only 193.0.0.0/24 ( /8 not a leaf )", leaves)
	}
	walk, skip := PartitionLeaves(leaves)
	if len(walk) != 1 || len(skip) != 0 {
		t.Fatalf("walk=%+v skip=%+v", walk, skip)
	}
}

func TestSelectLeavesSkipsCoarseIPv4Leftover(t *testing.T) {
	t.Parallel()
	rows := []postgres.RDNSDelegation{
		{Zone: "10.in-addr.arpa.", Prefix: "10.0.0.0/8", Nservers: []string{"ns.example.net"}, Source: opconst.ARIN},
	}
	leaves := SelectLeaves(rows)
	if len(leaves) != 1 {
		t.Fatalf("leftover /8 is still a SQL-shaped leaf: %+v", leaves)
	}
	walk, skip := PartitionLeaves(leaves)
	if len(walk) != 0 || len(skip) != 1 || skip[0].Reason != SkipTooCoarse {
		t.Fatalf("walk=%+v skip=%+v", walk, skip)
	}
}

func TestIPv6Slash32NotExpanded(t *testing.T) {
	t.Parallel()
	rows := []postgres.RDNSDelegation{
		{Zone: "2.0.0.1.ip6.arpa.", Prefix: "2001:200::/32", Nservers: []string{"ns1.apnic.net"}, Source: opconst.APNIC},
	}
	leaves := SelectLeaves(rows)
	walk, skip := PartitionLeaves(leaves)
	if len(walk) != 0 {
		t.Fatalf("must not walk IPv6 /32: walk=%+v", walk)
	}
	if len(skip) != 1 || skip[0].Reason != SkipTooCoarse {
		t.Fatalf("skip=%+v", skip)
	}
	if SkipReason("2001:db8::/32") != SkipTooCoarse {
		t.Fatal("IPv6 /32 is too coarse")
	}
}

func TestIPv6Slash48NotHostEnumerated(t *testing.T) {
	t.Parallel()
	if SkipReason("2001:db8::/48") != SkipIPv6TooWide {
		t.Fatal("/48 is a leaf but must not enumerate 2^80 hosts")
	}
	if SkipReason("2001:db8::/120") != "" {
		t.Fatal("/120 should enumerate (256 addrs)")
	}
}

func TestEnumerateAddressesV4Slash24(t *testing.T) {
	t.Parallel()
	ips, err := EnumerateAddresses("192.0.2.0/24", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 256 {
		t.Fatalf("len=%d", len(ips))
	}
	if ips[0].String() != "192.0.2.0" || ips[255].String() != "192.0.2.255" {
		t.Fatalf("range %s .. %s", ips[0], ips[255])
	}
	_, err = EnumerateAddresses("10.0.0.0/8", 256)
	if err == nil {
		t.Fatal("/8 must not enumerate without truncating")
	}
}

func TestShuffleAddressesKeepsSet(t *testing.T) {
	t.Parallel()
	ips, err := EnumerateAddresses("192.0.2.0/24", 256)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]struct{}{}
	for _, ip := range ips {
		before[ip.String()] = struct{}{}
	}
	ShuffleAddresses(ips)
	if len(ips) != 256 {
		t.Fatalf("len=%d", len(ips))
	}
	for _, ip := range ips {
		if _, ok := before[ip.String()]; !ok {
			t.Fatalf("shuffle introduced %s", ip)
		}
		delete(before, ip.String())
	}
	if len(before) != 0 {
		t.Fatalf("shuffle dropped %d addrs", len(before))
	}
}

func TestValidateUserPrefixRefusesSlash8(t *testing.T) {
	t.Parallel()
	err := ValidateUserPrefix("10.0.0.0/8", false, 0)
	if err == nil {
		t.Fatal("want error")
	}
	if err := ValidateUserPrefix("10.0.0.0/8", true, 256); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUserPrefix("192.0.2.0/24", false, 0); err != nil {
		t.Fatal(err)
	}
}

func TestIntersectPrefixAndZoneFilter(t *testing.T) {
	t.Parallel()
	got, err := IntersectPrefix("193.0.0.0/24", "193.0.0.0/25")
	if err != nil || got != "193.0.0.0/25" {
		t.Fatalf("got %s err=%v", got, err)
	}
	leaves := []postgres.RDNSLeaf{
		{Zone: "0.0.193.in-addr.arpa.", Prefix: "193.0.0.0/24", Nservers: []string{"ns"}, Source: "RIPE"},
		{Zone: "1.0.1.in-addr.arpa.", Prefix: "1.0.1.0/24", Nservers: []string{"ns"}, Source: "APNIC"},
	}
	gotLeaves := filterLeavesByZone(leaves, "0.0.193.in-addr.arpa")
	if len(gotLeaves) != 1 || !strings.HasPrefix(gotLeaves[0].Prefix, "193.0.0.0/") {
		t.Fatalf("%+v", gotLeaves)
	}
	under8 := filterLeavesByZone(leaves, "193.in-addr.arpa")
	if len(under8) != 1 {
		t.Fatalf(" /8 zone should keep child /24: %+v", under8)
	}
}
