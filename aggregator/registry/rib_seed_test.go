package registry

import (
	"bytes"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/bgptools/fgbgp/messages"
	mrt2 "github.com/bgptools/fgbgp/mrt"
	"go.uber.org/zap"
)

// writeRibRecord appends one TABLE_DUMP_V2 RIB record for cidr, with entries
// peers announcing it. The repo has no full RIB fixture (the only MRT file
// vendored with fgbgp is a 2003 TABLE_DUMP v1 dump, which this walk ignores by
// design), so the stream is synthesized through the same writer the decoder
// reads.
func writeRibRecord(t *testing.T, buf *bytes.Buffer, cidr string, entries int) {
	t.Helper()

	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %q: %v", cidr, err)
	}
	afi := uint16(messages.AFI_IPV4)
	if netw.IP.To4() == nil {
		afi = uint16(messages.AFI_IPV6)
	}

	rec := mrt2.NewMrtTableDumpV2_RibAfiSafi(0, afi, messages.SAFI_UNICAST,
		messages.NLRI_IPPrefix{Prefix: *netw}, time.Unix(0, 0))
	for i := 0; i < entries; i++ {
		rec.AddEntry(uint16(i), time.Unix(0, 0), nil)
	}
	rec.Write(buf)
}

func TestDecodeRibPrefixes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writeRibRecord(t, &buf, "192.0.2.0/24", 1)
	// Several peers announcing the same prefix must still yield one CIDR.
	writeRibRecord(t, &buf, "198.51.100.0/22", 3)
	writeRibRecord(t, &buf, "2001:db8::/32", 2)
	// Repeated in a later record (a second collector view of the same prefix).
	writeRibRecord(t, &buf, "192.0.2.0/24", 1)

	got := decodeRibPrefixes(&buf, zap.NewNop())
	want := []string{"192.0.2.0/24", "198.51.100.0/22", "2001:db8::/32"}
	if !reflect.DeepEqual(sortedKeys(got), want) {
		t.Fatalf("got %#v, want %#v", sortedKeys(got), want)
	}
}

func TestDecodeRibPrefixesDropsDefaultRoutesAndEmptyRecords(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writeRibRecord(t, &buf, "0.0.0.0/0", 2)
	writeRibRecord(t, &buf, "::/0", 2)
	// A record with no rib entries announces nothing.
	writeRibRecord(t, &buf, "203.0.113.0/24", 0)
	writeRibRecord(t, &buf, "192.0.2.0/24", 1)

	got := decodeRibPrefixes(&buf, zap.NewNop())
	want := []string{"192.0.2.0/24"}
	if !reflect.DeepEqual(sortedKeys(got), want) {
		t.Fatalf("got %#v, want %#v", sortedKeys(got), want)
	}
}

func TestDecodeRibPrefixesEmptyStream(t *testing.T) {
	t.Parallel()

	if got := decodeRibPrefixes(bytes.NewReader(nil), zap.NewNop()); len(got) != 0 {
		t.Fatalf("got %#v, want empty", got)
	}
}

func TestIsDefaultRoute(t *testing.T) {
	t.Parallel()

	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if !isDefaultRoute(cidr) {
			t.Fatalf("%s must be a default route", cidr)
		}
	}
	for _, cidr := range []string{"0.0.0.0/8", "::/8", "192.0.2.0/24"} {
		if isDefaultRoute(cidr) {
			t.Fatalf("%s must not be a default route", cidr)
		}
	}
}

func TestNewRibSeederResolvesSlugs(t *testing.T) {
	t.Parallel()

	s, err := NewRibSeeder(zap.NewNop(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Collectors) != len(DefaultRibSeedCollectors) {
		t.Fatalf("got %d collectors, want %d", len(s.Collectors), len(DefaultRibSeedCollectors))
	}
	for i, want := range DefaultRibSeedCollectors {
		if s.Collectors[i].Slug != want {
			t.Fatalf("collector %d = %q, want %q", i, s.Collectors[i].Slug, want)
		}
		if s.Collectors[i].Host == "" {
			t.Fatalf("collector %q was not resolved from opbgp.BGPLocations", want)
		}
	}

	if _, err := NewRibSeeder(zap.NewNop(), nil, []string{"route-views.nowhere"}); err == nil {
		t.Fatal("unknown slug must error")
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
