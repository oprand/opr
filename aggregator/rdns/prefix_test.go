package rdns

import (
	"strings"
	"testing"
)

func TestZoneToPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		zone string
		want string
	}{
		{"193.in-addr.arpa", "193.0.0.0/8"},
		{"193.in-addr.arpa.", "193.0.0.0/8"},
		{"0.193.in-addr.arpa", "193.0.0.0/16"},
		{"1.0.193.in-addr.arpa", "193.0.1.0/24"},
		{"0.0.193.in-addr.arpa", "193.0.0.0/24"},
		{"5.1.0.193.in-addr.arpa", "193.0.1.5/32"},
		{"128/25.2.0.192.in-addr.arpa", "192.0.2.128/25"},
		{"0/25.2.0.192.in-addr.arpa", "192.0.2.0/25"},
		{"0.4.2.ip6.arpa", "2400::/12"},
		{"0.4.2.ip6.arpa.", "2400::/12"},
		{"a.8.ip6.arpa", "8a00::/8"},
	}
	for _, tc := range cases {
		got, err := ZoneToPrefix(tc.zone)
		if err != nil {
			t.Errorf("%s: %v", tc.zone, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.zone, got, tc.want)
		}
		if strings.Contains(tc.zone, "/") {
			continue
		}
		back, err := PrefixToZone(got)
		if err != nil {
			t.Errorf("PrefixToZone(%s): %v", got, err)
			continue
		}
		wantZone := canonicalZone(tc.zone)
		if back != wantZone {
			t.Errorf("PrefixToZone(%s)=%s, want %s", got, back, wantZone)
		}
	}
}

func TestZoneToPrefixRejectsParents(t *testing.T) {
	t.Parallel()
	for _, z := range []string{"in-addr.arpa", "ip6.arpa.", "example.com"} {
		if _, err := ZoneToPrefix(z); err == nil {
			t.Errorf("%s: want error", z)
		}
	}
}
