package geoip

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/oprand/opr/store/postgres"
)

func TestAnycastURLsEqualStatusKeys(t *testing.T) {
	t.Parallel()
	if AnycastV4DumpURL != postgres.AnycastV4DumpURL || AnycastV6DumpURL != postgres.AnycastV6DumpURL {
		t.Fatalf("aggregator URLs must alias store keys: %q %q", AnycastV4DumpURL, AnycastV6DumpURL)
	}
	if len(AnycastDumpURLs) != 2 || AnycastDumpURLs[0] != AnycastV4DumpURL || AnycastDumpURLs[1] != AnycastV6DumpURL {
		t.Fatalf("AnycastDumpURLs = %#v", AnycastDumpURLs)
	}
	if !strings.Contains(AnycastV4DumpURL, "anycatch-v4-prefixes.csv") {
		t.Fatalf("v4 url = %q", AnycastV4DumpURL)
	}
	if !strings.Contains(AnycastV6DumpURL, "anycatch-v6-prefixes.csv") {
		t.Fatalf("v6 url = %q", AnycastV6DumpURL)
	}
}

func TestParseAnycastTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        string
		wantNets  []string
		wantHosts []string
		wantEmpty bool
	}{
		{
			name:      "v4 prefix and host",
			in:        "1.1.1.0/24,1.1.1.0\n",
			wantNets:  []string{"1.1.1.0/24"},
			wantHosts: []string{"1.1.1.0"},
		},
		{
			name:      "v6 prefix and host",
			in:        "2001:db8::/32,2001:db8::1\n",
			wantNets:  []string{"2001:db8::/32"},
			wantHosts: []string{"2001:db8::1"},
		},
		{
			name:     "invalid cidr skipped valid kept",
			in:       "not-a-prefix,1.1.1.0\n198.51.100.0/24,198.51.100.1\n",
			wantNets: []string{"198.51.100.0/24"},
		},
		{
			name:      "bare ip is not a cidr skipped",
			in:        "192.0.2.9,192.0.2.9\n",
			wantEmpty: true,
		},
		{
			name:     "host bits cidr skipped canonical kept",
			in:       "192.0.2.5/24,192.0.2.5\n192.0.2.0/24,192.0.2.1\n",
			wantNets: []string{"192.0.2.0/24"},
		},
		{
			name:     "ipv6 host bits skipped",
			in:       "2001:db8::1/32,2001:db8::1\n2001:db8::/32,2001:db8::1\n",
			wantNets: []string{"2001:db8::/32"},
		},
		{
			name:      "prefix only null host",
			in:        "192.0.2.0/24\n",
			wantNets:  []string{"192.0.2.0/24"},
			wantHosts: []string{nilStr},
		},
		{
			name:      "invalid host kept prefix",
			in:        "192.0.2.0/24,not-an-ip\n",
			wantNets:  []string{"192.0.2.0/24"},
			wantHosts: []string{nilStr},
		},
		{
			name:      "comments and empty lines skipped",
			in:        "# anycast dump\n\n  \n# another\n203.0.113.0/24,203.0.113.1\n",
			wantNets:  []string{"203.0.113.0/24"},
			wantEmpty: false,
		},
		{
			name:      "comments only is empty success",
			in:        "# only comments\n\n# still\n",
			wantEmpty: true,
		},
		{
			name:     "header-like first row skipped as invalid cidr",
			in:       "prefix,example_host\n1.0.0.0/24,1.0.0.1\n",
			wantNets: []string{"1.0.0.0/24"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			items, err := ParseAnycast(strings.NewReader(tc.in), AnycastV4DumpURL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tc.wantEmpty {
				if len(items) != 0 {
					t.Fatalf("got %d items, want 0", len(items))
				}
				return
			}
			if len(items) != len(tc.wantNets) {
				t.Fatalf("got %d items, want %d", len(items), len(tc.wantNets))
			}
			for i, it := range items {
				if it.Netblock != tc.wantNets[i] {
					t.Errorf("netblock[%d]=%q, want %q", i, it.Netblock, tc.wantNets[i])
				}
				if it.SourceURL != AnycastV4DumpURL {
					t.Errorf("source_url[%d]=%q", i, it.SourceURL)
				}
			}
			if tc.wantHosts != nil {
				if len(tc.wantHosts) != len(items) {
					t.Fatalf("hosts: got %d items, want %d values", len(items), len(tc.wantHosts))
				}
				for i, it := range items {
					got := ptrStr(it.ExampleHost)
					if got != tc.wantHosts[i] {
						t.Errorf("host[%d]=%q, want %q", i, got, tc.wantHosts[i])
					}
				}
			}
		})
	}
}

func TestParseAnycastNetblockRejectsGarbageAndHostBits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "not-a-cidr", ok: false},
		{in: "", ok: false},
		{in: "192.0.2.5/24", ok: false},
		{in: "192.0.2.0/24", want: "192.0.2.0/24", ok: true},
		{in: "192.0.2.9", ok: false},
		{in: "2001:db8::1", ok: false},
		{in: "2001:db8::1/32", ok: false},
		{in: "2001:db8::/32", want: "2001:db8::/32", ok: true},
	}
	for _, tc := range cases {
		got, ok := parseAnycastNetblock(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseAnycastNetblock(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseAnycastStickyErrorDoesNotHang(t *testing.T) {
	t.Parallel()
	r := &stickyErrReader{err: errors.New("sticky csv")}
	_, err := ParseAnycast(r, AnycastV4DumpURL)
	if err == nil {
		t.Fatal("sticky error must be returned")
	}
	if !strings.Contains(err.Error(), "sticky csv") {
		t.Fatalf("err=%v, want wrapped sticky csv", err)
	}
	if r.n > 100 {
		t.Fatalf("too many reads (%d); ParseAnycast must not continue on sticky error", r.n)
	}
}

func TestParseAnycastBodyTooLarge(t *testing.T) {
	t.Parallel()
	r := newCapReader(strings.NewReader(strings.Repeat("a", 8)), 4, ErrAnycastTooLarge)
	b, err := io.ReadAll(r)
	if !errors.Is(err, ErrAnycastTooLarge) {
		t.Fatalf("err=%v, want ErrAnycastTooLarge", err)
	}
	if string(b) != "aaaa" {
		t.Fatalf("got %q", b)
	}
}
