package geofeeds

import (
	"strings"
	"testing"
)

func TestLooksLikeHTML(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{in: "<!DOCTYPE html><html>", want: true},
		{in: "  <HTML lang=en>", want: true},
		{in: "<head><title>x</title>", want: true},
		{in: "192.0.2.0/24,US", want: false},
		{in: "# comment\n192.0.2.0/24,US", want: false},
		{in: "", want: false},
	}
	for _, tc := range cases {
		if got := looksLikeHTML(tc.in); got != tc.want {
			t.Errorf("looksLikeHTML(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseRFC8805Table(t *testing.T) {
	t.Parallel()
	const url = "https://example.com/feed.csv"
	cases := []struct {
		name      string
		in        string
		wantNets  []string
		wantCC    []string
		wantCity  []string
		wantEmpty bool
	}{
		{
			name:     "five fields",
			in:       "192.0.2.0/24,US,US-CA,Mountain View,94043\n",
			wantNets: []string{"192.0.2.0/24"},
			wantCC:   []string{"US"},
			wantCity: []string{"Mountain View"},
		},
		{
			name:     "short row two fields",
			in:       "192.0.2.0/24,US\n",
			wantNets: []string{"192.0.2.0/24"},
			wantCC:   []string{"US"},
			wantCity: []string{""},
		},
		{
			name:     "short row prefix only",
			in:       "192.0.2.0/24\n",
			wantNets: []string{"192.0.2.0/24"},
			wantCC:   []string{""},
		},
		{
			name:     "comments and empty lines skipped",
			in:       "# RFC 8805\n\n  \n# another\n203.0.113.0/24,DE\n",
			wantNets: []string{"203.0.113.0/24"},
			wantCC:   []string{"DE"},
		},
		{
			name:      "comments only is empty success",
			in:        "# only comments\n\n# still\n",
			wantEmpty: true,
		},
		{
			name:     "invalid cidr skipped valid kept",
			in:       "not-a-prefix,US\n198.51.100.0/24,BR\n",
			wantNets: []string{"198.51.100.0/24"},
			wantCC:   []string{"BR"},
		},
		{
			name:     "ipv6",
			in:       "2001:db8::/32,US\n",
			wantNets: []string{"2001:db8::/32"},
			wantCC:   []string{"US"},
		},
		{
			name:     "does not require five fields mixed",
			in:       "192.0.2.0/24,US,US-NY\n198.51.100.0/24,GB,GB-ENG,London,EC1A\n",
			wantNets: []string{"192.0.2.0/24", "198.51.100.0/24"},
			wantCC:   []string{"US", "GB"},
			wantCity: []string{"", "London"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			items, err := ParseRFC8805(strings.NewReader(tc.in), url, "")
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
				gotCC := ""
				if it.CountryCode != nil {
					gotCC = *it.CountryCode
				}
				if i < len(tc.wantCC) && gotCC != tc.wantCC[i] {
					t.Errorf("cc[%d]=%q, want %q", i, gotCC, tc.wantCC[i])
				}
				if i < len(tc.wantCity) {
					gotCity := ""
					if it.City != nil {
						gotCity = *it.City
					}
					if gotCity != tc.wantCity[i] {
						t.Errorf("city[%d]=%q, want %q", i, gotCity, tc.wantCity[i])
					}
				}
				if it.Source == nil || *it.Source != SourceGEOFEED {
					t.Errorf("source[%d]=%v, want GEOFEED", i, it.Source)
				}
				if it.SourceURL == nil || *it.SourceURL != url {
					t.Errorf("source_url[%d]=%v, want %s", i, it.SourceURL, url)
				}
			}
		})
	}
}

func TestParseGeofeedBodyHTMLUnparseable(t *testing.T) {
	t.Parallel()
	_, err := parseGeofeedBody(strings.NewReader("<!DOCTYPE html><html><body>nope</body></html>"), "https://example.com/f.csv", "text/html")
	if err != ErrUnparseable {
		t.Fatalf("content-type html: err=%v, want ErrUnparseable", err)
	}
	_, err = parseGeofeedBody(strings.NewReader("<html><p>not csv</p></html>"), "https://example.com/f.csv", "text/plain")
	if err != ErrUnparseable {
		t.Fatalf("body html: err=%v, want ErrUnparseable", err)
	}
}

func TestParseGeofeedBodyCSVOK(t *testing.T) {
	t.Parallel()
	items, err := parseGeofeedBody(strings.NewReader("192.0.2.0/24,US\n"), "https://example.com/f.csv", "text/csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Netblock != "192.0.2.0/24" {
		t.Fatalf("got %+v", items)
	}
}

func TestCharsetFromContentType(t *testing.T) {
	t.Parallel()
	if got := charsetFromContentType(`text/csv; charset=ISO-8859-1`); !strings.EqualFold(got, "ISO-8859-1") {
		t.Fatalf("got %q", got)
	}
	if got := charsetFromContentType("text/csv"); got != "" {
		t.Fatalf("got %q", got)
	}
}
