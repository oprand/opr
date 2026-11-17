package rdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsChecksumName(t *testing.T) {
	t.Parallel()
	yes := []string{
		"193.in-addr.arpa-RIPE.md5",
		"193.in-addr.arpa-RIPE.asc",
		"zone.sig",
		"file.sha256",
		"SHA256SUMS",
		"MD5SUMS",
		"checksums",
		"checksum.txt",
	}
	for _, n := range yes {
		if !IsChecksumName(n) {
			t.Errorf("%s: want checksum skip", n)
		}
	}
	no := []string{
		"193.in-addr.arpa-RIPE",
		"0.4.2.ip6.arpa-APNIC",
		"0.0.1.in-addr.arpa-JPNIC",
	}
	for _, n := range no {
		if IsChecksumName(n) {
			t.Errorf("%s: must not skip", n)
		}
	}
}

func TestParseZoneListingSkipsChecksums(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "listing.html"))
	if err != nil {
		t.Fatal(err)
	}
	got := ParseZoneListing("https://ftp.ripe.net/pub/zones/", string(body))
	want := map[string]bool{
		"https://ftp.ripe.net/pub/zones/193.in-addr.arpa-RIPE": true,
		"https://ftp.ripe.net/pub/zones/0.4.2.ip6.arpa-APNIC":  true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected %s", u)
		}
	}
}

func TestParseZoneListingPlainText(t *testing.T) {
	t.Parallel()
	body := "193.in-addr.arpa-RIPE\n193.in-addr.arpa-RIPE.md5\nREADME.txt\n"
	got := ParseZoneListing("https://ftp.example.net/zones/", body)
	if len(got) != 1 || got[0] != "https://ftp.example.net/zones/193.in-addr.arpa-RIPE" {
		t.Fatalf("got %v", got)
	}
}

func TestParseZoneListingRIRFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file    string
		base    string
		source  string
		want    []string
		notWant []string
	}{
		{
			file:   "listing_ripe.html",
			base:   "https://ftp.ripe.net/pub/zones/",
			source: "RIPE",
			want: []string{
				"https://ftp.ripe.net/pub/zones/193.in-addr.arpa-RIPE",
				"https://ftp.ripe.net/pub/zones/0.4.2.ip6.arpa-RIPE",
			},
		},
		{
			file:   "listing_apnic.html",
			base:   "https://ftp.apnic.net/zones/",
			source: "APNIC",
			want: []string{
				"https://ftp.apnic.net/zones/1.in-addr.arpa-APNIC",
				"https://ftp.apnic.net/zones/0.4.2.ip6.arpa-APNIC",
			},
		},
		{
			file:   "listing_arin.html",
			base:   "https://ftp.arin.net/pub/zones/",
			source: "ARIN",
			want: []string{
				"https://ftp.arin.net/pub/zones/1.in-addr.arpa-ARIN",
				"https://ftp.arin.net/pub/zones/0.6.2.ip6.arpa",
			},
		},
		{
			file:   "listing_afrinic.html",
			base:   "https://ftp.afrinic.net/pub/zones/",
			source: "AFRINIC",
			want: []string{
				"https://ftp.afrinic.net/pub/zones/41.in-addr.arpa-AFRINIC",
				"https://ftp.afrinic.net/pub/zones/0.c.2.ip6.arpa-AFRINIC",
			},
			notWant: []string{
				"https://ftp.afrinic.net/pub/zones/41.in-addr.arpa",
				"https://ftp.afrinic.net/pub/zones/0.c.2.ip6.arpa",
			},
		},
		{
			file:   "listing_lacnic.html",
			base:   "https://ftp.lacnic.net/pub/zones/",
			source: "LACNIC",
			want: []string{
				"https://ftp.lacnic.net/pub/zones/2.in-addr.arpa-LACNIC",
				"https://ftp.lacnic.net/pub/zones/0.8.2.ip6.arpa-LACNIC",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			raw := ParseZoneListing(tc.base, string(body))
			got := PreferRIRZoneFiles(tc.source, raw)
			if len(got) == 0 {
				t.Fatalf("fixture %s ingested zero files; parser must handle this RIR HTML", tc.file)
			}
			if !ListingHasHrefs(string(body)) {
				t.Fatal("RIR fixture must look like HTML with hrefs")
			}
			set := map[string]bool{}
			for _, u := range got {
				set[u] = true
			}
			for _, w := range tc.want {
				if !set[w] {
					t.Errorf("missing %s in %v", w, got)
				}
			}
			for _, w := range tc.notWant {
				if set[w] {
					t.Errorf("must not ingest duplicate %s", w)
				}
			}
		})
	}
}

func TestParseZoneListingHrefsButNoZones(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join("testdata", "listing_empty_hrefs.html"))
	if err != nil {
		t.Fatal(err)
	}
	got := ParseZoneListing("https://ftp.example.net/pub/zones/", string(body))
	if !ListingHasHrefs(string(body)) {
		t.Fatal("expected hrefs")
	}
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestPreferRIRZoneFilesDropsUnsuffixedDuplicate(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://ftp.afrinic.net/pub/zones/41.in-addr.arpa",
		"https://ftp.afrinic.net/pub/zones/41.in-addr.arpa-AFRINIC",
		"https://ftp.afrinic.net/pub/zones/41.in-addr.arpa-AFRINIC.md5",
	}
	got := PreferRIRZoneFiles("AFRINIC", ParseZoneListing("https://ftp.afrinic.net/pub/zones/", strings.Join(urls, "\n")))
	if len(got) != 1 || got[0] != "https://ftp.afrinic.net/pub/zones/41.in-addr.arpa-AFRINIC" {
		t.Fatalf("got %v", got)
	}
}

func TestZoneFileOrigin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"193.in-addr.arpa-RIPE", "193.in-addr.arpa.", true},
		{"0.4.2.ip6.arpa-APNIC", "0.4.2.ip6.arpa.", true},
		{"0.0.1.in-addr.arpa-JPNIC", "0.0.1.in-addr.arpa.", true},
		{"193.in-addr.arpa-RIPE.md5", "", false},
		{"README.txt", "", false},
	}
	for _, tc := range cases {
		got, ok := ZoneFileOrigin(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: got %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
