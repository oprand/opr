package fdns

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"
)

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Example.COM.", "example.com", true},
		{"  www.Google.com  ", "www.google.com", true},
		{"https://www.google.com/search?q=1", "www.google.com", true},
		{"https://WWW.Example.com:443/path", "www.example.com", true},
		{"192.0.2.1", "", false},
		{"localhost", "", false},
		{"", "", false},
		{"*.example.com", "", false},
		{"-bad.example.com", "", false},
		{"not a host", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeHostname(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeHostname(%q)=%q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestUnSURTHostName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"uk,co,bbc", "bbc.co.uk", true},
		{"org,commoncrawl", "commoncrawl.org", true},
		{"com,example,www", "www.example.com", true},
		{"org,wikipedia,fr", "fr.wikipedia.org", true},
		{"", "", false},
		{"uk,co,", "", false},
		{",bbc", "", false},
		{"  uk,co,bbc  ", "bbc.co.uk", true},
	}
	for _, tc := range cases {
		got, ok := UnSURTHostName(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("UnSURTHostName(%q)=%q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestUnSURTThenNormalize(t *testing.T) {
	t.Parallel()
	fqdn, ok := UnSURTHostName("uk,co,bbc")
	if !ok {
		t.Fatal("unsurt")
	}
	norm, ok := NormalizeHostname(fqdn)
	if !ok || norm != "bbc.co.uk" {
		t.Fatalf("got %q %v", norm, ok)
	}
	// Reversed IPv4 SURT becomes an IP literal and must be skipped.
	ipFQDN, ok := UnSURTHostName("1,2,0,192")
	if !ok {
		t.Fatal("unsurt ip")
	}
	if _, ok := NormalizeHostname(ipFQDN); ok {
		t.Fatalf("IP literal %q must be rejected", ipFQDN)
	}
}

func TestParseRankedCSVTranco(t *testing.T) {
	t.Parallel()
	in := "1,GOOGLE.COM.\n2,invalid host\n3,www.example.com\n3,www.example.com\n"
	rows, err := ParseListCSV(strings.NewReader(in), List{Name: SourceTranco, Format: FormatRankedCSV}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]postgres.HostName{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if len(byName) != 2 {
		t.Fatalf("rows=%d want 2 valid names, got %+v", len(byName), byName)
	}
	g := byName["google.com"]
	if g.RankTranco == nil || *g.RankTranco != 1 {
		t.Fatalf("google rank=%v", g.RankTranco)
	}
	if len(g.Source) != 1 || g.Source[0] != SourceTranco {
		t.Fatalf("source=%v", g.Source)
	}
	if byName["www.example.com"].RankTranco == nil || *byName["www.example.com"].RankTranco != 3 {
		t.Fatalf("example rank=%v", byName["www.example.com"].RankTranco)
	}
}

func TestParseRankedCSVSkipsHeader(t *testing.T) {
	t.Parallel()
	in := "rank,domain\n1,example.com\n"
	rows, err := ParseListCSV(strings.NewReader(in), List{Name: SourceUmbrella, Format: FormatRankedCSV}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "example.com" {
		t.Fatalf("%+v", rows)
	}
	if rows[0].RankUmbrella == nil || *rows[0].RankUmbrella != 1 {
		t.Fatalf("umbrella rank=%v", rows[0].RankUmbrella)
	}
}

func TestParseCrUXCSVOriginAndRank(t *testing.T) {
	t.Parallel()
	in := "origin,rank\nhttps://www.google.com/,1000\nhttps://www.youtube.com,5000\nnot-a-url\n"
	rows, err := ParseListCSV(strings.NewReader(in), List{Name: SourceCrux, Format: FormatCrUXCSV}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, r := range rows {
		if r.RankCrux == nil {
			t.Fatalf("missing rank for %s", r.Name)
		}
		byName[r.Name] = *r.RankCrux
	}
	if byName["www.google.com"] != 1000 || byName["www.youtube.com"] != 5000 {
		t.Fatalf("%v", byName)
	}
}

func TestParseCrUXCSVOriginOnly(t *testing.T) {
	t.Parallel()
	in := "origin\nhttps://a.example.com\nhttps://b.example.com\n"
	rows, err := ParseListCSV(strings.NewReader(in), List{Name: SourceCrux, Format: FormatCrUXCSV}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("len=%d", len(rows))
	}
}

func TestParseListCSVHTMLUnparseable(t *testing.T) {
	t.Parallel()
	_, err := ParseListCSV(strings.NewReader("<!DOCTYPE html><html><body>nope</body></html>"),
		List{Name: SourceTranco, Format: FormatRankedCSV}, time.Time{})
	if err != ErrUnparseable {
		t.Fatalf("err=%v, want ErrUnparseable", err)
	}
}

func TestSelectLists(t *testing.T) {
	t.Parallel()
	all := DefaultLists()
	got, err := SelectLists(all, []string{" Umbrella ", "tranco", "tranco"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != SourceUmbrella || got[1].Name != SourceTranco {
		t.Fatalf("%+v", got)
	}
	if _, err := SelectLists(all, []string{"majestic"}); err == nil {
		t.Fatal("unknown list must error")
	}
}
