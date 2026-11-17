package asnames

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"
)

func TestParseLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		line   string
		want   Entry
		wantOK bool
	}{
		{
			name:   "sample",
			line:   "10000 NCM - Nagasaki Cable Media Inc., JP",
			want:   Entry{ASN: 10000, Name: "NCM - Nagasaki Cable Media Inc.", CountryCode: "JP"},
			wantOK: true,
		},
		{
			name:   "name with commas",
			line:   `15169 Google LLC, Google, US`,
			want:   Entry{ASN: 15169, Name: "Google LLC, Google", CountryCode: "US"},
			wantOK: true,
		},
		{
			name:   "32-bit ASN",
			line:   "4200000000 Example 32-bit Network, CN",
			want:   Entry{ASN: 4200000000, Name: "Example 32-bit Network", CountryCode: "CN"},
			wantOK: true,
		},
		{
			name:   "lowercase cc",
			line:   "1 LVLT-1, us",
			want:   Entry{ASN: 1, Name: "LVLT-1", CountryCode: "US"},
			wantOK: true,
		},
		{
			name: "reserved",
			line: "0 -Reserved AS-, ZZ",
		},
		{
			name: "reserved in name",
			line: "65535 -Reserved AS- Private Use, ZZ",
		},
		{
			name: "missing comma",
			line: "10000 NCM - Nagasaki Cable Media Inc. JP",
		},
		{
			name: "no space",
			line: "10000NCM, JP",
		},
		{
			name: "non-numeric ASN",
			line: "AS10000 NCM, JP",
		},
		{
			name: "empty name",
			line: "10000 , JP",
		},
		{
			name: "missing cc",
			line: "10000 NCM,",
		},
		{
			name: "cc too long",
			line: "10000 NCM, JPN",
		},
		{
			name: "asn zero",
			line: "0 Example, US",
		},
		{
			name: "empty",
			line: "",
		},
		{
			name: "whitespace",
			line: "   ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSparseAutNumLeavesSourceNilAndStampsASNames(t *testing.T) {
	t.Parallel()

	rec := SparseAutNum(Entry{ASN: 10000, Name: "NCM - Nagasaki Cable Media Inc.", CountryCode: "JP"})
	if rec.Source != nil {
		t.Fatalf("Source=%v, want nil (a RIR source would fake bulk coverage)", *rec.Source)
	}
	if rec.AutNum != 10000 {
		t.Fatalf("AutNum=%d", rec.AutNum)
	}
	if rec.ASName != "NCM - Nagasaki Cable Media Inc." {
		t.Fatalf("ASName=%q", rec.ASName)
	}
	if rec.CountryCode == nil || *rec.CountryCode != "JP" {
		t.Fatalf("CountryCode=%v", rec.CountryCode)
	}
	if rec.FetchMethod == nil || *rec.FetchMethod != whoisdb.FetchMethodASNames {
		t.Fatalf("FetchMethod=%v, want %q", rec.FetchMethod, whoisdb.FetchMethodASNames)
	}
	if rec.LastFetchedAt == nil || rec.LastSeenInSourceAt == nil {
		t.Fatal("StampFetch must set last_fetched_at and last_seen_in_source_at")
	}
	if rec.LastChangedAt != nil || rec.ContentHash != nil {
		t.Fatal("must not compute last_changed_at or content_hash")
	}
	if rec.Org != nil || rec.AdminC != nil || rec.Descr != nil {
		t.Fatal("sparse row must not invent org/contacts/descr")
	}
}

func TestPrepareForSaveUsesEmptySourceNotRIR(t *testing.T) {
	t.Parallel()

	rec := SparseAutNum(Entry{ASN: 1, Name: "LVLT-1", CountryCode: "US"})
	prepareForSave(rec)
	if rec.Source == nil {
		t.Fatal("persistable Source must be non-nil (SaveWhoisAutNum drops nil; column is NOT NULL)")
	}
	if *rec.Source != "" {
		t.Fatalf("Source=%q, want empty string (not a RIR name)", *rec.Source)
	}
	prepareForSave(rec)
	if rec.Source == nil || *rec.Source != "" {
		t.Fatalf("idempotent persist Source=%v", rec.Source)
	}
}

func TestCollectIntersectsPendingAndSkipsReserved(t *testing.T) {
	t.Parallel()

	const fixture = `
10000 NCM - Nagasaki Cable Media Inc., JP
15169 Google LLC, Google, US
4200000000 Example 32-bit Network, CN
0 -Reserved AS-, ZZ
65535 -Reserved AS- Private Use, ZZ
not-a-line
12345 Missing comma CN
99999 Unparseable
`
	pending := map[uint32]struct{}{
		10000:      {},
		15169:      {},
		4200000000: {},
		65535:      {}, // reserved in file; must not be collected
		424242:     {}, // pending but absent from file
	}

	recs, err := Collect(strings.NewReader(fixture), pending)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}

	byASN := make(map[uint32]*whoisdb.WhoisAutNum, len(recs))
	for _, rec := range recs {
		if rec.Source != nil {
			t.Fatalf("AS%d Source=%v, want nil", rec.AutNum, rec.Source)
		}
		if rec.FetchMethod == nil || *rec.FetchMethod != whoisdb.FetchMethodASNames {
			t.Fatalf("AS%d FetchMethod=%v", rec.AutNum, rec.FetchMethod)
		}
		byASN[rec.AutNum] = rec
	}
	if rec := byASN[10000]; rec == nil || rec.ASName != "NCM - Nagasaki Cable Media Inc." {
		t.Fatalf("AS10000=%v", rec)
	}
	if rec := byASN[15169]; rec == nil || rec.ASName != "Google LLC, Google" || rec.CountryCode == nil || *rec.CountryCode != "US" {
		t.Fatalf("AS15169=%v", rec)
	}
	if rec := byASN[4200000000]; rec == nil || rec.ASName != "Example 32-bit Network" {
		t.Fatalf("AS4200000000=%v", rec)
	}
}

func TestCollectEmptyPendingDownloadsNothingUseful(t *testing.T) {
	t.Parallel()
	recs, err := Collect(strings.NewReader("10000 NCM - Nagasaki Cable Media Inc., JP\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d, want none when pending is empty", len(recs))
	}
}

func TestCollectHTTPFixtureDoesNotHitNetwork(t *testing.T) {
	t.Parallel()

	const body = "10000 NCM - Nagasaki Cable Media Inc., JP\n15169 Google LLC, US\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%s, want GET", r.Method)
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	recs, err := Collect(resp.Body, map[uint32]struct{}{10000: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].AutNum != 10000 {
		t.Fatalf("got %#v", recs)
	}
	if recs[0].Source != nil {
		t.Fatalf("Source=%v, want nil", recs[0].Source)
	}
}

func TestPendingSetSkipsJunk(t *testing.T) {
	t.Parallel()
	got := pendingSet([]string{"10000", "0", "nope", "4200000000", ""})
	if _, ok := got[10000]; !ok {
		t.Fatal("missing 10000")
	}
	if _, ok := got[4200000000]; !ok {
		t.Fatal("missing 32-bit ASN")
	}
	if _, ok := got[0]; ok {
		t.Fatal("ASN 0 must be skipped")
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
}
