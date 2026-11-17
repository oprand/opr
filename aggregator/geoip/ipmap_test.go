package geoip

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/oprand/opr/store/postgres"
)

const nilStr = "<nil>"

func TestRIPEIPMAPEqualsStatusSource(t *testing.T) {
	t.Parallel()
	if RIPE_IPMAP != postgres.GeoIPStatusSourceIPMAP {
		t.Fatalf("RIPE_IPMAP = %q, GeoIPStatusSourceIPMAP = %q", RIPE_IPMAP, postgres.GeoIPStatusSourceIPMAP)
	}
	if IPMAPDumpURL != postgres.IPMAPDumpURL {
		t.Fatalf("IPMAPDumpURL = %q, postgres.IPMAPDumpURL = %q", IPMAPDumpURL, postgres.IPMAPDumpURL)
	}
}

func TestParseIPMAPTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        string
		wantNets  []string
		wantLoc   []string
		wantLat   []string
		wantLon   []string
		wantScore []string
		wantCC    []string
		wantCity  []string
		wantEmpty bool
	}{
		{
			name:      "full dump line",
			in:        "1.0.0.1/32,TAIPEI-TW-04-WSQQMXBCC2GKRKKG7WXV,Taipei,Taipei City,Taiwan,TW,TWN,25.04776,121.53185,26.71795968030481\n",
			wantNets:  []string{"1.0.0.1/32"},
			wantLoc:   []string{"TAIPEI-TW-04-WSQQMXBCC2GKRKKG7WXV"},
			wantLat:   []string{"25.04776"},
			wantLon:   []string{"121.53185"},
			wantScore: []string{"26.71795968030481"},
			wantCC:    []string{"TW"},
			wantCity:  []string{"Taipei"},
		},
		{
			name:      "score zero stored",
			in:        "192.0.2.1/32,LOC-0,City,State,Country,us,USA,1.5,-3.5,0\n",
			wantNets:  []string{"192.0.2.1/32"},
			wantLoc:   []string{"LOC-0"},
			wantLat:   []string{"1.5"},
			wantLon:   []string{"-3.5"},
			wantScore: []string{"0"},
			wantCC:    []string{"US"},
		},
		{
			name:     "invalid cidr skipped valid kept",
			in:       "not-a-prefix,LOC,City,State,Country,US,USA,1,2,3\n198.51.100.0/24,LOC-OK,City,State,Country,BR,BRA,-15.8,-47.9,40\n",
			wantNets: []string{"198.51.100.0/24"},
			wantLoc:  []string{"LOC-OK"},
			wantCC:   []string{"BR"},
		},
		{
			name:     "header row skipped",
			in:       "ip,geolocation_id,city_name,state_name,country_name,country_code_alpha2,country_code_alpha3,latitude,longitude,score\n203.0.113.1/32,LOC-H,City,State,Country,DE,DEU,52.5,13.4,10\n",
			wantNets: []string{"203.0.113.1/32"},
			wantLoc:  []string{"LOC-H"},
		},
		{
			name:     "bare ipv4 becomes /32",
			in:       "192.0.2.9,LOC-BARE,City,State,Country,US,USA,10,20,5\n",
			wantNets: []string{"192.0.2.9/32"},
			wantLoc:  []string{"LOC-BARE"},
		},
		{
			name:     "bare ipv6 becomes /128",
			in:       "2001:db8::1,LOC-BARE6,City,State,Country,US,USA,10,20,5\n",
			wantNets: []string{"2001:db8::1/128"},
			wantLoc:  []string{"LOC-BARE6"},
		},
		{
			name:     "ipv6 cidr",
			in:       "2001:db8::/32,LOC-V6,City,State,Country,US,USA,40.7,-74.0,12\n",
			wantNets: []string{"2001:db8::/32"},
			wantLoc:  []string{"LOC-V6"},
		},
		{
			name:      "missing lat lon score still stores prefix",
			in:        "192.0.2.0/24,LOC-ONLY,,,,,,,,\n",
			wantNets:  []string{"192.0.2.0/24"},
			wantLoc:   []string{"LOC-ONLY"},
			wantLat:   []string{nilStr},
			wantLon:   []string{nilStr},
			wantScore: []string{nilStr},
		},
		{
			name:     "empty location id is nil not empty string",
			in:       "192.0.2.8/32,,City,State,Country,NL,NLD,52.37,4.89,8\n",
			wantNets: []string{"192.0.2.8/32"},
			wantLoc:  []string{nilStr},
		},
		{
			name:     "host bits cidr skipped canonical kept",
			in:       "192.0.2.5/24,LOC-BAD,City,State,Country,US,USA,1,2,3\n192.0.2.0/24,LOC-OK,City,State,Country,US,USA,1,2,3\n",
			wantNets: []string{"192.0.2.0/24"},
			wantLoc:  []string{"LOC-OK"},
		},
		{
			name:      "comments and empty lines skipped",
			in:        "# ipmap dump\n\n  \n# another\n192.0.2.4/32,LOC-C,City,State,Country,FR,FRA,48.8,2.3,9\n",
			wantNets:  []string{"192.0.2.4/32"},
			wantLoc:   []string{"LOC-C"},
			wantEmpty: false,
		},
		{
			name:      "comments only is empty success",
			in:        "# only comments\n\n# still\n",
			wantEmpty: true,
		},
		{
			name:     "nan inf out of range coords skipped",
			in:       "192.0.2.1/32,LOC,City,State,Country,US,USA,NaN,2,3\n192.0.2.2/32,LOC,City,State,Country,US,USA,1,Inf,3\n192.0.2.3/32,LOC,City,State,Country,US,USA,-Inf,0,3\n192.0.2.4/32,LOC,City,State,Country,US,USA,91,0,3\n192.0.2.5/32,LOC,City,State,Country,US,USA,0,181,3\n192.0.2.6/32,LOC-OK,City,State,Country,US,USA,90,180,3\n192.0.2.7/32,LOC-OK2,City,State,Country,US,USA,-90,-180,3\n",
			wantNets: []string{"192.0.2.6/32", "192.0.2.7/32"},
			wantLoc:  []string{"LOC-OK", "LOC-OK2"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			items, err := ParseIPMAP(strings.NewReader(tc.in), IPMAPDumpURL)
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
				if it.Source == nil || *it.Source != RIPE_IPMAP {
					t.Errorf("source[%d]=%v, want RIPE_IPMAP", i, it.Source)
				}
				if it.SourceURL == nil || *it.SourceURL != IPMAPDumpURL {
					t.Errorf("source_url[%d]=%v, want %s", i, it.SourceURL, IPMAPDumpURL)
				}
			}
			assertFieldCol(t, "location_id", tc.wantLoc, items, func(it *postgres.GeoIPItem) string { return ptrStr(it.LocationID) })
			assertFieldCol(t, "lat", tc.wantLat, items, func(it *postgres.GeoIPItem) string { return floatPtr(it.Latitude) })
			assertFieldCol(t, "lon", tc.wantLon, items, func(it *postgres.GeoIPItem) string { return floatPtr(it.Longitude) })
			assertFieldCol(t, "score", tc.wantScore, items, func(it *postgres.GeoIPItem) string { return floatPtr(it.Score) })
			assertFieldCol(t, "cc", tc.wantCC, items, func(it *postgres.GeoIPItem) string { return ptrStr(it.CountryCode) })
			assertFieldCol(t, "city", tc.wantCity, items, func(it *postgres.GeoIPItem) string { return ptrStr(it.City) })
		})
	}
}

func assertFieldCol(t *testing.T, name string, want []string, items []*postgres.GeoIPItem, got func(*postgres.GeoIPItem) string) {
	t.Helper()
	if want == nil {
		return
	}
	if len(want) != len(items) {
		t.Fatalf("%s: got %d items, want %d values", name, len(items), len(want))
	}
	for i, it := range items {
		if g := got(it); g != want[i] {
			t.Errorf("%s[%d]=%q, want %q", name, i, g, want[i])
		}
	}
}

func TestParseIPMAPOffShapeSkippedAndFail(t *testing.T) {
	t.Parallel()

	var mixed9 strings.Builder
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&mixed9, "192.0.2.%d/32,LOC,City,State,Country,US,USA,1,2,3\n", i)
	}
	mixed9.WriteString("198.51.100.1/32,LOC,City,State,Country,US,USA,1,2\n") // 9 fields

	var mixed11 strings.Builder
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&mixed11, "203.0.113.%d/32,LOC,City,State,Country,US,USA,1,2,3\n", i)
	}
	mixed11.WriteString("198.51.100.1/32,LOC,City,State,Country,US,USA,1,2,3,extra\n") // 11 fields

	cases := []struct {
		name    string
		in      string
		wantN   int
		wantErr error
	}{
		{name: "9-field among valid skipped", in: mixed9.String(), wantN: 9},
		{name: "11-field among valid skipped", in: mixed11.String(), wantN: 9},
		{
			name:    "all 9-field fails",
			in:      "192.0.2.1/32,a,b,c,d,e,f,g,h\n192.0.2.2/32,a,b,c,d,e,f,g,h\n",
			wantErr: ErrIPMAPUnparseable,
		},
		{
			name:    "all 11-field fails",
			in:      "192.0.2.1/32,a,b,c,d,e,f,g,h,i,j\n192.0.2.2/32,a,b,c,d,e,f,g,h,i,j\n",
			wantErr: ErrIPMAPUnparseable,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			items, err := ParseIPMAP(strings.NewReader(tc.in), IPMAPDumpURL)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v, want %v", err, tc.wantErr)
				}
				if items != nil {
					t.Fatalf("failed parse must not return rows, got %d", len(items))
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(items) != tc.wantN {
				t.Fatalf("got %d items, want %d", len(items), tc.wantN)
			}
		})
	}
}

func TestParseIPMAPStickyErrorDoesNotHang(t *testing.T) {
	t.Parallel()
	r := &stickyErrReader{err: errors.New("sticky csv")}
	_, err := ParseIPMAP(r, IPMAPDumpURL)
	if err == nil {
		t.Fatal("sticky error must be returned")
	}
	if !strings.Contains(err.Error(), "sticky csv") {
		t.Fatalf("err=%v, want wrapped sticky csv", err)
	}
	if r.n > 100 {
		t.Fatalf("too many reads (%d); ParseIPMAP must not continue on sticky error", r.n)
	}
}

func TestParseIPMAPBodyHTMLUnparseable(t *testing.T) {
	t.Parallel()
	_, err := parseIPMAPBody(strings.NewReader("<!DOCTYPE html><html><body>nope</body></html>"), IPMAPDumpURL)
	if !errors.Is(err, ErrIPMAPUnparseable) {
		t.Fatalf("body html: err=%v, want ErrIPMAPUnparseable", err)
	}
}

func TestParseIPMAPBodyPlainCSV(t *testing.T) {
	t.Parallel()
	items, err := parseIPMAPBody(strings.NewReader("192.0.2.1/32,LOC,City,State,Country,US,USA,1,2,3\n"), IPMAPDumpURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Netblock != "192.0.2.1/32" {
		t.Fatalf("got %+v", items)
	}
}

func TestParseIPMAPBodyBzip2(t *testing.T) {
	t.Parallel()
	// bunzip2 of: 192.0.2.1/32,LOC-1,City,State,Country,US,USA,1.25,-3.5,10\n
	raw, err := hex.DecodeString("425a68393141592653599f2505e500000c5f8000100007fa2028048a00222196202000545346803400d01a994da98d27a9ea7a406896b9570b910eb316a6e419b5326479847b695bc2ca300e5f07c91d3667d67be2ee48a70a1213e4a0bca0")
	if err != nil {
		t.Fatal(err)
	}
	items, err := parseIPMAPBody(bytes.NewReader(raw), IPMAPDumpURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Netblock != "192.0.2.1/32" {
		t.Fatalf("got %+v", items)
	}
	if items[0].LocationID == nil || *items[0].LocationID != "LOC-1" {
		t.Fatalf("location_id=%v", items[0].LocationID)
	}
}

func TestParseIPMAPBodyGzip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("192.0.2.1/32,LOC-GZ,City,State,Country,US,USA,1,2,3\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	items, err := parseIPMAPBody(&buf, IPMAPDumpURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Netblock != "192.0.2.1/32" {
		t.Fatalf("got %+v", items)
	}
}

func TestParseIPMAPBodyTruncatedGzip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("192.0.2.1/32,LOC,City,State,Country,US,USA,1,2,3\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if len(raw) < 8 {
		t.Fatalf("gzip too short: %d", len(raw))
	}
	_, err := parseIPMAPBody(bytes.NewReader(raw[:len(raw)/2]), IPMAPDumpURL)
	if err == nil {
		t.Fatal("truncated gzip must return a parse error")
	}
}

func TestParseIPMAPNetblockRejectsGarbageAndHostBits(t *testing.T) {
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
		{in: "192.0.2.9", want: "192.0.2.9/32", ok: true},
		{in: "2001:db8::1", want: "2001:db8::1/128", ok: true},
		{in: "2001:db8::1/32", ok: false},
		{in: "2001:db8::/32", want: "2001:db8::/32", ok: true},
	}
	for _, tc := range cases {
		got, ok := parseIPMAPNetblock(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseIPMAPNetblock(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCapReaderOverflowIsFatal(t *testing.T) {
	t.Parallel()
	r := newCapReader(strings.NewReader("hello"), 4, ErrIPMAPTooLarge)
	b, err := io.ReadAll(r)
	if !errors.Is(err, ErrIPMAPTooLarge) {
		t.Fatalf("err=%v, want ErrIPMAPTooLarge", err)
	}
	if string(b) != "hell" {
		t.Fatalf("got %q", b)
	}
}

func TestCapReaderExactLimitOK(t *testing.T) {
	t.Parallel()
	r := newCapReader(strings.NewReader("hell"), 4, ErrIPMAPTooLarge)
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hell" {
		t.Fatalf("got %q", b)
	}
}

type stickyErrReader struct {
	err error
	n   int
}

func (s *stickyErrReader) Read(p []byte) (int, error) {
	s.n++
	if s.n > 10000 {
		panic("ParseIPMAP hung on sticky error")
	}
	return 0, s.err
}

func ptrStr(p *string) string {
	if p == nil {
		return nilStr
	}
	return *p
}

func floatPtr(p *float64) string {
	if p == nil {
		return nilStr
	}
	return strconv.FormatFloat(*p, 'f', -1, 64)
}

type memIPMAPStore struct {
	mu        sync.Mutex
	meta      map[string]*postgres.ResponseMetadataItem
	replaced  map[string][]*postgres.GeoIPItem
	existing  map[string]int64
	replaceN  int
	saveMetaN int
}

func newMemIPMAPStore() *memIPMAPStore {
	return &memIPMAPStore{
		meta:     make(map[string]*postgres.ResponseMetadataItem),
		replaced: make(map[string][]*postgres.GeoIPItem),
		existing: make(map[string]int64),
	}
}

func (m *memIPMAPStore) GetResponseMetadata(url string) *postgres.ResponseMetadataItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[url]
}

func (m *memIPMAPStore) SaveResponseMetadata(meta *postgres.ResponseMetadataItem) {
	if meta == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveMetaN++
	cp := *meta
	m.meta[meta.Url] = &cp
}

func (m *memIPMAPStore) ReplaceGeoIPBySourceURL(ctx context.Context, sourceURL string, items []*postgres.GeoIPItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replaceN++
	m.replaced[sourceURL] = append([]*postgres.GeoIPItem(nil), items...)
	return nil
}

func (m *memIPMAPStore) CountGeoIPBySourceURL(ctx context.Context, sourceURL string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.existing[sourceURL], nil
}
