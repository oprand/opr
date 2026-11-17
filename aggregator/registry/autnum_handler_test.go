package registry

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/oprand/opr/aggregator/crawl"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

func TestIsAutnumRange(t *testing.T) {
	t.Parallel()
	ptr := func(v uint32) *uint32 { return &v }

	cases := []struct {
		name string
		a    *rdap.Autnum
		want bool
	}{
		{name: "nil autnum", a: nil, want: false},
		{name: "unset start and end", a: &rdap.Autnum{}, want: false},
		{name: "only start set", a: &rdap.Autnum{StartAutnum: ptr(100)}, want: false},
		{name: "only end set", a: &rdap.Autnum{EndAutnum: ptr(200)}, want: false},
		{name: "both zero", a: &rdap.Autnum{StartAutnum: ptr(0), EndAutnum: ptr(0)}, want: false},
		{name: "single ASN equal", a: &rdap.Autnum{StartAutnum: ptr(15169), EndAutnum: ptr(15169)}, want: false},
		{name: "equal but not queried ASN", a: &rdap.Autnum{StartAutnum: ptr(1), EndAutnum: ptr(1)}, want: false},
		{name: "as-block range", a: &rdap.Autnum{StartAutnum: ptr(131072), EndAutnum: ptr(132095)}, want: true},
		{name: "small assignment range", a: &rdap.Autnum{StartAutnum: ptr(838), EndAutnum: ptr(842)}, want: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isAutnumRange(tc.a); got != tc.want {
				t.Fatalf("isAutnumRange() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAutnumBlockHandle(t *testing.T) {
	t.Parallel()
	ptr := func(v uint32) *uint32 { return &v }

	if got := autnumBlockHandle(nil); got != "" {
		t.Fatalf("nil: got %q", got)
	}
	if got := autnumBlockHandle(&rdap.Autnum{Handle: "  AS131072 - AS132095  "}); got != "AS131072 - AS132095" {
		t.Fatalf("handle: got %q", got)
	}
	if got := autnumBlockHandle(&rdap.Autnum{StartAutnum: ptr(10), EndAutnum: ptr(20)}); got != "AS10 - AS20" {
		t.Fatalf("start-end fallback: got %q", got)
	}
}

func decodeAutnumFixture(t *testing.T, file string) *rdap.Autnum {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rdap", file))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	obj, err := rdap.NewDecoder(raw).Decode()
	if err != nil {
		t.Fatalf("decode RDAP JSON: %v", err)
	}
	resp, ok := obj.(*rdap.Autnum)
	if !ok || resp == nil {
		t.Fatalf("decoded %T, want *rdap.Autnum", obj)
	}
	return resp
}

func assertAutnumsToPersistWidth(t *testing.T, queried uint32, a *rdap.Autnum) {
	t.Helper()
	asns := autnumsToPersist(queried, a)
	want := int(*a.EndAutnum-*a.StartAutnum) + 1
	if len(asns) != want {
		t.Fatalf("autnumsToPersist len=%d, want width %d", len(asns), want)
	}
	if asns[0] != *a.StartAutnum || asns[len(asns)-1] != *a.EndAutnum {
		t.Fatalf("autnumsToPersist range [%d, %d], want [%d, %d]", asns[0], asns[len(asns)-1], *a.StartAutnum, *a.EndAutnum)
	}
}

func TestResultForParsedAutnumASBlockFixture(t *testing.T) {
	t.Parallel()
	resp := decodeAutnumFixture(t, "AS131072-block.json")
	if !isAutnumRange(resp) {
		t.Fatal("fixture must decode as an as-block (endAutnum > startAutnum)")
	}
	if !shouldFanOutAutnumRange(131072, resp) {
		t.Fatal("CNNIC covering block must fan out")
	}

	saved := false
	got := resultForParsedAutnum(131072, resp, func() error {
		saved = true
		return nil
	})
	if !saved {
		t.Fatal("as-block must persist/SaveWhoisAutNum")
	}
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome: got %v, want OutcomeSuccess", got.Outcome)
	}
	if got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("status: got %v, want 200", got.StatusCode)
	}
	assertAutnumsToPersistWidth(t, 131072, resp)

	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	rows, _, _ := mapAutnumRangeFromRDAP(aggr, 131072, resp, opconst.APNIC, opconst.APNIC)
	if len(rows) != 1024 {
		t.Fatalf("persist batch: got %d rows, want 1024", len(rows))
	}
}

func TestResultForParsedAutnumCNNICSmallBlockFixture(t *testing.T) {
	t.Parallel()
	resp := decodeAutnumFixture(t, "AS37945-block.json")
	if !isAutnumRange(resp) {
		t.Fatal("fixture must decode as an as-block (endAutnum > startAutnum)")
	}
	if resp.Name != "" {
		t.Fatalf("live CNNIC small block has empty name, got %q", resp.Name)
	}
	if !shouldFanOutAutnumRange(37947, resp) {
		t.Fatal("CNNIC covering block must fan out")
	}

	saved := false
	got := resultForParsedAutnum(37947, resp, func() error {
		saved = true
		return nil
	})
	if !saved {
		t.Fatal("CNNIC as-block must persist/SaveWhoisAutNum")
	}
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome: got %v, want OutcomeSuccess", got.Outcome)
	}
	if got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("status: got %v, want 200", got.StatusCode)
	}
	assertAutnumsToPersistWidth(t, 37947, resp)
	want := []uint32{37945, 37946, 37947, 37948, 37949, 37950}
	asns := autnumsToPersist(37947, resp)
	if len(asns) != len(want) {
		t.Fatalf("autnumsToPersist: got %v, want %v", asns, want)
	}
	for i := range want {
		if asns[i] != want[i] {
			t.Fatalf("autnumsToPersist: got %v, want %v", asns, want)
		}
	}
}

func TestResultForParsedAutnumSingleASNFixture(t *testing.T) {
	t.Parallel()
	resp := decodeAutnumFixture(t, "AS15169.json")
	if isAutnumRange(resp) {
		t.Fatal("AS15169 fixture must remain a single aut-num (start == end)")
	}

	saved := false
	got := resultForParsedAutnum(15169, resp, func() error {
		saved = true
		return nil
	})
	if !saved {
		t.Fatal("single aut-num must persist")
	}
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome: got %v, want OutcomeSuccess", got.Outcome)
	}
	if got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("status: got %v, want 200", got.StatusCode)
	}
}

func TestResultForParsedAutnumARINSmallRangeFanout(t *testing.T) {
	t.Parallel()
	resp := decodeAutnumFixture(t, "AS838.json")
	if !isAutnumRange(resp) {
		t.Fatal("AS838 fixture must decode as a range (endAutnum > startAutnum)")
	}
	if !shouldFanOutAutnumRange(838, resp) {
		t.Fatal("AS838 assignment must fan out")
	}

	saved := false
	got := resultForParsedAutnum(838, resp, func() error {
		saved = true
		return nil
	})
	if !saved {
		t.Fatal("small assignment range must persist")
	}
	if got.Outcome != crawl.OutcomeSuccess {
		t.Fatalf("outcome: got %v, want OutcomeSuccess", got.Outcome)
	}
	if got.StatusCode == nil || *got.StatusCode != http.StatusOK {
		t.Fatalf("status: got %v, want 200", got.StatusCode)
	}

	asns := autnumsToPersist(838, resp)
	want := []uint32{838, 839, 840, 841, 842}
	if len(asns) != len(want) {
		t.Fatalf("autnumsToPersist: got %v, want %v", asns, want)
	}
	for i := range want {
		if asns[i] != want[i] {
			t.Fatalf("autnumsToPersist: got %v, want %v", asns, want)
		}
	}

	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	rows, roles, orgs := mapAutnumRangeFromRDAP(aggr, 838, resp, opconst.ARIN, opconst.ARIN)
	if len(rows) != 5 {
		t.Fatalf("persist batch: got %d rows, want 5", len(rows))
	}
	for i, n := range want {
		if rows[i] == nil || rows[i].AutNum != n {
			t.Fatalf("row %d aut_num=%v, want %d", i, rows[i], n)
		}
		if rows[i].ASName != "CANET2-ASN" {
			t.Errorf("row %d as_name=%q, want CANET2-ASN", i, rows[i].ASName)
		}
		if ptrStr(rows[i].FetchMethod) != whoisdb.FetchMethodRDAP {
			t.Errorf("row %d fetch_method=%q, want rdap", i, ptrStr(rows[i].FetchMethod))
		}
	}
	if len(roles) == 0 {
		t.Fatal("roles should be mapped once and non-empty")
	}
	if len(orgs) == 0 {
		t.Fatal("orgs should be mapped once and non-empty")
	}
}

func TestResultForParsedAutnumSmallRangeHeuristic(t *testing.T) {
	t.Parallel()
	ptr := func(v uint32) *uint32 { return &v }
	range838 := func(handle string) *rdap.Autnum {
		return &rdap.Autnum{
			Handle:      handle,
			StartAutnum: ptr(838),
			EndAutnum:   ptr(842),
			Name:        "CANET2-ASN",
		}
	}

	cases := []struct {
		name        string
		queried     uint32
		a           *rdap.Autnum
		wantFanout  bool
		wantPersist bool
		wantOutcome crawl.Outcome
	}{
		{
			name:        "width 1024 non-CNNIC",
			queried:     1,
			a:           &rdap.Autnum{Handle: "AS1", StartAutnum: ptr(1), EndAutnum: ptr(1024)},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:    "width 512 exactly",
			queried: 1,
			a: &rdap.Autnum{
				Handle:      "AS1",
				StartAutnum: ptr(1),
				EndAutnum:   ptr(512),
			},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:    "width 511",
			queried: 1,
			a: &rdap.Autnum{
				Handle:      "AS1",
				StartAutnum: ptr(1),
				EndAutnum:   ptr(511),
			},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:        "handle range form",
			queried:     838,
			a:           range838("AS838 - AS842"),
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:    "APNIC hyphen handle",
			queried: 147235,
			a: &rdap.Autnum{
				Handle:      "AS147191-AS147290",
				StartAutnum: ptr(147191),
				EndAutnum:   ptr(147290),
			},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:    "CNNIC covering block",
			queried: 131072,
			a: &rdap.Autnum{
				Handle:      "AS131072 - AS132095",
				StartAutnum: ptr(131072),
				EndAutnum:   ptr(132095),
				Name:        "CNNIC-AS-BLOCK",
			},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:    "CNNIC small covering block",
			queried: 37947,
			a: &rdap.Autnum{
				Handle:      "AS37945 - AS37950",
				StartAutnum: ptr(37945),
				EndAutnum:   ptr(37950),
				Name:        "CNNIC-AS-BLOCK",
				Remarks: []rdap.Remark{{
					Title:       "description",
					Description: []string{"CNNIC ASN block"},
				}},
			},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:        "queried ASN outside range",
			queried:     843,
			a:           range838("AS838"),
			wantFanout:  false,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:        "handle case",
			queried:     838,
			a:           range838("as838"),
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
		{
			name:        "width 32 exactly",
			queried:     1,
			a:           &rdap.Autnum{Handle: "AS1", StartAutnum: ptr(1), EndAutnum: ptr(32)},
			wantFanout:  true,
			wantPersist: true,
			wantOutcome: crawl.OutcomeSuccess,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldFanOutAutnumRange(tc.queried, tc.a); got != tc.wantFanout {
				t.Fatalf("shouldFanOutAutnumRange() = %v, want %v", got, tc.wantFanout)
			}
			saved := false
			got := resultForParsedAutnum(tc.queried, tc.a, func() error {
				saved = true
				return nil
			})
			if saved != tc.wantPersist {
				t.Fatalf("persist called=%v, want %v", saved, tc.wantPersist)
			}
			if got.Outcome != tc.wantOutcome {
				t.Fatalf("outcome: got %v, want %v", got.Outcome, tc.wantOutcome)
			}
			asns := autnumsToPersist(tc.queried, tc.a)
			if tc.wantFanout {
				wantN := int(*tc.a.EndAutnum-*tc.a.StartAutnum) + 1
				if len(asns) != wantN {
					t.Fatalf("autnumsToPersist len=%d, want width %d", len(asns), wantN)
				}
			} else if len(asns) != 1 || asns[0] != tc.queried {
				t.Fatalf("autnumsToPersist=%v, want [%d]", asns, tc.queried)
			}
		})
	}
}

func TestResultForParsedAutnumPersistError(t *testing.T) {
	t.Parallel()
	resp := decodeAutnumFixture(t, "AS15169.json")
	wantErr := errors.New("save failed")
	got := resultForParsedAutnum(15169, resp, func() error { return wantErr })
	if got.Outcome != crawl.OutcomeRetry {
		t.Fatalf("outcome: got %v, want OutcomeRetry", got.Outcome)
	}
	if got.Err != wantErr {
		t.Fatalf("err: got %v, want %v", got.Err, wantErr)
	}
}
