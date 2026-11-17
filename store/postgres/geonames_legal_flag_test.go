package postgres

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// TestInitialMigrationLegalFlagShape checks the squashed baseline still
// has the table the legal-flag queries depend on. The treaty seed rows
// lived in the historical 0072 file and are not part of the schema dump.
func TestInitialMigrationLegalFlagShape(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("migrations/0001_initial.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if !strings.Contains(sql, "CREATE TABLE public.country_legal_flag") {
		t.Fatal("baseline must create country_legal_flag")
	}
	if !strings.Contains(sql, "UNIQUE (iso, flag, admin1_code)") {
		t.Fatal("unique key must be (iso, flag, admin1_code)")
	}
	if !strings.Contains(sql, "admin1_code text DEFAULT ''::text NOT NULL") {
		t.Fatal("admin1_code must be NOT NULL DEFAULT '' so the unique key holds")
	}
	if strings.Contains(sql, "place_legal_flag") {
		t.Fatal("place rows live in country_legal_flag.admin1_code, not a sibling table")
	}
	if strings.Contains(sql, "REFERENCES country_info") {
		t.Fatal("no FK: country_info.iso has no unique constraint and may be unloaded")
	}
	if !strings.Contains(sql, "idx_country_legal_flag_flag") {
		t.Fatal("reverse lookup (who is in five_eyes) needs an index on flag")
	}
}

// TestRemapCountryCodeForLegal pins the one place the legal path parts
// company with the gazetteer path. The gazetteer wants a usable centroid
// for a mislabelled geofeed, so CV → PT is right there and must stay; a
// legal flag is a claim about which law reaches an address, so the same
// rewrite would hand Cabo Verde the Portuguese state's treaties.
func TestRemapCountryCodeForLegal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		in         string
		wantLegal  string
		wantPlace  string
		wantDiffer bool
	}{
		{name: "CV stays Cabo Verde for legal, still PT for places", in: "CV", wantLegal: "CV", wantPlace: "PT", wantDiffer: true},
		{name: "lowercase cv", in: "cv", wantLegal: "CV", wantPlace: "PT", wantDiffer: true},
		{name: "padded cv", in: " Cv ", wantLegal: "CV", wantPlace: "PT", wantDiffer: true},
		{name: "UK still remaps", in: "UK", wantLegal: "GB", wantPlace: "GB"},
		{name: "EL still remaps", in: "EL", wantLegal: "GR", wantPlace: "GR"},
		{name: "FX still remaps", in: "FX", wantLegal: "FR", wantPlace: "FR"},
		{name: "TP still remaps", in: "TP", wantLegal: "TL", wantPlace: "TL"},
		{name: "ZR still remaps", in: "ZR", wantLegal: "CD", wantPlace: "CD"},
		{name: "DD still remaps", in: "DD", wantLegal: "DE", wantPlace: "DE"},
		{name: "BU still remaps", in: "BU", wantLegal: "MM", wantPlace: "MM"},
		{name: "PT passes through", in: "PT", wantLegal: "PT", wantPlace: "PT"},
		{name: "EU is not a country", in: "EU", wantLegal: "EU", wantPlace: "EU"},
		{name: "AP is not a country", in: "AP", wantLegal: "AP", wantPlace: "AP"},
		{name: "A1", in: "A1", wantLegal: "A1", wantPlace: "A1"},
		{name: "A2", in: "A2", wantLegal: "A2", wantPlace: "A2"},
		{name: "O1", in: "O1", wantLegal: "O1", wantPlace: "O1"},
		{name: "XX", in: "XX", wantLegal: "XX", wantPlace: "XX"},
		{name: "ZZ", in: "ZZ", wantLegal: "ZZ", wantPlace: "ZZ"},
		{name: "empty", in: "", wantLegal: "", wantPlace: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RemapCountryCodeForLegal(tc.in); got != tc.wantLegal {
				t.Errorf("RemapCountryCodeForLegal(%q) = %q, want %q", tc.in, got, tc.wantLegal)
			}
			// ResolveGeoNamesPlace must be untouched by this change.
			if got := RemapCountryCode(tc.in); got != tc.wantPlace {
				t.Errorf("RemapCountryCode(%q) = %q, want %q", tc.in, got, tc.wantPlace)
			}
			if tc.wantDiffer && tc.wantLegal == tc.wantPlace {
				t.Errorf("%q must resolve differently for legal flags than for places", tc.in)
			}
		})
	}

	// The divergence is exactly IntentionalISOOverrides and nothing else,
	// so adding a remap entry cannot quietly change the legal answer.
	for from := range CountryCodeRemap {
		_, override := IntentionalISOOverrides[from]
		differs := RemapCountryCodeForLegal(from) != RemapCountryCode(from)
		if differs != override {
			t.Errorf("remap %s→%s: legal path differs = %v, IntentionalISOOverrides = %v",
				from, CountryCodeRemap[from], differs, override)
		}
	}
}

// TestResolveLegalFlagsCaboVerdeIsNotPortugal is the specific regression:
// CV must resolve as Cabo Verde, which carries no seeded flag, and must
// never pick up Portugal's eu / gdpr / schengen / nato rows.

func TestResolveLegalFlagsSQLShape(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(resolveLegalFlagsSQL)
	if !strings.Contains(sql, "from country_code_remap") {
		t.Fatal("resolve must go through country_code_remap so UK/EL land on an ISO")
	}
	// The Go guard alone is not enough: country_code_remap is a table and
	// can drift from CountryCodeRemap, so a stale CV→PT row would put
	// Portugal's flags back on Cabo Verde unless the join excludes it too.
	if !strings.Contains(sql, "r.from_code = any($3::text[])") {
		t.Fatal("resolve must exclude IntentionalISOOverrides from the remap join, not just in Go")
	}
	if !strings.Contains(sql, "not (r.from_code = any($3::text[]))") {
		t.Fatal("the override list must be an exclusion (NOT ... = ANY), not a filter that keeps them")
	}
	if !strings.Contains(sql, "join country_legal_flag") {
		t.Fatal("expected JOIN country_legal_flag")
	}
	if !strings.Contains(sql, "upper(trim($1))") {
		t.Fatal("country code must be upper/trimmed before the remap lookup")
	}
	if !strings.Contains(sql, "f.admin1_code = ''") {
		t.Fatal("country-wide rows are admin1_code = ''")
	}
	if !strings.Contains(sql, "f.admin1_code = q.admin1") {
		t.Fatal("place rows must only match the requested admin1")
	}
	if !strings.Contains(sql, "order by f.flag") {
		t.Fatal("resolve must be stable by flag")
	}
	for _, write := range []string{"insert ", "update ", "delete "} {
		if strings.Contains(sql, write) {
			t.Fatalf("resolve must be read-only, found %q", write)
		}
	}
}

func TestListCountryLegalFlagsSQLShape(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(listCountryLegalFlagsSQL)
	if !strings.Contains(sql, "from country_legal_flag") {
		t.Fatal("expected FROM country_legal_flag")
	}
	if !strings.Contains(sql, "f.iso = $1") {
		t.Fatal("list is an exact by-ISO read")
	}
	// ListCountryLegalFlags documents a trusted-ISO contract, and the
	// contract is the whole point: remapping here would silently accept a
	// geoip code and answer for a different country.
	if strings.Contains(sql, "country_code_remap") {
		t.Fatal("list must not remap; that is ResolveLegalFlags")
	}
	if !strings.Contains(sql, "order by f.flag") {
		t.Fatal("list must be stable by flag")
	}
}

func TestLegalFlagISOsMissingFromCountryInfoSQLShape(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(LegalFlagISOsMissingFromCountryInfoSQL)
	if !strings.Contains(sql, "from country_legal_flag") || !strings.Contains(sql, "country_info") {
		t.Fatal("drift check compares country_legal_flag against country_info")
	}
	if !strings.Contains(sql, "not exists") {
		t.Fatal("drift check must be an anti-join")
	}
	if !strings.Contains(sql, "upper(ci.iso)") {
		t.Fatal("country_info.iso must be uppercased before comparing")
	}
	for _, write := range []string{"insert ", "update ", "delete "} {
		if strings.Contains(sql, write) {
			t.Fatalf("drift check must be read-only, found %q", write)
		}
	}
}

// TestCountryLegalFlagJSONContract pins the wire shape: snake_case like
// GeoNamesStatusSnapshot, and as_of as a plain date. as_of is a SQL `date`
// with no time and no zone, so an RFC3339 midnight would invite a reader
// to compare it against a clock.
func TestCountryLegalFlagJSONContract(t *testing.T) {
	t.Parallel()
	notes := "California only"
	row := CountryLegalFlag{
		ISO:        "US",
		Flag:       LegalFlagUSCCPA,
		Admin1Code: "CA",
		Source:     "ccpa_cpra",
		AsOf:       NewLegalDate(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)),
		Notes:      &notes,
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	want := `{"iso":"US","flag":"us_ccpa","admin1_code":"CA","source":"ccpa_cpra","as_of":"2026-09-09","notes":"California only"}`
	if got != want {
		t.Fatalf("json = %s\nwant %s", got, want)
	}
	if strings.Contains(got, "T00:00:00") {
		t.Fatal("as_of is a date, not a timestamp")
	}

	var back CountryLegalFlag
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.AsOf.Equal(row.AsOf.Time) {
		t.Fatalf("as_of round trip = %s, want %s", back.AsOf, row.AsOf)
	}
	if back.Flag != row.Flag || back.Admin1Code != row.Admin1Code {
		t.Fatalf("round trip = %+v, want %+v", back, row)
	}
}

// TestLegalDateDropsTimeOfDay keeps the board and --json agreeing even
// when pgx hands back a date in a non-UTC location.

// TestLegalDateDropsTimeOfDay keeps the board and --json agreeing even
// when pgx hands back a date in a non-UTC location.
func TestLegalDateDropsTimeOfDay(t *testing.T) {
	t.Parallel()
	berlin := time.FixedZone("CEST", 2*60*60)
	d := NewLegalDate(time.Date(2026, 9, 9, 0, 0, 0, 0, berlin))
	if got := d.String(); got != "2026-09-08" {
		t.Fatalf("midnight in +02:00 is %s UTC, got %s", "2026-09-08", got)
	}
	if h, m, s := d.Clock(); h != 0 || m != 0 || s != 0 {
		t.Fatalf("LegalDate must keep no time of day, got %02d:%02d:%02d", h, m, s)
	}
}

func TestLegalFlagSubsetOfPairsAreDistinct(t *testing.T) {
	t.Parallel()
	if len(LegalFlagSubsetOf) == 0 {
		t.Fatal("LegalFlagSubsetOf must document the club invariants")
	}
	for _, pair := range LegalFlagSubsetOf {
		if pair[0] == pair[1] {
			t.Fatalf("subset pair %v is degenerate", pair)
		}
	}
}
