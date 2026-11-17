package postgres

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// legalFlagSeedPath is the curated seed applied by `opr geonames flags --apply`.
// The lists are static (refreshed by editing the SQL, never crawled), so
// these tests read the file back instead of duplicating the lists in Go. No
// database and no network.
const legalFlagSeedPath = "seed/country_legal_flag.sql"

// Every seed statement is written in the same shape:
//
//	SELECT t.iso, '<flag>', '<admin1>', '<source>', DATE '<as_of>', '<notes>'
//	FROM UNNEST(ARRAY['XX','YY']) AS t(iso)
var (
	legalFlagSeedStmtRe  = regexp.MustCompile(`SELECT t\.iso, '([a-z0-9_]+)', '([A-Z]*)', '([a-z0-9_]+)', DATE '(\d{4}-\d{2}-\d{2})'`)
	legalFlagSeedArrayRe = regexp.MustCompile(`ARRAY\[([^\]]*)\]`)
	legalFlagSeedISORe   = regexp.MustCompile(`'([A-Z]{2})'`)
)

type legalFlagSeedRow struct {
	ISO    string
	Flag   string
	Admin1 string
	Source string
	AsOf   string
}

func readLegalFlagSeed(t *testing.T) []legalFlagSeedRow {
	t.Helper()
	raw, err := os.ReadFile(legalFlagSeedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	chunks := strings.Split(string(raw), "INSERT INTO country_legal_flag")
	if len(chunks) < 2 {
		t.Fatal("seed file has no country_legal_flag INSERT")
	}
	out := make([]legalFlagSeedRow, 0, 256)
	for i, chunk := range chunks[1:] {
		stmt := legalFlagSeedStmtRe.FindStringSubmatch(chunk)
		if stmt == nil {
			t.Fatalf("INSERT %d does not use the uniform seed shape", i)
		}
		arr := legalFlagSeedArrayRe.FindStringSubmatch(chunk)
		if arr == nil {
			t.Fatalf("INSERT %d (%s) has no UNNEST(ARRAY[...])", i, stmt[1])
		}
		isos := legalFlagSeedISORe.FindAllStringSubmatch(arr[1], -1)
		if len(isos) == 0 {
			t.Fatalf("INSERT %d (%s) seeds no ISO codes", i, stmt[1])
		}
		for _, iso := range isos {
			out = append(out, legalFlagSeedRow{
				ISO:    iso[1],
				Flag:   stmt[1],
				Admin1: stmt[2],
				Source: stmt[3],
				AsOf:   stmt[4],
			})
		}
	}
	return out
}

// seedByFlag is flag → sorted ISO codes.
func seedByFlag(rows []legalFlagSeedRow) map[string][]string {
	out := make(map[string][]string)
	for _, r := range rows {
		out[r.Flag] = append(out[r.Flag], r.ISO)
	}
	for flag := range out {
		slices.Sort(out[flag])
	}
	return out
}

// seedByISO is ISO → sorted flags, the shape ResolveLegalFlags returns for
// a country-wide lookup.
func seedByISO(rows []legalFlagSeedRow) map[string][]string {
	out := make(map[string][]string)
	for _, r := range rows {
		if r.Admin1 != "" {
			continue
		}
		out[r.ISO] = append(out[r.ISO], r.Flag)
	}
	for iso := range out {
		slices.Sort(out[iso])
	}
	return out
}

// TestLegalFlagSeedCounts pins the member count of every seeded flag, so a
// hand edit to one of the ISO arrays cannot silently change a club.
func TestLegalFlagSeedCounts(t *testing.T) {
	t.Parallel()
	byFlag := seedByFlag(readLegalFlagSeed(t))

	cases := []struct {
		flag string
		want int
	}{
		{LegalFlagEU, 27},
		// EU 27 + 3 EEA EFTA + the 7 EU-integral territories.
		{LegalFlagGDPR, 37},
		{LegalFlagEEAEFTA, 3},
		{LegalFlagUKGDPR, 1},
		{LegalFlagCHFADP, 1},
		{LegalFlagEUAdequacy, 14},
		{LegalFlagEUAdequacyUSDPF, 1},
		{"br_lgpd", 1},
		{"ca_pipeda", 1},
		{"jp_appi", 1},
		{"kr_pipa", 1},
		{"za_popia", 1},
		{"au_privacy", 1},
		{"in_dpdp", 1},
		{"cn_pipl", 1},
		{LegalFlagUSCCPA, 1},
		{LegalFlagOFACComprehensive, 3},
		{LegalFlagFiveEyes, 5},
		{LegalFlagNineEyes, 9},
		{LegalFlagFourteenEyes, 14},
		{LegalFlagAUKUS, 3},
		{LegalFlagNATO, 32},
		// 29 states plus AX, which is inside the area but reported as its
		// own code.
		{LegalFlagSchengen, 30},
		{LegalFlagOECD, 38},
		{LegalFlagCouncilOfEurope, 46},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			t.Parallel()
			if got := len(byFlag[tc.flag]); got != tc.want {
				t.Fatalf("flag %s has %d rows, want %d: %v", tc.flag, got, tc.want, byFlag[tc.flag])
			}
		})
	}
	if len(byFlag) != len(cases) {
		t.Fatalf("seed has %d flags, %d are pinned here: %v", len(byFlag), len(cases), byFlag)
	}
}

// TestLegalFlagSeedMembers pins the exact membership of the lists that are
// easy to get wrong, and of the ones a caller filters on by name.
func TestLegalFlagSeedMembers(t *testing.T) {
	t.Parallel()
	byFlag := seedByFlag(readLegalFlagSeed(t))

	cases := []struct {
		flag string
		want []string
	}{
		{LegalFlagFiveEyes, []string{"AU", "CA", "GB", "NZ", "US"}},
		{LegalFlagNineEyes, []string{"AU", "CA", "DK", "FR", "GB", "NL", "NO", "NZ", "US"}},
		{LegalFlagFourteenEyes, []string{"AU", "BE", "CA", "DE", "DK", "ES", "FR", "GB", "IT", "NL", "NO", "NZ", "SE", "US"}},
		{LegalFlagAUKUS, []string{"AU", "GB", "US"}},
		{LegalFlagEEAEFTA, []string{"IS", "LI", "NO"}},
		{LegalFlagOFACComprehensive, []string{"CU", "IR", "KP"}},
		{LegalFlagEUAdequacy, []string{"AD", "AR", "CA", "CH", "FO", "GB", "GG", "IL", "IM", "JE", "JP", "KR", "NZ", "UY"}},
		{LegalFlagEUAdequacyUSDPF, []string{"US"}},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			t.Parallel()
			if !slices.Equal(byFlag[tc.flag], tc.want) {
				t.Fatalf("flag %s = %v, want %v", tc.flag, byFlag[tc.flag], tc.want)
			}
		})
	}

	// US must never carry blanket adequacy: DPF is certification-scoped.
	if slices.Contains(byFlag[LegalFlagEUAdequacy], "US") {
		t.Fatal("US must not be seeded as eu_adequacy; DPF is eu_adequacy_us_dpf")
	}
	// gdpr is EU, plus the EEA EFTA states, plus the EU-integral
	// territories reported under their own code, and nothing else.
	want := slices.Concat(byFlag[LegalFlagEU], byFlag[LegalFlagEEAEFTA], LegalFlagGDPRTerritories)
	slices.Sort(want)
	if !slices.Equal(byFlag[LegalFlagGDPR], want) {
		t.Fatalf("gdpr = %v, want eu ∪ eea_efta ∪ territories = %v", byFlag[LegalFlagGDPR], want)
	}
}

// TestLegalFlagSeedTerritoryCoverage is the reverse drift check that
// `--check` cannot do: --check only finds seeded ISOs missing from
// country_info, so a territory that should carry gdpr and has no row at
// all is invisible to it and silently resolves to "no law applies". This
// pins the expected membership from the Go side, in both directions, so
// dropping a seed row or quietly widening the list fails here.
func TestLegalFlagSeedTerritoryCoverage(t *testing.T) {
	t.Parallel()
	byFlag := seedByFlag(readLegalFlagSeed(t))

	for _, iso := range LegalFlagGDPRTerritories {
		if !slices.Contains(byFlag[LegalFlagGDPR], iso) {
			t.Errorf("territory %s is EU-integral but carries no gdpr row; it would resolve to zero flags", iso)
		}
		// eu is the member-state list: a territory is covered through its
		// member state, so a row here would make WHERE flag = 'eu' wrong.
		if slices.Contains(byFlag[LegalFlagEU], iso) {
			t.Errorf("territory %s must not be seeded eu; it is not a member state in its own right", iso)
		}
	}

	// Schengen splits the territory list: AX is inside the area, the
	// French outermost regions are outside it and keep their own border.
	for _, iso := range LegalFlagGDPRTerritories {
		wantSchengen := slices.Contains(LegalFlagSchengenTerritories, iso)
		gotSchengen := slices.Contains(byFlag[LegalFlagSchengen], iso)
		if wantSchengen != gotSchengen {
			t.Errorf("territory %s schengen = %v, want %v", iso, gotSchengen, wantSchengen)
		}
	}

	// OCTs and Svalbard are associated with the EU, not part of it. BL is
	// the sharp case: same island as MF, opposite answer.
	for _, iso := range LegalFlagNonEULegalTerritories {
		for _, flag := range []string{LegalFlagEU, LegalFlagGDPR, LegalFlagSchengen} {
			if slices.Contains(byFlag[flag], iso) {
				t.Errorf("%s is an OCT / excluded territory and must not carry %s", iso, flag)
			}
		}
	}

	// The two lists describe the same island pair and must stay disjoint.
	for _, iso := range LegalFlagSchengenTerritories {
		if !slices.Contains(LegalFlagGDPRTerritories, iso) {
			t.Errorf("%s is listed as a schengen territory but not as a gdpr territory", iso)
		}
	}
	for _, iso := range LegalFlagNonEULegalTerritories {
		if slices.Contains(LegalFlagGDPRTerritories, iso) {
			t.Errorf("%s is in both the covered and the excluded territory list", iso)
		}
	}
}

// TestLegalFlagSeedSupersetsAreConsistent is the reason supersets are
// separate flags: every five_eyes member must also be seeded nine_eyes and
// fourteen_eyes, so WHERE flag = 'five_eyes' can stay exact.
func TestLegalFlagSeedSupersetsAreConsistent(t *testing.T) {
	t.Parallel()
	byFlag := seedByFlag(readLegalFlagSeed(t))
	for _, pair := range LegalFlagSubsetOf {
		sub, super := pair[0], pair[1]
		t.Run(sub+"_in_"+super, func(t *testing.T) {
			t.Parallel()
			if len(byFlag[sub]) == 0 || len(byFlag[super]) == 0 {
				t.Fatalf("both flags must be seeded: %s=%d %s=%d", sub, len(byFlag[sub]), super, len(byFlag[super]))
			}
			for _, iso := range byFlag[sub] {
				if !slices.Contains(byFlag[super], iso) {
					t.Fatalf("%s member %s is missing from %s", sub, iso, super)
				}
			}
			if len(byFlag[sub]) > len(byFlag[super]) {
				t.Fatalf("%s (%d) cannot be larger than %s (%d)", sub, len(byFlag[sub]), super, len(byFlag[super]))
			}
		})
	}
}

// TestLegalFlagSeedNoDuplicateRows mirrors the
// UNIQUE (iso, flag, admin1_code) constraint: the ON CONFLICT clauses in
// the seed would hide a duplicate at apply time.
func TestLegalFlagSeedNoDuplicateRows(t *testing.T) {
	t.Parallel()
	seen := make(map[[3]string]struct{})
	for _, r := range readLegalFlagSeed(t) {
		key := [3]string{r.ISO, r.Flag, r.Admin1}
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate seed row %v", key)
		}
		seen[key] = struct{}{}
	}
}

// legalFlagWithdrawnISOs are alpha-2 codes that were withdrawn from ISO
// 3166-1 and so have no country_info row. The remap sources (UK, EL, FX,
// TP, ZR, DD, BU) are checked separately against CountryCodeRemap.
var legalFlagWithdrawnISOs = []string{"AN", "CS", "YU", "SU", "TP", "ZR", "DD", "BU", "FX"}

// TestLegalFlagSeedISOsAreCurrentCodes is the offline half of the seed
// consistency check: shape, no reserved/vendor codes, and no remap source
// used where its target belongs. The authoritative check against
// country_info needs a loaded dump and is
// LegalFlagISOsMissingFromCountryInfoSQL / `opr geonames flags --check`.
func TestLegalFlagSeedISOsAreCurrentCodes(t *testing.T) {
	t.Parallel()
	rows := readLegalFlagSeed(t)
	if len(rows) == 0 {
		t.Fatal("seed is empty")
	}
	isoShape := regexp.MustCompile(`^[A-Z]{2}$`)
	for _, r := range rows {
		if !isoShape.MatchString(r.ISO) {
			t.Fatalf("iso %q is not two uppercase letters (%s)", r.ISO, r.Flag)
		}
		if _, bad := UnmappedGeoIPCodes[r.ISO]; bad {
			t.Fatalf("iso %q (%s) is a non-country geoip code and has no country_info row", r.ISO, r.Flag)
		}
		if _, remapped := CountryCodeRemap[r.ISO]; remapped {
			if _, ok := IntentionalISOOverrides[r.ISO]; !ok {
				t.Fatalf("iso %q (%s) is a country_code_remap source; seed the target %q instead", r.ISO, r.Flag, CountryCodeRemap[r.ISO])
			}
		}
		if slices.Contains(legalFlagWithdrawnISOs, r.ISO) {
			t.Fatalf("iso %q (%s) was withdrawn from ISO 3166-1", r.ISO, r.Flag)
		}
		if _, err := time.Parse("2006-01-02", r.AsOf); err != nil {
			t.Fatalf("as_of %q (%s) is not a date: %v", r.AsOf, r.Flag, err)
		}
		if r.Source == "" || r.Source != strings.ToLower(r.Source) {
			t.Fatalf("source %q (%s) must be a lowercase label", r.Source, r.Flag)
		}
	}
}

// TestLegalFlagSeedPlaceRows pins the one place-specific list: CCPA is
// California, never the whole US.
func TestLegalFlagSeedPlaceRows(t *testing.T) {
	t.Parallel()
	var place []legalFlagSeedRow
	for _, r := range readLegalFlagSeed(t) {
		if r.Admin1 != "" {
			place = append(place, r)
		}
	}
	if len(place) != 1 {
		t.Fatalf("expected exactly one place-specific seed row, got %+v", place)
	}
	got := place[0]
	if got.ISO != "US" || got.Flag != LegalFlagUSCCPA || got.Admin1 != "CA" {
		t.Fatalf("place row = %+v, want US/us_ccpa/CA", got)
	}
	// A country-wide us_ccpa row would make the whole US look covered.
	for _, r := range readLegalFlagSeed(t) {
		if r.Flag == LegalFlagUSCCPA && r.Admin1 == "" {
			t.Fatal("us_ccpa must not have a country-wide row")
		}
	}
}

// TestResolveLegalFlagsCaboVerdeIsNotPortugal is the specific regression:
// CV must resolve as Cabo Verde, which carries no seeded flag, and must
// never pick up Portugal's eu / gdpr / schengen / nato rows.
func TestResolveLegalFlagsCaboVerdeIsNotPortugal(t *testing.T) {
	t.Parallel()
	byISO := seedByISO(readLegalFlagSeed(t))

	portugal := byISO[RemapCountryCodeForLegal("PT")]
	if len(portugal) == 0 {
		t.Fatal("PT must carry the Portuguese set")
	}
	for _, flag := range []string{
		LegalFlagEU, LegalFlagGDPR, LegalFlagSchengen,
		LegalFlagNATO, LegalFlagCouncilOfEurope, LegalFlagOECD,
	} {
		if !slices.Contains(portugal, flag) {
			t.Errorf("PT flags %v are missing %s", portugal, flag)
		}
	}

	for _, in := range []string{"CV", "cv", " CV "} {
		cv := byISO[RemapCountryCodeForLegal(in)]
		if len(cv) != 0 {
			t.Errorf("%q resolved to %v; Cabo Verde carries no legal flag", in, cv)
		}
		for _, flag := range portugal {
			if slices.Contains(cv, flag) {
				t.Errorf("%q inherited Portugal's %s", in, flag)
			}
		}
	}
}

// TestResolveLegalFlagsRemapPath is the geoip → remap → flags path with
// the seed read off disk: geofeed codes must land on the remapped
// country's flags, and a non-country code must resolve to nothing.
func TestResolveLegalFlagsRemapPath(t *testing.T) {
	t.Parallel()
	rows := readLegalFlagSeed(t)
	byISO := seedByISO(rows)

	cases := []struct {
		name         string
		countryCode  string
		regionCode   string
		wantISO      string
		wantEmpty    bool
		wantFlags    []string
		wantNotFlags []string
		wantPlace    []string
	}{
		{name: "geofeed UK resolves to GB", countryCode: "UK", wantISO: "GB"},
		{name: "lowercase uk resolves to GB", countryCode: "uk", wantISO: "GB"},
		{name: "EL resolves to GR", countryCode: "EL", wantISO: "GR"},
		{
			// CV → PT is right for a gazetteer centroid and wrong here.
			name:        "CV stays Cabo Verde and carries nothing",
			countryCode: "CV",
			wantISO:     "CV",
			wantEmpty:   true,
		},
		{
			name:        "FX resolves to FR and picks up French flags",
			countryCode: "FX",
			wantISO:     "FR",
			wantFlags:   []string{LegalFlagEU, LegalFlagGDPR, LegalFlagSchengen},
		},
		{
			name:        "PT still carries the Portuguese set",
			countryCode: "PT",
			wantISO:     "PT",
			wantFlags:   []string{LegalFlagEU, LegalFlagGDPR, LegalFlagSchengen, LegalFlagNATO},
		},
		{
			name:         "AX is GDPR and Schengen through Finland",
			countryCode:  "AX",
			wantISO:      "AX",
			wantFlags:    []string{LegalFlagGDPR, LegalFlagSchengen},
			wantNotFlags: []string{LegalFlagEU},
		},
		{
			name:         "MQ is GDPR but outside Schengen",
			countryCode:  "MQ",
			wantISO:      "MQ",
			wantFlags:    []string{LegalFlagGDPR},
			wantNotFlags: []string{LegalFlagSchengen, LegalFlagEU},
		},
		{name: "BL is an OCT and carries nothing", countryCode: "BL", wantISO: "BL", wantEmpty: true},
		{name: "GB passes through", countryCode: "GB", wantISO: "GB"},
		{name: "EU is not a country", countryCode: "EU", wantISO: "EU", wantEmpty: true},
		{name: "AP is not a country", countryCode: "AP", wantISO: "AP", wantEmpty: true},
		{name: "A1 is not a country", countryCode: "A1", wantISO: "A1", wantEmpty: true},
		{name: "A2 is not a country", countryCode: "A2", wantISO: "A2", wantEmpty: true},
		{name: "O1 is not a country", countryCode: "O1", wantISO: "O1", wantEmpty: true},
		{name: "XX is not a country", countryCode: "XX", wantISO: "XX", wantEmpty: true},
		{name: "ZZ is not a country", countryCode: "ZZ", wantISO: "ZZ", wantEmpty: true},
		{name: "empty code", countryCode: "", wantISO: "", wantEmpty: true},
		{
			name:        "US without region is country-wide only",
			countryCode: "US",
			wantISO:     "US",
			wantFlags:   []string{LegalFlagEUAdequacyUSDPF, LegalFlagFiveEyes},
		},
		{
			name:        "US-CA also matches us_ccpa",
			countryCode: "US",
			regionCode:  "US-CA",
			wantISO:     "US",
			wantPlace:   []string{LegalFlagUSCCPA},
		},
		{
			name:        "bare CA region also matches us_ccpa",
			countryCode: "US",
			regionCode:  "CA",
			wantISO:     "US",
			wantPlace:   []string{LegalFlagUSCCPA},
		},
		{
			name:        "US-NY does not match us_ccpa",
			countryCode: "US",
			regionCode:  "US-NY",
			wantISO:     "US",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cc := RemapCountryCodeForLegal(tc.countryCode)
			if cc != tc.wantISO {
				t.Fatalf("RemapCountryCodeForLegal(%q) = %q, want %q", tc.countryCode, cc, tc.wantISO)
			}
			admin1 := StripISO31662(tc.regionCode)

			got := slices.Clone(byISO[cc])
			for _, r := range rows {
				if r.ISO == cc && r.Admin1 != "" && r.Admin1 == admin1 {
					got = append(got, r.Flag)
				}
			}
			slices.Sort(got)

			if tc.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("%q must resolve to no flags, got %v", tc.countryCode, got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("%q resolved to no flags", tc.countryCode)
			}
			for _, flag := range tc.wantFlags {
				if !slices.Contains(got, flag) {
					t.Fatalf("%s flags %v missing %s", cc, got, flag)
				}
			}
			for _, flag := range tc.wantNotFlags {
				if slices.Contains(got, flag) {
					t.Fatalf("%s flags %v must not include %s", cc, got, flag)
				}
			}
			for _, flag := range tc.wantPlace {
				if !slices.Contains(got, flag) {
					t.Fatalf("%s/%s flags %v missing place flag %s", cc, admin1, got, flag)
				}
			}
			if len(tc.wantPlace) == 0 && slices.Contains(got, LegalFlagUSCCPA) {
				t.Fatalf("%s/%s must not carry us_ccpa: %v", cc, admin1, got)
			}
		})
	}
}

// TestLegalFlagSeedRetiredFlagNames guards the rename. The seed is
// re-runnable, so it must both stop seeding the old names and clear them
// from a database that applied an earlier draft.
func TestLegalFlagSeedRetiredFlagNames(t *testing.T) {
	t.Parallel()
	retired := []string{"eea", "ofac"}

	byFlag := seedByFlag(readLegalFlagSeed(t))
	for _, flag := range retired {
		if len(byFlag[flag]) != 0 {
			t.Errorf("flag %q was renamed and must not be seeded any more: %v", flag, byFlag[flag])
		}
	}

	raw, err := os.ReadFile(legalFlagSeedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	for _, flag := range retired {
		want := "DELETE FROM country_legal_flag WHERE flag = '" + flag + "';"
		if !strings.Contains(string(raw), want) {
			t.Errorf("seed must clear the retired flag name: missing %q", want)
		}
	}
}

// TestLegalFlagSeedFileShape checks the seed file is data only. The table
// itself stays in 0001_initial; every INSERT must refresh on conflict.
func TestLegalFlagSeedFileShape(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(legalFlagSeedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	sql := string(raw)
	if strings.Contains(sql, "CREATE TABLE") {
		t.Fatal("seed file is data only; CREATE TABLE stays in 0001_initial")
	}
	inserts := strings.Count(sql, "INSERT INTO country_legal_flag")
	updates := strings.Count(sql, "ON CONFLICT (iso, flag, admin1_code) DO UPDATE")
	if inserts == 0 || inserts != updates {
		t.Fatalf("every seed INSERT must be a refreshable ON CONFLICT DO UPDATE (%d inserts, %d updates)", inserts, updates)
	}
}

// TestCountryLegalFlagSeedSplitsCleanly keeps ApplyCountryLegalFlagSeed
// from dropping a statement when it splits the file for pgx.
func TestCountryLegalFlagSeedSplitsCleanly(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(legalFlagSeedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	sql := string(raw)
	stmts := splitSQLStatements(sql)
	want := strings.Count(sql, "INSERT INTO country_legal_flag") + strings.Count(sql, "DELETE FROM country_legal_flag")
	if len(stmts) != want {
		t.Fatalf("split into %d statements, want %d", len(stmts), want)
	}
	for i, stmt := range stmts {
		if strings.Contains(stmt, "--") {
			t.Fatalf("statement %d still contains a comment: %s", i, stmt)
		}
		if !strings.HasSuffix(strings.TrimSpace(stmt), ";") {
			t.Fatalf("statement %d does not end with a semicolon", i)
		}
	}
}
