package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func TestCLIRegistersGeoNamesFlagsSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	gn := findCommand(app.Commands, "geonames")
	if gn == nil {
		t.Fatal("geonames must be registered")
	}
	flags := findCommand(gn.Subcommands, "flags")
	if flags == nil {
		t.Fatal("geonames flags must be registered")
	}
	if flags.Usage == "" {
		t.Fatal("geonames flags must have Usage")
	}
	names := flagNameSet(flags.Flags)
	for _, want := range []string{"iso", "region", "check", "json", "apply"} {
		if !names[want] {
			t.Errorf("geonames flags missing flag %q", want)
		}
	}
	// Lookup itself does not download. --apply writes the curated seed.
	for _, unwanted := range []string{"force", "url"} {
		if names[unwanted] {
			t.Errorf("geonames flags must not register %q", unwanted)
		}
	}
}

func TestRunGeoNamesFlagsNeedsISOOrCheck(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	set := flag.NewFlagSet("flags", flag.ContinueOnError)
	err := runGeoNamesFlags(cli.NewContext(app, set, nil))
	if err == nil {
		t.Fatal("expected an error without --iso or --check")
	}
	if !strings.Contains(err.Error(), "--iso, --check, or --apply") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func sampleLegalFlags() []postgres.CountryLegalFlag {
	asOf := postgres.NewLegalDate(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC))
	return []postgres.CountryLegalFlag{
		{ISO: "US", Flag: postgres.LegalFlagEUAdequacyUSDPF, Source: "ec_adequacy_dpf", AsOf: asOf},
		{ISO: "US", Flag: postgres.LegalFlagFiveEyes, Source: "ukusa", AsOf: asOf},
		{ISO: "US", Flag: postgres.LegalFlagUSCCPA, Admin1Code: "CA", Source: "ccpa_cpra", AsOf: asOf},
	}
}

const legalFlagsBoardGolden = `LEGAL FLAGS   US CA

                    scope    source           as of
eu_adequacy_us_dpf  country  ec_adequacy_dpf  2026-09-09
five_eyes           country  ukusa            2026-09-09
us_ccpa             CA       ccpa_cpra        2026-09-09
`

func TestFormatLegalFlagsGolden(t *testing.T) {
	t.Parallel()
	got := formatLegalFlags("US", "US-CA", sampleLegalFlags(), false)
	if got != legalFlagsBoardGolden {
		t.Fatalf("board mismatch\nGOT:\n%s\nWANT:\n%s", got, legalFlagsBoardGolden)
	}
}

func TestFormatLegalFlagsShowsRemap(t *testing.T) {
	t.Parallel()
	got := formatLegalFlags("uk", "", nil, false)
	if !strings.Contains(got, "GB (UK)") {
		t.Fatalf("board must show the remapped ISO and the input code:\n%s", got)
	}
	if !strings.Contains(got, "NONE") {
		t.Fatalf("no rows must say NONE:\n%s", got)
	}
}

// TestFormatLegalFlagsDoesNotRemapCaboVerde: the header must name the
// country the rows actually came from. ResolveLegalFlags leaves CV alone,
// so a header reading "PT (CV)" would be the board lying about Cabo Verde.
func TestFormatLegalFlagsDoesNotRemapCaboVerde(t *testing.T) {
	t.Parallel()
	got := formatLegalFlags("cv", "", nil, false)
	if strings.Contains(got, "PT") {
		t.Fatalf("CV must not be shown as Portugal:\n%s", got)
	}
	if !strings.Contains(got, "CV") || !strings.Contains(got, "NONE") {
		t.Fatalf("CV must resolve to itself with no flags:\n%s", got)
	}
}

func TestFormatLegalFlagsNoANSIWhenColorOff(t *testing.T) {
	t.Parallel()
	if got := formatLegalFlags("US", "US-CA", sampleLegalFlags(), false); strings.Contains(got, "\033[") {
		t.Fatal("color-off output must not contain ANSI")
	}
}

// TestLegalFlagsJSONIsSnakeCase pins what --json emits: the same
// vocabulary as `geonames status --json`, and as_of as a plain date so the
// JSON and the board show the same string.
func TestLegalFlagsJSONIsSnakeCase(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sampleLegalFlags()); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := buf.String()
	for _, key := range []string{`"iso"`, `"flag"`, `"admin1_code"`, `"source"`, `"as_of"`, `"notes"`} {
		if !strings.Contains(got, key) {
			t.Errorf("--json must emit %s:\n%s", key, got)
		}
	}
	for _, key := range []string{`"ISO"`, `"Flag"`, `"Admin1Code"`, `"AsOf"`} {
		if strings.Contains(got, key) {
			t.Errorf("--json must not emit the Go field name %s:\n%s", key, got)
		}
	}
	if !strings.Contains(got, `"as_of": "2026-09-09"`) {
		t.Errorf("as_of must render as a date:\n%s", got)
	}
	if !strings.Contains(got, "\n  {\n") {
		t.Errorf("--json must be indented like the other geonames commands:\n%s", got)
	}
}

func TestFormatLegalFlagCheck(t *testing.T) {
	t.Parallel()
	clean := formatLegalFlagCheck(nil, false)
	if !strings.Contains(clean, "OK") || strings.Contains(clean, "MISSING") {
		t.Fatalf("clean seed must say OK:\n%s", clean)
	}
	drift := formatLegalFlagCheck([]string{"XK"}, false)
	if !strings.Contains(drift, "MISSING") || !strings.Contains(drift, "XK") {
		t.Fatalf("drift must name the ISO:\n%s", drift)
	}
}
