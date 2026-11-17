package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func geonamesFlagsCommand() *cli.Command {
	return &cli.Command{
		Name:  "flags",
		Usage: "Look up country_legal_flag rows for one country (GDPR-like regimes, OFAC, Five/Nine/Fourteen Eyes, NATO, AUKUS). No downloads. The country code goes through country_code_remap, so UK resolves to GB. --apply writes the curated seed and is safe to repeat.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "iso",
				Usage: "Country code to look up. A geoip/geofeed code is fine (UK resolves to GB, EL to GR). A code that is a live ISO country is never rewritten, so CV stays Cabo Verde",
			},
			&cli.StringFlag{
				Name:  "region",
				Usage: "ISO 3166-2 region to also match place-specific flags, with or without the country prefix (US-CA or CA). Omit for country-wide flags only",
			},
			&cli.BoolFlag{
				Name:  "check",
				Usage: "Instead of a lookup, list seeded ISO codes that are absent from country_info (needs a loaded countryInfo dump). Empty output means the seed is consistent",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same rows as JSON",
			},
			&cli.BoolFlag{
				Name:  "apply",
				Usage: "Apply the curated country_legal_flag seed. Idempotent: a second run only refreshes source, as_of, and notes. Safe on a database that already has the rows",
			},
		},
		Action: runGeoNamesFlags,
	}
}

func runGeoNamesFlags(c *cli.Context) error {
	iso := strings.TrimSpace(c.String("iso"))
	check := c.Bool("check")
	apply := c.Bool("apply")
	if iso == "" && !check && !apply {
		return fmt.Errorf("geonames flags needs --iso, --check, or --apply")
	}

	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	if apply {
		if err := postgres.RunMigrations(logger.Named("store"), c.String("dsn")); err != nil {
			return err
		}
	}
	st, err := postgres.New(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return err
	}
	defer st.Close()

	if apply {
		if err := st.ApplyCountryLegalFlagSeed(c.Context); err != nil {
			return err
		}
	}
	if iso == "" && !check {
		return nil
	}

	if check {
		missing, err := st.ListLegalFlagISOsMissingFromCountryInfo(c.Context)
		if err != nil {
			return err
		}
		if c.Bool("json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(missing)
		}
		_, err = io.WriteString(os.Stdout, formatLegalFlagCheck(missing, stdoutColorEnabled()))
		return err
	}

	flags, err := st.ResolveLegalFlags(c.Context, iso, c.String("region"))
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(flags)
	}
	_, err = io.WriteString(os.Stdout, formatLegalFlags(iso, c.String("region"), flags, stdoutColorEnabled()))
	return err
}

// formatLegalFlags renders the lookup as a status board in the same style
// as geonames status: all-caps label, column-aligned, words not symbols.
// The header echoes the remapped ISO so UK -> GB is visible. It must use
// the same remap as ResolveLegalFlags, or the header would claim a country
// the rows do not come from.
func formatLegalFlags(iso, region string, flags []postgres.CountryLegalFlag, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	resolved := postgres.RemapCountryCodeForLegal(iso)
	label := resolved
	if resolved != strings.ToUpper(strings.TrimSpace(iso)) {
		label = fmt.Sprintf("%s (%s)", resolved, strings.ToUpper(strings.TrimSpace(iso)))
	}
	if admin1 := postgres.StripISO31662(region); admin1 != "" {
		label += " " + admin1
	}
	fmt.Fprintf(&b, "%s   %s\n\n", st.bold("LEGAL FLAGS"), st.dim(label))

	if len(flags) == 0 {
		fmt.Fprintf(&b, "%s\n", padRight("NONE", labelWidth))
		return b.String()
	}

	headers := []string{"", "scope", "source", "as of"}
	right := []bool{false, false, false, false}
	rows := make([][]string, 0, len(flags))
	for _, f := range flags {
		scope := "country"
		if !f.CountryWide() {
			scope = f.Admin1Code
		}
		rows = append(rows, []string{f.Flag, scope, f.Source, f.AsOf.String()})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
	return b.String()
}

// formatLegalFlagCheck renders the seed drift check. No rows is the good
// case and says OK rather than printing nothing.
func formatLegalFlagCheck(missing []string, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", st.bold("LEGAL FLAG SEED"))
	if len(missing) == 0 {
		fmt.Fprintf(&b, "%s  %s\n", padRight("country_info", labelWidth), "OK")
		return b.String()
	}
	fmt.Fprintf(&b, "%s  %s\n", padRight("country_info", labelWidth), "MISSING")
	for _, iso := range missing {
		fmt.Fprintf(&b, "%s  %s\n", padRight(iso, labelWidth), "not in country_info")
	}
	return b.String()
}
