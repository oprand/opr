package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func geonamesStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Print a read-only status board for GeoNames dump tables, lookup match kinds, remap, and dump clocks. No downloads. Needs Postgres.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same snapshot as JSON",
			},
			&cli.DurationFlag{
				Name:  "stale-after",
				Usage: "Flag dump clocks as STALE when last verified (meta_added_at after an unchanged HEAD, else last_modified) is older than this. Default 48h is 2× geonames CrawlInterval.",
				Value: postgres.DefaultGeoNamesStaleAfter,
			},
		},
		Action: runGeoNamesStatus,
	}
}

func runGeoNamesStatus(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), c.String("postgres-db"))
	if err != nil {
		return err
	}
	defer st.Close()

	opts := postgres.GeoNamesStatusOptions{
		Now:        time.Now().UTC(),
		StaleAfter: c.Duration("stale-after"),
	}
	snap, err := st.FetchGeoNamesStatus(c.Context, opts)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	_, err = io.WriteString(os.Stdout, formatGeoNamesStatus(snap, stdoutColorEnabled()))
	return err
}

// formatGeoNamesStatus renders the snapshot as a USG-style status board:
// all-caps section labels, column-aligned numbers, STALE/MISSING/NEVER
// in words, no decorative box drawing. Color is optional and must
// survive NO_COLOR / pipes.
func formatGeoNamesStatus(s postgres.GeoNamesStatusSnapshot, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	when := s.GeneratedAt.UTC().Format(tsLayout) + " UTC"
	fmt.Fprintf(&b, "%s   %s\n", st.bold("GEONAMES"), st.dim(when))
	b.WriteByte('\n')

	writeGeoNamesTables(&b, st, s)
	b.WriteByte('\n')
	writeGeoNamesMatchKind(&b, st, s)
	b.WriteByte('\n')
	writeGeoNamesDumps(&b, st, s)
	return b.String()
}

func writeGeoNamesTables(b *strings.Builder, st termStyle, s postgres.GeoNamesStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("TABLES"))
	headers := []string{"", "rows", ""}
	right := []bool{false, true, false}
	rows := make([][]string, 0, len(s.Tables)+1)
	for _, tbl := range s.Tables {
		note := ""
		if tbl.Missing {
			note = "MISSING"
		}
		rows = append(rows, []string{tbl.Table, formatInt(tbl.Rows), note})
	}
	remapNote := ""
	if s.RemapRows == 0 {
		remapNote = "MISSING"
	}
	rows = append(rows, []string{"remap", formatInt(s.RemapRows), remapNote})
	flagNote := ""
	if s.LegalFlagRows == 0 {
		flagNote = "MISSING"
	}
	rows = append(rows, []string{"legal_flags", formatInt(s.LegalFlagRows), flagNote})
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeGeoNamesMatchKind(b *strings.Builder, st termStyle, s postgres.GeoNamesStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("MATCH KIND"))
	headers := []string{"", "rows"}
	right := []bool{false, true}
	rows := make([][]string, 0, len(s.MatchKind))
	for _, k := range s.MatchKind {
		rows = append(rows, []string{k.Kind, formatInt(k.Rows)})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeGeoNamesDumps(b *strings.Builder, st termStyle, s postgres.GeoNamesStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("DUMPS"))
	if len(s.Dumps) == 0 {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	headers := []string{"", "last seen", "etag", ""}
	right := []bool{false, false, false, false}
	rows := make([][]string, 0, len(s.Dumps))
	for _, d := range s.Dumps {
		seen := geoNamesTimeLabel(d.LastSeen)
		note := ""
		// NEVER and STALE are exclusive (same rule as geoip LACNIC).
		if !d.Never && seen != "NEVER" && d.Stale {
			note = "STALE"
		}
		etag := "no"
		if d.ETagPresent {
			etag = "yes"
		}
		rows = append(rows, []string{
			geoNamesDumpLabel(d.URL),
			seen,
			etag,
			note,
		})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func geoNamesDumpLabel(url string) string {
	if url == "" {
		return ""
	}
	if base := path.Base(url); base != "" && base != "." && base != "/" {
		return base
	}
	return url
}

func geoNamesTimeLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "NEVER"
	}
	return t.UTC().Format(tsLayout)
}
