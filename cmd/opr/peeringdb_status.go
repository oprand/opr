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

func peeringdbStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Print a read-only status board for PeeringDB dump tables, dump clocks, and the last data clock. No downloads. Needs Postgres.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same snapshot as JSON",
			},
			&cli.DurationFlag{
				Name:  "stale-after",
				Usage: "Flag dump clocks as STALE when last verified (meta_added_at after an unchanged HEAD, else last_modified) is older than this. Default 48h is 2× peeringdb CrawlInterval.",
				Value: postgres.DefaultPeeringDBStaleAfter,
			},
		},
		Action: runPeeringDBStatus,
	}
}

func runPeeringDBStatus(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return err
	}
	defer st.Close()

	opts := postgres.PeeringDBStatusOptions{
		Now:        time.Now().UTC(),
		StaleAfter: c.Duration("stale-after"),
	}
	snap, err := st.FetchPeeringDBStatus(c.Context, opts)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	_, err = io.WriteString(os.Stdout, formatPeeringDBStatus(snap, stdoutColorEnabled()))
	return err
}

// formatPeeringDBStatus renders the snapshot as a USG-style status board:
// all-caps section labels, column-aligned numbers, STALE/MISSING/NEVER
// in words, no decorative box drawing. Color is optional and must
// survive NO_COLOR / pipes.
func formatPeeringDBStatus(s postgres.PeeringDBStatusSnapshot, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	when := s.GeneratedAt.UTC().Format(tsLayout) + " UTC"
	fmt.Fprintf(&b, "%s   %s\n", st.bold("PEERINGDB"), st.dim(when))
	b.WriteByte('\n')

	writePeeringDBTables(&b, st, s)
	b.WriteByte('\n')
	writePeeringDBDumps(&b, st, s)
	b.WriteByte('\n')
	writePeeringDBSync(&b, st, s)
	return b.String()
}

func writePeeringDBTables(b *strings.Builder, st termStyle, s postgres.PeeringDBStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("TABLES"))
	headers := []string{"", "rows", ""}
	right := []bool{false, true, false}
	rows := make([][]string, 0, len(s.Tables))
	for _, tbl := range s.Tables {
		note := ""
		if tbl.Missing {
			note = "MISSING"
		}
		rows = append(rows, []string{tbl.Table, formatInt(tbl.Rows), note})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writePeeringDBDumps(b *strings.Builder, st termStyle, s postgres.PeeringDBStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("DUMPS"))
	if len(s.Dumps) == 0 {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	headers := []string{"", "last seen", "etag", ""}
	right := []bool{false, false, false, false}
	rows := make([][]string, 0, len(s.Dumps))
	for _, d := range s.Dumps {
		seen := peeringDBTimeLabel(d.LastSeen)
		note := ""
		// NEVER and STALE are exclusive (same rule as geonames).
		if !d.Never && seen != "NEVER" && d.Stale {
			note = "STALE"
		}
		etag := "no"
		if d.ETagPresent {
			etag = "yes"
		}
		rows = append(rows, []string{
			peeringDBDumpLabel(d.URL),
			seen,
			etag,
			note,
		})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writePeeringDBSync(b *strings.Builder, st termStyle, s postgres.PeeringDBStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("SYNC"))
	if s.Sync.Never {
		fmt.Fprintf(b, "%s  %s\n", padRight("last data", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	fmt.Fprintf(b, "%s  %s\n", padRight("last data", labelWidth), peeringDBTimeLabel(s.Sync.LastUpdated))
	if s.Sync.Stale {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), "STALE")
	}
}

func peeringDBDumpLabel(url string) string {
	if url == "" {
		return ""
	}
	if base := path.Base(url); base != "" && base != "." && base != "/" {
		return base
	}
	return url
}

func peeringDBTimeLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "NEVER"
	}
	return t.UTC().Format(tsLayout)
}
