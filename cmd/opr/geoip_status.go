package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func geoIPStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Print a read-only status board for geofeeds, geoip, LACNIC, IPmap, and anycast. No downloads. Needs Postgres.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same snapshot as JSON",
			},
			&cli.DurationFlag{
				Name:  "stale-after",
				Usage: "Flag CATALOG / LACNIC / IPMAP / ANYCAST as STALE when last fetch or ingest is older than this. Default 168h matches crawl-geofeeds --refresh-older-than (feed content), not the 48h NRO clock. Does not change the due count interval.",
				Value: postgres.DefaultGeoIPStaleAfter,
			},
		},
		Action: runGeoIPStatus,
	}
}

func runGeoIPStatus(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return err
	}
	defer st.Close()

	opts := postgres.GeoIPStatusOptions{
		Now:        time.Now().UTC(),
		StaleAfter: c.Duration("stale-after"),
	}
	snap, err := st.FetchGeoIPStatus(c.Context, opts)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	_, err = io.WriteString(os.Stdout, formatGeoIPStatus(snap, stdoutColorEnabled()))
	return err
}

// formatGeoIPStatus renders the snapshot as a USG-style status board:
// all-caps section labels, column-aligned numbers, STALE/NEVER/DUE/
// QUARANTINE/MISSING in words, no decorative box drawing. Color is optional
// and must survive NO_COLOR / pipes.
func formatGeoIPStatus(s postgres.GeoIPStatusSnapshot, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	when := s.GeneratedAt.UTC().Format(tsLayout) + " UTC"
	fmt.Fprintf(&b, "%s   %s\n", st.bold("GEOIP"), st.dim(when))
	b.WriteByte('\n')

	writeGeoIPCatalog(&b, st, s)
	b.WriteByte('\n')
	writeGeoIPSources(&b, st, s)
	b.WriteByte('\n')
	writeGeoIPFileClock(&b, st, "LACNIC", s.Lacnic.Never, s.Lacnic.Stale, s.Lacnic.LastSeen, s.Lacnic.Rows)
	b.WriteByte('\n')
	writeGeoIPFileClock(&b, st, "IPMAP", s.IPMap.Never, s.IPMap.Stale, s.IPMap.LastSeen, s.IPMap.Rows)
	b.WriteByte('\n')
	writeGeoIPFileClock(&b, st, "ANYCAST V4", s.AnycastV4.Never, s.AnycastV4.Stale, s.AnycastV4.LastSeen, s.AnycastV4.Rows)
	b.WriteByte('\n')
	writeGeoIPFileClock(&b, st, "ANYCAST V6", s.AnycastV6.Never, s.AnycastV6.Stale, s.AnycastV6.LastSeen, s.AnycastV6.Rows)
	return b.String()
}

func writeGeoIPCatalog(b *strings.Builder, st termStyle, s postgres.GeoIPStatusSnapshot) {
	c := s.Catalog
	fmt.Fprintf(b, "%s\n", st.bold("CATALOG"))
	fmt.Fprintf(b, "%s  %s   fetched %s   never %s\n",
		padRight("urls", labelWidth),
		formatInt(c.URLs),
		formatInt(c.Fetched),
		formatInt(c.NeverFetched),
	)
	fmt.Fprintf(b, "%s  %s   quarantine %s   invalid %s\n",
		padRight("due", labelWidth),
		formatInt(c.Due),
		formatInt(c.Quarantined),
		formatInt(c.Invalid),
	)
	fmt.Fprintf(b, "%s  %s   checked %s   whois %s\n",
		padRight("last fetch", labelWidth),
		geoIPTimeLabel(c.LastFetchedAt),
		geoIPTimeLabel(c.LastCheckedAt),
		geoIPTimeLabel(c.LastSeenInWhois),
	)

	flags := make([]string, 0, 4)
	if c.Never {
		flags = append(flags, "NEVER")
	}
	if c.Stale {
		flags = append(flags, "STALE")
	}
	if c.Due > 0 {
		flags = append(flags, "DUE")
	}
	if c.Quarantined > 0 {
		flags = append(flags, "QUARANTINE")
	}
	if len(flags) == 0 {
		flags = append(flags, "OK")
	}
	fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), strings.Join(flags, "   "))
}

func writeGeoIPSources(b *strings.Builder, st termStyle, s postgres.GeoIPStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("GEOIP"))
	headers := []string{"", "rows", "urls", "newest", ""}
	right := []bool{false, true, true, false, false}
	rows := make([][]string, 0, len(s.GeoIP))
	for _, src := range s.GeoIP {
		note := ""
		if src.Missing {
			note = "MISSING"
		}
		rows = append(rows, []string{
			src.Source,
			formatInt(src.Rows),
			formatInt(src.DistinctURLs),
			geoIPTimeLabel(src.NewestAddedAt),
			note,
		})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeGeoIPFileClock(b *strings.Builder, st termStyle, label string, never, stale bool, lastSeen *time.Time, rows int64) {
	if never {
		fmt.Fprintf(b, "%s  %s\n", padRight(label, labelWidth), padRight("NEVER", tsWidth))
		return
	}
	fmt.Fprintf(b, "%s  %s   %s rows\n",
		padRight(label, labelWidth),
		geoIPTimeLabel(lastSeen),
		formatInt(rows),
	)
	flags := make([]string, 0, 1)
	if stale {
		flags = append(flags, "STALE")
	}
	if len(flags) == 0 {
		flags = append(flags, "OK")
	}
	fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), strings.Join(flags, "   "))
}

func geoIPTimeLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "NEVER"
	}
	return t.UTC().Format(tsLayout)
}
