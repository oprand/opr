package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/asnames"
	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
)

func registryCrawlStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Print a read-only status board for NRO, bulk dumps, RIB/asnames watermarks, coverage, and the RDAP queue",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same snapshot as JSON",
			},
			&cli.DurationFlag{
				Name:  "stale-after",
				Usage: "Flag NRO as STALE when ingested_at is older than this",
				Value: postgres.DefaultNROStaleAfter,
			},
		},
		Action: runRegistryCrawlStatus,
	}
}

func runRegistryCrawlStatus(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), c.String("dsn"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := c.Context
	opts := postgres.CrawlStatusOptions{
		Now:        time.Now().UTC(),
		StaleAfter: c.Duration("stale-after"),
		BulkFiles:  whoisdb.RegistrationDumpFiles(),
		ASNamesURL: asnames.DefaultURL,
	}
	snap, err := st.FetchCrawlStatus(ctx, opts)
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	_, err = io.WriteString(os.Stdout, formatCrawlStatus(snap, stdoutColorEnabled()))
	return err
}

func stdoutColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

type termStyle struct {
	color bool
}

func (t termStyle) bold(s string) string {
	if !t.color || s == "" {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func (t termStyle) dim(s string) string {
	if !t.color || s == "" {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

const (
	labelWidth = 10
	tsLayout   = "2006-01-02 15:04"
	tsWidth    = 16
	dateLayout = "2006-01-02"
)

// formatCrawlStatus renders the snapshot as a USG-style status board:
// all-caps section labels, column-aligned numbers, STALE/NEVER/MISSING in
// words, no decorative box drawing. Color is optional and must survive
// NO_COLOR / pipes.
func formatCrawlStatus(s postgres.CrawlStatusSnapshot, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	when := s.GeneratedAt.UTC().Format(tsLayout) + " UTC"
	fmt.Fprintf(&b, "%s   %s\n", st.bold("REGISTRY CRAWL"), st.dim(when))
	b.WriteByte('\n')

	writeNRO(&b, st, s)
	b.WriteByte('\n')
	writeBulk(&b, st, s)
	b.WriteByte('\n')
	writeWatermark(&b, st, "RIB", s.RIB, "run seed without --skip-ribs", "")
	writeASNames(&b, st, s.ASNames)
	b.WriteByte('\n')
	writeCoverage(&b, st, "COVERAGE  autnum",
		[]string{"nro", "target", "whoisdb"},
		coverageAutnumRows(s.Coverage.Autnum))
	b.WriteByte('\n')
	writeCoverage(&b, st, "COVERAGE  ipnet",
		[]string{"target", "inetnum", "inet6num"},
		coverageIpnetRows(s.Coverage.Ipnet))
	b.WriteByte('\n')
	for i, q := range s.Queue {
		writeQueue(&b, st, q)
		if i+1 < len(s.Queue) {
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	writeRDAP(&b, st, s)
	return b.String()
}

func writeNRO(b *strings.Builder, st termStyle, s postgres.CrawlStatusSnapshot) {
	n := s.NRO
	fmt.Fprintf(b, "%s  %s rows   file_date %s   ingested %s\n",
		padRight("nro", labelWidth),
		formatInt(n.Rows),
		fileDateLabel(n.FileDate),
		ingestedLabel(n.IngestedAt, s.GeneratedAt),
	)
	flags := make([]string, 0, 2)
	if n.Empty {
		flags = append(flags, "NEVER")
	}
	if n.Stale {
		flags = append(flags, "STALE")
	}
	if len(flags) == 0 {
		flags = append(flags, "OK")
	}
	fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), strings.Join(flags, "   "))
}

func writeBulk(b *strings.Builder, st termStyle, s postgres.CrawlStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("BULK"))
	whois := make(map[string]postgres.WhoisDBSourceCount, len(s.WhoisDB))
	for _, w := range s.WhoisDB {
		whois[w.Source] = w
	}

	headers := []string{"", "fetched", "files", "autnum", "inetnum", "inet6num", "as-set", "as-block", "irt", ""}
	rows := make([][]string, 0, len(s.Bulk))
	right := []bool{false, false, true, true, true, true, true, true, true, false}
	for _, src := range s.Bulk {
		w := whois[src.Source]
		fetched := "NEVER"
		if src.LastSeen != nil {
			fetched = src.LastSeen.UTC().Format(tsLayout)
		}
		note := ""
		switch {
		case src.Never:
			note = "MISSING"
		case src.Missing:
			note = "MISSING"
		}
		if !src.Coverage {
			if note != "" {
				note += "   not coverage"
			} else {
				note = "not coverage"
			}
		}
		rows = append(rows, []string{
			src.Source,
			fetched,
			fmt.Sprintf("%d/%d", src.Present, src.Files),
			formatInt(w.Autnum),
			formatInt(w.Inetnum),
			formatInt(w.Inet6num),
			formatInt(w.AsSet),
			formatInt(w.AsBlock),
			formatInt(w.Irt),
			note,
		})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeWatermark(b *strings.Builder, st termStyle, label string, w postgres.FileWatermark, neverHint, extra string) {
	label = padRight(label, labelWidth)
	if w.Never {
		line := fmt.Sprintf("%s  %s", label, padRight("NEVER", tsWidth))
		if neverHint != "" {
			line += "  " + neverHint
		}
		if extra != "" {
			line += "   " + extra
		}
		b.WriteString(line + "\n")
		return
	}
	when := st.dim(w.LastSeen.UTC().Format(tsLayout))
	line := fmt.Sprintf("%s  %s", label, when)
	if extra != "" {
		line += "   " + extra
	}
	b.WriteString(line + "\n")
}

func writeASNames(b *strings.Builder, st termStyle, a postgres.ASNamesStatus) {
	extra := formatInt(a.Rows) + " rows"
	writeWatermark(b, st, "ASNAMES", a.FileWatermark, extra, extraIfSeen(a.FileWatermark, extra))
}

func extraIfSeen(w postgres.FileWatermark, extra string) string {
	if w.Never {
		return ""
	}
	return extra
}

func writeCoverage(b *strings.Builder, st termStyle, title string, headers []string, rows [][]string) {
	fmt.Fprintf(b, "%s\n", st.bold(title))
	cols := append([]string{""}, headers...)
	right := make([]bool, len(cols))
	for i := 1; i < len(cols); i++ {
		right[i] = true
	}
	b.WriteString(formatAlignedTable(cols, rows, right, st))
}

func coverageAutnumRows(in []postgres.AutnumCoverage) [][]string {
	out := make([][]string, 0, len(in))
	for _, r := range in {
		out = append(out, []string{r.Registry, formatInt(r.NRO), formatInt(r.Target), formatInt(r.WhoisDB)})
	}
	return out
}

func coverageIpnetRows(in []postgres.IpnetCoverage) [][]string {
	out := make([][]string, 0, len(in))
	for _, r := range in {
		out = append(out, []string{r.Registry, formatInt(r.Target), formatInt(r.Inetnum), formatInt(r.Inet6num)})
	}
	return out
}

func writeQueue(b *strings.Builder, st termStyle, q postgres.QueueSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("QUEUE  "+q.Kind))
	headers := []string{"", "pending", "in_prog", "done", "failed", "gone"}
	right := []bool{false, true, true, true, true, true}
	rows := make([][]string, 0, len(q.Registries))
	for _, r := range q.Registries {
		rows = append(rows, []string{
			r.Registry,
			formatInt(r.Pending),
			formatInt(r.InProgress),
			formatInt(r.Done),
			formatInt(r.Failed),
			formatInt(r.Gone),
		})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeRDAP(b *strings.Builder, st termStyle, s postgres.CrawlStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("RDAP"))
	h := s.RDAP
	fmt.Fprintf(b, "%s  %s\n", padRight("429s", labelWidth), formatInt(h.Status429))
	lease := formatInt(h.StaleLeases) + " stale (>" + compactDuration(postgres.RDAPStaleLeaseAfter) + ")"
	fmt.Fprintf(b, "%s  %s\n", padRight("leases", labelWidth), lease)

	pending := "NEVER"
	if h.OldestPendingAt != nil {
		pending = h.OldestPendingAt.UTC().Format(dateLayout)
	}
	failed := "NEVER"
	if h.OldestFailedRetry != nil {
		failed = relTo(s.GeneratedAt, *h.OldestFailedRetry)
	}
	fmt.Fprintf(b, "%s  pending %s   failed retry %s\n", padRight("oldest", labelWidth), pending, failed)

	if len(h.Errors) == 0 {
		fmt.Fprintf(b, "%s  0\n", padRight("errors", labelWidth))
		return
	}
	for i, e := range h.Errors {
		label := ""
		if i == 0 {
			label = "errors"
		}
		fmt.Fprintf(b, "%s  %s (%s)\n", padRight(label, labelWidth), clip(e.Error, 72), formatInt(e.Count))
	}
}

func fileDateLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "MISSING"
	}
	return t.UTC().Format(dateLayout)
}

func ingestedLabel(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "NEVER"
	}
	return compactDuration(now.Sub(*t)) + " ago"
}

func relTo(now, t time.Time) string {
	d := t.Sub(now)
	if d >= 0 {
		return "in " + compactDuration(d)
	}
	return compactDuration(-d) + " ago"
}

func compactDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func formatInt(n int64) string {
	return strconv.FormatInt(n, 10)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func padLeft(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

func clip(s string, n int) string {
	if n < 4 || len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// formatAlignedTable is a monospace board: first column left, selected
// columns right-aligned on the wider of header or values. Trailing empty
// note columns are kept so MISSING / not coverage sit in a fixed gutter.
func formatAlignedTable(headers []string, rows [][]string, right []bool, st termStyle) string {
	if len(headers) == 0 {
		return ""
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i := 0; i < len(headers) && i < len(row); i++ {
			if l := len(row[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}
	if widths[0] < labelWidth {
		widths[0] = labelWidth
	}

	var b strings.Builder
	writeRow := func(cols []string, header bool) {
		var row strings.Builder
		for i := 0; i < len(headers); i++ {
			cell := ""
			if i < len(cols) {
				cell = cols[i]
			}
			if i > 0 {
				row.WriteString("  ")
			}
			if i < len(right) && right[i] {
				cell = padLeft(cell, widths[i])
			} else {
				cell = padRight(cell, widths[i])
			}
			if header {
				cell = st.dim(cell)
			}
			row.WriteString(cell)
		}
		b.WriteString(strings.TrimRight(row.String(), " "))
		b.WriteByte('\n')
	}
	writeRow(headers, true)
	for _, row := range rows {
		writeRow(row, false)
	}
	return b.String()
}
