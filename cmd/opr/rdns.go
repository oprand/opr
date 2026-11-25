package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/rdns"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/store/postgres"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func rdnsCommand() *cli.Command {
	return &cli.Command{
		Name:     "rdns",
		Category: commandCategoryData,
		Usage:    "RIR reverse-DNS zones, IANA parent cuts, and WHOIS enrich into rdns_delegation. ingest and crawl-ptr also run under opr run ([rdns.*]).",
		Description: `Pick a subcommand. ingest writes NS/DS/CNAME (plus IANA/WHOIS enrich); crawl-ptr queries PTR at delegated nservers; status is read-only.

Needs Postgres.`,
		Subcommands: []*cli.Command{
			{
				Name:  "ingest",
				Usage: "List RIR /zones/, fetch changed master files, persist NS/DS/CNAME, then IANA/WHOIS enrich. One failed RIR does not wipe another.",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Re-download even when the ETag / Last-Modified is unchanged",
					},
					&cli.StringSliceFlag{
						Name:  "only-registries",
						Usage: "Only ingest these RIRs. Valid names: " + strings.Join(rdnsRegistryNames(), ", "),
					},
					&cli.StringFlag{
						Name:  "ripe-url",
						Usage: "RIPE /zones/ directory URL",
						Value: rdns.DefaultRIPEZonesURL,
					},
					&cli.StringFlag{
						Name:  "apnic-url",
						Usage: "APNIC /zones/ directory URL",
						Value: rdns.DefaultAPNICZonesURL,
					},
					&cli.StringFlag{
						Name:  "arin-url",
						Usage: "ARIN /zones/ directory URL",
						Value: rdns.DefaultARINZonesURL,
					},
					&cli.StringFlag{
						Name:  "afrinic-url",
						Usage: "AFRINIC /zones/ directory URL",
						Value: rdns.DefaultAFRINICZonesURL,
					},
					&cli.StringFlag{
						Name:  "lacnic-url",
						Usage: "LACNIC /zones/ directory URL",
						Value: rdns.DefaultLACNICZonesURL,
					},
					&cli.BoolFlag{
						Name:  "skip-iana",
						Usage: "Skip InterNIC in-addr.arpa / ip6.arpa parent zones",
					},
					&cli.StringFlag{
						Name:  "iana-inaddr-url",
						Usage: "InterNIC in-addr.arpa parent zone URL",
						Value: rdns.DefaultIANAInAddrURL,
					},
					&cli.StringFlag{
						Name:  "iana-ip6-url",
						Usage: "InterNIC ip6.arpa parent zone URL",
						Value: rdns.DefaultIANAIP6URL,
					},
					&cli.BoolFlag{
						Name:  "skip-whois",
						Usage: "Skip RIPE/APNIC/AFRINIC reverse domain: dumps",
					},
					&cli.StringFlag{
						Name:  "ripe-domain-url",
						Usage: "RIPE ripe.db.domain.gz URL",
						Value: rdns.DefaultRIPEDomainURL,
					},
					&cli.StringFlag{
						Name:  "apnic-domain-url",
						Usage: "APNIC apnic.db.domain.gz URL",
						Value: rdns.DefaultAPNICDomainURL,
					},
					&cli.StringFlag{
						Name:  "afrinic-db-url",
						Usage: "AFRINIC mixed whois dump URL (domain: objects only; same file as whoisdb)",
						Value: rdns.DefaultAFRINICWhoisURL,
					},
					&cli.BoolFlag{
						Name:  "skip-lacnic-whois",
						Usage: "Skip LACNIC inetnum nserver harvest",
					},
					&cli.StringFlag{
						Name:  "lacnic-db-url",
						Usage: "LACNIC lacnic.db.gz URL for inetnum nserver",
						Value: rdns.DefaultLACNICWhoisDBURL,
					},
				},
				Action: runRDNSIngest,
			},
			rdnsStatusCommand(),
			rdnsCrawlPTRCommand(),
		},
	}
}

func rdnsStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Print read-only per-RIR counts, IANA expected vs fetched, WHOIS enrich, PTR crawl stats, and dump clocks. No downloads.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Dump the same snapshot as JSON",
			},
			&cli.DurationFlag{
				Name:  "stale-after",
				Usage: "Flag RIR last-fetch, PTR last-fetch, and dump clocks as STALE when older than this. Default 168h.",
				Value: postgres.DefaultRDNSStaleAfter,
			},
		},
		Action: runRDNSStatus,
	}
}

func rdnsCrawlPTRCommand() *cli.Command {
	return &cli.Command{
		Name:  "crawl-ptr",
		Usage: "Query PTR at delegated nservers. Unscoped full crawl is a /24 block queue (resume via rdns_ptr_block). In opr run this is the continuous unscoped [rdns.crawl-ptr] job.",
		Description: `Does: PTR queries at leaf nservers. Scoped --zone/--prefix uses the GiST deepest-cut (smoke). Unscoped seeds rdns_ptr_block (IPv4 /24–32, IPv6 /120+) and claims one block at a time.

Needs: Postgres; prior rdns ingest so leaves exist.

When: after ingest. Smoke: opr rdns crawl-ptr --prefix 193.0.0.0/24 --limit 256 --only-registries RIPE. Full/resume: opr rdns crawl-ptr.`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "prefix",
				Usage: "Only addresses in this prefix (must overlap a leaf). IPv4 shorter than /24 or IPv6 shorter than /120 needs --i-mean-it --max-addresses",
			},
			&cli.StringFlag{
				Name:  "zone",
				Usage: "Only this reverse zone and child leaves (e.g. 0.0.193.in-addr.arpa)",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "Max address PTR queries this run (0 = no cap). Smoke: --limit 256 on a /24",
			},
			&cli.StringSliceFlag{
				Name:  "only-registries",
				Usage: "Only leaves from these RIRs. Valid names: " + strings.Join(rdnsRegistryNames(), ", "),
			},
			&cli.Float64Flag{
				Name:  "qps",
				Usage: "Max PTR queries per nameserver",
				Value: rdns.DefaultPTRQPS,
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Per-query DNS timeout",
				Value: rdns.DefaultPTRTimeout,
			},
			&cli.BoolFlag{
				Name:  "i-mean-it",
				Usage: "Allow a coarse --prefix (still requires --max-addresses)",
			},
			&cli.IntFlag{
				Name:  "max-addresses",
				Usage: "Cap addresses enumerated per leaf (default 256). Required with --i-mean-it on a coarse prefix",
			},
		},
		Action: runRDNSCrawlPTR,
	}
}

func rdnsRegistryNames() []string {
	return []string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}
}

func runRDNSIngest(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.rdns.ingest")

	sources, err := rdnsSourcesFromCLI(c)
	if err != nil {
		return err
	}

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	in := rdns.NewIngestor(logger, st, &http.Client{Timeout: 15 * time.Minute}, sources)
	in.Force = c.Bool("force")
	in.SkipIANA = c.Bool("skip-iana")
	in.IANAInAddrURL = c.String("iana-inaddr-url")
	in.IANAIP6URL = c.String("iana-ip6-url")
	in.SkipWhois = c.Bool("skip-whois")
	in.WhoisDumps = rdnsWhoisDumpsFromCLI(c, sources)
	in.SkipLacnic = c.Bool("skip-lacnic-whois") || !rdnsSourceSelected(sources, opconst.LACNIC)
	in.LacnicDBURL = c.String("lacnic-db-url")
	if err := in.Ingest(c.Context); err != nil {
		logger.Error("rdns ingest finished with errors; last good rows kept for failed files/RIRs", zap.Error(err))
		return err
	}
	logger.Info("rdns ingest finished")
	return nil
}

func rdnsSourcesFromCLI(c *cli.Context) ([]rdns.Source, error) {
	return rdnsSources(rdnsZoneURLs{
		AFRINIC: c.String("afrinic-url"),
		APNIC:   c.String("apnic-url"),
		ARIN:    c.String("arin-url"),
		LACNIC:  c.String("lacnic-url"),
		RIPE:    c.String("ripe-url"),
	}, c.StringSlice("only-registries"))
}

// rdnsZoneURLs are the five RIR /zones/ directory URLs.
type rdnsZoneURLs struct {
	AFRINIC, APNIC, ARIN, LACNIC, RIPE string
}

// rdnsSources is shared by `rdns ingest` and the daemon's rdns.ingest job:
// the five RIR sources, filtered and ordered by only (empty = all).
func rdnsSources(urls rdnsZoneURLs, only []string) ([]rdns.Source, error) {
	all := []rdns.Source{
		{Name: opconst.AFRINIC, ListURL: urls.AFRINIC},
		{Name: opconst.APNIC, ListURL: urls.APNIC},
		{Name: opconst.ARIN, ListURL: urls.ARIN},
		{Name: opconst.LACNIC, ListURL: urls.LACNIC},
		{Name: opconst.RIPE, ListURL: urls.RIPE},
	}
	if len(only) == 0 {
		return all, nil
	}
	valid := rdnsRegistryNames()
	var out []rdns.Source
	for _, name := range only {
		name = strings.ToUpper(strings.TrimSpace(name))
		if !slices.Contains(valid, name) {
			return nil, fmt.Errorf("unknown registry name: %s. Valid names: %s", name, strings.Join(valid, ", "))
		}
		for _, src := range all {
			if src.Name == name {
				out = append(out, src)
				break
			}
		}
	}
	return out, nil
}

func rdnsSourceSelected(sources []rdns.Source, name string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, src := range sources {
		if src.Name == name {
			return true
		}
	}
	return false
}

func rdnsWhoisDumpsFromCLI(c *cli.Context, sources []rdns.Source) []rdns.WhoisDump {
	return rdnsWhoisDumps(c.String("ripe-domain-url"), c.String("apnic-domain-url"), c.String("afrinic-db-url"),
		c.StringSlice("only-registries"), sources)
}

// rdnsWhoisDumps is shared by `rdns ingest` and the daemon's rdns.ingest
// job: the reverse domain: dumps, limited to the selected sources when
// only is set.
func rdnsWhoisDumps(ripeDomainURL, apnicDomainURL, afrinicDBURL string, only []string, sources []rdns.Source) []rdns.WhoisDump {
	all := []rdns.WhoisDump{
		{Name: opconst.RIPE, URL: ripeDomainURL, Kind: rdns.WhoisDumpDomain},
		{Name: opconst.APNIC, URL: apnicDomainURL, Kind: rdns.WhoisDumpDomain},
		{Name: opconst.AFRINIC, URL: afrinicDBURL, Kind: rdns.WhoisDumpMixedDomain},
	}
	if len(only) == 0 {
		return all
	}
	var out []rdns.WhoisDump
	for _, dump := range all {
		if rdnsSourceSelected(sources, dump.Name) {
			out = append(out, dump)
		}
	}
	return out
}

func runRDNSStatus(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), c.String("postgres-db"))
	if err != nil {
		return err
	}
	defer st.Close()

	snap, err := st.FetchRDNSStatus(c.Context, postgres.RDNSStatusOptions{
		Now:        time.Now().UTC(),
		StaleAfter: c.Duration("stale-after"),
	})
	if err != nil {
		return err
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	_, err = io.WriteString(os.Stdout, formatRDNSStatus(snap, stdoutColorEnabled()))
	return err
}

func runRDNSCrawlPTR(c *cli.Context) error {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return err
	}
	logger = logger.Named("opr.rdns.crawl-ptr")

	only, err := rdnsOnlyRegistriesFromCLI(c)
	if err != nil {
		return err
	}

	dsn := c.String("postgres-db")
	if err := postgres.RunMigrations(logger.Named("store"), dsn); err != nil {
		return err
	}
	st, err := postgres.New(logger.Named("store"), dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	cr := rdns.NewPTRCrawler(logger, st)
	cr.Prefix = c.String("prefix")
	cr.Zone = c.String("zone")
	cr.Limit = c.Int("limit")
	cr.OnlyRegistries = only
	cr.QPS = c.Float64("qps")
	cr.Timeout = c.Duration("timeout")
	cr.LockedBy = fmt.Sprintf("crawl-ptr-%d", os.Getpid())
	cr.IMeanIt = c.Bool("i-mean-it")
	cr.MaxAddresses = c.Int("max-addresses")
	cr.Truncate = cr.IMeanIt && cr.MaxAddresses > 0
	if err := cr.Crawl(c.Context); err != nil {
		logger.Error("rdns crawl-ptr finished with errors", zap.Error(err))
		return err
	}
	return nil
}

func rdnsOnlyRegistriesFromCLI(c *cli.Context) ([]string, error) {
	return rdnsOnlyRegistries(c.StringSlice("only-registries"))
}

// rdnsOnlyRegistries upper-cases and validates an --only-registries list.
// Empty returns nil (no filter).
func rdnsOnlyRegistries(only []string) ([]string, error) {
	if len(only) == 0 {
		return nil, nil
	}
	valid := rdnsRegistryNames()
	out := make([]string, 0, len(only))
	for _, name := range only {
		name = strings.ToUpper(strings.TrimSpace(name))
		if !slices.Contains(valid, name) {
			return nil, fmt.Errorf("unknown registry name: %s. Valid names: %s", name, strings.Join(valid, ", "))
		}
		out = append(out, name)
	}
	return out, nil
}

func formatRDNSStatus(s postgres.RDNSStatusSnapshot, color bool) string {
	st := termStyle{color: color}
	var b strings.Builder

	when := s.GeneratedAt.UTC().Format(tsLayout) + " UTC"
	fmt.Fprintf(&b, "%s   %s\n", st.bold("RDNS"), st.dim(when))
	b.WriteByte('\n')
	writeRDNSSources(&b, st, s)
	b.WriteByte('\n')
	writeRDNSIANA(&b, st, s)
	b.WriteByte('\n')
	writeRDNSWhois(&b, st, s)
	b.WriteByte('\n')
	writeRDNSPTR(&b, st, s)
	b.WriteByte('\n')
	writeRDNSDumps(&b, st, s)
	return b.String()
}

func writeRDNSSources(b *strings.Builder, st termStyle, s postgres.RDNSStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("SOURCES"))
	if len(s.Sources) == 0 {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	headers := []string{"", "rows", "last fetch", "last modified", ""}
	right := []bool{false, true, false, false, false}
	rows := make([][]string, 0, len(s.Sources))
	for _, src := range s.Sources {
		fetch := "NEVER"
		if !src.Never && src.LastFetchedAt != nil && !src.LastFetchedAt.IsZero() {
			fetch = src.LastFetchedAt.UTC().Format(tsLayout)
		}
		mod := ""
		if src.LastChangedAt != nil && !src.LastChangedAt.IsZero() {
			mod = src.LastChangedAt.UTC().Format(tsLayout)
		}
		note := ""
		if src.Never {
			note = "NEVER"
		} else if src.Stale {
			note = "STALE"
		}
		rows = append(rows, []string{src.Source, formatInt(src.Rows), fetch, mod, note})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeRDNSIANA(b *strings.Builder, st termStyle, s postgres.RDNSStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("IANA"))
	if s.IANA.Expected == 0 {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	headers := []string{"", "count"}
	right := []bool{false, true}
	rows := [][]string{
		{"expected", formatInt(int64(s.IANA.Expected))},
		{"fetched", formatInt(int64(s.IANA.Fetched))},
		{"missing", formatInt(int64(s.IANA.Missing))},
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
	for _, gap := range s.IANA.Gaps {
		fmt.Fprintf(b, "  %s\n", gap)
	}
}

func writeRDNSWhois(b *strings.Builder, st termStyle, s postgres.RDNSStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("WHOIS"))
	headers := []string{"", "count"}
	right := []bool{false, true}
	rows := [][]string{
		{"eligible", formatInt(s.WhoisEligible)},
		{"enriched", formatInt(s.WhoisEnriched)},
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func writeRDNSPTR(b *strings.Builder, st termStyle, s postgres.RDNSStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("PTR"))
	p := s.PTR
	rcodes := p.Rcodes
	if len(rcodes) == 0 {
		rcodes = postgres.EvaluateRDNSPTRStatus(p.Rows, p.WithPTR, p.LastFetchedAt, nil, 0, time.Time{}).Rcodes
	}

	headers := []string{"", "count"}
	right := []bool{false, true}
	rows := [][]string{
		{"rows", formatInt(p.Rows)},
		{"with ptr", formatInt(p.WithPTR)},
		{"empty", formatInt(p.Empty)},
	}
	for _, rc := range rcodes {
		rows = append(rows, []string{rc.Rcode, formatInt(rc.Rows)})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))

	never := p.Never || p.Rows == 0
	fetch := "NEVER"
	if !never && p.LastFetchedAt != nil && !p.LastFetchedAt.IsZero() {
		fetch = p.LastFetchedAt.UTC().Format(tsLayout)
	}
	note := ""
	if never {
		note = "NEVER"
	} else if p.Stale {
		note = "STALE"
	}
	clockHeaders := []string{"", "last fetch", ""}
	clockRight := []bool{false, false, false}
	clockRows := [][]string{{"fetched_at", fetch, note}}
	b.WriteString(formatAlignedTable(clockHeaders, clockRows, clockRight, st))
}

func writeRDNSDumps(b *strings.Builder, st termStyle, s postgres.RDNSStatusSnapshot) {
	fmt.Fprintf(b, "%s\n", st.bold("DUMPS"))
	if len(s.Dumps) == 0 {
		fmt.Fprintf(b, "%s  %s\n", padRight("", labelWidth), padRight("NEVER", tsWidth))
		return
	}
	headers := []string{"", "last seen", "etag", ""}
	right := []bool{false, false, false, false}
	rows := make([][]string, 0, len(s.Dumps))
	for _, d := range s.Dumps {
		seen := "NEVER"
		if d.LastSeen != nil && !d.LastSeen.IsZero() {
			seen = d.LastSeen.UTC().Format(tsLayout)
		} else if d.Never {
			seen = "NEVER"
		}
		note := ""
		if !d.Never && seen != "NEVER" && d.Stale {
			note = "STALE"
		}
		etag := "no"
		if d.ETagPresent {
			etag = "yes"
		}
		rows = append(rows, []string{rdnsDumpLabel(d.URL), seen, etag, note})
	}
	b.WriteString(formatAlignedTable(headers, rows, right, st))
}

func rdnsDumpLabel(url string) string {
	if url == "" {
		return ""
	}
	if base := path.Base(url); base != "" && base != "." && base != "/" {
		return base
	}
	return url
}
