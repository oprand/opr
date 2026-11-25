package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oprand/opr/aggregator/fdns"
	"github.com/oprand/opr/internal/opconfig"
	"github.com/oprand/opr/store/clickhouse"

	"github.com/urfave/cli/v2"
)

func TestCLIDoesNotRegisterRemovedCommands(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	removed := []string{"nro", "rdap-registry", "rdap", "whois-db", "wdb", "prefix", "p"}
	for _, name := range removed {
		if cmd := findCommand(app.Commands, name); cmd != nil {
			t.Errorf("command %q should not be registered (found as %q)", name, cmd.Name)
		}
	}
}

func TestCLIRegistersGeoIPSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	geo := findCommand(app.Commands, "geoip")
	if geo == nil {
		t.Fatal("geoip must be registered")
	}
	if geo.Action != nil {
		t.Fatal("bare opr geoip must print help, not fetch")
	}
	for _, sub := range []string{"crawl-geofeeds", "prune", "lacnic", "ipmap", "anycast", "status"} {
		if findCommand(geo.Subcommands, sub) == nil {
			t.Errorf("geoip %s must be registered", sub)
		}
	}

	status := findCommand(geo.Subcommands, "status")
	if status == nil {
		t.Fatal("geoip status must be registered")
	}
	statusFlags := flagNameSet(status.Flags)
	for _, want := range []string{"json", "stale-after"} {
		if !statusFlags[want] {
			t.Errorf("status missing flag %q", want)
		}
	}

	crawl := findCommand(geo.Subcommands, "crawl-geofeeds")
	if crawl == nil {
		t.Fatal("geoip crawl-geofeeds must be registered")
	}
	crawlFlags := flagNameSet(crawl.Flags)
	for _, want := range []string{"worker-count", "refresh-older-than", "once", "force"} {
		if !crawlFlags[want] {
			t.Errorf("crawl-geofeeds missing flag %q", want)
		}
	}
	if crawlFlags["force-request"] {
		t.Error("crawl-geofeeds must use --force, not --force-request")
	}

	ipmap := findCommand(geo.Subcommands, "ipmap")
	if ipmap == nil {
		t.Fatal("geoip ipmap must be registered")
	}
	ipmapFlags := flagNameSet(ipmap.Flags)
	for _, want := range []string{"force", "url"} {
		if !ipmapFlags[want] {
			t.Errorf("ipmap missing flag %q", want)
		}
	}

	anycast := findCommand(geo.Subcommands, "anycast")
	if anycast == nil {
		t.Fatal("geoip anycast must be registered")
	}
	anycastFlags := flagNameSet(anycast.Flags)
	if !anycastFlags["force"] {
		t.Error("anycast missing flag \"force\"")
	}
	if anycast.Usage == "" {
		t.Fatal("anycast must have Usage")
	}

	prune := findCommand(geo.Subcommands, "prune")
	if prune == nil {
		t.Fatal("geoip prune must be registered")
	}
	pruneFlags := flagNameSet(prune.Flags)
	for _, want := range []string{"dry-run", "source"} {
		if !pruneFlags[want] {
			t.Errorf("prune missing flag %q", want)
		}
	}

	blob := strings.ToLower(geo.Usage + " " + geo.Description)
	for _, phrase := range []string{"geofeeds catalog", "not rdap", "crawl_target", "lacnic", "ipmap", "anycast"} {
		if !strings.Contains(blob, phrase) {
			t.Errorf("geoip help missing %q", phrase)
		}
	}
	if crawl.Usage == "" || prune.Usage == "" {
		t.Fatal("subcommands must have Usage")
	}
}

func TestCLIRegistersGeoNamesSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	gn := findCommand(app.Commands, "geonames")
	if gn == nil {
		t.Fatal("geonames must be registered")
	}
	if findCommand(app.Commands, "gn") == nil {
		t.Fatal("geonames alias gn must be registered")
	}
	if gn.Action == nil {
		t.Fatal("bare opr geonames must still ingest (RunOnce)")
	}
	status := findCommand(gn.Subcommands, "status")
	if status == nil {
		t.Fatal("geonames status must be registered")
	}
	statusFlags := flagNameSet(status.Flags)
	for _, want := range []string{"json", "stale-after"} {
		if !statusFlags[want] {
			t.Errorf("status missing flag %q", want)
		}
	}
	if status.Usage == "" {
		t.Fatal("geonames status must have Usage")
	}
}

func TestGeoNamesUnknownSubcommandDoesNotIngest(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	set := flag.NewFlagSet("geonames", flag.ContinueOnError)
	if err := set.Parse([]string{"stat"}); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(app, set, nil)
	if err := rejectUnknownGeoNamesSubcommand(c); err == nil {
		t.Fatal("expected unknown subcommand error")
	} else if !strings.Contains(err.Error(), `unknown geonames subcommand "stat"`) {
		t.Fatalf("guard: %v", err)
	}

	empty := flag.NewFlagSet("geonames", flag.ContinueOnError)
	if err := rejectUnknownGeoNamesSubcommand(cli.NewContext(app, empty, nil)); err != nil {
		t.Fatalf("bare geonames must still ingest: %v", err)
	}

	gn := findCommand(app.Commands, "geonames")
	if gn == nil || gn.Action == nil {
		t.Fatal("geonames Action required")
	}
	err := gn.Action(c)
	if err == nil {
		t.Fatal("Action must error on unknown subcommand and not ingest")
	}
	if !strings.Contains(err.Error(), `unknown geonames subcommand "stat"`) {
		t.Fatalf("Action must return the guard, not ingest: %v", err)
	}
}

func TestCLIRegistersPeeringDBSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	pdb := findCommand(app.Commands, "peeringdb")
	if pdb == nil {
		t.Fatal("peeringdb must be registered")
	}
	if findCommand(app.Commands, "pdb") == nil {
		t.Fatal("peeringdb alias pdb must be registered")
	}
	if pdb.Action == nil {
		t.Fatal("bare opr peeringdb must still ingest (DoPeeringDbSync)")
	}
	pdbFlags := flagNameSet(pdb.Flags)
	for _, want := range []string{"apikey", "force"} {
		if !pdbFlags[want] {
			t.Errorf("peeringdb missing flag %q", want)
		}
	}
	status := findCommand(pdb.Subcommands, "status")
	if status == nil {
		t.Fatal("peeringdb status must be registered")
	}
	statusFlags := flagNameSet(status.Flags)
	for _, want := range []string{"json", "stale-after"} {
		if !statusFlags[want] {
			t.Errorf("status missing flag %q", want)
		}
	}
	if statusFlags["force"] {
		t.Error("peeringdb status must not register --force")
	}
	if status.Usage == "" {
		t.Fatal("peeringdb status must have Usage")
	}
}

func TestPeeringDBUnknownSubcommandDoesNotIngest(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	set := flag.NewFlagSet("peeringdb", flag.ContinueOnError)
	if err := set.Parse([]string{"stat"}); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(app, set, nil)
	if err := rejectUnknownPeeringDBSubcommand(c); err == nil {
		t.Fatal("expected unknown subcommand error")
	} else if !strings.Contains(err.Error(), `unknown peeringdb subcommand "stat"`) {
		t.Fatalf("guard: %v", err)
	}

	empty := flag.NewFlagSet("peeringdb", flag.ContinueOnError)
	if err := rejectUnknownPeeringDBSubcommand(cli.NewContext(app, empty, nil)); err != nil {
		t.Fatalf("bare peeringdb must still ingest: %v", err)
	}

	pdb := findCommand(app.Commands, "peeringdb")
	if pdb == nil || pdb.Action == nil {
		t.Fatal("peeringdb Action required")
	}
	err := pdb.Action(c)
	if err == nil {
		t.Fatal("Action must error on unknown subcommand and not ingest")
	}
	if !strings.Contains(err.Error(), `unknown peeringdb subcommand "stat"`) {
		t.Fatalf("Action must return the guard, not ingest: %v", err)
	}
}

func TestCLIRegistersRPKISurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	rpki := findCommand(app.Commands, "rpki")
	if rpki == nil {
		t.Fatal("rpki must be registered")
	}
	if rpki.Action != nil {
		t.Fatal("bare opr rpki must print help, not ingest")
	}
	ingest := findCommand(rpki.Subcommands, "ingest")
	if ingest == nil {
		t.Fatal("rpki ingest must be registered")
	}
	flags := flagNameSet(ingest.Flags)
	for _, want := range []string{"routinator-addr", "routinator-fallback-addr"} {
		if !flags[want] {
			t.Errorf("rpki ingest missing flag %q", want)
		}
	}
	if ingest.Usage == "" {
		t.Fatal("rpki ingest must have Usage")
	}
}

func TestCLIRegistersRDNSSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	rdns := findCommand(app.Commands, "rdns")
	if rdns == nil {
		t.Fatal("rdns must be registered")
	}
	if rdns.Action != nil {
		t.Fatal("bare opr rdns must print help, not ingest")
	}
	ingest := findCommand(rdns.Subcommands, "ingest")
	if ingest == nil {
		t.Fatal("rdns ingest must be registered")
	}
	flags := flagNameSet(ingest.Flags)
	for _, want := range []string{
		"force", "only-registries",
		"ripe-url", "apnic-url", "arin-url", "afrinic-url", "lacnic-url",
		"skip-iana", "iana-inaddr-url", "iana-ip6-url",
		"skip-whois", "ripe-domain-url", "apnic-domain-url", "afrinic-db-url",
		"skip-lacnic-whois", "lacnic-db-url",
	} {
		if !flags[want] {
			t.Errorf("rdns ingest missing flag %q", want)
		}
	}
	if ingest.Usage == "" {
		t.Fatal("rdns ingest must have Usage")
	}

	status := findCommand(rdns.Subcommands, "status")
	if status == nil {
		t.Fatal("rdns status must be registered")
	}
	statusFlags := flagNameSet(status.Flags)
	for _, want := range []string{"json", "stale-after"} {
		if !statusFlags[want] {
			t.Errorf("rdns status missing flag %q", want)
		}
	}
	if status.Usage == "" {
		t.Fatal("rdns status must have Usage")
	}

	crawl := findCommand(rdns.Subcommands, "crawl-ptr")
	if crawl == nil {
		t.Fatal("rdns crawl-ptr must be registered")
	}
	crawlFlags := flagNameSet(crawl.Flags)
	for _, want := range []string{
		"prefix", "zone", "limit", "only-registries",
		"qps", "timeout", "i-mean-it", "max-addresses",
	} {
		if !crawlFlags[want] {
			t.Errorf("rdns crawl-ptr missing flag %q", want)
		}
	}
	if crawl.Action == nil {
		t.Fatal("crawl-ptr must have Action")
	}

	blob := strings.ToLower(rdns.Usage + " " + rdns.Description)
	if strings.Contains(blob, "not wired") || strings.Contains(blob, "not in opr run") {
		t.Error("rdns help must not say it is not wired into run; ingest and crawl-ptr are daemon jobs")
	}
}

func TestCLIRegistersFDNSSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	fdns := findCommand(app.Commands, "fdns")
	if fdns == nil {
		t.Fatal("fdns must be registered")
	}
	if fdns.Action != nil {
		t.Fatal("bare opr fdns must print help, not ingest")
	}
	ingest := findCommand(fdns.Subcommands, "ingest-lists")
	if ingest == nil {
		t.Fatal("fdns ingest-lists must be registered")
	}
	flags := flagNameSet(ingest.Flags)
	for _, want := range []string{"force", "only", "tranco-url", "umbrella-url", "crux-url"} {
		if !flags[want] {
			t.Errorf("fdns ingest-lists missing flag %q", want)
		}
	}
	if ingest.Usage == "" {
		t.Fatal("fdns ingest-lists must have Usage")
	}
	if ingest.Action == nil {
		t.Fatal("ingest-lists must have Action")
	}

	resolve := findCommand(fdns.Subcommands, "resolve")
	if resolve == nil {
		t.Fatal("fdns resolve must be registered")
	}
	if resolve.Usage == "" || resolve.Action == nil {
		t.Fatal("fdns resolve must have Usage and Action")
	}
	if strings.Contains(strings.ToLower(resolve.Usage), "not implemented") {
		t.Fatal("fdns resolve must not say not implemented")
	}
	resolveFlags := flagNameSet(resolve.Flags)
	for _, want := range []string{"qps", "resolver", "af", "limit", "stale-after", "timeout", "lease", "batch", "worker-id"} {
		if !resolveFlags[want] {
			t.Errorf("fdns resolve missing flag %q", want)
		}
	}
	if !isStringSliceFlag(resolve.Flags, "resolver") {
		t.Fatal("fdns resolve --resolver must be a string slice (repeatable / comma-separated)")
	}
	help := strings.ToLower(resolve.Usage + " " + resolve.Description)
	for _, phrase := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "74.82.42.42", "rate-limit", "127.0.0.1", "per resolver", "repeatable"} {
		if !strings.Contains(help, phrase) {
			t.Errorf("fdns resolve help missing %q", phrase)
		}
	}
	for _, f := range resolve.Flags {
		df, ok := f.(*cli.DurationFlag)
		if !ok || df.Name != "stale-after" {
			continue
		}
		u := strings.ToLower(df.Usage)
		if strings.Contains(u, "re-query") {
			t.Error("resolve --stale-after must not claim it re-queries resolved_at")
		}
		if !strings.Contains(u, "unused") && !strings.Contains(help, "unused") {
			t.Error("resolve --stale-after must say it is unused at claim time")
		}
	}

	cc := findCommand(fdns.Subcommands, "ingest-cc")
	if cc == nil {
		t.Fatal("fdns ingest-cc must be registered")
	}
	if cc.Usage == "" || cc.Action == nil {
		t.Fatal("fdns ingest-cc must have Usage and Action")
	}
	if strings.Contains(strings.ToLower(cc.Usage), "not implemented") {
		t.Fatal("fdns ingest-cc must not say not implemented")
	}
	ccFlags := flagNameSet(cc.Flags)
	for _, want := range []string{
		"crawl", "parquet-dir",
		"force", "skip-download", "keep-parquet",
		"clickhouse-url", "clickhouse-db", "clickhouse-user", "clickhouse-password", "clickhouse-timeout",
	} {
		if !ccFlags[want] {
			t.Errorf("fdns ingest-cc missing flag %q", want)
		}
	}
	for _, retired := range []string{"duckdb-bin", "duckdb-memory", "duckdb-threads", "copy-batch"} {
		if ccFlags[retired] {
			t.Errorf("fdns ingest-cc must not register retired flag %q", retired)
		}
	}
	ccHelp := strings.ToLower(cc.Usage + " " + cc.Description + " " + fdns.Usage + " " + fdns.Description)
	for _, phrase := range []string{
		"host index", "parquet",
		"clickhouse", "fdns_cc_host", "exchange tables", "opr clickhouse migrate",
	} {
		if !strings.Contains(ccHelp, phrase) {
			t.Errorf("fdns ingest-cc help missing %q", phrase)
		}
	}
	for _, banned := range []string{"warc_ip", "subset=warc", "200 gib", "cc-index-table", "duckdb", "copy-batch"} {
		if strings.Contains(ccHelp, banned) {
			t.Errorf("fdns ingest-cc help must not mention %q", banned)
		}
	}

	seed := findCommand(fdns.Subcommands, "seed-queue")
	if seed == nil {
		t.Fatal("fdns seed-queue must be registered")
	}
	if seed.Usage == "" || seed.Action == nil {
		t.Fatal("fdns seed-queue must have Usage and Action")
	}
	if strings.Contains(strings.ToLower(seed.Usage), "not implemented") {
		t.Fatal("fdns seed-queue must not say not implemented")
	}
	seedFlags := flagNameSet(seed.Flags)
	for _, want := range []string{
		"min-fetch-200", "min-hcrank10", "min-prank10", "tld", "crawl",
		"limit", "order", "queue-high-water", "dry-run", "stale-after",
		"clickhouse-url", "clickhouse-db", "clickhouse-user", "clickhouse-password", "clickhouse-timeout",
	} {
		if !seedFlags[want] {
			t.Errorf("fdns seed-queue missing flag %q", want)
		}
	}
	if !isStringSliceFlag(seed.Flags, "tld") {
		t.Fatal("fdns seed-queue --tld must be a string slice (repeatable)")
	}
	seedHelp := strings.ToLower(seed.Usage + " " + seed.Description + " " + fdns.Usage + " " + fdns.Description)
	for _, phrase := range []string{
		"clickhouse", "fdns_resolve_queue", "normalizehostname", "opr clickhouse migrate",
		"fdns:cc-seed-cursor", "high-water", "approximate",
	} {
		if !strings.Contains(seedHelp, phrase) {
			t.Errorf("fdns seed-queue help missing %q", phrase)
		}
	}

	status := findCommand(fdns.Subcommands, "status")
	if status == nil {
		t.Fatal("fdns status must be registered")
	}
	if status.Usage == "" {
		t.Error("fdns status must have Usage")
	}
	if status.Action == nil {
		t.Error("fdns status must have Action (stub is ok)")
	}
	statusFlags := flagNameSet(status.Flags)
	for _, want := range []string{"json", "stale-after"} {
		if !statusFlags[want] {
			t.Errorf("fdns status missing flag %q", want)
		}
	}

	blob := strings.ToLower(fdns.Usage + " " + fdns.Description)
	if strings.Contains(blob, "not wired") || strings.Contains(blob, "not in opr run") {
		t.Error("fdns help must not say it is not wired into run; every subcommand but status is a daemon job")
	}
}

func TestCLIRegistersClickHouseSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	ch := findCommand(app.Commands, "clickhouse")
	if ch == nil {
		t.Fatal("clickhouse must be registered")
	}
	if ch.Action != nil {
		t.Fatal("bare opr clickhouse must print help, not migrate")
	}

	migrate := findCommand(ch.Subcommands, "migrate")
	if migrate == nil {
		t.Fatal("clickhouse migrate must be registered")
	}
	if migrate.Usage == "" || migrate.Action == nil {
		t.Fatal("clickhouse migrate must have Usage and Action")
	}
	migrateFlags := flagNameSet(migrate.Flags)
	for _, want := range []string{
		"clickhouse-url", "clickhouse-db", "clickhouse-user", "clickhouse-password",
		"clickhouse-timeout", "dry-run",
	} {
		if !migrateFlags[want] {
			t.Errorf("clickhouse migrate missing flag %q", want)
		}
	}

	version := findCommand(ch.Subcommands, "version")
	if version == nil {
		t.Fatal("clickhouse version must be registered")
	}
	if version.Usage == "" || version.Action == nil {
		t.Fatal("clickhouse version must have Usage and Action")
	}
	if flagNameSet(version.Flags)["dry-run"] {
		t.Error("clickhouse version must not register --dry-run")
	}

	if ch.Category != commandCategoryManagement {
		t.Errorf("clickhouse category=%q, want %q", ch.Category, commandCategoryManagement)
	}
	blob := strings.ToLower(ch.Usage + " " + ch.Description)
	for _, phrase := range []string{"management", "schema", "explicit", "fdns_cc_host", "ingest-cc", "seed-queue"} {
		if !strings.Contains(blob, phrase) {
			t.Errorf("clickhouse help missing %q", phrase)
		}
	}
}

func TestCLIRegistersPostgresSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	pg := findCommand(app.Commands, "postgres")
	if pg == nil {
		t.Fatal("postgres must be registered")
	}
	if pg.Action != nil {
		t.Fatal("bare opr postgres must print help, not migrate")
	}
	if pg.Category != commandCategoryManagement {
		t.Errorf("postgres category=%q, want %q", pg.Category, commandCategoryManagement)
	}
	if len(pg.Aliases) != 0 {
		t.Fatalf("postgres aliases=%v, want none", pg.Aliases)
	}

	migrate := findCommand(pg.Subcommands, "migrate")
	if migrate == nil {
		t.Fatal("postgres migrate must be registered")
	}
	if migrate.Usage == "" || migrate.Action == nil {
		t.Fatal("postgres migrate must have Usage and Action")
	}

	version := findCommand(pg.Subcommands, "version")
	if version == nil {
		t.Fatal("postgres version must be registered")
	}
	if version.Usage == "" || version.Action == nil {
		t.Fatal("postgres version must have Usage and Action")
	}

	blob := strings.ToLower(pg.Usage + " " + pg.Description)
	for _, phrase := range []string{"management", "schema", "opr_migrations", "does not ingest"} {
		if !strings.Contains(blob, phrase) {
			t.Errorf("postgres help missing %q", phrase)
		}
	}

	for _, name := range []string{
		"run", "registry-crawl", "fdns", "rdns", "geoip", "geonames", "peeringdb", "rpki", "aspop",
	} {
		cmd := findCommand(app.Commands, name)
		if cmd == nil {
			t.Errorf("command %q must be registered", name)
			continue
		}
		if cmd.Category == commandCategoryManagement {
			t.Errorf("%s must not be a management command", name)
		}
		if cmd.Category != commandCategoryData {
			t.Errorf("%s category=%q, want %q", name, cmd.Category, commandCategoryData)
		}
	}
}

func TestPostgresCommandsRequireDSN(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard

	if err := app.Run([]string{"opr", "help"}); err != nil {
		t.Fatal(err)
	}
	if err := app.Run([]string{"opr", "postgres", "--help"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"postgres", "version"},
		{"postgres", "migrate"},
	} {
		got, err := postgresDSNFromBefore(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got != opconfig.DefaultDSN {
			t.Fatalf("%v dsn=%q, want default %q", args, got, opconfig.DefaultDSN)
		}
	}
}

func TestCLIHelpUsageShowsGlobalOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"opr", "--help"}, "opr [global options] command [command options]"},
		{[]string{"opr", "geoip", "--help"}, "opr [global options] geoip [subcommand] [options]"},
		{[]string{"opr", "geoip", "ipmap", "--help"}, "opr [global options] geoip ipmap [options]"},
		{[]string{"opr", "fdns", "--help"}, "opr [global options] fdns [subcommand] [options]"},
		{[]string{"opr", "fdns", "resolve", "--help"}, "opr [global options] fdns resolve [options]"},
		{[]string{"opr", "registry-crawl", "--help"}, "opr [global options] registry-crawl [subcommand] [options]"},
		{[]string{"opr", "postgres", "--help"}, "opr [global options] postgres [subcommand] [options]"},
		{[]string{"opr", "run", "--help"}, "opr [global options] run [options]"},
	}
	for _, tc := range cases {
		app := newCLIApp()
		var buf strings.Builder
		app.Writer = &buf
		app.ErrWriter = io.Discard
		if err := app.Run(tc.args); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		out := buf.String()
		if !strings.Contains(out, tc.want) {
			t.Errorf("%v USAGE missing %q:\n%s", tc.args, tc.want, out)
		}
	}

	helpCmd := findCommand(newCLIApp().Commands, "help")
	if helpCmd == nil {
		t.Fatal("help must be registered")
	}
	if helpCmd.UsageText != "opr [global options] help [command]" {
		t.Errorf("help UsageText=%q", helpCmd.UsageText)
	}

	// Parent Description must not re-list subcommand blurbs already under SUBCOMMANDS.
	app := newCLIApp()
	var buf strings.Builder
	app.Writer = &buf
	app.ErrWriter = io.Discard
	if err := app.Run([]string{"opr", "geoip", "--help"}); err != nil {
		t.Fatal(err)
	}
	geoHelp := buf.String()
	if strings.Contains(geoHelp, "Subcommands:") {
		t.Fatalf("geoip parent help must not duplicate a Subcommands: list:\n%s", geoHelp)
	}
	descAt := strings.Index(geoHelp, "DESCRIPTION:")
	subsAt := strings.Index(geoHelp, "SUBCOMMANDS:")
	if descAt < 0 || subsAt < 0 || descAt > subsAt {
		t.Fatalf("geoip help missing DESCRIPTION/SUBCOMMANDS:\n%s", geoHelp)
	}
	desc := geoHelp[descAt:subsAt]
	for _, phrase := range []string{
		"One HTTP GET per unique catalog URL",
		"Deletes geoip rows whose source_url",
		"bgptools anycatch v4/v6",
	} {
		if strings.Contains(desc, phrase) {
			t.Errorf("geoip DESCRIPTION repeats subcommand Usage %q", phrase)
		}
	}
}

func TestCLIHelpGroupsManagementCommands(t *testing.T) {
	t.Parallel()

	helpCmd := findCommand(newCLIApp().Commands, "help")
	if helpCmd == nil {
		t.Fatal("help must be registered")
	}
	if helpCmd.Category != commandCategoryManagement {
		t.Errorf("help category=%q, want %q", helpCmd.Category, commandCategoryManagement)
	}

	for _, args := range [][]string{
		{"opr"},
		{"opr", "help"},
		{"opr", "--help"},
	} {
		app := newCLIApp()
		var buf strings.Builder
		app.Writer = &buf
		app.ErrWriter = io.Discard
		if err := app.Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		out := buf.String()
		dataAt := strings.Index(out, "DATA:")
		mgmtAt := strings.Index(out, "MANAGEMENT:")
		globalAt := strings.Index(out, "GLOBAL OPTIONS:")
		if dataAt < 0 || mgmtAt < 0 || globalAt < 0 || dataAt > mgmtAt || mgmtAt > globalAt {
			t.Fatalf("%v help headings missing or out of order:\n%s", args, out)
		}
		data := out[dataAt:mgmtAt]
		mgmt := out[mgmtAt:globalAt]
		// Category lines are "     <name>" (urfave's named-category template).
		// Match that indent so a usage mention of fdns_cc_host is not a command.
		listed := func(section, name string) bool {
			return strings.Contains(section, "\n     "+name)
		}
		for _, name := range []string{"clickhouse", "postgres", "help"} {
			if !listed(mgmt, name) {
				t.Errorf("%v MANAGEMENT section missing %s:\n%s", args, name, mgmt)
			}
			if listed(data, name) {
				t.Errorf("%v %s listed under DATA:\n%s", args, name, data)
			}
		}
		for _, name := range []string{"run", "registry-crawl", "fdns", "rdns", "geoip", "geonames", "peeringdb", "rpki", "aspop"} {
			if !listed(data, name) {
				t.Errorf("%v DATA section missing %s:\n%s", args, name, data)
			}
			if listed(mgmt, name) {
				t.Errorf("%v %s listed under MANAGEMENT:\n%s", args, name, mgmt)
			}
		}
	}

	app := newCLIApp()
	var buf strings.Builder
	app.Writer = &buf
	app.ErrWriter = io.Discard
	if err := app.Run([]string{"opr", "postgres", "--help"}); err != nil {
		t.Fatal(err)
	}
	pgHelp := buf.String()
	for _, phrase := range []string{"CATEGORY:\n   MANAGEMENT", "migrate", "version", "schema"} {
		if !strings.Contains(pgHelp, phrase) {
			t.Errorf("postgres --help missing %q:\n%s", phrase, pgHelp)
		}
	}
}

func TestClickHouseFlagDefaults(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	ch := findCommand(app.Commands, "clickhouse")
	if ch == nil {
		t.Fatal("clickhouse must be registered")
	}
	migrate := findCommand(ch.Subcommands, "migrate")
	if migrate == nil {
		t.Fatal("clickhouse migrate must be registered")
	}
	set := flag.NewFlagSet("migrate", flag.ContinueOnError)
	for _, f := range migrate.Flags {
		if err := f.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(nil); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(app, set, nil)
	if got := c.String("clickhouse-url"); got != clickhouse.DefaultURL {
		t.Errorf("clickhouse-url default=%q, want %q", got, clickhouse.DefaultURL)
	}
	if got := c.String("clickhouse-db"); got != clickhouse.DefaultDatabase {
		t.Errorf("clickhouse-db default=%q, want %q", got, clickhouse.DefaultDatabase)
	}
	if got := c.Duration("clickhouse-timeout"); got != clickhouse.DefaultTimeout {
		t.Errorf("clickhouse-timeout default=%s, want %s", got, clickhouse.DefaultTimeout)
	}
	client := clickhouseClientFromCLI(c)
	if client.URL != clickhouse.DefaultURL || client.Database != clickhouse.DefaultDatabase {
		t.Fatalf("client=%+v", client)
	}
}

func TestClickHouseCommandsDoNotRequireDSN(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard

	if err := app.Run([]string{"opr", "clickhouse", "migrate", "--help"}); err != nil {
		t.Fatal(err)
	}
	if err := app.Run([]string{"opr", "fdns", "ingest-cc", "--help"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"clickhouse", "migrate"},
		{"fdns", "ingest-cc"},
	} {
		got, err := postgresDSNFromBefore(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got != "" {
			t.Fatalf("%v dsn=%q, want empty when flag and env are unset", args, got)
		}
	}
	for _, args := range [][]string{
		{"fdns", "ingest-lists"},
		{"fdns", "seed-queue"},
	} {
		got, err := postgresDSNFromBefore(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got != opconfig.DefaultDSN {
			t.Fatalf("%v dsn=%q, want default %q", args, got, opconfig.DefaultDSN)
		}
	}
}

func TestFDNSResolveResolverFlagEmptyUsesDefaults(t *testing.T) {
	t.Parallel()
	c := fdnsResolveFlagContext(t)
	addrs, err := fdns.ParseResolverAddrs(c.StringSlice("resolver"))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 5 {
		t.Fatalf("omitted --resolver → %d addrs, want 5 defaults", len(addrs))
	}
	if addrs[0] != "1.1.1.1:53" || addrs[4] != "74.82.42.42:53" {
		t.Fatalf("defaults=%v", addrs)
	}
}

func TestFDNSResolveResolverFlagReplacesDefaults(t *testing.T) {
	t.Parallel()
	c := fdnsResolveFlagContext(t, "--resolver", "127.0.0.1", "--resolver", "9.9.9.9")
	addrs, err := fdns.ParseResolverAddrs(c.StringSlice("resolver"))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0] != "127.0.0.1:53" || addrs[1] != "9.9.9.9:53" {
		t.Fatalf("explicit --resolver=%v (must replace defaults)", addrs)
	}
	c = fdnsResolveFlagContext(t, "--resolver", "8.8.8.8,1.1.1.1")
	addrs, err = fdns.ParseResolverAddrs(c.StringSlice("resolver"))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0] != "8.8.8.8:53" || addrs[1] != "1.1.1.1:53" {
		t.Fatalf("comma-separated --resolver=%v", addrs)
	}
}

func TestCLIRegistersRegistryCrawlSurface(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	crawl := findCommand(app.Commands, "registry-crawl")
	if crawl == nil {
		t.Fatal("registry-crawl must be registered")
	}
	for _, sub := range []string{"seed", "bulk", "worker"} {
		if findCommand(crawl.Subcommands, sub) == nil {
			t.Errorf("registry-crawl %s must be registered", sub)
		}
	}

	seed := findCommand(crawl.Subcommands, "seed")
	if seed == nil {
		t.Fatal("registry-crawl seed must be registered")
	}
	flags := flagNameSet(seed.Flags)
	if flags["refresh-nro"] {
		t.Error("seed must not register --refresh-nro")
	}
	for _, want := range []string{"skip-ribs", "delegated-stats-url", "only-registries"} {
		if !flags[want] {
			t.Errorf("seed missing flag %q", want)
		}
	}

	worker := findCommand(crawl.Subcommands, "worker")
	if worker == nil {
		t.Fatal("registry-crawl worker must be registered")
	}
	workerFlags := flagNameSet(worker.Flags)
	for _, want := range []string{"rdap-autnum", "rdap-ipnet", "kind", "once", "only-registries", "include-bulk-gaps", "lease", "batch", "proxies"} {
		if !workerFlags[want] {
			t.Errorf("worker missing flag %q", want)
		}
	}
	for _, old := range []string{"aut-num-fetch", "route-fetch"} {
		if workerFlags[old] {
			t.Errorf("worker must not register retired flag %q (no aliases)", old)
		}
	}

	bulk := findCommand(crawl.Subcommands, "bulk")
	if bulk == nil {
		t.Fatal("registry-crawl bulk must be registered")
	}
	if !flagNameSet(bulk.Flags)["with-whoisdb-route-fetch"] {
		t.Error("bulk must keep --with-whoisdb-route-fetch (IRR route objects, toml registry-crawl.bulk.with-route-objects)")
	}
}

func TestNoCommandRegistersRetiredRDAPFlagNames(t *testing.T) {
	t.Parallel()
	var walk func(prefix string, cmds []*cli.Command)
	walk = func(prefix string, cmds []*cli.Command) {
		for _, cmd := range cmds {
			names := flagNameSet(cmd.Flags)
			for _, old := range []string{"aut-num-fetch", "route-fetch"} {
				if names[old] {
					t.Errorf("%s%s registers retired flag %q", prefix, cmd.Name, old)
				}
			}
			walk(prefix+cmd.Name+" ", cmd.Subcommands)
		}
	}
	walk("", newCLIApp().Commands)
}

func TestRunCommandHasOnlyConfigFlag(t *testing.T) {
	t.Parallel()
	app := newCLIApp()
	run := findCommand(app.Commands, "run")
	if run == nil {
		t.Fatal("run must be registered")
	}
	if findCommand(app.Commands, "r") == nil {
		t.Fatal("run alias r must be registered")
	}
	if len(run.Subcommands) != 0 {
		t.Fatalf("run must have no subcommands, got %d", len(run.Subcommands))
	}
	if len(run.Flags) != 1 {
		t.Fatalf("run must have exactly one flag, got %d: %v", len(run.Flags), flagNameSet(run.Flags))
	}
	sf, ok := run.Flags[0].(*cli.StringFlag)
	if !ok || sf.Name != "config" {
		t.Fatalf("run's only flag must be the string flag config, got %T %v", run.Flags[0], run.Flags[0].Names())
	}
	if len(sf.EnvVars) != 0 {
		t.Errorf("run --config must not use urfave EnvVars (precedence is resolved explicitly), got %v", sf.EnvVars)
	}
	blob := strings.ToLower(run.Usage + " " + run.Description)
	for _, phrase := range []string{"--config", "opr_config", "opr.config.toml", "opr_postgres_db", "opr_clickhouse_password", "opr_peeringdb_apikey", opconfig.DefaultDSN} {
		if !strings.Contains(blob, phrase) {
			t.Errorf("run help missing %q", phrase)
		}
	}
	for _, old := range []string{"aut-num-fetch", "route-fetch"} {
		if strings.Contains(blob, old) {
			t.Errorf("run help must not mention %q", old)
		}
	}
}

func TestRunRejectsOtherFlagsAndArgs(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	t.Setenv("OPR_CONFIG", "")
	cfgPath := writeTempConfig(t, "")

	for _, args := range [][]string{
		{"opr", "run", "--rdap-autnum"},
		{"opr", "run", "--aut-num-fetch"},
		{"opr", "run", "--route-fetch"},
		{"opr", "run", "--whoisdb-period", "1h"},
		{"opr", "run", "--apikey", "x"},
		{"opr", "run", "--config", cfgPath, "extra"},
	} {
		app := newCLIApp()
		app.Writer = io.Discard
		app.ErrWriter = io.Discard
		if err := app.Run(args); err == nil {
			t.Errorf("%v must fail", args)
		}
	}

	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	err := app.Run([]string{"opr", "--postgres-db", "postgresql://u:p@127.0.0.1:1/db", "run", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "OPR_POSTGRES_DB") || !strings.Contains(err.Error(), "--postgres-db") {
		t.Fatalf("run with --postgres-db err=%v, want rejection pointing at OPR_POSTGRES_DB", err)
	}
}

func TestRunConfigPathPrecedenceAndMissingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPR_POSTGRES_DB", "")
	t.Setenv("OPR_CONFIG", "")

	// Default path: missing file is an error and is not created.
	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	err := app.Run([]string{"opr", "run"})
	defaultPath := filepath.Join(home, ".config", "opr.config.toml")
	if err == nil || !strings.Contains(err.Error(), defaultPath) || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("run with no config err=%v, want missing %s", err, defaultPath)
	}
	if _, statErr := os.Stat(defaultPath); statErr == nil {
		t.Fatal("run must not create the default config file")
	}

	// OPR_CONFIG beats the default.
	envPath := filepath.Join(home, "env.toml")
	t.Setenv("OPR_CONFIG", envPath)
	err = app.Run([]string{"opr", "run"})
	if err == nil || !strings.Contains(err.Error(), envPath) {
		t.Fatalf("run with OPR_CONFIG err=%v, want missing %s", err, envPath)
	}

	// --config beats OPR_CONFIG.
	flagPath := filepath.Join(home, "flag.toml")
	err = app.Run([]string{"opr", "run", "--config", flagPath})
	if err == nil || !strings.Contains(err.Error(), flagPath) {
		t.Fatalf("run with --config err=%v, want missing %s", err, flagPath)
	}
}

func TestRunRequiresOPRDSNBeforeConnecting(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	t.Setenv("OPR_CONFIG", "")
	if got := opconfig.PostgresDSN(); got != opconfig.DefaultDSN {
		t.Fatalf("PostgresDSN()=%q, want default %q", got, opconfig.DefaultDSN)
	}

	// Every job disabled, so run resolves the DSN and returns before migrate.
	cfgPath := writeTempConfig(t, `
[registry-crawl.worker]
enabled = false
ipnet = false
[registry-crawl.seed]
enabled = false
[registry-crawl.bulk]
enabled = false
[geonames]
enabled = false
[peeringdb]
enabled = false
[aspop]
enabled = false
[geoip.lacnic]
enabled = false
[geoip.ipmap]
enabled = false
[geoip.anycast]
enabled = false
[geoip.crawl-geofeeds]
enabled = false
[rpki.ingest]
enabled = false
[fdns.ingest-lists]
enabled = false
[fdns.resolve]
enabled = false
[fdns.ingest-cc]
enabled = false
[fdns.seed-queue]
enabled = false
[rdns.ingest]
enabled = false
[rdns.crawl-ptr]
enabled = false
`)

	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	err := app.Run([]string{"opr", "run", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "every job is disabled") {
		t.Fatalf("run without OPR_POSTGRES_DB err=%v, want the default DSN applied and then no enabled jobs", err)
	}
	if strings.Contains(err.Error(), "requires the OPR_POSTGRES_DB") {
		t.Fatalf("run treated a missing OPR_POSTGRES_DB as an error: %v", err)
	}

	// A secret in the file is rejected before OPR_POSTGRES_DB is even looked at.
	secretPath := writeTempConfig(t, "[peeringdb]\napikey = \"x\"\n")
	err = app.Run([]string{"opr", "run", "--config", secretPath})
	if err == nil || !strings.Contains(err.Error(), "OPR_PEERINGDB_APIKEY") || strings.Contains(err.Error(), "requires the OPR_POSTGRES_DB") {
		t.Fatalf("run with secret in file err=%v, want secret rejection", err)
	}

	// Unknown keys too.
	unknownPath := writeTempConfig(t, "[registry-crawl.worker]\nbogus = 1\n")
	err = app.Run([]string{"opr", "run", "--config", unknownPath})
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("run with unknown key err=%v, want unknown key", err)
	}
}

func TestOneShotsDoNotAcceptConfigFlag(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	for _, args := range [][]string{
		{"opr", "--postgres-db", "postgresql://u:p@127.0.0.1:1/db", "aspop", "--config", "/tmp/x.toml"},
		{"opr", "--postgres-db", "postgresql://u:p@127.0.0.1:1/db", "registry-crawl", "seed", "--config", "/tmp/x.toml"},
		{"opr", "--config", "/tmp/x.toml", "--postgres-db", "postgresql://u:p@127.0.0.1:1/db", "aspop"},
	} {
		app := newCLIApp()
		app.Writer = io.Discard
		app.ErrWriter = io.Discard
		err := app.Run(args)
		if err == nil || !strings.Contains(err.Error(), "config") {
			t.Errorf("%v err=%v, want flag provided but not defined: -config", args, err)
		}
	}
}

func TestOneShotsFallBackToOPRDSN(t *testing.T) {
	const fromEnv = "postgresql://u:p@127.0.0.1:1/db?connect_timeout=1"
	t.Setenv("OPR_POSTGRES_DB", fromEnv)
	got, err := postgresDSNFromBefore(t, "postgres", "version")
	if err != nil {
		t.Fatal(err)
	}
	if got != fromEnv {
		t.Fatalf("dsn=%q, want env %q", got, fromEnv)
	}

	app := newCLIApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	// Before hook accepts the env fallback; the command then fails on the
	// unreachable port, which is past the flag check.
	err = app.Run([]string{"opr", "postgres", "version"})
	if err == nil {
		t.Skip("postgres version unexpectedly reached a database on 127.0.0.1:1")
	}
	if strings.Contains(err.Error(), `Required flag "postgres-db" not set`) {
		t.Fatalf("one-shot must fall back to OPR_POSTGRES_DB when --postgres-db is empty, got %v", err)
	}
	if strings.Contains(err.Error(), opconfig.DefaultDSN) {
		t.Fatalf("one-shot used the default DSN instead of OPR_POSTGRES_DB: %v", err)
	}
}

func TestPostgresDSNExplicitFlagWins(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "postgresql://from-env/db")
	const fromFlag = "postgresql://from-flag/db"
	got, err := postgresDSNFromBefore(t, "--postgres-db", fromFlag, "aspop")
	if err != nil {
		t.Fatal(err)
	}
	if got != fromFlag {
		t.Fatalf("dsn=%q, want flag %q", got, fromFlag)
	}

	t.Setenv("OPR_POSTGRES_DB", "")
	got, err = postgresDSNFromBefore(t, "--postgres-db", fromFlag, "rpki", "ingest")
	if err != nil {
		t.Fatal(err)
	}
	if got != fromFlag {
		t.Fatalf("dsn=%q, want flag %q when env is unset", got, fromFlag)
	}
}

func TestPostgresDSNDefaultWhenFlagAndEnvEmpty(t *testing.T) {
	t.Setenv("OPR_POSTGRES_DB", "")
	for _, args := range [][]string{
		{"aspop"},
		{"peeringdb"},
		{"rpki", "ingest"},
		{"postgres", "version"},
		{"registry-crawl", "seed"},
	} {
		got, err := postgresDSNFromBefore(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got != opconfig.DefaultDSN {
			t.Fatalf("%v dsn=%q, want default %q", args, got, opconfig.DefaultDSN)
		}
	}

	app := newCLIApp()
	for _, f := range app.Flags {
		sf, ok := f.(*cli.StringFlag)
		if !ok || sf.Name != "postgres-db" {
			continue
		}
		if !strings.Contains(sf.Usage, opconfig.DefaultDSN) {
			t.Fatalf("postgres-db usage missing default URL: %s", sf.Usage)
		}
		return
	}
	t.Fatal("postgres-db flag not found")
}

// postgresDSNFromBefore runs the root Before hook without invoking a command
// action, so a resolved DSN is not dialed.
func postgresDSNFromBefore(t *testing.T, args ...string) (string, error) {
	t.Helper()
	app := newCLIApp()
	set := flag.NewFlagSet("opr", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	for _, f := range app.Flags {
		if err := f.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(app, set, nil)
	err := app.Before(c)
	return c.String("postgres-db"), err
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opr.config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func findCommand(cmds []*cli.Command, name string) *cli.Command {
	for _, cmd := range cmds {
		if cmd.HasName(name) {
			return cmd
		}
	}
	return nil
}

func flagNameSet(flags []cli.Flag) map[string]bool {
	out := make(map[string]bool)
	for _, f := range flags {
		for _, n := range f.Names() {
			out[n] = true
		}
	}
	return out
}

func isStringSliceFlag(flags []cli.Flag, name string) bool {
	for _, f := range flags {
		sf, ok := f.(*cli.StringSliceFlag)
		if !ok {
			continue
		}
		for _, n := range sf.Names() {
			if n == name {
				return true
			}
		}
	}
	return false
}

func fdnsResolveFlagContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	app := newCLIApp()
	fdnsCmd := findCommand(app.Commands, "fdns")
	if fdnsCmd == nil {
		t.Fatal("fdns must be registered")
	}
	resolve := findCommand(fdnsCmd.Subcommands, "resolve")
	if resolve == nil {
		t.Fatal("fdns resolve must be registered")
	}
	set := flag.NewFlagSet("resolve", flag.ContinueOnError)
	for _, f := range resolve.Flags {
		if err := f.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(app, set, nil)
	c.Command = resolve
	return c
}
