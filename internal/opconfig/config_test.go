package opconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/fdns"
	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/aggregator/peeringdb"
	"github.com/oprand/opr/aggregator/rpki"
	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/store/clickhouse"
)

func TestParseEmptyFileIsDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	if cfg.RDAP.Lease.Std() != DefaultRDAPLease || cfg.RDAP.Batch != DefaultRDAPBatch {
		t.Errorf("rdap defaults: %+v", cfg.RDAP)
	}
	if cfg.Seed.Interval.Std() != 24*time.Hour || cfg.Seed.DelegatedStatsURL != nro.DefaultDelegatedStatsURL || cfg.Seed.SkipRIBs || len(cfg.Seed.OnlyRegistries) != 0 {
		t.Errorf("seed defaults: %+v", cfg.Seed)
	}
	if cfg.WhoisDB.Period.Std() != time.Hour || cfg.WhoisDB.BufferMaxSize != 5000 || !cfg.WhoisDB.WithRouteObjects || cfg.WhoisDB.Prefetch != whoisdb.DefaultPrefetchDepth {
		t.Errorf("whoisdb defaults: %+v", cfg.WhoisDB)
	}
	if cfg.PeeringDB.Interval.Std() != peeringdb.DefaultCrawlInterval || cfg.PeeringDB.Force {
		t.Errorf("peeringdb defaults: %+v", cfg.PeeringDB)
	}
	if cfg.ASPop.Interval.Std() != 6*time.Hour {
		t.Errorf("aspop defaults: %+v", cfg.ASPop)
	}
	if cfg.GeoIP.WorkerCount != geofeeds.DefaultWorkerCount || cfg.GeoIP.GeofeedRefreshOlderThan.Std() != geofeeds.DefaultRefreshOlderThan || cfg.GeoIP.IPMapForce || cfg.GeoIP.AnycastForce {
		t.Errorf("geoip defaults: %+v", cfg.GeoIP)
	}
	if cfg.RPKI.Interval.Std() != time.Hour || cfg.RPKI.RoutinatorAddr != rpki.DefaultRoutinatorAddr || cfg.RPKI.RoutinatorFallbackAddr != "" {
		t.Errorf("rpki defaults: %+v", cfg.RPKI)
	}
	if len(cfg.FDNS.Resolve.Resolver) != len(fdns.DefaultResolverAddrs) || cfg.FDNS.Resolve.QPS != fdns.DefaultResolveQPS || cfg.FDNS.Resolve.AF != "both" {
		t.Errorf("fdns.resolve defaults: %+v", cfg.FDNS.Resolve)
	}
	if cfg.FDNS.IngestCC.Interval.Std() != 720*time.Hour || !cfg.FDNS.IngestCC.KeepParquet || cfg.FDNS.IngestCC.ParquetDir != fdns.DefaultParquetDir() {
		t.Errorf("fdns.ingest-cc defaults: %+v", cfg.FDNS.IngestCC)
	}
	if cfg.FDNS.SeedQueue.Limit != fdns.DefaultSeedQueueLimit || cfg.FDNS.SeedQueue.Order != "key" || cfg.FDNS.SeedQueue.QueueHighWater != 0 {
		t.Errorf("fdns.seed-queue defaults: %+v", cfg.FDNS.SeedQueue)
	}
	if cfg.RDNS.CrawlPTR.QPS != 5 || cfg.RDNS.CrawlPTR.Timeout.Std() != 2*time.Second {
		t.Errorf("rdns.crawl-ptr defaults: %+v", cfg.RDNS.CrawlPTR)
	}
	if cfg.ClickHouse.URL != clickhouse.DefaultURL || cfg.ClickHouse.Database != clickhouse.DefaultDatabase || cfg.ClickHouse.User != clickhouse.DefaultUser || cfg.ClickHouse.Timeout.Std() != clickhouse.DefaultTimeout {
		t.Errorf("clickhouse defaults: %+v", cfg.ClickHouse)
	}
	if cfg.RDNS.Ingest.RIPEURL != want.RDNS.Ingest.RIPEURL {
		t.Errorf("rdns.ingest defaults: %+v", cfg.RDNS.Ingest)
	}
}

func TestEnabledDefaultsTrue(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[rdap]
lease = "5m"

[fdns.resolve]
qps = 10.0
`))
	if err != nil {
		t.Fatal(err)
	}
	for name, enabled := range map[string]bool{
		"rdap":              cfg.RDAP.Enabled,
		"rdap.ipnet":        cfg.RDAP.Ipnet,
		"seed":              cfg.Seed.Enabled,
		"whoisdb":           cfg.WhoisDB.Enabled,
		"geonames":          cfg.GeoNames.Enabled,
		"peeringdb":         cfg.PeeringDB.Enabled,
		"aspop":             cfg.ASPop.Enabled,
		"geoip":             cfg.GeoIP.Enabled,
		"rpki":              cfg.RPKI.Enabled,
		"fdns.ingest-lists": cfg.FDNS.IngestLists.Enabled,
		"fdns.resolve":      cfg.FDNS.Resolve.Enabled,
		"fdns.ingest-cc":    cfg.FDNS.IngestCC.Enabled,
		"fdns.seed-queue":   cfg.FDNS.SeedQueue.Enabled,
		"rdns.ingest":       cfg.RDNS.Ingest.Enabled,
		"rdns.crawl-ptr":    cfg.RDNS.CrawlPTR.Enabled,
	} {
		if !enabled {
			t.Errorf("%s.enabled must default to true", name)
		}
	}
	if cfg.RDAP.Lease.Std() != 5*time.Minute || cfg.FDNS.Resolve.QPS != 10 {
		t.Errorf("explicit keys not applied: %+v %+v", cfg.RDAP, cfg.FDNS.Resolve)
	}
	if !cfg.AnyEnabled() {
		t.Error("AnyEnabled must be true for defaults")
	}
}

func TestEnabledFalse(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[rdap]
enabled = false
ipnet = false

[fdns.ingest-cc]
enabled = false

[rdns.crawl-ptr]
enabled = false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RDAP.Enabled || cfg.RDAP.Ipnet || cfg.FDNS.IngestCC.Enabled || cfg.RDNS.CrawlPTR.Enabled {
		t.Errorf("enabled=false not applied: %+v %+v %+v", cfg.RDAP, cfg.FDNS.IngestCC, cfg.RDNS.CrawlPTR)
	}
	if !cfg.Seed.Enabled || !cfg.FDNS.Resolve.Enabled {
		t.Error("other jobs must stay enabled")
	}
}

func TestUnknownKeyIsError(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"[rdap]\nenabled = true\nbogus = 1\n",
		"[nosuch]\nenabled = true\n",
		"[fdns.resolve]\nresolvers = [\"1.1.1.1\"]\n",
		"[fdns.nosuch]\nenabled = true\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("unknown key accepted:\n%s", src)
		} else if !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("unknown key error should say so: %v", err)
		}
	}
}

func TestSecretKeysAreErrors(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"dsn = \"postgresql://x\"\n":                      EnvDSN,
		"[clickhouse]\npassword = \"x\"\n":                EnvClickHousePassword,
		"[clickhouse]\nclickhouse-password = \"x\"\n":     EnvClickHousePassword,
		"[peeringdb]\napikey = \"x\"\n":                   EnvPeeringDBAPIKey,
		"[fdns.ingest-cc]\npassword = \"x\"\n":            EnvClickHousePassword,
		"[rdap]\nenabled = true\n[seed]\ndsn = \"x\"\n":   EnvDSN,
		"[whoisdb]\nPassword = \"x\"\n":                   EnvClickHousePassword,
		"[[proxies]]\napikey = \"x\"\n":                   EnvPeeringDBAPIKey,
		"[clickhouse]\nnested = { password = \"x\" }\n":   EnvClickHousePassword,
		"[fdns]\n[fdns.resolve]\ndsn = \"postgresql://\"": EnvDSN,
	}
	for src, env := range cases {
		_, err := Parse([]byte(src))
		if err == nil {
			t.Errorf("secret accepted:\n%s", src)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "secret") || !strings.Contains(msg, env) {
			t.Errorf("secret error must name the env var %s: %v", env, err)
		}
	}
}

func TestDurationsParse(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[seed]
interval = "36h"

[whoisdb]
period = "90m"

[rdap]
lease = "1h30m"

[rdns.crawl-ptr]
timeout = "1500ms"

[clickhouse]
timeout = "45s"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Seed.Interval.Std() != 36*time.Hour {
		t.Errorf("seed.interval=%s", cfg.Seed.Interval)
	}
	if cfg.WhoisDB.Period.Std() != 90*time.Minute {
		t.Errorf("whoisdb.period=%s", cfg.WhoisDB.Period)
	}
	if cfg.RDAP.Lease.Std() != 90*time.Minute {
		t.Errorf("rdap.lease=%s", cfg.RDAP.Lease)
	}
	if cfg.RDNS.CrawlPTR.Timeout.Std() != 1500*time.Millisecond {
		t.Errorf("rdns.crawl-ptr.timeout=%s", cfg.RDNS.CrawlPTR.Timeout)
	}
	if cfg.ClickHouse.Timeout.Std() != 45*time.Second {
		t.Errorf("clickhouse.timeout=%s", cfg.ClickHouse.Timeout)
	}
	for _, bad := range []string{
		"[seed]\ninterval = \"tomorrow\"\n",
		"[seed]\ninterval = \"0s\"\n",
		"[seed]\ninterval = \"-1h\"\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("bad duration accepted:\n%s", bad)
		}
	}
}

func TestSlicesReplaceDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[fdns.resolve]
resolver = ["127.0.0.1:5353"]

[rdap]
only-registries = ["ARIN"]
proxies = []
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FDNS.Resolve.Resolver) != 1 || cfg.FDNS.Resolve.Resolver[0] != "127.0.0.1:5353" {
		t.Errorf("resolver must replace the defaults, got %v", cfg.FDNS.Resolve.Resolver)
	}
	if len(cfg.RDAP.OnlyRegistries) != 1 || cfg.RDAP.OnlyRegistries[0] != "ARIN" {
		t.Errorf("only-registries=%v", cfg.RDAP.OnlyRegistries)
	}
	if len(cfg.RDAP.Proxies) != 0 {
		t.Errorf("proxies=%v", cfg.RDAP.Proxies)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"[rdap]\nonly-registries = [\"MARS\"]\n",
		"[rdap]\nbatch = 0\n",
		"[geoip]\nworker-count = 0\n",
		"[fdns.resolve]\naf = \"5\"\n",
		"[fdns.ingest-lists]\nonly = [\"alexa\"]\n",
		"[fdns.seed-queue]\norder = \"random\"\n",
		"[rdns.ingest]\nonly-registries = [\"NOPE\"]\n",
		"[rpki]\nroutinator-addr = \"\"\n",
		"[clickhouse]\nurl = \"http://user:s3cret@127.0.0.1:8123\"\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("invalid value accepted:\n%s", bad)
		}
	}
}

func TestValidateRejectsClickHouseURLUserinfo(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte(`[clickhouse]
url = "http://user:s3cret@127.0.0.1:8123"
`))
	if err == nil {
		t.Fatal("expected userinfo rejection")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cret") {
		t.Fatalf("error must not echo password: %q", msg)
	}
	if !strings.Contains(msg, "userinfo") || !strings.Contains(msg, EnvClickHousePassword) {
		t.Fatalf("got %q", msg)
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfig, "")

	got, err := ResolvePath("")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "opr.config.toml"); got != want {
		t.Errorf("default path=%q, want %q", got, want)
	}

	t.Setenv(EnvConfig, "/env/opr.toml")
	got, err = ResolvePath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/env/opr.toml" {
		t.Errorf("env path=%q", got)
	}

	got, err = ResolvePath("/flag/opr.toml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/flag/opr.toml" {
		t.Errorf("flag must beat env, got %q", got)
	}
}

func TestLoadMissingFileDoesNotCreateIt(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "opr.config.toml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("missing file must be an error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should say the file does not exist: %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("Load must not create the file")
	}
}

func TestLoadExampleFile(t *testing.T) {
	t.Parallel()
	cfg, err := Load(filepath.Join("..", "..", "opr.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RDAP.Enabled || !cfg.RDAP.Ipnet || !cfg.FDNS.IngestCC.Enabled || !cfg.RDNS.CrawlPTR.Enabled {
		t.Errorf("example file must enable every job: %+v", cfg)
	}
	if cfg.FDNS.IngestCC.Interval.Std() != 720*time.Hour || cfg.PeeringDB.Interval.Std() != 24*time.Hour || cfg.RPKI.Interval.Std() != time.Hour {
		t.Errorf("example intervals: %+v %+v %+v", cfg.FDNS.IngestCC, cfg.PeeringDB, cfg.RPKI)
	}
	wantResolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "74.82.42.42"}
	if len(cfg.FDNS.Resolve.Resolver) != len(wantResolvers) {
		t.Fatalf("example resolver=%v", cfg.FDNS.Resolve.Resolver)
	}
	for i, want := range wantResolvers {
		if cfg.FDNS.Resolve.Resolver[i] != want {
			t.Fatalf("example resolver=%v", cfg.FDNS.Resolve.Resolver)
		}
	}
	if cfg.GeoIP.IPMapForce || cfg.GeoIP.AnycastForce {
		t.Fatal("example ipmap-force and anycast-force must be false")
	}
	if len(cfg.Seed.OnlyRegistries) != 0 {
		t.Fatalf("example seed only-registries=%v", cfg.Seed.OnlyRegistries)
	}
}

func TestRDAPOnlyRegistriesNormalized(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("[rdap]\nonly-registries = [\"arin\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RDAP.OnlyRegistries) != 1 || cfg.RDAP.OnlyRegistries[0] != "ARIN" {
		t.Fatalf("only-registries=%v, want [ARIN]", cfg.RDAP.OnlyRegistries)
	}
}

func TestProxyUserinfoAllowedAndTrimmed(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-password"
	cfg, err := Parse([]byte("[rdap]\nproxies = [\"  http://user:" + secret + "@127.0.0.1:8080  \"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := "http://user:" + secret + "@127.0.0.1:8080"
	if len(cfg.RDAP.Proxies) != 1 || cfg.RDAP.Proxies[0] != want {
		t.Fatalf("proxies=%q, want trimmed %q", cfg.RDAP.Proxies, want)
	}
	if _, err := Parse([]byte("[rdap]\nproxies = [\"http://127.0.0.1:8080\"]\n")); err != nil {
		t.Fatal(err)
	}
}

func TestProxyParseErrorHidesSecret(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-password"
	raw := "http://user:" + secret + "@[::1"
	_, err := Parse([]byte("[rdap]\nproxies = [\"" + raw + "\"]\n"))
	if err == nil {
		t.Fatal("expected a parse error")
	}
	msg := err.Error()
	if strings.Contains(msg, secret) || strings.Contains(msg, raw) || strings.Contains(msg, "user:") {
		t.Fatalf("error leaked proxy URL: %v", err)
	}
	if !strings.Contains(msg, "index 0") {
		t.Fatalf("error should name the index: %v", err)
	}
}

func TestSeedOnlyRegistriesRoundTrip(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("[seed]\nonly-registries = [\"ripe\", \"ARIN\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Seed.OnlyRegistries) != 2 || cfg.Seed.OnlyRegistries[0] != "RIPE" || cfg.Seed.OnlyRegistries[1] != "ARIN" {
		t.Fatalf("seed only-registries=%v", cfg.Seed.OnlyRegistries)
	}
}
