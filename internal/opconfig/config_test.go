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
	wc := cfg.RegistryCrawl.Worker
	if wc.Lease.Std() != DefaultRDAPLease || wc.Batch != DefaultRDAPBatch {
		t.Errorf("registry-crawl.worker defaults: %+v", wc)
	}
	sc := cfg.RegistryCrawl.Seed
	if sc.Interval.Std() != 24*time.Hour || sc.DelegatedStatsURL != nro.DefaultDelegatedStatsURL || sc.SkipRIBs || len(sc.OnlyRegistries) != 0 {
		t.Errorf("registry-crawl.seed defaults: %+v", sc)
	}
	bc := cfg.RegistryCrawl.Bulk
	if bc.Period.Std() != time.Hour || bc.BufferMaxSize != 5000 || !bc.WithRouteObjects || bc.Prefetch != whoisdb.DefaultPrefetchDepth {
		t.Errorf("registry-crawl.bulk defaults: %+v", bc)
	}
	if cfg.PeeringDB.Interval.Std() != peeringdb.DefaultCrawlInterval || cfg.PeeringDB.Force {
		t.Errorf("peeringdb defaults: %+v", cfg.PeeringDB)
	}
	if cfg.ASPop.Interval.Std() != 6*time.Hour {
		t.Errorf("aspop defaults: %+v", cfg.ASPop)
	}
	if cfg.GeoIP.CrawlGeofeeds.WorkerCount != geofeeds.DefaultWorkerCount ||
		cfg.GeoIP.CrawlGeofeeds.GeofeedRefreshOlderThan.Std() != geofeeds.DefaultRefreshOlderThan ||
		cfg.GeoIP.IPMap.Force || cfg.GeoIP.Anycast.Force {
		t.Errorf("geoip defaults: %+v", cfg.GeoIP)
	}
	if cfg.RPKI.Ingest.Interval.Std() != time.Hour || cfg.RPKI.Ingest.RoutinatorAddr != rpki.DefaultRoutinatorAddr || cfg.RPKI.Ingest.RoutinatorFallbackAddr != "" {
		t.Errorf("rpki.ingest defaults: %+v", cfg.RPKI.Ingest)
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
[registry-crawl.worker]
lease = "5m"

[fdns.resolve]
qps = 10.0
`))
	if err != nil {
		t.Fatal(err)
	}
	for name, enabled := range map[string]bool{
		"registry-crawl.worker":       cfg.RegistryCrawl.Worker.Enabled,
		"registry-crawl.worker.ipnet": cfg.RegistryCrawl.Worker.Ipnet,
		"registry-crawl.seed":         cfg.RegistryCrawl.Seed.Enabled,
		"registry-crawl.bulk":         cfg.RegistryCrawl.Bulk.Enabled,
		"geonames":                    cfg.GeoNames.Enabled,
		"peeringdb":                   cfg.PeeringDB.Enabled,
		"aspop":                       cfg.ASPop.Enabled,
		"geoip.lacnic":                cfg.GeoIP.Lacnic.Enabled,
		"geoip.ipmap":                 cfg.GeoIP.IPMap.Enabled,
		"geoip.anycast":               cfg.GeoIP.Anycast.Enabled,
		"geoip.crawl-geofeeds":        cfg.GeoIP.CrawlGeofeeds.Enabled,
		"rpki.ingest":                 cfg.RPKI.Ingest.Enabled,
		"fdns.ingest-lists":           cfg.FDNS.IngestLists.Enabled,
		"fdns.resolve":                cfg.FDNS.Resolve.Enabled,
		"fdns.ingest-cc":              cfg.FDNS.IngestCC.Enabled,
		"fdns.seed-queue":             cfg.FDNS.SeedQueue.Enabled,
		"rdns.ingest":                 cfg.RDNS.Ingest.Enabled,
		"rdns.crawl-ptr":              cfg.RDNS.CrawlPTR.Enabled,
	} {
		if !enabled {
			t.Errorf("%s.enabled must default to true", name)
		}
	}
	if cfg.RegistryCrawl.Worker.Lease.Std() != 5*time.Minute || cfg.FDNS.Resolve.QPS != 10 {
		t.Errorf("explicit keys not applied: %+v %+v", cfg.RegistryCrawl.Worker, cfg.FDNS.Resolve)
	}
	if !cfg.AnyEnabled() {
		t.Error("AnyEnabled must be true for defaults")
	}
}

func TestEnabledFalse(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[registry-crawl.worker]
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
	if cfg.RegistryCrawl.Worker.Enabled || cfg.RegistryCrawl.Worker.Ipnet || cfg.FDNS.IngestCC.Enabled || cfg.RDNS.CrawlPTR.Enabled {
		t.Errorf("enabled=false not applied: %+v %+v %+v", cfg.RegistryCrawl.Worker, cfg.FDNS.IngestCC, cfg.RDNS.CrawlPTR)
	}
	if !cfg.RegistryCrawl.Seed.Enabled || !cfg.FDNS.Resolve.Enabled {
		t.Error("other jobs must stay enabled")
	}
}

func TestGeoIPEnabledIndependence(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
[geoip.lacnic]
enabled = false

[geoip.ipmap]
enabled = true

[geoip.anycast]
enabled = false

[geoip.crawl-geofeeds]
enabled = true
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GeoIP.Lacnic.Enabled {
		t.Error("geoip.lacnic must be disabled")
	}
	if !cfg.GeoIP.IPMap.Enabled {
		t.Error("geoip.ipmap must stay enabled")
	}
	if cfg.GeoIP.Anycast.Enabled {
		t.Error("geoip.anycast must be disabled")
	}
	if !cfg.GeoIP.CrawlGeofeeds.Enabled {
		t.Error("geoip.crawl-geofeeds must stay enabled")
	}
	if !cfg.AnyEnabled() {
		t.Error("AnyEnabled must be true when some geoip jobs remain on")
	}
}

func TestOldSectionNamesAreErrors(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"[rdap]\nenabled = true\n",
		"[seed]\nenabled = true\n",
		"[whoisdb]\nenabled = true\n",
		"[geoip]\nenabled = true\n",
		"[geoip]\nlacnic-interval = \"24h\"\n",
		"[rpki]\nenabled = true\n",
		"[registry-crawl.worker]\nlacnic-interval = \"24h\"\n",
		"[geoip.lacnic]\nlacnic-interval = \"24h\"\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("old section/key accepted:\n%s", src)
		} else if !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("old section/key error should say unknown key: %v\n%s", err, src)
		}
	}
}

func TestUnknownKeyIsError(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"[registry-crawl.worker]\nenabled = true\nbogus = 1\n",
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
		"dsn = \"postgresql://x\"\n":                                                    EnvDSN,
		"postgres-db = \"postgresql://x\"\n":                                            EnvDSN,
		"[clickhouse]\npassword = \"x\"\n":                                              EnvClickHousePassword,
		"[clickhouse]\nclickhouse-password = \"x\"\n":                                   EnvClickHousePassword,
		"[peeringdb]\napikey = \"x\"\n":                                                 EnvPeeringDBAPIKey,
		"[fdns.ingest-cc]\npassword = \"x\"\n":                                          EnvClickHousePassword,
		"[registry-crawl.worker]\nenabled = true\n[registry-crawl.seed]\ndsn = \"x\"\n": EnvDSN,
		"[registry-crawl.bulk]\nPassword = \"x\"\n":                                     EnvClickHousePassword,
		"[[proxies]]\napikey = \"x\"\n":                                                 EnvPeeringDBAPIKey,
		"[clickhouse]\nnested = { password = \"x\" }\n":                                 EnvClickHousePassword,
		"[fdns]\n[fdns.resolve]\ndsn = \"postgresql://\"":                               EnvDSN,
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
[registry-crawl.seed]
interval = "36h"

[registry-crawl.bulk]
period = "90m"

[registry-crawl.worker]
lease = "1h30m"

[geoip.lacnic]
interval = "12h"

[rdns.crawl-ptr]
timeout = "1500ms"

[clickhouse]
timeout = "45s"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RegistryCrawl.Seed.Interval.Std() != 36*time.Hour {
		t.Errorf("registry-crawl.seed.interval=%s", cfg.RegistryCrawl.Seed.Interval)
	}
	if cfg.RegistryCrawl.Bulk.Period.Std() != 90*time.Minute {
		t.Errorf("registry-crawl.bulk.period=%s", cfg.RegistryCrawl.Bulk.Period)
	}
	if cfg.RegistryCrawl.Worker.Lease.Std() != 90*time.Minute {
		t.Errorf("registry-crawl.worker.lease=%s", cfg.RegistryCrawl.Worker.Lease)
	}
	if cfg.GeoIP.Lacnic.Interval.Std() != 12*time.Hour {
		t.Errorf("geoip.lacnic.interval=%s", cfg.GeoIP.Lacnic.Interval)
	}
	if cfg.RDNS.CrawlPTR.Timeout.Std() != 1500*time.Millisecond {
		t.Errorf("rdns.crawl-ptr.timeout=%s", cfg.RDNS.CrawlPTR.Timeout)
	}
	if cfg.ClickHouse.Timeout.Std() != 45*time.Second {
		t.Errorf("clickhouse.timeout=%s", cfg.ClickHouse.Timeout)
	}
	for _, bad := range []string{
		"[registry-crawl.seed]\ninterval = \"tomorrow\"\n",
		"[registry-crawl.seed]\ninterval = \"0s\"\n",
		"[registry-crawl.seed]\ninterval = \"-1h\"\n",
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

[registry-crawl.worker]
only-registries = ["ARIN"]
proxies = []
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FDNS.Resolve.Resolver) != 1 || cfg.FDNS.Resolve.Resolver[0] != "127.0.0.1:5353" {
		t.Errorf("resolver must replace the defaults, got %v", cfg.FDNS.Resolve.Resolver)
	}
	if len(cfg.RegistryCrawl.Worker.OnlyRegistries) != 1 || cfg.RegistryCrawl.Worker.OnlyRegistries[0] != "ARIN" {
		t.Errorf("only-registries=%v", cfg.RegistryCrawl.Worker.OnlyRegistries)
	}
	if len(cfg.RegistryCrawl.Worker.Proxies) != 0 {
		t.Errorf("proxies=%v", cfg.RegistryCrawl.Worker.Proxies)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"[registry-crawl.worker]\nonly-registries = [\"MARS\"]\n",
		"[registry-crawl.worker]\nbatch = 0\n",
		"[geoip.crawl-geofeeds]\nworker-count = 0\n",
		"[fdns.resolve]\naf = \"5\"\n",
		"[fdns.ingest-lists]\nonly = [\"alexa\"]\n",
		"[fdns.seed-queue]\norder = \"random\"\n",
		"[rdns.ingest]\nonly-registries = [\"NOPE\"]\n",
		"[rpki.ingest]\nroutinator-addr = \"\"\n",
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
	cfg, err := Load(filepath.Join("..", "..", "config", "opr.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RegistryCrawl.Worker.Enabled || !cfg.RegistryCrawl.Worker.Ipnet ||
		!cfg.FDNS.IngestCC.Enabled || !cfg.RDNS.CrawlPTR.Enabled ||
		!cfg.GeoIP.Lacnic.Enabled || !cfg.GeoIP.CrawlGeofeeds.Enabled ||
		!cfg.RPKI.Ingest.Enabled {
		t.Errorf("example file must enable every job: %+v", cfg)
	}
	if cfg.FDNS.IngestCC.Interval.Std() != 720*time.Hour || cfg.PeeringDB.Interval.Std() != 24*time.Hour || cfg.RPKI.Ingest.Interval.Std() != time.Hour {
		t.Errorf("example intervals: %+v %+v %+v", cfg.FDNS.IngestCC, cfg.PeeringDB, cfg.RPKI.Ingest)
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
	if cfg.GeoIP.IPMap.Force || cfg.GeoIP.Anycast.Force {
		t.Fatal("example geoip.ipmap/anycast force must be false")
	}
	if len(cfg.RegistryCrawl.Seed.OnlyRegistries) != 0 {
		t.Fatalf("example seed only-registries=%v", cfg.RegistryCrawl.Seed.OnlyRegistries)
	}
}

func TestLoadSampleConfigs(t *testing.T) {
	t.Parallel()
	jobs := func(c *Config) map[string]bool {
		return map[string]bool{
			"registry-crawl.worker": c.RegistryCrawl.Worker.Enabled,
			"registry-crawl.seed":   c.RegistryCrawl.Seed.Enabled,
			"registry-crawl.bulk":   c.RegistryCrawl.Bulk.Enabled,
			"geonames":              c.GeoNames.Enabled,
			"peeringdb":             c.PeeringDB.Enabled,
			"aspop":                 c.ASPop.Enabled,
			"geoip.lacnic":          c.GeoIP.Lacnic.Enabled,
			"geoip.ipmap":           c.GeoIP.IPMap.Enabled,
			"geoip.anycast":         c.GeoIP.Anycast.Enabled,
			"geoip.crawl-geofeeds":  c.GeoIP.CrawlGeofeeds.Enabled,
			"rpki.ingest":           c.RPKI.Ingest.Enabled,
			"fdns.ingest-lists":     c.FDNS.IngestLists.Enabled,
			"fdns.resolve":          c.FDNS.Resolve.Enabled,
			"fdns.ingest-cc":        c.FDNS.IngestCC.Enabled,
			"fdns.seed-queue":       c.FDNS.SeedQueue.Enabled,
			"rdns.ingest":           c.RDNS.Ingest.Enabled,
			"rdns.crawl-ptr":        c.RDNS.CrawlPTR.Enabled,
		}
	}
	samples := map[string][]string{
		"aspop-peeringdb.toml": {"aspop", "peeringdb"},
		"geoip-geonames.toml":  {"geoip.lacnic", "geoip.ipmap", "geoip.anycast", "geonames"},
		"registry-crawl.toml":  {"registry-crawl.seed", "registry-crawl.bulk"},
	}
	for file, on := range samples {
		cfg, err := Load(filepath.Join("..", "..", "config", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		want := map[string]bool{}
		for _, name := range on {
			want[name] = true
		}
		for name, enabled := range jobs(cfg) {
			if enabled != want[name] {
				t.Errorf("%s: %s enabled=%v, want %v", file, name, enabled, want[name])
			}
		}
		if cfg.RegistryCrawl.Worker.Ipnet {
			t.Errorf("%s: registry-crawl.worker.ipnet must be false so the RDAP queue stays off", file)
		}
		if !cfg.AnyEnabled() {
			t.Errorf("%s: AnyEnabled must be true", file)
		}
	}
}

func TestWorkerOnlyRegistriesNormalized(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("[registry-crawl.worker]\nonly-registries = [\"arin\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RegistryCrawl.Worker.OnlyRegistries) != 1 || cfg.RegistryCrawl.Worker.OnlyRegistries[0] != "ARIN" {
		t.Fatalf("only-registries=%v, want [ARIN]", cfg.RegistryCrawl.Worker.OnlyRegistries)
	}
}

func TestProxyUserinfoAllowedAndTrimmed(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-password"
	cfg, err := Parse([]byte("[registry-crawl.worker]\nproxies = [\"  http://user:" + secret + "@127.0.0.1:8080  \"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := "http://user:" + secret + "@127.0.0.1:8080"
	if len(cfg.RegistryCrawl.Worker.Proxies) != 1 || cfg.RegistryCrawl.Worker.Proxies[0] != want {
		t.Fatalf("proxies=%q, want trimmed %q", cfg.RegistryCrawl.Worker.Proxies, want)
	}
	if _, err := Parse([]byte("[registry-crawl.worker]\nproxies = [\"http://127.0.0.1:8080\"]\n")); err != nil {
		t.Fatal(err)
	}
}

func TestProxyParseErrorHidesSecret(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-password"
	raw := "http://user:" + secret + "@[::1"
	_, err := Parse([]byte("[registry-crawl.worker]\nproxies = [\"" + raw + "\"]\n"))
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

func TestPostgresDSNDefaultAndOverride(t *testing.T) {
	t.Setenv(EnvDSN, "")
	if got := PostgresDSN(); got != DefaultDSN {
		t.Fatalf("PostgresDSN()=%q, want default %q", got, DefaultDSN)
	}
	if DefaultDSN != "postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable" {
		t.Fatalf("DefaultDSN=%q", DefaultDSN)
	}

	t.Setenv(EnvDSN, "  ")
	if got := PostgresDSN(); got != DefaultDSN {
		t.Fatalf("whitespace env PostgresDSN()=%q, want default", got)
	}

	const explicit = "postgresql://from-env/db"
	t.Setenv(EnvDSN, explicit)
	if got := PostgresDSN(); got != explicit {
		t.Fatalf("PostgresDSN()=%q, want explicit %q", got, explicit)
	}
}

func TestSeedOnlyRegistriesRoundTrip(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("[registry-crawl.seed]\nonly-registries = [\"ripe\", \"ARIN\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RegistryCrawl.Seed.OnlyRegistries) != 2 || cfg.RegistryCrawl.Seed.OnlyRegistries[0] != "RIPE" || cfg.RegistryCrawl.Seed.OnlyRegistries[1] != "ARIN" {
		t.Fatalf("seed only-registries=%v", cfg.RegistryCrawl.Seed.OnlyRegistries)
	}
}
