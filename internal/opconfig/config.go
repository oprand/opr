// Package opconfig loads the TOML file behind `opr run`.
//
// `opr run` takes exactly one flag, --config. The file holds every job
// setting; secrets (OPR_POSTGRES_DB, OPR_CLICKHOUSE_PASSWORD, OPR_PEERINGDB_APIKEY)
// come from the environment only and are rejected when they appear in the
// file. When OPR_POSTGRES_DB is unset, Postgres uses DefaultDSN. One-shot
// commands keep their own flags and never read this file; an empty
// --postgres-db falls back to OPR_POSTGRES_DB, then the same default.
//
// Omitted keys use the same defaults as the one-shot flags (the exported
// Default* constants from the aggregator packages). Every job table has
// `enabled`, which defaults to true, so a short file still runs the full
// daemon. Unknown keys are errors. Durations are TOML strings parsed with
// time.ParseDuration ("24h", "2m", "1h30m").
//
// Job section names match CLI syntax: [command] or [command.subcommand]
// (e.g. [registry-crawl.worker], [geoip.lacnic], [rpki.ingest]).
package opconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/oprand/opr/aggregator/asnames"
	"github.com/oprand/opr/aggregator/aspop"
	"github.com/oprand/opr/aggregator/fdns"
	"github.com/oprand/opr/aggregator/geofeeds"
	"github.com/oprand/opr/aggregator/geonames"
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/aggregator/peeringdb"
	"github.com/oprand/opr/aggregator/rdns"
	"github.com/oprand/opr/aggregator/rpki"
	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/clickhouse"

	"github.com/pelletier/go-toml/v2"
)

const (
	// EnvConfig names the environment variable that sets the config path
	// when --config is not passed.
	EnvConfig = "OPR_CONFIG"
	// EnvDSN overrides DefaultDSN for `opr run` and for one-shots when
	// --postgres-db is empty. The config file cannot set it.
	EnvDSN = "OPR_POSTGRES_DB"
	// DefaultDSN is the local compose Postgres URL used when --postgres-db
	// and EnvDSN are both empty. The scheme is postgres, not postgresql.
	DefaultDSN = "postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	// EnvClickHouseURL overrides [clickhouse].url for the daemon when set.
	// One-shot --clickhouse-url reads the same variable. The password stays
	// EnvClickHousePassword.
	EnvClickHouseURL = "OPR_CLICKHOUSE_URL"
	// EnvClickHousePassword is the only way the daemon learns the ClickHouse password.
	EnvClickHousePassword = "OPR_CLICKHOUSE_PASSWORD"
	// EnvPeeringDBAPIKey is the only way the daemon learns the PeeringDB API key.
	EnvPeeringDBAPIKey = "OPR_PEERINGDB_APIKEY"

	// DefaultRelativePath is appended to os.UserHomeDir() when neither
	// --config nor OPR_CONFIG is set. Not $XDG_CONFIG_HOME.
	DefaultRelativePath = ".config/opr.config.toml"
)

// Daemon-only defaults that have no one-shot flag counterpart.
const (
	DefaultSeedInterval         = 24 * time.Hour
	DefaultASPopInterval        = aspop.DefaultCrawlInterval
	DefaultGeoIPLacnicInterval  = 24 * time.Hour
	DefaultGeoIPIPMapInterval   = 24 * time.Hour
	DefaultGeoIPAnycastInterval = 24 * time.Hour
	DefaultRPKIInterval         = time.Hour
	DefaultFDNSListsInterval    = 24 * time.Hour
	DefaultFDNSCCInterval       = 720 * time.Hour
	DefaultFDNSSeedInterval     = 24 * time.Hour
	DefaultRDNSIngestInterval   = 24 * time.Hour

	// Defaults that mirror one-shot flag values declared inline in cmd/opr.
	DefaultWhoisDBPeriod        = time.Hour
	DefaultWhoisDBBufferMaxSize = 5000
	DefaultRDAPLease            = 2 * time.Minute
	DefaultRDAPBatch            = 1
)

// PostgresDSN returns OPR_POSTGRES_DB when it is set to a non-empty value,
// otherwise DefaultDSN. An explicit --postgres-db flag is applied by the
// CLI before this is consulted; this function does not look at flags.
func PostgresDSN() string {
	if env := strings.TrimSpace(os.Getenv(EnvDSN)); env != "" {
		return env
	}
	return DefaultDSN
}

// secretKeys are rejected anywhere in the file, whatever the table.
// "dsn" and "postgres-db" are the same secret: the Postgres connection string.
var secretKeys = map[string]string{
	"dsn":                 EnvDSN,
	"postgres-db":         EnvDSN,
	"password":            EnvClickHousePassword,
	"apikey":              EnvPeeringDBAPIKey,
	"clickhouse-password": EnvClickHousePassword,
}

// Duration is a time.Duration written as a TOML string ("24h", "2m",
// "1h30m") and parsed with time.ParseDuration. Bare integers are rejected.
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler for go-toml.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(text)))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Std returns the time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String formats like time.Duration.
func (d Duration) String() string { return time.Duration(d).String() }

// Config is the whole opr.config.toml.
type Config struct {
	RegistryCrawl RegistryCrawl `toml:"registry-crawl"`
	GeoNames      GeoNames      `toml:"geonames"`
	PeeringDB     PeeringDB     `toml:"peeringdb"`
	ASPop         ASPop         `toml:"aspop"`
	GeoIP         GeoIP         `toml:"geoip"`
	RPKI          RPKI          `toml:"rpki"`
	FDNS          FDNS          `toml:"fdns"`
	RDNS          RDNS          `toml:"rdns"`
	ClickHouse    ClickHouse    `toml:"clickhouse"`
}

// RegistryCrawl groups the [registry-crawl.*] tables.
type RegistryCrawl struct {
	Worker RegistryCrawlWorker `toml:"worker"`
	Seed   RegistryCrawlSeed   `toml:"seed"`
	Bulk   RegistryCrawlBulk   `toml:"bulk"`
}

// RegistryCrawlWorker is [registry-crawl.worker]: the durable crawl_target
// queue workers. `enabled` starts autnum workers; `ipnet` starts ipnet
// workers in the same process.
type RegistryCrawlWorker struct {
	Enabled         bool     `toml:"enabled"`
	Ipnet           bool     `toml:"ipnet"`
	OnlyRegistries  []string `toml:"only-registries"`
	IncludeBulkGaps bool     `toml:"include-bulk-gaps"`
	Lease           Duration `toml:"lease"`
	Batch           int      `toml:"batch"`
	Proxies         []string `toml:"proxies"`
}

// RegistryCrawlSeed is [registry-crawl.seed]: NRO delegated-stats refresh
// plus crawl_target enqueue (autnum, ipnet, RouteViews RIBs), same as
// `registry-crawl seed`.
type RegistryCrawlSeed struct {
	Enabled           bool     `toml:"enabled"`
	Interval          Duration `toml:"interval"`
	SkipRIBs          bool     `toml:"skip-ribs"`
	DelegatedStatsURL string   `toml:"delegated-stats-url"`
	// OnlyRegistries limits the seed to these RIRs. Empty means all five.
	OnlyRegistries []string `toml:"only-registries"`
}

// RegistryCrawlBulk is [registry-crawl.bulk]: bulk whois dumps, same as
// `registry-crawl bulk`.
type RegistryCrawlBulk struct {
	Enabled          bool     `toml:"enabled"`
	Period           Duration `toml:"period"`
	BufferMaxSize    int      `toml:"buffer-max-size"`
	WithRouteObjects bool     `toml:"with-route-objects"`
	Prefetch         int      `toml:"prefetch"`
	AsnamesURL       string   `toml:"asnames-url"`
}

// GeoNames is [geonames].
type GeoNames struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
}

// PeeringDB is [peeringdb]. The API key is OPR_PEERINGDB_APIKEY.
type PeeringDB struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
	Force    bool     `toml:"force"`
}

// ASPop is [aspop].
type ASPop struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
}

// GeoIP groups the [geoip.*] tables.
type GeoIP struct {
	Lacnic        GeoIPLacnic        `toml:"lacnic"`
	IPMap         GeoIPIPMap         `toml:"ipmap"`
	Anycast       GeoIPAnycast       `toml:"anycast"`
	CrawlGeofeeds GeoIPCrawlGeofeeds `toml:"crawl-geofeeds"`
}

// GeoIPLacnic is [geoip.lacnic]: the LACNIC inetnum CSV on interval.
type GeoIPLacnic struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
}

// GeoIPIPMap is [geoip.ipmap]: the RIPE IPmap dump on interval.
type GeoIPIPMap struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
	// Force ignores the stored ETag. Default false, so a normal daemon run
	// still skips an unchanged dump.
	Force bool `toml:"force"`
}

// GeoIPAnycast is [geoip.anycast]: bgptools anycatch CSVs on interval.
type GeoIPAnycast struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
	// Force ignores the stored ETag. Default false.
	Force bool `toml:"force"`
}

// GeoIPCrawlGeofeeds is [geoip.crawl-geofeeds]: the continuous geofeeds crawl.
type GeoIPCrawlGeofeeds struct {
	Enabled                 bool     `toml:"enabled"`
	GeofeedRefreshOlderThan Duration `toml:"geofeed-refresh-older-than"`
	WorkerCount             int      `toml:"worker-count"`
}

// RPKI groups the [rpki.*] tables.
type RPKI struct {
	Ingest RPKIIngest `toml:"ingest"`
}

// RPKIIngest is [rpki.ingest].
type RPKIIngest struct {
	Enabled                bool     `toml:"enabled"`
	Interval               Duration `toml:"interval"`
	RoutinatorAddr         string   `toml:"routinator-addr"`
	RoutinatorFallbackAddr string   `toml:"routinator-fallback-addr"`
}

// FDNS groups the [fdns.*] tables.
type FDNS struct {
	IngestLists FDNSIngestLists `toml:"ingest-lists"`
	Resolve     FDNSResolve     `toml:"resolve"`
	IngestCC    FDNSIngestCC    `toml:"ingest-cc"`
	SeedQueue   FDNSSeedQueue   `toml:"seed-queue"`
}

// FDNSIngestLists is [fdns.ingest-lists].
type FDNSIngestLists struct {
	Enabled     bool     `toml:"enabled"`
	Interval    Duration `toml:"interval"`
	Only        []string `toml:"only"`
	TrancoURL   string   `toml:"tranco-url"`
	UmbrellaURL string   `toml:"umbrella-url"`
	CruxURL     string   `toml:"crux-url"`
}

// FDNSResolve is [fdns.resolve]: the continuous fdns_resolve_queue worker.
type FDNSResolve struct {
	Enabled  bool     `toml:"enabled"`
	Resolver []string `toml:"resolver"`
	QPS      float64  `toml:"qps"`
	AF       string   `toml:"af"`
	Lease    Duration `toml:"lease"`
	Batch    int      `toml:"batch"`
	Timeout  Duration `toml:"timeout"`
}

// FDNSIngestCC is [fdns.ingest-cc]: Common Crawl Host Index into ClickHouse.
type FDNSIngestCC struct {
	Enabled     bool     `toml:"enabled"`
	Interval    Duration `toml:"interval"`
	KeepParquet bool     `toml:"keep-parquet"`
	ParquetDir  string   `toml:"parquet-dir"`
	Crawl       string   `toml:"crawl"`
}

// FDNSSeedQueue is [fdns.seed-queue].
type FDNSSeedQueue struct {
	Enabled        bool     `toml:"enabled"`
	Interval       Duration `toml:"interval"`
	Limit          int      `toml:"limit"`
	QueueHighWater int      `toml:"queue-high-water"`
	Order          string   `toml:"order"`
	MinFetch200    int64    `toml:"min-fetch-200"`
	MinHCRank10    float64  `toml:"min-hcrank10"`
	MinPRank10     float64  `toml:"min-prank10"`
	TLD            []string `toml:"tld"`
	Crawl          string   `toml:"crawl"`
	StaleAfter     Duration `toml:"stale-after"`
}

// RDNS groups the [rdns.*] tables.
type RDNS struct {
	Ingest   RDNSIngest   `toml:"ingest"`
	CrawlPTR RDNSCrawlPTR `toml:"crawl-ptr"`
}

// RDNSIngest is [rdns.ingest].
type RDNSIngest struct {
	Enabled         bool     `toml:"enabled"`
	Interval        Duration `toml:"interval"`
	OnlyRegistries  []string `toml:"only-registries"`
	RIPEURL         string   `toml:"ripe-url"`
	APNICURL        string   `toml:"apnic-url"`
	ARINURL         string   `toml:"arin-url"`
	AFRINICURL      string   `toml:"afrinic-url"`
	LACNICURL       string   `toml:"lacnic-url"`
	SkipIANA        bool     `toml:"skip-iana"`
	IANAInAddrURL   string   `toml:"iana-inaddr-url"`
	IANAIP6URL      string   `toml:"iana-ip6-url"`
	SkipWhois       bool     `toml:"skip-whois"`
	RIPEDomainURL   string   `toml:"ripe-domain-url"`
	APNICDomainURL  string   `toml:"apnic-domain-url"`
	AFRINICDBURL    string   `toml:"afrinic-db-url"`
	SkipLacnicWhois bool     `toml:"skip-lacnic-whois"`
	LacnicDBURL     string   `toml:"lacnic-db-url"`
}

// RDNSCrawlPTR is [rdns.crawl-ptr]: the continuous /24 block queue.
type RDNSCrawlPTR struct {
	Enabled        bool     `toml:"enabled"`
	QPS            float64  `toml:"qps"`
	Timeout        Duration `toml:"timeout"`
	OnlyRegistries []string `toml:"only-registries"`
}

// ClickHouse is [clickhouse]. The password is OPR_CLICKHOUSE_PASSWORD.
type ClickHouse struct {
	URL      string   `toml:"url"`
	Database string   `toml:"database"`
	User     string   `toml:"user"`
	Timeout  Duration `toml:"timeout"`
}

// Default returns the configuration an empty file produces: every job
// enabled, every setting at its one-shot flag default.
func Default() *Config {
	return &Config{
		RegistryCrawl: RegistryCrawl{
			Worker: RegistryCrawlWorker{
				Enabled:        true,
				Ipnet:          true,
				OnlyRegistries: []string{},
				Lease:          Duration(DefaultRDAPLease),
				Batch:          DefaultRDAPBatch,
				Proxies:        []string{},
			},
			Seed: RegistryCrawlSeed{
				Enabled:           true,
				Interval:          Duration(DefaultSeedInterval),
				DelegatedStatsURL: nro.DefaultDelegatedStatsURL,
				OnlyRegistries:    []string{},
			},
			Bulk: RegistryCrawlBulk{
				Enabled:          true,
				Period:           Duration(DefaultWhoisDBPeriod),
				BufferMaxSize:    DefaultWhoisDBBufferMaxSize,
				WithRouteObjects: true,
				Prefetch:         whoisdb.DefaultPrefetchDepth,
				AsnamesURL:       asnames.DefaultURL,
			},
		},
		GeoNames: GeoNames{
			Enabled:  true,
			Interval: Duration(geonames.DefaultCrawlInterval),
		},
		PeeringDB: PeeringDB{
			Enabled:  true,
			Interval: Duration(peeringdb.DefaultCrawlInterval),
		},
		ASPop: ASPop{
			Enabled:  true,
			Interval: Duration(DefaultASPopInterval),
		},
		GeoIP: GeoIP{
			Lacnic: GeoIPLacnic{
				Enabled:  true,
				Interval: Duration(DefaultGeoIPLacnicInterval),
			},
			IPMap: GeoIPIPMap{
				Enabled:  true,
				Interval: Duration(DefaultGeoIPIPMapInterval),
			},
			Anycast: GeoIPAnycast{
				Enabled:  true,
				Interval: Duration(DefaultGeoIPAnycastInterval),
			},
			CrawlGeofeeds: GeoIPCrawlGeofeeds{
				Enabled:                 true,
				GeofeedRefreshOlderThan: Duration(geofeeds.DefaultRefreshOlderThan),
				WorkerCount:             geofeeds.DefaultWorkerCount,
			},
		},
		RPKI: RPKI{
			Ingest: RPKIIngest{
				Enabled:        true,
				Interval:       Duration(DefaultRPKIInterval),
				RoutinatorAddr: rpki.DefaultRoutinatorAddr,
			},
		},
		FDNS: FDNS{
			IngestLists: FDNSIngestLists{
				Enabled:     true,
				Interval:    Duration(DefaultFDNSListsInterval),
				Only:        []string{},
				TrancoURL:   fdns.DefaultTrancoURL,
				UmbrellaURL: fdns.DefaultUmbrellaURL,
				CruxURL:     fdns.DefaultCrUXURL,
			},
			Resolve: FDNSResolve{
				Enabled:  true,
				Resolver: append([]string(nil), fdns.DefaultResolverAddrs...),
				QPS:      fdns.DefaultResolveQPS,
				AF:       "both",
				Lease:    Duration(fdns.DefaultResolveLease),
				Batch:    fdns.DefaultResolveBatch,
				Timeout:  Duration(fdns.DefaultResolveTimeout),
			},
			IngestCC: FDNSIngestCC{
				Enabled:     true,
				Interval:    Duration(DefaultFDNSCCInterval),
				KeepParquet: true,
				ParquetDir:  fdns.DefaultParquetDir(),
			},
			SeedQueue: FDNSSeedQueue{
				Enabled:    true,
				Interval:   Duration(DefaultFDNSSeedInterval),
				Limit:      fdns.DefaultSeedQueueLimit,
				Order:      "key",
				TLD:        []string{},
				StaleAfter: Duration(fdns.DefaultResolveStaleAfter),
			},
		},
		RDNS: RDNS{
			Ingest: RDNSIngest{
				Enabled:        true,
				Interval:       Duration(DefaultRDNSIngestInterval),
				OnlyRegistries: []string{},
				RIPEURL:        rdns.DefaultRIPEZonesURL,
				APNICURL:       rdns.DefaultAPNICZonesURL,
				ARINURL:        rdns.DefaultARINZonesURL,
				AFRINICURL:     rdns.DefaultAFRINICZonesURL,
				LACNICURL:      rdns.DefaultLACNICZonesURL,
				IANAInAddrURL:  rdns.DefaultIANAInAddrURL,
				IANAIP6URL:     rdns.DefaultIANAIP6URL,
				RIPEDomainURL:  rdns.DefaultRIPEDomainURL,
				APNICDomainURL: rdns.DefaultAPNICDomainURL,
				AFRINICDBURL:   rdns.DefaultAFRINICWhoisURL,
				LacnicDBURL:    rdns.DefaultLACNICWhoisDBURL,
			},
			CrawlPTR: RDNSCrawlPTR{
				Enabled:        true,
				QPS:            rdns.DefaultPTRQPS,
				Timeout:        Duration(rdns.DefaultPTRTimeout),
				OnlyRegistries: []string{},
			},
		},
		ClickHouse: ClickHouse{
			URL:      clickhouse.DefaultURL,
			Database: clickhouse.DefaultDatabase,
			User:     clickhouse.DefaultUser,
			Timeout:  Duration(clickhouse.DefaultTimeout),
		},
	}
}

// DefaultPath is os.UserHomeDir() + "/.config/opr.config.toml".
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve default config path: %w", err)
	}
	return filepath.Join(home, DefaultRelativePath), nil
}

// ResolvePath picks the config path: the --config flag value, then the
// OPR_CONFIG environment variable, then DefaultPath. It does not check
// that the file exists.
func ResolvePath(flagValue string) (string, error) {
	if p := strings.TrimSpace(flagValue); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv(EnvConfig)); p != "" {
		return p, nil
	}
	return DefaultPath()
}

// Load reads and parses the file at path. A missing file is an error; Load
// never creates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %s does not exist; copy config/opr.example.toml there or pass --config / set %s", path, EnvConfig)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes TOML bytes on top of Default. Unknown keys and secret keys
// are errors; the result is validated.
func Parse(data []byte) (*Config, error) {
	if err := rejectSecretKeys(data); err != nil {
		return nil, err
	}
	cfg := Default()
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return nil, fmt.Errorf("unknown key: %s", strings.TrimSpace(strict.String()))
		}
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectSecretKeys walks the raw document and refuses dsn / postgres-db /
// password / apikey / clickhouse-password wherever they appear.
func rejectSecretKeys(data []byte) error {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return err
	}
	return walkSecretKeys("", raw)
}

func walkSecretKeys(prefix string, m map[string]any) error {
	for k, v := range m {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		if env, ok := secretKeys[strings.ToLower(k)]; ok {
			return fmt.Errorf("key %q is a secret and may not be set in the config file; set the %s environment variable instead", full, env)
		}
		switch child := v.(type) {
		case map[string]any:
			if err := walkSecretKeys(full, child); err != nil {
				return err
			}
		case []map[string]any:
			for _, c := range child {
				if err := walkSecretKeys(full, c); err != nil {
					return err
				}
			}
		case []any:
			for _, c := range child {
				if cm, ok := c.(map[string]any); ok {
					if err := walkSecretKeys(full, cm); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

var validRegistries = []string{opconst.AFRINIC, opconst.APNIC, opconst.ARIN, opconst.LACNIC, opconst.RIPE}

// Validate checks values that would otherwise fail deep inside a job.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	positive := func(key string, d Duration) {
		if d.Std() <= 0 {
			add("%s must be a positive duration, got %s", key, d)
		}
	}
	registries := func(key string, names []string) {
		for _, r := range names {
			if !slices.Contains(validRegistries, strings.ToUpper(strings.TrimSpace(r))) {
				add("%s: unknown registry %q; valid names: %s", key, r, strings.Join(validRegistries, ", "))
			}
		}
	}
	// normalizeRegistries uppercases registry names so "arin" matches ARIN.
	normalizeRegistries := func(key string, names []string) []string {
		out := make([]string, len(names))
		for i, r := range names {
			u := strings.ToUpper(strings.TrimSpace(r))
			out[i] = u
			if !slices.Contains(validRegistries, u) {
				add("%s: unknown registry %q; valid names: %s", key, r, strings.Join(validRegistries, ", "))
			}
		}
		return out
	}

	wc := &c.RegistryCrawl.Worker
	positive("registry-crawl.worker.lease", wc.Lease)
	if wc.Batch < 1 {
		add("registry-crawl.worker.batch must be >= 1, got %d", wc.Batch)
	}
	wc.OnlyRegistries = normalizeRegistries("registry-crawl.worker.only-registries", wc.OnlyRegistries)
	for i, raw := range wc.Proxies {
		trimmed := strings.TrimSpace(raw)
		wc.Proxies[i] = trimmed
		// Keep userinfo. The parse error from net/url includes the raw input,
		// which may be a password, so the message only names the index.
		if _, err := url.Parse(trimmed); err != nil {
			add("registry-crawl.worker.proxies: invalid proxy URL at index %d", i)
		}
	}

	sc := &c.RegistryCrawl.Seed
	positive("registry-crawl.seed.interval", sc.Interval)
	sc.OnlyRegistries = normalizeRegistries("registry-crawl.seed.only-registries", sc.OnlyRegistries)

	bc := &c.RegistryCrawl.Bulk
	positive("registry-crawl.bulk.period", bc.Period)
	if bc.BufferMaxSize < 1 {
		add("registry-crawl.bulk.buffer-max-size must be >= 1, got %d", bc.BufferMaxSize)
	}
	if bc.Prefetch < 1 {
		add("registry-crawl.bulk.prefetch must be >= 1, got %d", bc.Prefetch)
	}

	positive("geonames.interval", c.GeoNames.Interval)
	positive("peeringdb.interval", c.PeeringDB.Interval)
	positive("aspop.interval", c.ASPop.Interval)

	positive("geoip.lacnic.interval", c.GeoIP.Lacnic.Interval)
	positive("geoip.ipmap.interval", c.GeoIP.IPMap.Interval)
	positive("geoip.anycast.interval", c.GeoIP.Anycast.Interval)
	positive("geoip.crawl-geofeeds.geofeed-refresh-older-than", c.GeoIP.CrawlGeofeeds.GeofeedRefreshOlderThan)
	if c.GeoIP.CrawlGeofeeds.WorkerCount < 1 {
		add("geoip.crawl-geofeeds.worker-count must be >= 1, got %d", c.GeoIP.CrawlGeofeeds.WorkerCount)
	}

	ri := &c.RPKI.Ingest
	positive("rpki.ingest.interval", ri.Interval)
	if strings.TrimSpace(ri.RoutinatorAddr) == "" {
		add("rpki.ingest.routinator-addr must not be empty")
	}

	positive("fdns.ingest-lists.interval", c.FDNS.IngestLists.Interval)
	if _, err := fdns.SelectLists(fdns.DefaultLists(), c.FDNS.IngestLists.Only); err != nil {
		add("fdns.ingest-lists.only: %v", err)
	}
	if _, _, err := fdns.ParseAF(c.FDNS.Resolve.AF); err != nil {
		add("fdns.resolve.af: %v", err)
	}
	if _, err := fdns.ParseResolverAddrs(c.FDNS.Resolve.Resolver); err != nil {
		add("fdns.resolve.resolver: %v", err)
	}
	if c.FDNS.Resolve.QPS < 0 {
		add("fdns.resolve.qps must be >= 0, got %v", c.FDNS.Resolve.QPS)
	}
	positive("fdns.resolve.lease", c.FDNS.Resolve.Lease)
	positive("fdns.resolve.timeout", c.FDNS.Resolve.Timeout)
	if c.FDNS.Resolve.Batch < 1 {
		add("fdns.resolve.batch must be >= 1, got %d", c.FDNS.Resolve.Batch)
	}
	positive("fdns.ingest-cc.interval", c.FDNS.IngestCC.Interval)
	if strings.TrimSpace(c.FDNS.IngestCC.ParquetDir) == "" {
		add("fdns.ingest-cc.parquet-dir must not be empty")
	}
	positive("fdns.seed-queue.interval", c.FDNS.SeedQueue.Interval)
	switch c.FDNS.SeedQueue.Order {
	case "key", "rank":
	default:
		add("fdns.seed-queue.order must be key or rank, got %q", c.FDNS.SeedQueue.Order)
	}
	if c.FDNS.SeedQueue.QueueHighWater < 0 {
		add("fdns.seed-queue.queue-high-water must be >= 0, got %d", c.FDNS.SeedQueue.QueueHighWater)
	}

	positive("rdns.ingest.interval", c.RDNS.Ingest.Interval)
	registries("rdns.ingest.only-registries", c.RDNS.Ingest.OnlyRegistries)
	if c.RDNS.CrawlPTR.QPS <= 0 {
		add("rdns.crawl-ptr.qps must be > 0, got %v", c.RDNS.CrawlPTR.QPS)
	}
	positive("rdns.crawl-ptr.timeout", c.RDNS.CrawlPTR.Timeout)
	registries("rdns.crawl-ptr.only-registries", c.RDNS.CrawlPTR.OnlyRegistries)

	if strings.TrimSpace(c.ClickHouse.URL) == "" {
		add("clickhouse.url must not be empty")
	} else if err := RejectClickHouseURLUserinfo(c.ClickHouse.URL, "clickhouse.url"); err != nil {
		errs = append(errs, err)
	}
	positive("clickhouse.timeout", c.ClickHouse.Timeout)

	return errors.Join(errs...)
}

// RejectClickHouseURLUserinfo refuses http://user:pass@host forms. Auth uses
// OPR_CLICKHOUSE_PASSWORD (X-ClickHouse-Key), never URL userinfo. The error
// never echoes the password or the raw URL.
func RejectClickHouseURLUserinfo(raw, label string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s: invalid URL", label)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo; set %s instead", label, EnvClickHousePassword)
	}
	return nil
}

// AnyEnabled reports whether at least one job would start.
func (c *Config) AnyEnabled() bool {
	return c.RegistryCrawl.Worker.Enabled || c.RegistryCrawl.Worker.Ipnet ||
		c.RegistryCrawl.Seed.Enabled || c.RegistryCrawl.Bulk.Enabled ||
		c.GeoNames.Enabled || c.PeeringDB.Enabled || c.ASPop.Enabled ||
		c.GeoIP.Lacnic.Enabled || c.GeoIP.IPMap.Enabled || c.GeoIP.Anycast.Enabled ||
		c.GeoIP.CrawlGeofeeds.Enabled || c.RPKI.Ingest.Enabled ||
		c.FDNS.IngestLists.Enabled || c.FDNS.Resolve.Enabled ||
		c.FDNS.IngestCC.Enabled || c.FDNS.SeedQueue.Enabled ||
		c.RDNS.Ingest.Enabled || c.RDNS.CrawlPTR.Enabled
}
