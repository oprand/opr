package registry

import (
	"github.com/oprand/opr/aggregator/nro"
	"github.com/oprand/opr/store/postgres"
	"net/url"
	"sync"
	"time"

	"github.com/oprand/opr/pkg/openrdap/rdap"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type Proxy struct {
	URL *url.URL
	// RdapClient is a long-lived client with its own persistent Transport, so
	// connections are reused and no shared client is mutated mid-flight.
	RdapClient *rdap.Client
}

type RingLoadBalancer struct {
	proxies []*Proxy
	index   int
	mu      sync.Mutex
}

// AdaptiveLimiter implements AIMD rate control for one destination RDAP host
// in *this process* (rdap.lacnic.net and rdap.registro.br are separate).
// On success it additively increases the request rate; on 429/403 it
// multiplicatively decreases the rate and pauses. LACNIC (and some others)
// omit Retry-After; a missing header still pauses, doubling on consecutive
// 429s, or the floor rate would keep firing forever.
//
// This is complementary to crawl_target.next_retry_at (queue backoff):
// the limiter paces how fast we hit that RIR; next_retry_at is when the
// *job* is due again so SKIP LOCKED workers do not stampede the same ASN.
// Do not fold queue backoff into AIMD or vice versa — that would double-delay
// on 429 or let other processes immediately re-claim a throttled object.
type AdaptiveLimiter struct {
	mu                  sync.Mutex
	limiter             *rate.Limiter
	cur                 rate.Limit
	min                 rate.Limit
	max                 rate.Limit
	addStep             rate.Limit
	backoff             float64
	pausedUntil         time.Time
	consecutiveThrottle int
}

type RegistryWorker struct {
	Name      string
	ProxyRing *RingLoadBalancer
	Limiter   *AdaptiveLimiter

	// rirSearch1 is cached from a one-shot RDAP help probe (rdapConformance
	// contains "rirSearch1"). Unprobed workers must not enqueue handle: jobs.
	rirSearchMu     sync.Mutex
	rirSearchProbed bool
	rirSearch1      bool
}

// CrawlConfig is how the CLI / daemon run crawl.Worker goroutines.
// Batch defaults to 1 so one in-flight object matches the per-RIR AIMD limiter;
// claiming many rows then processing sequentially would hold extra leases.
// Autnum and ipnet for the same destination host share that host's AdaptiveLimiter.
type CrawlConfig struct {
	Lease time.Duration
	Batch int
	Once  bool
}

type RegistryAggregator struct {
	Logger *zap.Logger
	Store  *postgres.Store
	//
	RegistriesOfInterest []string
	// Resolver is the source of truth for asn/prefix -> registry attribution,
	// backed by the NRO delegated_stats snapshot (replaces the IANA bootstrap).
	Resolver *nro.Resolver
	//
	RegistryWorkers map[string]*RegistryWorker
	// hostLimiters is AIMD keyed by RDAP hostname (rdap.lacnic.net vs
	// rdap.registro.br). Autnum and ipnet for the same host share one limiter
	// so a lacnic.net pause does not stall NIC.br.
	hostLimitersMu sync.Mutex
	hostLimiters   map[string]*AdaptiveLimiter
}
