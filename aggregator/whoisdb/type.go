package whoisdb

import (
	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"
	"net/http"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"go.uber.org/zap"
)

const WhoisDB = "whoisdb"

// Line charsets. RIR dumps are not consistent: a UTF-8 file decoded as latin-1
// turns every accented name into mojibake, while raw latin-1 bytes left
// undecoded are invalid UTF-8 and a UTF8 Postgres database rejects the INSERT
// outright. Neither fixed choice is correct for the whole source list, so the
// default resolves per line.
const (
	// CharsetAuto decodes a line as ISO-8859-1 only when it is not already
	// valid UTF-8. Every byte has an ISO-8859-1 mapping, so this never fails.
	CharsetAuto    = "auto"
	CharsetUTF8    = "utf-8"
	CharsetISO8859 = "iso-8859-1"
)

// parseConfig is per-parse state. It is deliberately NOT stored on
// WhoisDBAggregator: the old WithCharsetISO8859 option set an aggregator-wide
// field that nothing ever reset, so one latin-1 file silently switched every
// later file in the run to latin-1 decoding.
type parseConfig struct {
	charset string
}

// ParseOption configures a single ParseWhoisDBFile call.
type ParseOption func(*parseConfig)

// WithCharset pins the charset used to decode lines of one file.
func WithCharset(charset string) ParseOption {
	return func(cfg *parseConfig) {
		if charset != "" {
			cfg.charset = charset
		}
	}
}

type whoisDBSource struct {
	url             string
	isAuthoritative bool
	source          string
	recordType      opconst.RecordType
	// charset pins this source's encoding when it is known to differ from
	// what the server declares. Empty means resolve at fetch time.
	charset string
}

type WhoisDBAggregator struct {
	Name             string `json:"name"`
	HTTPClient       *http.Client
	Logger           *zap.Logger
	Store            *postgres.Store
	WithRouteFetch   bool
	RecordChan       chan whoisdb_store.WhoisRecord
	ForceSaveSignal  chan struct{}
	SavingDoneSignal chan struct{}
	// Geofeeds we saw when parsing all whoisdb file,
	// and how many we save to the database at a time.
	Geofeeds mapset.Set[string]
	// Used to buffer records before saving to database
	BufferMaxSize  int
	BufferASN      []*whoisdb_store.WhoisAutNum
	BufferInetNum  []*whoisdb_store.WhoisInetNum
	BufferInet6Num []*whoisdb_store.WhoisInet6Num
	BufferOrg      []*whoisdb_store.WhoisOrganization
	BufferRole     []*whoisdb_store.WhoisRole
	BufferRoute    []*whoisdb_store.WhoisRoute
	BufferRoute6   []*whoisdb_store.WhoisRoute6
	BufferAsSet    []*whoisdb_store.WhoisAsSet
	BufferAsBlock  []*whoisdb_store.WhoisAsBlock
	BufferIrt      []*whoisdb_store.WhoisIrt
	// PrefetchDepth bounds how many sources are downloaded to temp files ahead
	// of the parse loop. It caps concurrent downloads and temp files on disk.
	PrefetchDepth int
	// AsNamesURL overrides the RIPE asnames.txt source. Empty means DefaultURL.
	AsNamesURL string
	// Status metadata
	StatusMetadata WhoisDBStatusMetadata
	// Crawl Interval is the interval between two consecutive whoisdb file fetches.
	CrawlInterval time.Duration
}

type WhoisDBStatusMetadata struct {
	IsRunning         bool                         `json:"is_running"`
	IsHealthy         *bool                        `json:"is_healthy"`
	HealthyRatio      float64                      `json:"healthy_ratio"`
	IRRHealthyRatio   float64                      `json:"irr_healthy_ratio"`
	StartTime         time.Time                    `json:"start_time"`
	NextFetchTime     time.Time                    `json:"next_fetch_time"`
	TotalJobDuration  time.Duration                `json:"total_job_duration"`
	TotalGeofeedCount int                          `json:"total_geofeed_count"`
	URLs              map[string]*WhoisDBURLStatus `json:"urls"`
}

type WhoisDBURLStatus struct {
	URL string `json:"url"`
	// RecordTypes is the object-type set this job accepted. The same URL is
	// fetched by both passes for disjoint types (ARIN and AFRINIC ship mixed
	// dumps), so URL alone does not identify a job.
	RecordTypes        []string                     `json:"record_types"`
	Source             string                       `json:"source"`
	IsAuthoritative    bool                         `json:"is_authoritative"`
	Charset            string                       `json:"charset"`
	HTTPStatus         string                       `json:"http_status"`
	FetchError         string                       `json:"fetch_error"`
	LineCount          int64                        `json:"lines_count"`
	ParsedRecordsCount map[opconst.RecordType]int64 `json:"parsed_item_count"`
	SavedRecordsCount  map[opconst.RecordType]int64 `json:"saved_item_count"`
	GeofeedCount       int                          `json:"geofeed_count"`
	StartTime          time.Time                    `json:"start_time"`
	HasChanged         bool                         `json:"has_changed"`
	IsRunning          bool                         `json:"is_running"`
	JobDuration        time.Duration                `json:"job_duration"`
	IsHealthy          *bool                        `json:"is_healthy"`
	IsSaved            bool                         `json:"is_saved"`
}
