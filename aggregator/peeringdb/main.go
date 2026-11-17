package peeringdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/internal/oplog"
	"github.com/oprand/opr/internal/opnet"
	"github.com/oprand/opr/store/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

const (
	PeeringDB = "peeringdb"

	// UserAgent identifies this client on dump HEAD/GET and API overlay.
	UserAgent = "opr-peeringdb"

	// APIBase is the live REST API used only for optional private overlay.
	APIBase = "https://www.peeringdb.com/api"

	apiPageLimit = 250
)

// DefaultCrawlInterval is how often the daemon re-fetches dumps. Status
// --stale-after defaults to 2× this window so a stable dump does not flap
// STALE between crawls.
const DefaultCrawlInterval = 24 * time.Hour

// dumpStore is the test seam for dump ingest (see memDumpStore in tests).
type dumpStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	TouchRemoteFileMetadata(ctx context.Context, url string) error
	ReplacePeeringDBTable(ctx context.Context, table string, src pgx.CopyFromSource) (int64, error)
}

var _ dumpStore = (*postgres.Store)(nil)

// PeeringDBSynchronizationClient holds the dump HTTP client and database.
type PeeringDBSynchronizationClient struct {
	Name   string
	APIKey string
	Force  bool
	Store  *postgres.Store
	Logger *zap.Logger
	HTTP   *http.Client
	dump   dumpStore
	// Status metadata
	StatusMetadata struct {
		IsRunning         bool          `json:"is_running"`
		IsHealthy         *bool         `json:"is_healthy"`
		IsSavedToDatabase bool          `json:"is_saved_to_database"`
		StartTime         time.Time     `json:"start_time"`
		LastFetchTime     time.Time     `json:"last_fetch_time"`
		JobDuration       time.Duration `json:"job_duration"`
		NextFetchTime     time.Time     `json:"next_fetch_time"`
		DumpsChanged      []string      `json:"dumps_changed"`
	}
	// Crawler interval
	CrawlInterval time.Duration
}

// New builds a client on an existing logger and store. apiKey may be empty
// (public dumps only). The caller owns the store.
func New(logger *zap.Logger, store *postgres.Store, apiKey string, force bool) *PeeringDBSynchronizationClient {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &PeeringDBSynchronizationClient{
		Name:          PeeringDB,
		APIKey:        apiKey,
		Force:         force,
		Store:         store,
		Logger:        logger,
		HTTP:          newDumpHTTPClient(),
		CrawlInterval: DefaultCrawlInterval,
	}
}

// NewPeeringDBClient is the one-shot constructor: logger, store, --apikey
// and --force from the CLI flags, migrations applied.
func NewPeeringDBClient(c *cli.Context) (*PeeringDBSynchronizationClient, error) {
	logger, err := oplog.NewFromCli(c)
	if err != nil {
		return nil, err
	}
	logger = logger.Named("opr.peeringdb")

	DSN := c.String("dsn")
	if !strings.HasPrefix(DSN, "postgresql://") {
		return nil, fmt.Errorf("--dsn value must start with `postgresql://`")
	}
	pgStore, err := postgres.New(logger.Named("store"), DSN)
	if err != nil {
		return nil, err
	}
	if err = postgres.RunMigrations(logger.Named("store"), DSN); err != nil {
		return nil, err
	}

	return New(logger, pgStore, c.String("apikey"), c.Bool("force")), nil
}

func (s *PeeringDBSynchronizationClient) dumpDB() dumpStore {
	if s.dump != nil {
		return s.dump
	}
	return s.Store
}

func newDumpHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Minute,
		Transport: &uaTransport{
			base: http.DefaultTransport,
			ua:   UserAgent,
		},
	}
}

type uaTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func (s *PeeringDBSynchronizationClient) GetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if s.StatusMetadata.LastFetchTime.IsZero() {
		s.StatusMetadata.IsHealthy = nil
	} else if s.StatusMetadata.LastFetchTime.After(time.Now().Add(-12 * time.Hour)) {
		isHealthy := true
		s.StatusMetadata.IsHealthy = &isHealthy
	} else {
		isHealthy := false
		s.StatusMetadata.IsHealthy = &isHealthy
	}
	s.StatusMetadata.StartTime = s.StatusMetadata.StartTime.UTC()
	json.NewEncoder(w).Encode(s.StatusMetadata)
}

func (s *PeeringDBSynchronizationClient) DoPeeringDbSync(ctx context.Context) error {
	s.Logger.Info("starting peeringdb dump synchronization")

	startTime := time.Now()
	s.StatusMetadata.IsRunning = true
	s.StatusMetadata.StartTime = startTime
	s.StatusMetadata.LastFetchTime = time.Time{}
	s.StatusMetadata.JobDuration = 0
	s.StatusMetadata.IsSavedToDatabase = false
	s.StatusMetadata.DumpsChanged = nil
	defer func() {
		s.StatusMetadata.IsRunning = false
		s.StatusMetadata.JobDuration = time.Since(s.StatusMetadata.StartTime)
	}()

	var dumpsChanged []string
	var errs []error

	for _, dump := range postgres.PeeringDBDumps {
		changed, err := s.ingestDump(ctx, dump)
		if err != nil {
			s.Logger.Error("peeringdb dump failed", zap.String("tag", dump.Tag), zap.Error(err))
			errs = append(errs, fmt.Errorf("%s: %w", dump.Tag, err))
			continue
		}
		if changed {
			dumpsChanged = append(dumpsChanged, dump.Tag)
		}
	}
	s.StatusMetadata.DumpsChanged = dumpsChanged

	if s.APIKey != "" {
		overlayChanged, err := s.applyPrivateOverlay(ctx)
		if err != nil {
			s.Logger.Error("peeringdb private overlay failed", zap.Error(err))
			errs = append(errs, err)
		} else if overlayChanged {
			dumpsChanged = append(dumpsChanged, "overlay")
			s.StatusMetadata.DumpsChanged = dumpsChanged
		}
	}

	s.StatusMetadata.LastFetchTime = time.Now()
	s.StatusMetadata.IsSavedToDatabase = true

	if len(dumpsChanged) == 0 {
		if len(errs) > 0 {
			return errs[0]
		}
		s.Logger.Info("all peeringdb dumps unchanged")
		return nil
	}

	s.Logger.Info("finished peeringdb dump synchronization",
		zap.Strings("changed", dumpsChanged),
		zap.Duration("duration", time.Since(startTime)))

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (s *PeeringDBSynchronizationClient) ingestDump(ctx context.Context, dump postgres.PeeringDBDumpRef) (bool, error) {
	return s.ifChanged(ctx, dump.URL, func() (*postgres.ResponseMetadataItem, error) {
		startTime := time.Now()
		resp, err := s.getOK(ctx, dump.URL, "")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		getMeta := dumpMetadataFromHeader(dump.URL, resp.Header)

		src, err := newDumpCopySource(resp.Body, func(obj map[string]any) ([]any, bool) {
			return MapDumpRow(dump.Tag, obj)
		})
		if err != nil {
			return nil, err
		}
		n, err := s.dumpDB().ReplacePeeringDBTable(ctx, dump.Table, src)
		if errors.Is(err, postgres.ErrPeeringDBEmptyDump) {
			s.Logger.Warn("peeringdb dump empty, keeping previous table",
				zap.String("tag", dump.Tag),
				zap.String("table", dump.Table))
			return nil, postgres.ErrPeeringDBEmptyDump
		}
		if err != nil {
			return nil, err
		}
		if src.Err() != nil {
			return nil, src.Err()
		}
		if !ShouldReplacePeeringDBDump(int(n)) {
			return nil, postgres.ErrPeeringDBEmptyDump
		}
		s.Logger.Info("processed peeringdb dump",
			zap.String("tag", dump.Tag),
			zap.String("table", dump.Table),
			zap.Int64("rows", n),
			zap.Duration("duration", time.Since(startTime)))
		return getMeta, nil
	})
}

// ifChanged is the ETag gate. Default HEADs via HasFileChanged and skips GET
// when the ETag is unchanged (still TouchRemoteFileMetadata). --force skips
// the HEAD and always GET + COPY-swap; metadata is taken from the GET
// response headers, matching geoip ipmap/anycast.
func (s *PeeringDBSynchronizationClient) ifChanged(ctx context.Context, dumpURL string, load func() (*postgres.ResponseMetadataItem, error)) (bool, error) {
	db := s.dumpDB()
	var newMetadata *postgres.ResponseMetadataItem
	if !s.Force {
		var changed bool
		newMetadata, changed = s.fileChanged(dumpURL)
		if !changed {
			s.Logger.Info("peeringdb dump unchanged", zap.String("url", dumpURL))
			if newMetadata == nil {
				return false, nil
			}
			if err := db.TouchRemoteFileMetadata(ctx, dumpURL); err != nil {
				return false, err
			}
			return false, nil
		}
		if newMetadata == nil {
			s.Logger.Warn("unable to get new metadata for peeringdb dump, downloading anyway")
		}
	}
	getMeta, err := load()
	if err != nil {
		if errors.Is(err, postgres.ErrPeeringDBEmptyDump) {
			return false, nil
		}
		return false, err
	}
	if newMetadata == nil {
		newMetadata = getMeta
	}
	db.SaveResponseMetadata(newMetadata)
	return true, nil
}

func (s *PeeringDBSynchronizationClient) fileChanged(url string) (*postgres.ResponseMetadataItem, bool) {
	if s.dump == nil {
		return opnet.HasFileChanged(s.Store, s.HTTP, url)
	}
	return dumpFileChanged(s.dump, s.HTTP, url)
}

// dumpFileChanged is HasFileChanged against dumpStore so tests can inject a
// mem postgres. Production (dump == nil) uses opnet.HasFileChanged.
func dumpFileChanged(st dumpStore, client *http.Client, url string) (*postgres.ResponseMetadataItem, bool) {
	prev := st.GetResponseMetadata(url)
	if prev == nil {
		now := time.Now()
		return &postgres.ResponseMetadataItem{
			Url:         url,
			MetaAddedAt: &now,
		}, true
	}

	resp, err := client.Head(url)
	if err != nil || resp == nil {
		return nil, true
	}
	defer resp.Body.Close()

	newMetadata := dumpMetadataFromHeader(url, resp.Header)
	if prev.Etag != nil && newMetadata.Etag != nil && *prev.Etag == *newMetadata.Etag {
		return newMetadata, false
	}
	return newMetadata, true
}

func dumpMetadataFromHeader(url string, h http.Header) *postgres.ResponseMetadataItem {
	etag := h.Get("Etag")
	contentType := h.Get("Content-Type")
	contentLength, _ := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	lastModified, _ := time.Parse(http.TimeFormat, h.Get("Last-Modified"))
	now := time.Now()
	return &postgres.ResponseMetadataItem{
		Etag:          &etag,
		Url:           url,
		ContentType:   &contentType,
		ContentLength: &contentLength,
		LastModified:  &lastModified,
		MetaAddedAt:   &now,
	}
}

func (s *PeeringDBSynchronizationClient) applyPrivateOverlay(ctx context.Context) (bool, error) {
	pocChanged, err := s.overlayPOC(ctx)
	if err != nil {
		return false, err
	}
	ixlanChanged, err := s.overlayIXLAN(ctx)
	if err != nil {
		return pocChanged, err
	}
	return pocChanged || ixlanChanged, nil
}

func (s *PeeringDBSynchronizationClient) overlayPOC(ctx context.Context) (bool, error) {
	var keepIDs []int
	n, err := s.eachAPIPage(ctx, "poc", func(obj map[string]any) error {
		row, ok := MapOverlayRow(postgres.PeeringDBDumpTagPOC, obj)
		if !ok {
			return nil
		}
		if err := s.Store.UpsertPeeringDBNetworkContact(ctx, row); err != nil {
			return err
		}
		keepIDs = append(keepIDs, dumpInt(obj, "id"))
		return nil
	})
	if err != nil {
		return false, err
	}
	if n == 0 {
		s.Logger.Info("peeringdb poc overlay returned no rows")
		return false, nil
	}
	if err := s.Store.DeleteStalePrivatePeeringDBContacts(ctx, keepIDs); err != nil {
		return false, err
	}
	s.Logger.Info("applied peeringdb poc overlay", zap.Int("rows", n))
	return true, nil
}

func (s *PeeringDBSynchronizationClient) overlayIXLAN(ctx context.Context) (bool, error) {
	n, err := s.eachAPIPage(ctx, "ixlan", func(obj map[string]any) error {
		row, ok := MapOverlayRow(postgres.PeeringDBDumpTagIXLAN, obj)
		if !ok {
			return nil
		}
		return s.Store.UpsertPeeringDBIXLAN(ctx, row)
	})
	if err != nil {
		return false, err
	}
	if n == 0 {
		s.Logger.Info("peeringdb ixlan overlay returned no rows")
		return false, nil
	}
	s.Logger.Info("applied peeringdb ixlan overlay", zap.Int("rows", n))
	return true, nil
}

func (s *PeeringDBSynchronizationClient) eachAPIPage(ctx context.Context, resource string, fn func(map[string]any) error) (int, error) {
	total := 0
	for skip := 0; ; skip += apiPageLimit {
		pageURL := APIBase + "/" + resource + "?limit=" + strconv.Itoa(apiPageLimit) + "&skip=" + strconv.Itoa(skip)
		resp, err := s.getOK(ctx, pageURL, s.APIKey)
		if err != nil {
			return total, err
		}
		n, err := decodeAPIPage(resp.Body, fn)
		resp.Body.Close()
		if err != nil {
			return total, err
		}
		total += n
		if n < apiPageLimit {
			return total, nil
		}
	}
}

func decodeAPIPage(r io.Reader, fn func(map[string]any) error) (int, error) {
	src, err := newDumpCopySource(r, func(obj map[string]any) ([]any, bool) {
		return []any{obj}, true
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for src.Next() {
		vals, err := src.Values()
		if err != nil {
			return n, err
		}
		obj, _ := vals[0].(map[string]any)
		if err := fn(obj); err != nil {
			return n, err
		}
		n++
	}
	return n, src.Err()
}

func (s *PeeringDBSynchronizationClient) getOK(ctx context.Context, rawURL, apiKey string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if apiKey != "" {
		req.Header.Set("Authorization", "Api-Key "+apiKey)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: status %d", rawURL, resp.StatusCode)
	}
	return resp, nil
}
