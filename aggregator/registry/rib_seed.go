package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/oprand/opr/aggregator/connectivity"
	"github.com/oprand/opr/internal/opbgp"
	"github.com/oprand/opr/store/postgres"

	"github.com/bgptools/fgbgp/messages"
	mrt2 "github.com/bgptools/fgbgp/mrt"
	"github.com/dsnet/compress/bzip2"
	"go.uber.org/zap"
)

// DefaultRibSeedCollectors are the RouteViews collectors walked by the ipnet
// leftover seed. Three geographically spread collectors are enough: the seed
// needs the union of announced space, not per-collector visibility, and every
// extra collector is another full RIB decode for a shrinking set of new CIDRs.
var DefaultRibSeedCollectors = []string{"route-views3", "route-views.chile", "route-views.fortaleza"}

// errArchiveNotFound marks a RIB URL the archive has not published (yet).
var errArchiveNotFound = errors.New("rib archive not found")

// ribDownloadTimeout covers one full RIB transfer, not one request. A collector
// RIB is 100-200 MB compressed and is decoded as it arrives.
const ribDownloadTimeout = 30 * time.Minute

// RibSeeder walks full RouteViews RIBs and enqueues the announced ARIN/LACNIC
// prefixes that the NRO delegated ranges do not name directly (an assignment
// inside an allocation is a distinct RDAP object).
//
// It shares nothing with aggregator/connectivity except ForgeMtrFileUrl, the
// archive URL builder. This type only ever writes crawl_target.
type RibSeeder struct {
	Logger     *zap.Logger
	Store      *postgres.Store
	Collectors []opbgp.BgpLocation

	httpClient *http.Client
}

// NewRibSeeder resolves collector slugs against opbgp.BGPLocations so the
// archive URLs stay derived from the shared location list. Empty slugs means
// DefaultRibSeedCollectors.
func NewRibSeeder(logger *zap.Logger, st *postgres.Store, slugs []string) (*RibSeeder, error) {
	if len(slugs) == 0 {
		slugs = DefaultRibSeedCollectors
	}
	locs := make([]opbgp.BgpLocation, 0, len(slugs))
	for _, slug := range slugs {
		loc, err := bgpLocationBySlug(slug)
		if err != nil {
			return nil, err
		}
		locs = append(locs, loc)
	}
	return &RibSeeder{
		Logger:     logger.Named("rib-seed"),
		Store:      st,
		Collectors: locs,
		httpClient: &http.Client{Timeout: ribDownloadTimeout},
	}, nil
}

func bgpLocationBySlug(slug string) (opbgp.BgpLocation, error) {
	for _, loc := range opbgp.BGPLocations {
		if loc.Slug == slug {
			return loc, nil
		}
	}
	return opbgp.BgpLocation{}, fmt.Errorf("unknown bgp location slug: %s", slug)
}

// SeedIpnetFromRIBs decodes every configured collector in parallel, merges their
// NLRI into one de-duplicated CIDR set, and inserts the subset covered by a
// seedable registry as pending ipnet jobs. Wall time is the slowest collector,
// not their sum. registries follows the postgres.IpnetSeedRegistriesFor convention.
//
// A collector that fails is logged and skipped; an error is returned only when
// all of them failed, since a partial union still seeds useful work.
func (s *RibSeeder) SeedIpnetFromRIBs(ctx context.Context, registries []string) (postgres.IpnetSeedResult, error) {
	started := time.Now()

	type collectorResult struct {
		slug  string
		cidrs map[string]struct{}
		err   error
	}
	results := make([]collectorResult, len(s.Collectors))

	var wg sync.WaitGroup
	for i, loc := range s.Collectors {
		wg.Add(1)
		go func(i int, loc opbgp.BgpLocation) {
			defer wg.Done()
			cidrs, err := s.collectPrefixes(ctx, loc)
			results[i] = collectorResult{slug: loc.Slug, cidrs: cidrs, err: err}
		}(i, loc)
	}
	wg.Wait()

	merged := make(map[string]struct{})
	var ok int
	for _, r := range results {
		if r.err != nil {
			s.Logger.Warn("skipping bgp collector for ipnet seed",
				zap.String("collector", r.slug), zap.Error(r.err))
			continue
		}
		ok++
		before := len(merged)
		for cidr := range r.cidrs {
			merged[cidr] = struct{}{}
		}
		s.Logger.Info("decoded bgp collector rib",
			zap.String("collector", r.slug),
			zap.Int("prefixes", len(r.cidrs)),
			zap.Int("new_prefixes", len(merged)-before),
		)
	}
	if ok == 0 {
		return postgres.IpnetSeedResult{}, fmt.Errorf("ipnet rib seed: all %d collectors failed", len(s.Collectors))
	}

	cidrs := make([]string, 0, len(merged))
	for cidr := range merged {
		cidrs = append(cidrs, cidr)
	}
	s.Logger.Info("merged announced prefixes from bgp collectors",
		zap.Int("collectors_ok", ok),
		zap.Int("collectors", len(s.Collectors)),
		zap.Int("unique_prefixes", len(cidrs)),
		zap.String("duration", time.Since(started).String()),
	)

	res, err := s.Store.SeedIpnetFromCIDRs(ctx, cidrs, registries)
	if err != nil {
		return res, err
	}
	if err := s.Store.TouchRemoteFileMetadata(ctx, postgres.RibSeedWatermarkURL); err != nil {
		return res, fmt.Errorf("rib seed watermark: %w", err)
	}
	s.Logger.Info("seeded ipnet crawl targets from announced prefixes",
		zap.Int64("inserted", res.Inserted),
		zap.Int64("dropped_no_nro_cover", res.NoCover),
		zap.Int64("dropped_other_registry", res.OtherRegistry),
		zap.Int64("dropped_unparseable", res.Invalid),
		zap.String("duration", time.Since(started).String()),
	)
	return res, nil
}

// collectPrefixes decodes one collector's current RIB. Archives are 2-hourly and
// ForgeMtrFileUrl only guesses which slot is published, so a 404 is retried once
// against the previous slot rather than failing the collector.
func (s *RibSeeder) collectPrefixes(ctx context.Context, loc opbgp.BgpLocation) (map[string]struct{}, error) {
	now := time.Now().UTC()

	url := connectivity.ForgeMtrFileUrl(&loc, now)
	cidrs, err := s.decodeRib(ctx, loc, url)
	if err == nil || !errors.Is(err, errArchiveNotFound) {
		return cidrs, err
	}

	prevURL := connectivity.ForgeMtrFileUrl(&loc, now.Add(-2*time.Hour))
	if prevURL == url {
		return nil, err
	}
	s.Logger.Info("rib archive slot not published, falling back one slot",
		zap.String("collector", loc.Slug), zap.String("url", prevURL))
	return s.decodeRib(ctx, loc, prevURL)
}

func (s *RibSeeder) decodeRib(ctx context.Context, loc opbgp.BgpLocation, url string) (map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build rib request %s: %w", url, err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download rib %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", errArchiveNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download rib %s: unexpected status %s", url, resp.Status)
	}

	// Decompress and decode straight off the wire. DownloadMrtFile io.ReadAll's
	// the whole body first; with three collectors running at once that is
	// ~450 MB of compressed RIB held in RAM for no gain, since nothing here
	// needs a second pass over the bytes.
	cr, err := bzip2.NewReader(resp.Body, &bzip2.ReaderConfig{})
	if err != nil {
		return nil, fmt.Errorf("bunzip2 rib %s: %w", url, err)
	}
	defer cr.Close()

	s.Logger.Info("streaming bgp collector rib", zap.String("collector", loc.Slug), zap.String("url", url))
	return decodeRibPrefixes(cr, s.Logger.With(zap.String("collector", loc.Slug))), nil
}

// decodeRibPrefixes walks a TABLE_DUMP_V2 stream and returns the canonical CIDR
// strings it announces.
//
// Only the record's NLRI is read. AS paths, peer indexes and per-peer attributes
// are irrelevant to enqueueing an ipnet job, and reading the NLRI once per record
// instead of once per rib entry makes the walk O(prefixes) rather than
// O(prefixes x peers) - tens of millions of entries on a full RIB. Records with
// no rib entries carry nothing announced and are skipped.
func decodeRibPrefixes(data io.Reader, logger *zap.Logger) map[string]struct{} {
	cidrs := make(map[string]struct{})

	r, err := mrt2.DecodeSingle(data)
	if err != nil {
		logger.Error("failed to decode single mrt", zap.Error(err))
	}

	var records, skipped uint64
	for r != nil {
		records++
		if t, ok := r.(*mrt2.MrtTableDumpV2_Rib); ok && len(t.RibEntries) > 0 {
			if pp, ok := t.NLRI.(messages.NLRI_IPPrefix); ok {
				cidr := pp.Prefix.String()
				if isDefaultRoute(cidr) {
					skipped++
				} else {
					cidrs[cidr] = struct{}{}
				}
			} else {
				skipped++
			}
		}

		r, err = mrt2.DecodeSingle(data)
		// A nil record with an error is just end-of-stream.
		if err != nil && r != nil {
			logger.Error("failed to decode single mrt, skipping", zap.Error(err))
		}
	}

	logger.Debug("rib walk finished",
		zap.Uint64("records", records),
		zap.Uint64("skipped", skipped),
		zap.Int("prefixes", len(cidrs)),
	)
	return cidrs
}

// isDefaultRoute filters the two prefixes naming the whole address space. They
// are announced by some peers and name no crawlable registry object.
func isDefaultRoute(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}
