package rdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	ingestHTTPTimeout = 15 * time.Minute
	// Zone files are master-file text; tens of MB would already be abnormal.
	maxZoneBytes = 64 << 20
	// RDNSReplaceFloor is the minimum new/existing row-count ratio before
	// ReplaceRDNSBySourceURL. A truncated 200 with a few NS must not stale-
	// delete the rest of that source_url.
	RDNSReplaceFloor = 0.50
)

// ErrEmptyZone is the internal signal that ParseZoneFile yielded no NS/DS/CNAME.
// ingestFile treats that as a successful skip (SOA+DNSSEC-only RIR files);
// it must not be joined into the process error. Kept for tests.
var ErrEmptyZone = errors.New("rdns: no NS/DS/CNAME in zone file")

// ErrEmptyListing is returned when an HTML directory listing has hrefs but
// no reverse zone files (or PreferRIRZoneFiles left none). Quiet success
// would skip retries of failed files.
var ErrEmptyListing = errors.New("rdns: directory listing had no reverse zone files")

// ErrRDNSReplaceFloor is returned when a non-empty parse is below
// RDNSReplaceFloor of the existing row count for that source_url.
var ErrRDNSReplaceFloor = errors.New("rdns: new row count below replace floor")

// Persist isolation (tasks 3–4):
//
//   - Each RIR is ingested independently. A listing/fetch failure for RIPE
//     does not touch APNIC rows (no global truncate).
//   - Each zone file is replaced by source_url. A failed or empty parse of
//     one file does not call replace, so that file's last good rows stay;
//     other files of the same RIR already persisted in this run stay.
//   - The live directory listing is always GET+parsed. Listing ETag is
//     stored as a hint only; it is not the file set (failed files missing
//     from rdns_delegation must still be retried).
//   - Unchanged per-file ETag / Last-Modified (2xx HEAD only) skips GET+parse+replace.
//   - Files that disappear from a listing are not deleted (no prune in
//     tasks 1–4).
type rdnsStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	ReplaceRDNSBySourceURL(ctx context.Context, sourceURL string, rows []postgres.RDNSDelegation) error
	CountRDNSBySourceURL(ctx context.Context, sourceURL string) (int64, error)
	UpsertRDNSDelegations(ctx context.Context, rows []postgres.RDNSDelegation) error
}

var _ rdnsStore = (*postgres.Store)(nil)

// Ingestor lists RIR /zones/ directories, fetches changed master files, and
// persists NS/DS/CNAME into rdns_delegation. Optional IANA parent zones and
// WHOIS dumps run after RIR files when their URLs are set (CLI defaults).
type Ingestor struct {
	Store   rdnsStore
	Client  *http.Client
	Logger  *zap.Logger
	Sources []Source
	Force   bool

	SkipIANA      bool
	IANAInAddrURL string
	IANAIP6URL    string

	SkipWhois   bool
	WhoisDumps  []WhoisDump
	SkipLacnic  bool
	LacnicDBURL string
}

// NewIngestor builds an ingest job. sources nil means DefaultSources.
func NewIngestor(logger *zap.Logger, st rdnsStore, client *http.Client, sources []Source) *Ingestor {
	if client == nil {
		client = &http.Client{Timeout: ingestHTTPTimeout}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(sources) == 0 {
		sources = append([]Source(nil), DefaultSources...)
	}
	return &Ingestor{Store: st, Client: client, Logger: logger, Sources: sources}
}

// Ingest walks every configured RIR. Per-source and per-file failures are
// joined and returned after the others have run, so one failed RIR cannot
// roll back another.
func (in *Ingestor) Ingest(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error
	for _, src := range in.Sources {
		if err := in.ingestSource(ctx, src); err != nil {
			in.Logger.Error("rdns ingest source failed; last good rows kept for files that did not persist",
				zap.String("source", src.Name), zap.Error(err))
			errs = append(errs, fmt.Errorf("%s: %w", src.Name, err))
		}
	}
	if err := in.ingestIANA(ctx); err != nil {
		in.Logger.Error("rdns IANA parent ingest failed; last good IANA rows kept", zap.Error(err))
		errs = append(errs, err)
	}
	if err := in.ingestWhoisDumps(ctx); err != nil {
		in.Logger.Error("rdns WHOIS domain ingest failed; last good rows kept", zap.Error(err))
		errs = append(errs, err)
	}
	if err := in.ingestLacnicNserver(ctx); err != nil {
		in.Logger.Error("rdns LACNIC nserver ingest failed; last good rows kept", zap.Error(err))
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (in *Ingestor) ingestSource(ctx context.Context, src Source) error {
	listURL := strings.TrimSpace(src.ListURL)
	if listURL == "" || src.Name == "" {
		return fmt.Errorf("rdns ingest: missing source name or list URL")
	}

	files, err := in.listZoneFiles(ctx, src)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%w: %s", ErrEmptyListing, listURL)
	}

	var fileErrs []error
	for _, fileURL := range files {
		if err := in.ingestFile(ctx, src.Name, fileURL); err != nil {
			in.Logger.Error("rdns zone file failed; last good rows for this URL kept",
				zap.String("source", src.Name), zap.String("url", fileURL), zap.Error(err))
			fileErrs = append(fileErrs, fmt.Errorf("%s: %w", path.Base(fileURL), err))
		}
	}
	return errors.Join(fileErrs...)
}

func (in *Ingestor) listZoneFiles(ctx context.Context, src Source) ([]string, error) {
	listURL := src.ListURL
	if !strings.HasSuffix(listURL, "/") {
		listURL += "/"
	}

	// Always GET+parse the live listing. A matching listing ETag used to
	// return only URLs already in rdns_delegation, so a 500 / oversize /
	// empty parse was never retried until --force or the directory changed.
	body, hdr, err := in.get(ctx, listURL)
	if err != nil {
		return nil, fmt.Errorf("rdns list %s: %w", listURL, err)
	}
	files := PreferRIRZoneFiles(src.Name, ParseZoneListing(listURL, string(body)))
	in.Store.SaveResponseMetadata(metadataFromHeader(listURL, hdr))
	if ListingHasHrefs(string(body)) && len(files) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyListing, listURL)
	}
	in.Logger.Info("rdns listed zone files",
		zap.String("source", src.Name), zap.String("url", listURL),
		zap.Int("files", len(files)))
	return files, nil
}

func (in *Ingestor) ingestFile(ctx context.Context, source, fileURL string) error {
	origin, ok := ZoneFileOrigin(fileURL)
	if !ok {
		return fmt.Errorf("rdns: not a reverse zone filename: %s", fileURL)
	}

	var newMeta *postgres.ResponseMetadataItem
	if !in.Force {
		var changed bool
		newMeta, changed = fileChanged(ctx, in.Store, in.Client, fileURL)
		if !changed {
			in.Logger.Info("rdns file not changed", zap.String("url", fileURL))
			return nil
		}
	}

	body, hdr, err := in.get(ctx, fileURL)
	if err != nil {
		return err
	}
	if newMeta == nil {
		newMeta = metadataFromHeader(fileURL, hdr)
	}

	parsed, err := ParseZoneFile(strings.NewReader(string(body)), origin, path.Base(fileURL))
	if err != nil {
		return err
	}
	if len(parsed) == 0 {
		// SOA+DNSSEC-only files (common on RIR ip6.arpa) are a successful
		// skip, not a failed ingest. Last good rows stay; ETag is stored so
		// the next run HEAD-skips until the file actually changes.
		in.Store.SaveResponseMetadata(newMeta)
		in.Logger.Warn("rdns empty_zone; last good rows kept",
			zap.String("source", source),
			zap.String("url", fileURL),
			zap.String("origin", origin),
			zap.Bool("empty_zone", true))
		return nil
	}

	existing, err := in.Store.CountRDNSBySourceURL(ctx, fileURL)
	if err != nil {
		return fmt.Errorf("rdns count: %w", err)
	}
	if existing > 0 && float64(len(parsed)) < RDNSReplaceFloor*float64(existing) {
		return fmt.Errorf("%w: %d new vs %d existing (floor %.0f%%) url %s",
			ErrRDNSReplaceFloor, len(parsed), existing, RDNSReplaceFloor*100, fileURL)
	}

	now := time.Now().UTC()
	method := postgres.FetchMethodZoneFile
	var lastChanged *time.Time
	if newMeta != nil && newMeta.LastModified != nil && !newMeta.LastModified.IsZero() {
		lastChanged = newMeta.LastModified
	}
	rows := make([]postgres.RDNSDelegation, 0, len(parsed))
	for _, p := range parsed {
		rows = append(rows, postgres.RDNSDelegation{
			Zone:               p.Zone,
			Prefix:             p.Prefix,
			Nservers:           p.Nservers,
			DS:                 p.DS,
			CNAMETarget:        p.CNAMETarget,
			Source:             source,
			SourceURL:          fileURL,
			MetaAddedAt:        &now,
			LastFetchedAt:      &now,
			LastChangedAt:      lastChanged,
			FetchMethod:        &method,
			LastSeenInSourceAt: &now,
		})
	}

	if err := in.Store.ReplaceRDNSBySourceURL(ctx, fileURL, rows); err != nil {
		return err
	}
	in.Store.SaveResponseMetadata(newMeta)
	in.Logger.Info("rdns zone persisted",
		zap.String("source", source),
		zap.String("url", fileURL),
		zap.Int("rows", len(rows)))
	return nil
}

func (in *Ingestor) get(ctx context.Context, rawURL string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := in.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxZoneBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxZoneBytes {
		return nil, nil, fmt.Errorf("rdns: body exceeds %d bytes", maxZoneBytes)
	}
	return body, resp.Header, nil
}

func fileChanged(ctx context.Context, st rdnsStore, client *http.Client, rawURL string) (*postgres.ResponseMetadataItem, bool) {
	prev := st.GetResponseMetadata(rawURL)
	if prev == nil || prev.Url == "" {
		now := time.Now()
		return &postgres.ResponseMetadataItem{Url: rawURL, MetaAddedAt: &now}, true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return nil, true
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil, true
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// 404/405/5xx headers are not cacheable; fall through to GET.
		return nil, true
	}

	newMeta := metadataFromHeader(rawURL, resp.Header)
	if etagEqual(prev.Etag, newMeta.Etag) {
		return newMeta, false
	}
	if lastModEqual(prev.LastModified, newMeta.LastModified) {
		return newMeta, false
	}
	return newMeta, true
}

func etagEqual(a, b *string) bool {
	av := ""
	bv := ""
	if a != nil {
		av = strings.TrimSpace(*a)
	}
	if b != nil {
		bv = strings.TrimSpace(*b)
	}
	return av != "" && av == bv
}

func lastModEqual(a, b *time.Time) bool {
	if a == nil || b == nil || a.IsZero() || b.IsZero() {
		return false
	}
	return a.UTC().Equal(b.UTC())
}

func metadataFromHeader(rawURL string, h http.Header) *postgres.ResponseMetadataItem {
	etag := h.Get("Etag")
	contentType := h.Get("Content-Type")
	contentLength, _ := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	lastModified, _ := time.Parse(http.TimeFormat, h.Get("Last-Modified"))
	now := time.Now()
	meta := &postgres.ResponseMetadataItem{
		Url:           rawURL,
		ContentType:   &contentType,
		ContentLength: &contentLength,
		LastModified:  &lastModified,
		MetaAddedAt:   &now,
	}
	if strings.TrimSpace(etag) != "" {
		meta.Etag = &etag
	}
	if lastModified.IsZero() {
		meta.LastModified = nil
	}
	return meta
}
