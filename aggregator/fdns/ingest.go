package fdns

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
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
	// Combined 1M lists are tens of MB; 64MiB / 256MiB is generous headroom.
	maxCompressedBytes   = 64 << 20
	maxUncompressedBytes = 256 << 20
)

// ErrTooLarge is a dump that exceeds maxCompressedBytes / maxUncompressedBytes.
var ErrTooLarge = errors.New("fdns: list exceeds size cap")

type fdnsStore interface {
	GetResponseMetadata(url string) *postgres.ResponseMetadataItem
	SaveResponseMetadata(meta *postgres.ResponseMetadataItem)
	TouchRemoteFileMetadata(ctx context.Context, url string) error
	UpsertHostNames(ctx context.Context, rows []postgres.HostName) error
}

var _ fdnsStore = (*postgres.Store)(nil)

// Ingestor downloads Tranco / Umbrella / CrUX and upserts fdns_host_name.
type Ingestor struct {
	Store  fdnsStore
	Client *http.Client
	Logger *zap.Logger
	Lists  []List
	Force  bool
}

// NewIngestor builds a list ingest job. lists nil means DefaultLists.
func NewIngestor(logger *zap.Logger, st fdnsStore, client *http.Client, lists []List) *Ingestor {
	if client == nil {
		client = &http.Client{Timeout: ingestHTTPTimeout}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(lists) == 0 {
		lists = DefaultLists()
	}
	return &Ingestor{Store: st, Client: client, Logger: logger, Lists: lists}
}

// Ingest walks every configured list. One failed list does not roll back
// another; last good fdns_host_name rows stay.
func (in *Ingestor) Ingest(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error
	for _, list := range in.Lists {
		if err := in.ingestList(ctx, list); err != nil {
			in.Logger.Error("fdns list ingest failed; last good rows kept",
				zap.String("source", list.Name), zap.String("url", list.URL), zap.Error(err))
			errs = append(errs, fmt.Errorf("%s: %w", list.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (in *Ingestor) ingestList(ctx context.Context, list List) error {
	if strings.TrimSpace(list.URL) == "" || list.Name == "" {
		return fmt.Errorf("fdns ingest: missing list name or URL")
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, list.URL, nil)
	if err != nil {
		return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
	}
	req.Header.Set("User-Agent", "opr-fdns")
	if !in.Force {
		prev := in.Store.GetResponseMetadata(list.URL)
		if prev != nil && prev.Etag != nil && strings.TrimSpace(*prev.Etag) != "" {
			req.Header.Set("If-None-Match", strings.TrimSpace(*prev.Etag))
		}
	}

	in.Logger.Info("fetching fdns list", zap.String("source", list.Name), zap.String("url", list.URL))
	resp, err := in.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if err := in.Store.TouchRemoteFileMetadata(ctx, list.URL); err != nil {
			return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
		}
		in.Logger.Info("fdns list not modified",
			zap.String("source", list.Name), zap.String("url", list.URL))
		return nil
	case http.StatusOK:
		// continue
	default:
		return fmt.Errorf("fdns ingest %s: status %s", list.Name, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCompressedBytes+1))
	if err != nil {
		return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
	}
	if len(body) > maxCompressedBytes {
		return fmt.Errorf("%w: compressed > %d bytes", ErrTooLarge, maxCompressedBytes)
	}

	csvBody, err := decompressList(body, list.Compression)
	if err != nil {
		return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
	}

	now := time.Now().UTC()
	rows, err := ParseListCSV(bytes.NewReader(csvBody), list, now)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("%w: %s", ErrEmptyList, list.URL)
	}

	// UpsertHostNames also inserts due names into fdns_resolve_queue at
	// priority 1 (choice B: resolve claims only the queue, so list ingest
	// must enqueue or Tranco / Umbrella / CrUX names would never be resolved,
	// and a 5M CC seed at priority 0 would starve them). Same transaction as
	// the catalog upsert; already-fresh resolved names skipped.
	if err := in.Store.UpsertHostNames(ctx, rows); err != nil {
		return fmt.Errorf("fdns ingest %s: %w", list.Name, err)
	}
	in.Store.SaveResponseMetadata(metadataFromHeader(list.URL, resp.Header))
	in.Logger.Info("fdns list persisted",
		zap.String("source", list.Name),
		zap.String("url", list.URL),
		zap.Int("rows", len(rows)),
		zap.Duration("duration", time.Since(start)))
	return nil
}

func decompressList(body []byte, c Compression) ([]byte, error) {
	switch c {
	case CompressZip:
		return unzipCSV(body)
	case CompressGzip:
		return gunzip(body)
	default:
		if int64(len(body)) > maxUncompressedBytes {
			return nil, fmt.Errorf("%w: uncompressed > %d bytes", ErrTooLarge, maxUncompressedBytes)
		}
		return body, nil
	}
}

func unzipCSV(body []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("unzip: %w", err)
	}
	var chosen *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := strings.ToLower(path.Base(f.Name))
		if strings.HasSuffix(base, ".csv") {
			chosen = f
			break
		}
		if chosen == nil {
			chosen = f
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("unzip: no file in archive")
	}
	rc, err := chosen.Open()
	if err != nil {
		return nil, fmt.Errorf("unzip %s: %w", chosen.Name, err)
	}
	defer rc.Close()
	out, err := io.ReadAll(io.LimitReader(rc, maxUncompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("unzip %s: %w", chosen.Name, err)
	}
	if len(out) > maxUncompressedBytes {
		return nil, fmt.Errorf("%w: uncompressed > %d bytes", ErrTooLarge, maxUncompressedBytes)
	}
	return out, nil
}

func gunzip(body []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gr.Close()
	out, err := io.ReadAll(io.LimitReader(gr, maxUncompressedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	if len(out) > maxUncompressedBytes {
		return nil, fmt.Errorf("%w: uncompressed > %d bytes", ErrTooLarge, maxUncompressedBytes)
	}
	return out, nil
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
