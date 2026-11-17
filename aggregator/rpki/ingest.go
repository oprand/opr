package rpki

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	DefaultRoutinatorAddr = "http://127.0.0.1:8323"
	jsonextTimeout        = 10 * time.Minute
	// minLastVRPForShrink is "substantial": smaller last snapshots only
	// reject empty payloads, not a 10% floor.
	minLastVRPForShrink int64 = 1000
	minVRPFloor         int64 = 1000
)

// ErrEmptyROAs is returned when /jsonext has no roas. Live vrp/aspa stay.
var ErrEmptyROAs = errors.New("rpki: routinator /jsonext returned zero ROAs")

// ErrImplausibleVRPShrink is returned when a payload is far smaller than
// the last snapshot (tiny/misconfigured Routinator).
var ErrImplausibleVRPShrink = errors.New("rpki: vrp count is implausibly small vs last snapshot")

// SnapshotStore persists a full VRP+ASPA snapshot.
type SnapshotStore interface {
	LatestVRPIngest(ctx context.Context) (*postgres.VRPIngest, error)
	ReplaceRPKISnapshot(ctx context.Context, vrps []postgres.VRP, aspas []postgres.ASPA, meta postgres.VRPIngest, keepASPA bool) error
}

// Ingestor fetches Routinator jsonext and COPY-swaps vrp/aspa.
type Ingestor struct {
	Store  SnapshotStore
	Client *http.Client
	Logger *zap.Logger
}

func NewIngestor(logger *zap.Logger, st SnapshotStore, client *http.Client) *Ingestor {
	if client == nil {
		client = &http.Client{Timeout: jsonextTimeout}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Ingestor{Store: st, Client: client, Logger: logger}
}

// ImplausibleVRPCount reports a payload too small to replace a substantial
// last snapshot. Empty is a hard failure (ErrEmptyROAs). When lastCount >=
// 1000, newCount must be at least max(1000, 10% of lastCount) so a
// misconfigured tiny primary cannot wipe a full table, while a real global
// shrink of tens of percent still proceeds.
func ImplausibleVRPCount(newCount, lastCount int64) bool {
	if newCount <= 0 {
		return true
	}
	if lastCount < minLastVRPForShrink {
		return false
	}
	floor := lastCount / 10
	if floor < minVRPFloor {
		floor = minVRPFloor
	}
	return newCount < floor
}

// Ingest GETs /jsonext from primary then optional fallback, then persists.
// Empty or implausibly small VRP payloads try the next base. Total failure
// leaves the last snapshot in place.
func (in *Ingestor) Ingest(ctx context.Context, primary, fallback string) error {
	last, err := in.Store.LatestVRPIngest(ctx)
	if err != nil {
		return err
	}

	payload, sourceURL, keepASPA, err := in.fetchJSONExt(ctx, primary, fallback, last)
	if err != nil {
		return err
	}

	meta := postgres.VRPIngest{
		FetchedAt: time.Now().UTC(),
		SourceURL: sourceURL,
		VRPCount:  int64(len(payload.VRPs)),
		ASPACount: int64(len(payload.ASPAs)),
	}
	if keepASPA && last != nil {
		meta.ASPACount = last.ASPACount
	}
	if err := in.Store.ReplaceRPKISnapshot(ctx, payload.VRPs, payload.ASPAs, meta, keepASPA); err != nil {
		return err
	}
	in.Logger.Info("rpki ingest persisted jsonext snapshot",
		zap.String("source_url", sourceURL),
		zap.Int("vrp_count", len(payload.VRPs)),
		zap.Int("aspa_count", len(payload.ASPAs)),
		zap.Bool("kept_previous_aspa", keepASPA))
	return nil
}

func (in *Ingestor) fetchJSONExt(ctx context.Context, primary, fallback string, last *postgres.VRPIngest) (*Payload, string, bool, error) {
	var bases []string
	if b := strings.TrimSpace(primary); b != "" {
		bases = append(bases, b)
	}
	if b := strings.TrimSpace(fallback); b != "" && b != strings.TrimSpace(primary) {
		bases = append(bases, b)
	}
	if len(bases) == 0 {
		return nil, "", false, fmt.Errorf("rpki ingest: no routinator address")
	}

	var lastCount int64
	var lastAspa int64
	if last != nil {
		lastCount = last.VRPCount
		lastAspa = last.ASPACount
	}

	var errs []error
	var tentative *Payload
	var tentativeURL string

	for i, base := range bases {
		url := jsonextURL(base)
		payload, err := in.getJSONExt(ctx, url)
		if err != nil {
			in.Logger.Warn("routinator jsonext fetch failed",
				zap.String("endpoint", url),
				zap.Error(err))
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		if len(payload.VRPs) == 0 {
			in.Logger.Warn("routinator /jsonext returned zero ROAs; ASPA/validation may still be running",
				zap.String("endpoint", url))
			errs = append(errs, fmt.Errorf("%s: %w", url, ErrEmptyROAs))
			continue
		}
		if ImplausibleVRPCount(int64(len(payload.VRPs)), lastCount) {
			in.Logger.Warn("routinator /jsonext VRP count is implausibly small vs last snapshot",
				zap.String("endpoint", url),
				zap.Int("vrp_count", len(payload.VRPs)),
				zap.Int64("last_vrp_count", lastCount))
			errs = append(errs, fmt.Errorf("%s: %w", url, ErrImplausibleVRPShrink))
			continue
		}

		needAspa := lastAspa > 0
		if !needAspa || len(payload.ASPAs) > 0 {
			if i > 0 {
				in.Logger.Info("routinator jsonext fallback won",
					zap.String("endpoint", url),
					zap.String("reason", "primary empty, shrunk, or missing ASPA"),
					zap.Int("vrp_count", len(payload.VRPs)),
					zap.Int("aspa_count", len(payload.ASPAs)))
			} else {
				in.Logger.Info("routinator jsonext fetch succeeded",
					zap.String("endpoint", url),
					zap.Int("vrp_count", len(payload.VRPs)),
					zap.Int("aspa_count", len(payload.ASPAs)))
			}
			return payload, url, false, nil
		}

		in.Logger.Warn("routinator /jsonext has VRPs but no ASPAs while last snapshot had ASPAs; trying fallback",
			zap.String("endpoint", url),
			zap.Int("vrp_count", len(payload.VRPs)),
			zap.Int64("last_aspa_count", lastAspa))
		if tentative == nil {
			tentative = payload
			tentativeURL = url
		}
	}

	if tentative != nil {
		in.Logger.Warn("keeping previous aspa table; jsonext VRPs are plausible but ASPA is empty on all bases",
			zap.String("endpoint", tentativeURL),
			zap.Int("vrp_count", len(tentative.VRPs)),
			zap.Int64("last_aspa_count", lastAspa))
		return tentative, tentativeURL, true, nil
	}
	return nil, "", false, fmt.Errorf("rpki ingest: all routinator bases failed: %w", errors.Join(errs...))
}

func (in *Ingestor) getJSONExt(ctx context.Context, url string) (*Payload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := in.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return DecodeJSONExt(resp.Body)
}

func jsonextURL(base string) string {
	return strings.TrimRight(strings.TrimSpace(base), "/") + "/jsonext"
}
