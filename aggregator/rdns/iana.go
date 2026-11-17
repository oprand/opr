package rdns

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func (in *Ingestor) ingestIANA(ctx context.Context) error {
	if in.SkipIANA {
		return nil
	}
	var errs []error
	for _, rawURL := range []string{in.IANAInAddrURL, in.IANAIP6URL} {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}
		if err := in.ingestIANAFile(ctx, rawURL); err != nil {
			in.Logger.Error("rdns IANA zone file failed; last good rows for this URL kept",
				zap.String("url", rawURL), zap.Error(err))
			errs = append(errs, fmt.Errorf("IANA %s: %w", path.Base(rawURL), err))
		}
	}
	return errors.Join(errs...)
}

func (in *Ingestor) ingestIANAFile(ctx context.Context, fileURL string) error {
	origin, ok := IANAZoneOrigin(fileURL)
	if !ok {
		return fmt.Errorf("rdns: not an InterNIC parent zone: %s", fileURL)
	}

	var newMeta *postgres.ResponseMetadataItem
	if !in.Force {
		var changed bool
		newMeta, changed = fileChanged(ctx, in.Store, in.Client, fileURL)
		if !changed {
			in.Logger.Info("rdns IANA file not changed", zap.String("url", fileURL))
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
	rows := ianaParentRows(parsed, fileURL, newMeta)
	if len(rows) == 0 {
		in.Store.SaveResponseMetadata(newMeta)
		in.Logger.Warn("rdns empty_zone; last good IANA rows kept",
			zap.String("url", fileURL),
			zap.String("origin", origin),
			zap.Bool("empty_zone", true))
		return nil
	}

	existing, err := in.Store.CountRDNSBySourceURL(ctx, fileURL)
	if err != nil {
		return fmt.Errorf("rdns count: %w", err)
	}
	if existing > 0 && float64(len(rows)) < RDNSReplaceFloor*float64(existing) {
		return fmt.Errorf("%w: %d new vs %d existing (floor %.0f%%) url %s",
			ErrRDNSReplaceFloor, len(rows), existing, RDNSReplaceFloor*100, fileURL)
	}

	if err := in.Store.ReplaceRDNSBySourceURL(ctx, fileURL, rows); err != nil {
		return err
	}
	in.Store.SaveResponseMetadata(newMeta)
	in.Logger.Info("rdns IANA parent persisted",
		zap.String("url", fileURL),
		zap.Int("rows", len(rows)))
	return nil
}

// IANAZoneOrigin maps InterNIC filenames (in-addr.arpa.zone, ip6.arpa) to
// the DNS origin. RIR ZoneFileOrigin rejects the .zone suffix.
func IANAZoneOrigin(fileURL string) (string, bool) {
	base := strings.ToLower(strings.TrimSpace(path.Base(fileURL)))
	switch base {
	case "in-addr.arpa.zone", "in-addr.arpa":
		return "in-addr.arpa.", true
	case "ip6.arpa.zone", "ip6.arpa":
		return "ip6.arpa.", true
	default:
		return ZoneFileOrigin(fileURL)
	}
}

func ianaParentRows(parsed []parsedRR, fileURL string, meta *postgres.ResponseMetadataItem) []postgres.RDNSDelegation {
	now := time.Now().UTC()
	method := postgres.FetchMethodIANAZone
	var lastChanged *time.Time
	if meta != nil && meta.LastModified != nil && !meta.LastModified.IsZero() {
		lastChanged = meta.LastModified
	}
	out := make([]postgres.RDNSDelegation, 0, len(parsed))
	for _, p := range parsed {
		if p.Zone == "in-addr.arpa." || p.Zone == "ip6.arpa." {
			continue
		}
		if len(p.Nservers) == 0 && len(p.DS) == 0 {
			continue
		}
		out = append(out, postgres.RDNSDelegation{
			Zone:               p.Zone,
			Prefix:             p.Prefix,
			Nservers:           p.Nservers,
			DS:                 p.DS,
			CNAMETarget:        p.CNAMETarget,
			Source:             postgres.RDNSSourceIANA,
			SourceURL:          fileURL,
			DelegatedRIR:       majorityRIR(p.Nservers),
			MetaAddedAt:        &now,
			LastFetchedAt:      &now,
			LastChangedAt:      lastChanged,
			FetchMethod:        &method,
			LastSeenInSourceAt: &now,
		})
	}
	return out
}

func majorityRIR(nservers []string) string {
	counts := make(map[string]int)
	for _, ns := range nservers {
		if rir := postgres.RIRFromNameserver(ns); rir != "" {
			counts[rir]++
		}
	}
	best := ""
	bestN := 0
	tie := false
	for rir, n := range counts {
		if n > bestN {
			best, bestN, tie = rir, n, false
			continue
		}
		if n == bestN {
			tie = true
		}
	}
	if tie || bestN == 0 {
		return ""
	}
	return best
}
