package geofeeds

import (
	"context"
	"fmt"
	"strings"

	"github.com/oprand/opr/store/postgres"
)

// PruneStore is the geoip orphan-cleanup surface.
type PruneStore interface {
	CountOrphanGeoIP(ctx context.Context, source string) (int64, error)
	PruneOrphanGeoIP(ctx context.Context, source string) (int64, error)
	CountOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error)
	PruneOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error)
}

const (
	PruneSourceGeofeed = "geofeed"
	PruneSourceAll     = "all"
)

var _ PruneStore = (*postgres.Store)(nil)

// Prune deletes geoip rows whose source_url is gone from the geofeeds catalog.
// source "geofeed" (default) only touches source=GEOFEED (empty source_url is
// an orphan). "all" also prunes LACNIC_DB_CSV rows that have a non-empty
// source_url missing from the catalog — empty LACNIC source_url is the normal
// CSV ingest key and is kept.
func Prune(ctx context.Context, st PruneStore, source string, dryRun bool) (int64, error) {
	if st == nil {
		return 0, fmt.Errorf("geofeed prune: nil store")
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", PruneSourceGeofeed:
		return pruneOne(ctx, st, SourceGEOFEED, true, dryRun)
	case PruneSourceAll:
		n, err := pruneOne(ctx, st, SourceGEOFEED, true, dryRun)
		if err != nil {
			return n, err
		}
		n2, err := pruneOne(ctx, st, "LACNIC_DB_CSV", false, dryRun)
		return n + n2, err
	default:
		return 0, fmt.Errorf("geofeed prune: unknown --source %q (want geofeed or all)", source)
	}
}

func pruneOne(ctx context.Context, st PruneStore, src string, includeEmpty, dryRun bool) (int64, error) {
	if dryRun {
		if includeEmpty {
			return st.CountOrphanGeoIP(ctx, src)
		}
		return st.CountOrphanGeoIPNonEmpty(ctx, src)
	}
	if includeEmpty {
		return st.PruneOrphanGeoIP(ctx, src)
	}
	return st.PruneOrphanGeoIPNonEmpty(ctx, src)
}
