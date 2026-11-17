package whoisdb

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestGeofeedHarvestURLsAreInetnumCapablePass1Files(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"jpnic.db.gz":              true,
		"twnic.db.gz":              true,
		"krnic.db.gz":              true,
		"apnic.db.inetnum.gz":      true,
		"apnic.db.inet6num.gz":     true,
		"afrinic.db.gz":            true,
		"arin.db.gz":               true,
		"lacnic.db.gz":             true,
		"ripe.db.inetnum.gz":       true,
		"ripe.db.inet6num.gz":      true,
		"apnic.db.aut-num.gz":      false,
		"apnic.db.organisation.gz": false,
		"apnic.db.role.gz":         false,
		"apnic.db.person.gz":       false,
		"apnic.db.as-set.gz":       false,
		"apnic.db.as-block.gz":     false,
		"apnic.db.irt.gz":          false,
		"ripe.db.aut-num.gz":       false,
		"ripe.db.organisation.gz":  false,
		"ripe.db.role.gz":          false,
		"ripe.db.person.gz":        false,
		"ripe.db.as-set.gz":        false,
		"ripe.db.as-block.gz":      false,
		"ripe.db.irt.gz":           false,
	}
	seen := map[string]bool{}
	for _, src := range registrationSources {
		name := src.url[strings.LastIndex(src.url, "/")+1:]
		got := isGeofeedHarvestURL(src.url)
		expect, ok := want[name]
		if !ok {
			t.Errorf("unexpected registration source %s", name)
			continue
		}
		if got != expect {
			t.Errorf("%s isGeofeedHarvestURL=%v, want %v", name, got, expect)
		}
		seen[name] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("registrationSources missing %s", name)
		}
	}
	if got := geofeedHarvestSources(); len(got) != 10 {
		t.Fatalf("geofeedHarvestSources len=%d, want 10", len(got))
	}
}

func TestPass1GeofeedHarvestComplete(t *testing.T) {
	t.Parallel()
	fullJobs := newPass(registrationSources, registrationRecordTypes)
	urls := []string{"https://example.com/feed.csv"}

	t.Run("complete", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		if !pass1GeofeedHarvestComplete(fullJobs, st) {
			t.Fatal("full parsed pass must be complete")
		}
		if reason := geofeedPruneSkipReason(fullJobs, st, urls, nil); reason != "" {
			t.Fatalf("skip reason %q, want empty", reason)
		}
	})

	t.Run("etag skip on inetnum file", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		key := statusKey("https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz", registrationRecordTypes)
		st[key] = &WhoisDBURLStatus{URL: st[key].URL, HasChanged: false}
		if pass1GeofeedHarvestComplete(fullJobs, st) {
			t.Fatal("ETag-skipped inetnum file must be incomplete")
		}
		if reason := geofeedPruneSkipReason(fullJobs, st, urls, nil); reason != "incomplete pass-1 harvest" {
			t.Fatalf("skip reason %q", reason)
		}
	})

	t.Run("person etag skip still complete", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		key := statusKey("https://ftp.ripe.net/ripe/dbase/split/ripe.db.person.gz", registrationRecordTypes)
		st[key] = &WhoisDBURLStatus{URL: st[key].URL, HasChanged: false}
		if !pass1GeofeedHarvestComplete(fullJobs, st) {
			t.Fatal("ETag-skipped person file must not fail the prune gate")
		}
	})

	t.Run("only-registries omits a rir", func(t *testing.T) {
		t.Parallel()
		var ripeOnly []whoisDBSource
		for _, src := range registrationSources {
			if src.source == opconst.RIPE {
				ripeOnly = append(ripeOnly, src)
			}
		}
		jobs := newPass(ripeOnly, registrationRecordTypes)
		st := completeHarvestStatuses()
		if pass1GeofeedHarvestComplete(jobs, st) {
			t.Fatal("filtered pass (only-registries) must be incomplete")
		}
	})

	t.Run("empty urls", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		if reason := geofeedPruneSkipReason(fullJobs, st, nil, nil); reason != "empty harvest" {
			t.Fatalf("skip reason %q, want empty harvest", reason)
		}
		if reason := geofeedPruneSkipReason(fullJobs, st, []string{}, nil); reason != "empty harvest" {
			t.Fatalf("skip reason %q, want empty harvest", reason)
		}
	})

	t.Run("save failed", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		if reason := geofeedPruneSkipReason(fullJobs, st, urls, errors.New("db down")); reason != "save failed" {
			t.Fatalf("skip reason %q, want save failed", reason)
		}
	})

	t.Run("fetch error on mixed dump", func(t *testing.T) {
		t.Parallel()
		st := completeHarvestStatuses()
		key := statusKey("https://ftp.arin.net/pub/rr/arin.db.gz", registrationRecordTypes)
		st[key].FetchError = "bad status code 500"
		if pass1GeofeedHarvestComplete(fullJobs, st) {
			t.Fatal("failed fetch must be incomplete")
		}
	})
}

func completeHarvestStatuses() map[string]*WhoisDBURLStatus {
	m := make(map[string]*WhoisDBURLStatus, len(registrationSources))
	for _, src := range registrationSources {
		m[statusKey(src.url, registrationRecordTypes)] = &WhoisDBURLStatus{
			URL:                src.url,
			HasChanged:         true,
			ParsedRecordsCount: map[opconst.RecordType]int64{},
		}
	}
	return m
}

func TestBulkHarvestDoesNotSeedGeofeedTargets(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "SeedGeofeedTargets") {
		t.Fatal("registry-crawl bulk must not seed crawl_target kind=geofeed")
	}
	if !strings.Contains(string(src), "SaveGeofeeds") {
		t.Fatal("bulk must still upsert the geofeeds catalog")
	}
	if !strings.Contains(string(src), "PruneStaleGeofeeds") {
		t.Fatal("bulk must still prune stale catalog URLs / mark leftover geofeed jobs gone")
	}
}
