package geofeeds

import (
	"context"
	"strings"
	"testing"
)

type memPruneStore struct {
	counts       map[string]int64
	countsNE     map[string]int64
	pruned       []string
	prunedNE     []string
	countCalls   int
	pruneCalls   int
	countNECalls int
	pruneNECalls int
}

func (m *memPruneStore) CountOrphanGeoIP(ctx context.Context, source string) (int64, error) {
	m.countCalls++
	if m.counts == nil {
		return 0, nil
	}
	return m.counts[source], nil
}

func (m *memPruneStore) PruneOrphanGeoIP(ctx context.Context, source string) (int64, error) {
	m.pruneCalls++
	m.pruned = append(m.pruned, source)
	if m.counts == nil {
		return 0, nil
	}
	return m.counts[source], nil
}

func (m *memPruneStore) CountOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error) {
	m.countNECalls++
	if m.countsNE == nil {
		return 0, nil
	}
	return m.countsNE[source], nil
}

func (m *memPruneStore) PruneOrphanGeoIPNonEmpty(ctx context.Context, source string) (int64, error) {
	m.pruneNECalls++
	m.prunedNE = append(m.prunedNE, source)
	if m.countsNE == nil {
		return 0, nil
	}
	return m.countsNE[source], nil
}

func TestPruneGeofeedDoesNotTouchLacnic(t *testing.T) {
	t.Parallel()
	st := &memPruneStore{counts: map[string]int64{SourceGEOFEED: 3, "LACNIC_DB_CSV": 99}}
	n, err := Prune(context.Background(), st, "geofeed", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("n=%d, want 3", n)
	}
	if st.pruneCalls != 1 || len(st.pruned) != 1 || st.pruned[0] != SourceGEOFEED {
		t.Fatalf("pruned sources = %v, want only GEOFEED", st.pruned)
	}
	if st.pruneNECalls != 0 {
		t.Fatal("GEOFEED prune must not delete LACNIC rows")
	}
}

func TestPruneDryRunWritesNothing(t *testing.T) {
	t.Parallel()
	st := &memPruneStore{counts: map[string]int64{SourceGEOFEED: 7}}
	n, err := Prune(context.Background(), st, "geofeed", true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("n=%d, want 7", n)
	}
	if st.pruneCalls != 0 || st.pruneNECalls != 0 {
		t.Fatalf("dry-run must not prune (prune=%d pruneNE=%d)", st.pruneCalls, st.pruneNECalls)
	}
	if st.countCalls != 1 {
		t.Fatalf("countCalls=%d, want 1", st.countCalls)
	}
}

func TestPruneAllIncludesLacnicNonEmpty(t *testing.T) {
	t.Parallel()
	st := &memPruneStore{
		counts:   map[string]int64{SourceGEOFEED: 2},
		countsNE: map[string]int64{"LACNIC_DB_CSV": 1},
	}
	n, err := Prune(context.Background(), st, "all", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("n=%d, want 3", n)
	}
	if len(st.pruned) != 1 || st.pruned[0] != SourceGEOFEED {
		t.Fatalf("GEOFEED pruned = %v", st.pruned)
	}
	if len(st.prunedNE) != 1 || st.prunedNE[0] != "LACNIC_DB_CSV" {
		t.Fatalf("LACNIC pruned = %v (empty source_url must use NonEmpty path)", st.prunedNE)
	}
}

func TestPruneAllDryRunWritesNothing(t *testing.T) {
	t.Parallel()
	st := &memPruneStore{
		counts:   map[string]int64{SourceGEOFEED: 2},
		countsNE: map[string]int64{"LACNIC_DB_CSV": 4},
	}
	n, err := Prune(context.Background(), st, "all", true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("n=%d, want 6", n)
	}
	if st.pruneCalls != 0 || st.pruneNECalls != 0 {
		t.Fatal("dry-run wrote deletes")
	}
}

func TestPruneUnknownSource(t *testing.T) {
	t.Parallel()
	_, err := Prune(context.Background(), &memPruneStore{}, "lacnic", false)
	if err == nil || !strings.Contains(err.Error(), "unknown --source") {
		t.Fatalf("err = %v", err)
	}
}

func TestPruneNilStore(t *testing.T) {
	t.Parallel()
	if _, err := Prune(context.Background(), nil, "geofeed", false); err == nil {
		t.Fatal("nil store must error")
	}
}
