package peeringdb

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"
)

func TestPeeringDBDumpURLConstants(t *testing.T) {
	t.Parallel()
	if postgres.PeeringDBDumpURL("org") != "https://public.peeringdb.com/org-0.json" {
		t.Fatalf("org url = %q", postgres.PeeringDBDumpURL("org"))
	}
	if postgres.PeeringDBOrgDumpURL != postgres.PeeringDBDumpURL("org") {
		t.Fatal("org constant must match PeeringDBDumpURL")
	}
	if len(postgres.PeeringDBDumps) != 10 {
		t.Fatalf("want 10 dumps, got %d", len(postgres.PeeringDBDumps))
	}
}

func TestShouldReplacePeeringDBDumpEmptyMustNotWipe(t *testing.T) {
	t.Parallel()
	if ShouldReplacePeeringDBDump(0) {
		t.Fatal("empty dump must not wipe")
	}
	if !ShouldReplacePeeringDBDump(1) {
		t.Fatal("non-empty dump must replace")
	}
}

func TestIsPublicVisible(t *testing.T) {
	t.Parallel()
	if !IsPublicVisible("Public") {
		t.Fatal("Public must be kept")
	}
	for _, v := range []string{"Users", "Private", "", "public"} {
		if IsPublicVisible(v) {
			t.Fatalf("%q must not be treated as public dump row", v)
		}
	}
}

func TestMapDumpRowIgnoresExtraFields(t *testing.T) {
	t.Parallel()
	created := "2024-01-02T03:04:05Z"
	obj := map[string]any{
		"id":           float64(42),
		"status":       "ok",
		"created":      created,
		"updated":      created,
		"name":         "Example Net",
		"aka":          "ex",
		"asn":          float64(64500),
		"org_id":       float64(7),
		"info_type":    "NSP",
		"info_types":   []any{"NSP", "Content"},
		"social_media": []any{map[string]any{"service": "website", "identifier": "https://ex.example"}},
		"info_unicast": true,
		"policy_ratio": false,
	}
	row, ok := MapDumpRow(postgres.PeeringDBDumpTagNet, obj)
	if !ok {
		t.Fatal("expected mapped network row")
	}
	cols := postgres.PeeringDBTableColumns(postgres.PeeringDBTableNetwork)
	if len(row) != len(cols) {
		t.Fatalf("row len=%d, want %d columns", len(row), len(cols))
	}
	if row[0] != 42 {
		t.Fatalf("id = %v", row[0])
	}
	if row[6] != "Example Net" {
		t.Fatalf("name = %v", row[6])
	}
	if row[17] != "NSP" {
		t.Fatalf("info_type = %v", row[17])
	}
	if row[13] != "" {
		t.Fatalf("notes_private must be empty string, got %v", row[13])
	}
	for _, v := range row {
		if s, ok := v.(string); ok && strings.Contains(s, "Content") {
			t.Fatal("info_types must be ignored")
		}
	}
}

func TestMapDumpRowSkipsZeroIDAndUnknownTag(t *testing.T) {
	t.Parallel()
	if _, ok := MapDumpRow(postgres.PeeringDBDumpTagOrg, map[string]any{"name": "x"}); ok {
		t.Fatal("missing id must skip")
	}
	if _, ok := MapDumpRow("campus", map[string]any{"id": float64(1)}); ok {
		t.Fatal("unknown tag must skip")
	}
}

func TestMapDumpRowPOCPublicOnly(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"id":      float64(9),
		"status":  "ok",
		"created": "2024-01-02T03:04:05Z",
		"updated": "2024-01-02T03:04:05Z",
		"role":    "Abuse",
		"name":    "NOC",
		"net_id":  float64(1),
	}
	pub := cloneMap(base)
	pub["visible"] = "Public"
	if _, ok := MapDumpRow(postgres.PeeringDBDumpTagPOC, pub); !ok {
		t.Fatal("Public poc must map")
	}
	priv := cloneMap(base)
	priv["visible"] = "Private"
	if _, ok := MapDumpRow(postgres.PeeringDBDumpTagPOC, priv); ok {
		t.Fatal("Private poc must not enter the public dump swap")
	}
	if row, ok := MapOverlayRow(postgres.PeeringDBDumpTagPOC, priv); !ok {
		t.Fatal("overlay must keep Private poc")
	} else if row[6] != "Private" {
		t.Fatalf("visible = %v", row[6])
	}
}

func TestMapDumpRowOrgExistingColumnsOnly(t *testing.T) {
	t.Parallel()
	when := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	obj := map[string]any{
		"id":       float64(1),
		"status":   "ok",
		"created":  when.Format(time.RFC3339),
		"updated":  when.Format(time.RFC3339),
		"name":     "Org",
		"aka":      "ignored",
		"campus":   float64(99),
		"carrier":  true,
		"address1": "1 Main",
		"country":  "US",
		"website":  "https://example",
		"notes":    "n",
	}
	row, ok := MapDumpRow(postgres.PeeringDBDumpTagOrg, obj)
	if !ok {
		t.Fatal("expected org row")
	}
	cols := postgres.PeeringDBTableColumns(postgres.PeeringDBTableOrganization)
	if len(row) != len(cols) {
		t.Fatalf("row len=%d want %d", len(row), len(cols))
	}
	if row[11] != "Org" || row[5] != "1 Main" || row[10] != "US" {
		t.Fatalf("mapped fields: %#v", row)
	}
}

func TestNewDumpCopySourceEmptyData(t *testing.T) {
	t.Parallel()
	src, err := newDumpCopySource(strings.NewReader(`{"meta":{},"data":[]}`), func(map[string]any) ([]any, bool) {
		return []any{1}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.Next() {
		t.Fatal("empty data must yield no rows")
	}
	if src.n != 0 {
		t.Fatalf("mapped rows = %d, want 0", src.n)
	}
	if ShouldReplacePeeringDBDump(src.n) {
		t.Fatal("empty decoded dump must not wipe")
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
