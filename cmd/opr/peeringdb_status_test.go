package main

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/peeringdb"
	"github.com/oprand/opr/store/postgres"
)

func TestPeeringDBStaleAfterMatchesCrawlInterval(t *testing.T) {
	t.Parallel()
	if postgres.DefaultPeeringDBStaleAfter != 2*peeringdb.DefaultCrawlInterval {
		t.Fatalf("DefaultPeeringDBStaleAfter = %s, want 2× DefaultCrawlInterval (%s)", postgres.DefaultPeeringDBStaleAfter, peeringdb.DefaultCrawlInterval)
	}
}

func samplePeeringDBStatusSnapshot(now time.Time) postgres.PeeringDBStatusSnapshot {
	orgSeen := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	facSeen := time.Date(2026, 8, 1, 4, 0, 0, 0, time.UTC)
	netSeen := time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)
	lastData := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)

	return postgres.PeeringDBStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  (48 * time.Hour).String(),
		Tables: []postgres.PeeringDBTableCount{
			{Table: postgres.PeeringDBTableOrganization, Rows: 12345},
			{Table: postgres.PeeringDBTableFacility, Rows: 8901},
			{Table: postgres.PeeringDBTableNetwork, Rows: 28000},
			{Table: postgres.PeeringDBTableIX, Rows: 1200},
			{Table: postgres.PeeringDBTableIXFacility, Rows: 3400},
			{Table: postgres.PeeringDBTableIXLAN, Rows: 1500},
			{Table: postgres.PeeringDBTableIXLANPrefix, Rows: 2800},
			{Table: postgres.PeeringDBTableNetworkContact, Rows: 9000},
			{Table: postgres.PeeringDBTableNetworkFacility, Rows: 45000},
			{Table: postgres.PeeringDBTableNetworkIXLAN, Rows: 120000},
		},
		Dumps: []postgres.PeeringDBDumpClock{
			{
				URL:         postgres.PeeringDBOrgDumpURL,
				LastSeen:    &orgSeen,
				MetaAddedAt: &orgSeen,
				ETagPresent: true,
			},
			{
				URL:         postgres.PeeringDBFacDumpURL,
				LastSeen:    &facSeen,
				MetaAddedAt: &facSeen,
				ETagPresent: true,
				Stale:       true,
			},
			{
				URL:         postgres.PeeringDBNetDumpURL,
				LastSeen:    &netSeen,
				MetaAddedAt: &netSeen,
			},
			{URL: postgres.PeeringDBIXDumpURL, Never: true},
		},
		Sync: postgres.PeeringDBSyncClock{
			LastUpdated: &lastData,
		},
	}
}

const peeringdbStatusBoardGolden = `PEERINGDB   2026-09-08 14:18 UTC

TABLES
                              rows
peeringdb_organization       12345
peeringdb_facility            8901
peeringdb_network            28000
peeringdb_ix                  1200
peeringdb_ix_facility         3400
peeringdb_ixlan               1500
peeringdb_ixlan_prefix        2800
peeringdb_network_contact     9000
peeringdb_network_facility   45000
peeringdb_network_ixlan     120000

DUMPS
            last seen         etag
org-0.json  2026-09-08 12:00  yes
fac-0.json  2026-08-01 04:00  yes   STALE
net-0.json  2026-09-08 11:00  no
ix-0.json   NEVER             no

SYNC
last data   2026-09-08 10:00
`

func TestFormatPeeringDBStatusGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatPeeringDBStatus(samplePeeringDBStatusSnapshot(now), false)
	if got != peeringdbStatusBoardGolden {
		t.Fatalf("human board mismatch\nGOT:\n%s\nWANT:\n%s", got, peeringdbStatusBoardGolden)
	}
}

func TestFormatPeeringDBStatusNoANSIWhenColorOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatPeeringDBStatus(samplePeeringDBStatusSnapshot(now), false)
	if strings.Contains(got, "\033[") {
		t.Fatal("color-off output must not contain ANSI")
	}
}

func TestFormatPeeringDBStatusFlags(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatPeeringDBStatus(samplePeeringDBStatusSnapshot(now), false)
	if !strings.Contains(got, "STALE") {
		t.Fatalf("missing %q in board:\n%s", "STALE", got)
	}
	if strings.Contains(got, "\u2500") || strings.Contains(got, "+--") {
		t.Fatal("board must not draw box art")
	}
}

func TestFormatPeeringDBStatusNumbersRightAligned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	got := formatPeeringDBStatus(samplePeeringDBStatusSnapshot(now), false)
	var header, netixlan, org string
	inTables := false
	for _, line := range strings.Split(got, "\n") {
		if line == "TABLES" {
			inTables = true
			continue
		}
		if !inTables {
			continue
		}
		if line == "" || line == "DUMPS" {
			break
		}
		if strings.Contains(line, "rows") && !strings.Contains(line, "peeringdb") {
			header = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "peeringdb_network_ixlan") {
			netixlan = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "peeringdb_organization") {
			org = line
		}
	}
	if header == "" || netixlan == "" || org == "" {
		t.Fatalf("table lines missing\n%s", got)
	}
	rowsAt := strings.Index(header, "rows")
	if rowsAt < 0 {
		t.Fatalf("headers: %q", header)
	}
	end := rowsAt + len("rows") - 1
	if end >= len(netixlan) || netixlan[end] != '0' {
		t.Fatalf("120000 not right-aligned under rows\n%s\n%s", header, netixlan)
	}
	if end >= len(org) || org[end] != '5' {
		t.Fatalf("12345 not right-aligned under rows\n%s\n%s", header, org)
	}
}

func TestFormatEmptyPeeringDBNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	s := postgres.PeeringDBStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  (48 * time.Hour).String(),
		Tables: []postgres.PeeringDBTableCount{
			{Table: postgres.PeeringDBTableOrganization, Missing: true},
			{Table: postgres.PeeringDBTableFacility, Missing: true},
			{Table: postgres.PeeringDBTableNetwork, Missing: true},
			{Table: postgres.PeeringDBTableIX, Missing: true},
			{Table: postgres.PeeringDBTableIXFacility, Missing: true},
			{Table: postgres.PeeringDBTableIXLAN, Missing: true},
			{Table: postgres.PeeringDBTableIXLANPrefix, Missing: true},
			{Table: postgres.PeeringDBTableNetworkContact, Missing: true},
			{Table: postgres.PeeringDBTableNetworkFacility, Missing: true},
			{Table: postgres.PeeringDBTableNetworkIXLAN, Missing: true},
		},
		Dumps: []postgres.PeeringDBDumpClock{
			{URL: postgres.PeeringDBOrgDumpURL, Never: true, Stale: true},
			{URL: postgres.PeeringDBNetDumpURL, Never: true},
		},
		Sync: postgres.PeeringDBSyncClock{Never: true},
	}
	got := formatPeeringDBStatus(s, false)
	if !strings.Contains(got, "NEVER") {
		t.Fatalf("empty dumps:\n%s", got)
	}
	if !strings.Contains(got, "MISSING") {
		t.Fatalf("empty tables must flag MISSING:\n%s", got)
	}
	if !strings.Contains(got, "peeringdb_network_ixlan") {
		t.Fatalf("TABLES must list base tables:\n%s", got)
	}
	if strings.Contains(got, "ix_expanded") {
		t.Fatalf("TABLES must not list dropped ix_expanded:\n%s", got)
	}
	if strings.Contains(got, "STALE") {
		t.Fatal("empty dumps must not also flag STALE")
	}
	if !strings.Contains(got, "SYNC") {
		t.Fatalf("SYNC missing:\n%s", got)
	}
}

func TestFormatPeeringDBOK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 14, 18, 0, 0, time.UTC)
	fresh := now.Add(-4 * time.Hour)
	s := samplePeeringDBStatusSnapshot(now)
	s.Tables = []postgres.PeeringDBTableCount{
		{Table: postgres.PeeringDBTableOrganization, Rows: 4},
		{Table: postgres.PeeringDBTableFacility, Rows: 4},
		{Table: postgres.PeeringDBTableNetwork, Rows: 4},
		{Table: postgres.PeeringDBTableIX, Rows: 4},
		{Table: postgres.PeeringDBTableIXFacility, Rows: 4},
		{Table: postgres.PeeringDBTableIXLAN, Rows: 4},
		{Table: postgres.PeeringDBTableIXLANPrefix, Rows: 4},
		{Table: postgres.PeeringDBTableNetworkContact, Rows: 4},
		{Table: postgres.PeeringDBTableNetworkFacility, Rows: 4},
		{Table: postgres.PeeringDBTableNetworkIXLAN, Rows: 4},
	}
	s.Dumps = []postgres.PeeringDBDumpClock{
		{URL: postgres.PeeringDBOrgDumpURL, LastSeen: &fresh, ETagPresent: true},
	}
	s.Sync = postgres.PeeringDBSyncClock{LastUpdated: &fresh}
	got := formatPeeringDBStatus(s, false)
	if strings.Contains(got, "MISSING") || strings.Contains(got, "STALE") || strings.Contains(got, "NEVER") {
		t.Fatalf("fresh board should not flag problems:\n%s", got)
	}
}

func TestPeeringDBDumpLabel(t *testing.T) {
	t.Parallel()
	got := peeringDBDumpLabel("https://public.peeringdb.com/org-0.json")
	if got != "org-0.json" {
		t.Fatalf("got %q", got)
	}
	if peeringDBDumpLabel("") != "" {
		t.Fatal("empty url")
	}
}
