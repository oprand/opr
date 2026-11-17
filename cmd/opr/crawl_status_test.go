package main

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/store/postgres"
)

func sampleStatusSnapshot(now time.Time) postgres.CrawlStatusSnapshot {
	fileDate := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	ingested := now.Add(-4 * time.Hour)
	ripeSeen := time.Date(2026, 9, 3, 6, 12, 0, 0, time.UTC)
	apnicSeen := time.Date(2026, 9, 3, 4, 1, 0, 0, time.UTC)
	pending := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	failedRetry := now.Add(-2 * time.Hour)

	return postgres.CrawlStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  (48 * time.Hour).String(),
		NRO: postgres.NROStatus{
			Rows:       769149,
			FileDate:   &fileDate,
			IngestedAt: &ingested,
			Stale:      true,
			Empty:      false,
		},
		Bulk: []postgres.BulkSourceStatus{
			{Source: opconst.RIPE, LastSeen: &ripeSeen, Files: 9, Present: 6, Missing: true, Coverage: true},
			{Source: opconst.APNIC, LastSeen: &apnicSeen, Files: 9, Present: 9, Coverage: true},
			{Source: opconst.AFRINIC, Files: 1, Present: 0, Missing: true, Never: true, Coverage: true},
			{Source: opconst.ARIN, Files: 1, Present: 0, Missing: true, Never: true, Coverage: false},
		},
		RIB: postgres.FileWatermark{URL: postgres.RibSeedWatermarkURL, Never: true},
		ASNames: postgres.ASNamesStatus{
			FileWatermark: postgres.FileWatermark{URL: "https://ftp.ripe.net/ripe/asnames/asn.txt", Never: true},
			Rows:          0,
		},
		WhoisDB: []postgres.WhoisDBSourceCount{
			{Source: opconst.RIPE, Autnum: 35000, Inetnum: 120000, Inet6num: 45000},
			{Source: opconst.APNIC, Autnum: 12000, Inetnum: 80000, Inet6num: 20000, AsSet: 500, AsBlock: 80, Irt: 200},
			{Source: opconst.AFRINIC},
			{Source: opconst.ARIN, Autnum: 12, Inetnum: 80, Inet6num: 4},
		},
		Coverage: postgres.CoverageStatus{
			Autnum: []postgres.AutnumCoverage{
				{Registry: opconst.ARIN, NRO: 18400, Target: 18400, WhoisDB: 12000},
				{Registry: opconst.LACNIC, NRO: 0, Target: 0, WhoisDB: 0},
			},
			Ipnet: []postgres.IpnetCoverage{
				{Registry: opconst.ARIN, Target: 89000, Inetnum: 1200, Inet6num: 400},
				{Registry: opconst.LACNIC, Target: 0, Inetnum: 0, Inet6num: 0},
			},
		},
		Queue: []postgres.QueueSnapshot{
			{
				Kind: postgres.CrawlKindAutnum,
				Registries: []postgres.QueueRegistryRow{
					{Registry: opconst.ARIN, Pending: 12041, InProgress: 2, Done: 21000, Failed: 12, Gone: 80},
					{Registry: opconst.LACNIC, Pending: 0, InProgress: 0, Done: 0, Failed: 0, Gone: 0},
				},
			},
		},
		RDAP: postgres.RDAPHealth{
			Status429:         14,
			StaleLeases:       2,
			StaleLeaseAfter:   (15 * time.Minute).String(),
			OldestPendingAt:   &pending,
			OldestFailedRetry: &failedRetry,
			Errors: []postgres.ErrorSample{
				{Error: "rdap as-block AS131072 - AS132095", Count: 12},
			},
		},
	}
}

const statusBoardGolden = `REGISTRY CRAWL   2026-09-03 14:18 UTC

nro         769149 rows   file_date 2026-09-02   ingested 4h ago
            STALE

BULK
            fetched           files  autnum  inetnum  inet6num  as-set  as-block  irt
RIPE        2026-09-03 06:12    6/9   35000   120000     45000       0         0    0  MISSING
APNIC       2026-09-03 04:01    9/9   12000    80000     20000     500        80  200
AFRINIC     NEVER               0/1       0        0         0       0         0    0  MISSING
ARIN        NEVER               0/1      12       80         4       0         0    0  MISSING   not coverage

RIB         NEVER             run seed without --skip-ribs
ASNAMES     NEVER             0 rows

COVERAGE  autnum
              nro  target  whoisdb
ARIN        18400   18400    12000
LACNIC          0       0        0

COVERAGE  ipnet
            target  inetnum  inet6num
ARIN         89000     1200       400
LACNIC           0        0         0

QUEUE  autnum
            pending  in_prog   done  failed  gone
ARIN          12041        2  21000      12    80
LACNIC            0        0      0       0     0

RDAP
429s        14
leases      2 stale (>15m)
oldest      pending 2026-08-28   failed retry 2h ago
errors      rdap as-block AS131072 - AS132095 (12)
`

func TestFormatCrawlStatusGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	got := formatCrawlStatus(sampleStatusSnapshot(now), false)
	if got != statusBoardGolden {
		t.Fatalf("human board mismatch\nGOT:\n%s\nWANT:\n%s", got, statusBoardGolden)
	}
}

func TestFormatCrawlStatusNoANSIWhenColorOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	got := formatCrawlStatus(sampleStatusSnapshot(now), false)
	if strings.Contains(got, "\033[") {
		t.Fatal("color-off output must not contain ANSI")
	}
}

func TestFormatCrawlStatusFlags(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	got := formatCrawlStatus(sampleStatusSnapshot(now), false)
	for _, word := range []string{"STALE", "NEVER", "MISSING", "not coverage"} {
		if !strings.Contains(got, word) {
			t.Fatalf("missing %q in board:\n%s", word, got)
		}
	}
	if strings.Contains(got, "\u2500") || strings.Contains(got, "+--") {
		t.Fatal("board must not draw box art")
	}
}

func TestFormatQueueNumbersRightAligned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	got := formatCrawlStatus(sampleStatusSnapshot(now), false)
	var header, arin string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "pending") && strings.Contains(line, "in_prog") {
			header = line
		}
		if strings.HasPrefix(strings.TrimRight(line, " "), "ARIN") && strings.Contains(line, "12041") {
			arin = line
		}
	}
	if header == "" || arin == "" {
		t.Fatalf("queue lines missing\n%s", got)
	}
	pendingAt := strings.Index(header, "pending")
	doneAt := strings.Index(header, "done")
	if pendingAt < 0 || doneAt < 0 {
		t.Fatalf("headers: %q", header)
	}
	// Right-aligned: last digit of 12041 sits on last column of "pending".
	if arin[pendingAt+len("pending")-1] != '1' {
		t.Fatalf("12041 not right-aligned under pending\n%s\n%s", header, arin)
	}
	if arin[doneAt+len("done")-1] != '0' {
		t.Fatalf("21000 not right-aligned under done\n%s\n%s", header, arin)
	}
}

func TestFormatEmptyNRONever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 14, 18, 0, 0, time.UTC)
	s := sampleStatusSnapshot(now)
	s.NRO = postgres.NROStatus{Rows: 0, Stale: true, Empty: true}
	got := formatCrawlStatus(s, false)
	if !strings.Contains(got, "0 rows") || !strings.Contains(got, "NEVER") || !strings.Contains(got, "STALE") {
		t.Fatalf("empty NRO:\n%s", got)
	}
	if strings.Contains(got, "file_date 2026-09-02") {
		t.Fatal("empty NRO must not keep a file_date")
	}
}
