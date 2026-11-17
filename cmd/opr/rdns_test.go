package main

import (
	"strings"
	"testing"
	"time"

	"github.com/oprand/opr/store/postgres"
)

func TestFormatRDNSStatusEmpty(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 15, 6, 0, 0, time.UTC)
	snap := postgres.RDNSStatusSnapshot{
		GeneratedAt: now,
		StaleAfter:  postgres.DefaultRDNSStaleAfter.String(),
		Sources: []postgres.RDNSSourceCount{
			{Source: "AFRINIC", Never: true},
			{Source: "APNIC", Never: true},
			{Source: "ARIN", Never: true},
			{Source: "LACNIC", Never: true},
			{Source: "RIPE", Never: true},
		},
		Dumps: postgres.MergeRDNSDumpClocks(nil, postgres.RDNSDumpURLs, postgres.DefaultRDNSStaleAfter, now),
	}
	got := formatRDNSStatus(snap, false)
	if !strings.Contains(got, "RDNS") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "NEVER") {
		t.Fatal("empty table must show NEVER")
	}
	if !strings.Contains(got, "IANA") {
		t.Fatal("status must have IANA coverage section")
	}
	if !strings.Contains(got, "WHOIS") {
		t.Fatal("status must have WHOIS enrich section")
	}
	if !strings.Contains(got, "DUMPS") {
		t.Fatal("status must have dump clocks")
	}
	if !strings.Contains(got, "PTR") {
		t.Fatal("status must have PTR crawl section")
	}
	if !strings.Contains(got, "NOERROR") {
		t.Fatal("PTR section must list rcode counts")
	}
	if !strings.Contains(got, "in-addr.arpa.zone") {
		t.Fatal("IANA dump URL must appear")
	}
}

func TestFormatRDNSStatusCounts(t *testing.T) {
	t.Parallel()
	fetched := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	snap := postgres.RDNSStatusSnapshot{
		GeneratedAt: time.Date(2026, 9, 15, 15, 6, 0, 0, time.UTC),
		Sources: []postgres.RDNSSourceCount{
			{Source: "RIPE", Rows: 12, LastFetchedAt: &fetched},
		},
		IANA: postgres.RDNSIANACoverage{
			Expected: 2,
			Fetched:  1,
			Missing:  1,
			Gaps:     []string{"AFRINIC 41.in-addr.arpa"},
		},
		WhoisEligible: 12,
		WhoisEnriched: 4,
		PTR: postgres.EvaluateRDNSPTRStatus(12, 4, &fetched, map[string]int64{
			"NOERROR":  4,
			"NXDOMAIN": 8,
		}, postgres.DefaultRDNSStaleAfter, fetched.Add(time.Hour)),
	}
	got := formatRDNSStatus(snap, false)
	if !strings.Contains(got, "RIPE") || !strings.Contains(got, "12") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "AFRINIC 41.in-addr.arpa") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "enriched") && !strings.Contains(got, "4") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "PTR") || !strings.Contains(got, "NXDOMAIN") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "with ptr") {
		t.Fatal(got)
	}
}

func TestFormatRDNSStatusStale(t *testing.T) {
	t.Parallel()
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	snap := postgres.RDNSStatusSnapshot{
		GeneratedAt: time.Date(2026, 9, 15, 15, 6, 0, 0, time.UTC),
		Sources: []postgres.RDNSSourceCount{
			{Source: "RIPE", Rows: 3, LastFetchedAt: &old, Stale: true},
		},
	}
	got := formatRDNSStatus(snap, false)
	if !strings.Contains(got, "STALE") {
		t.Fatal(got)
	}
}

func TestFormatRDNSStatusPTRNever(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 15, 6, 0, 0, time.UTC)
	snap := postgres.RDNSStatusSnapshot{
		GeneratedAt: now,
		PTR:         postgres.EvaluateRDNSPTRStatus(0, 0, nil, nil, postgres.DefaultRDNSStaleAfter, now),
	}
	got := formatRDNSStatus(snap, false)
	if !strings.Contains(got, "PTR") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "NEVER") {
		t.Fatal("empty PTR must show NEVER")
	}
	if !strings.Contains(got, "NOERROR") || !strings.Contains(got, "NXDOMAIN") {
		t.Fatal("PTR must list rcode zeros")
	}
	if strings.Contains(got, "STALE") {
		t.Fatal("NEVER must not also be STALE")
	}
}

func TestFormatRDNSStatusPTRStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 15, 15, 6, 0, 0, time.UTC)
	old := now.Add(-postgres.DefaultRDNSStaleAfter - time.Hour)
	snap := postgres.RDNSStatusSnapshot{
		GeneratedAt: now,
		PTR: postgres.EvaluateRDNSPTRStatus(3, 1, &old, map[string]int64{
			"NOERROR": 1,
			"TIMEOUT": 2,
		}, postgres.DefaultRDNSStaleAfter, now),
	}
	got := formatRDNSStatus(snap, false)
	if !strings.Contains(got, "PTR") || !strings.Contains(got, "TIMEOUT") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "STALE") {
		t.Fatal("old PTR clock must be STALE")
	}
}
