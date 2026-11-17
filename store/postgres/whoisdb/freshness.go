package whoisdb

import "time"

// fetch_method values on whoisdb_* rows. How this row was last refreshed:
//
//   - bulk_dump: RIR/NIR WHOIS dump ingest (RIPE, APNIC, AFRINIC, NIRs).
//     Typically a complete object from the daily/weekly dump.
//   - rdap: live RDAP query. Used for ARIN/LACNIC (dumps miss most ASNs)
//     and for dump gaps. The mapped object may be less complete than a dump.
//   - originas: historical. ARIN OriginAS RDAP extension, retired 28 July 2025.
//     Kept as an enum for existing rows; do not write this method.
//   - on_demand: ad-hoc lookup outside the scheduled crawl.
//   - asnames: RIPE asnames.txt name+country backfill for autnums no WHOIS
//     dump covers. Sparse rows only; must not be treated as dump coverage.
const (
	FetchMethodBulkDump = "bulk_dump"
	FetchMethodRDAP     = "rdap"
	FetchMethodOriginas = "originas"
	FetchMethodOnDemand = "on_demand"
	FetchMethodASNames  = "asnames"
)

// stampFetch records that an object was observed via method (a FetchMethod*
// constant). Sets last_fetched_at and last_seen_in_source_at to now.
// last_changed_at and content_hash are intentionally left unset: we do not
// compute payload hashes yet, and COALESCE on upsert leaves existing values.
func stampFetch(method string) (fetchMethod *string, lastFetchedAt, lastSeenInSourceAt *time.Time) {
	now := time.Now()
	m := method
	return &m, &now, &now
}
