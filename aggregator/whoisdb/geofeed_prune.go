package whoisdb

import (
	"strings"
)

// isGeofeedHarvestURL reports whether a pass-1 dump can contain inetnum/inet6num
// objects (the only ones that contribute geofeed URLs). Split org/role/person/
// aut-num files cannot; mixed RIR/NIR dumps (name.db.gz) can.
func isGeofeedHarvestURL(u string) bool {
	name := u
	if i := strings.LastIndex(u, "/"); i >= 0 {
		name = u[i+1:]
	}
	if strings.Contains(name, ".db.inetnum.") || strings.Contains(name, ".db.inet6num.") {
		return true
	}
	// Mixed dumps: afrinic.db.gz, arin.db.gz, lacnic.db.gz, jpnic.db.gz, …
	return strings.HasSuffix(name, ".db.gz") && strings.Count(name, ".") == 2
}

func geofeedHarvestSources() []whoisDBSource {
	out := make([]whoisDBSource, 0, 10)
	for _, src := range registrationSources {
		if isGeofeedHarvestURL(src.url) {
			out = append(out, src)
		}
	}
	return out
}

// sourceParsedThisRun is true when prefetch downloaded and parsePrefetched
// actually ran. ETag-skip sets HasChanged=false and never fills
// ParsedRecordsCount. Download/parse failure leaves FetchError set.
func sourceParsedThisRun(st *WhoisDBURLStatus) bool {
	if st == nil {
		return false
	}
	return st.HasChanged && st.FetchError == "" && st.ParsedRecordsCount != nil
}

// pass1GeofeedHarvestComplete is true only when every inetnum-capable pass-1
// source was scheduled and parsed this run. A filtered job list (only-registries
// or equivalent) or any ETag-skip / fetch failure on a meaningful file is
// incomplete. org/role/person/aut-num-only split files are ignored.
func pass1GeofeedHarvestComplete(jobs []prefetchJob, statuses map[string]*WhoisDBURLStatus) bool {
	scheduled := make(map[string]struct{}, len(jobs))
	for _, j := range jobs {
		scheduled[j.src.url] = struct{}{}
	}
	required := geofeedHarvestSources()
	if len(required) == 0 {
		return false
	}
	for _, src := range required {
		if _, ok := scheduled[src.url]; !ok {
			return false
		}
		if !sourceParsedThisRun(statuses[statusKey(src.url, registrationRecordTypes)]) {
			return false
		}
	}
	return true
}

// geofeedPruneSkipReason is empty when stale geofeeds may be pruned. Save
// failure, an empty harvest, or an incomplete pass-1 all block prune.
func geofeedPruneSkipReason(jobs []prefetchJob, statuses map[string]*WhoisDBURLStatus, urls []string, saveErr error) string {
	if saveErr != nil {
		return "save failed"
	}
	if len(urls) == 0 {
		return "empty harvest"
	}
	if !pass1GeofeedHarvestComplete(jobs, statuses) {
		return "incomplete pass-1 harvest"
	}
	return ""
}
