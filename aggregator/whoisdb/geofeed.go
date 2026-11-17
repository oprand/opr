package whoisdb

import (
	"strings"

	"github.com/oprand/opr/aggregator/geofeeds"
	whoisdb_store "github.com/oprand/opr/store/postgres/whoisdb"
)

func isGeofeedContinuationAttr(prevItem string) bool {
	switch prevItem {
	case "geofeed", "remarks", "descr", "Comment", "comment":
		return true
	default:
		return false
	}
}

// applyGeofeedFromLine extracts a geofeed URL from one dump line and, when the
// current object is an inetnum/inet6num, stores it on the object and in the
// URL catalog. official is true for the RPSL geofeed: attribute (and its
// continuation): that form wins over remarks/descr/Comment on the same object.
func (wdb *WhoisDBAggregator) applyGeofeedFromLine(record whoisdb_store.WhoisRecord, line string, official bool) {
	var dst **string
	switch w := record.(type) {
	case *whoisdb_store.WhoisInetNum:
		dst = &w.Geofeed
	case *whoisdb_store.WhoisInet6Num:
		dst = &w.Geofeed
	default:
		return
	}
	url := extractGeofeedURL(line)
	if url == "" {
		return
	}
	if official || *dst == nil || **dst == "" {
		*dst = &url
	}
	wdb.Geofeeds.Add(url)
}

// extractGeofeedURL returns a single canonical http(s) geofeed URL from one
// WHOIS line, or "" if the line is not a recognized geofeed form. Object-level
// priority (geofeed: wins over remarks) is applied by the parser, not here.
func extractGeofeedURL(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	attr, value, hasAttr := splitRPSLAttribute(line)
	if hasAttr {
		switch strings.ToLower(attr) {
		case "geofeed":
			return normalizeGeofeedURL(value)
		case "remarks", "comment", "descr":
			return urlAfterGeofeedToken(value)
		default:
			return ""
		}
	}

	if u := urlAfterGeofeedToken(line); u != "" {
		return u
	}
	return normalizeGeofeedURL(line)
}

func splitRPSLAttribute(line string) (attr, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", line, false
	}
	attr = strings.TrimSpace(line[:i])
	if attr == "" || strings.ContainsAny(attr, " \t") {
		return "", line, false
	}
	if strings.EqualFold(attr, "http") || strings.EqualFold(attr, "https") {
		return "", line, false
	}
	return attr, strings.TrimSpace(line[i+1:]), true
}

// urlAfterGeofeedToken requires the RFC 9632 Geofeed token (or loose
// geofeed / geofeed:) immediately before the URL. A later http(s) link
// after other words (e.g. an RFC-editor citation) is not accepted.
func urlAfterGeofeedToken(s string) string {
	lower := strings.ToLower(s)
	start := 0
	for {
		i := strings.Index(lower[start:], "geofeed")
		if i < 0 {
			return ""
		}
		i += start
		if i > 0 && isTokenChar(s[i-1]) {
			start = i + 7
			continue
		}
		after := i + 7
		if after < len(s) && isTokenChar(s[after]) {
			start = after
			continue
		}
		rest := strings.TrimSpace(s[after:])
		rest = strings.TrimPrefix(rest, ":")
		rest = strings.TrimSpace(rest)
		return normalizeGeofeedURL(rest)
	}
}

func isTokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func normalizeGeofeedURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "#"); i != -1 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)
	if !hasHTTPSchemePrefix(s) {
		return ""
	}
	if i := strings.IndexAny(s, " \t"); i != -1 {
		s = s[:i]
	}
	s = strings.TrimRight(s, `,;.)>'"`)
	if !hasHTTPSchemePrefix(s) || strings.EqualFold(s, "http://") || strings.EqualFold(s, "https://") {
		return ""
	}
	return geofeeds.CanonicalizeURL(s)
}

func hasHTTPSchemePrefix(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
