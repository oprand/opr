package rdns

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)

var checksumExt = []string{
	".md5", ".asc", ".sig", ".sha", ".sha1", ".sha256", ".sha512",
}

// IsChecksumName reports sidecar / checksum files that must not be ingested.
func IsChecksumName(name string) bool {
	base := strings.ToLower(strings.TrimSpace(path.Base(name)))
	if base == "" || base == "." || base == "/" {
		return true
	}
	for _, ext := range checksumExt {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	switch base {
	case "md5sums", "sha1sums", "sha256sums", "sha512sums", "checksums", "checksum.txt":
		return true
	}
	if strings.Contains(base, "checksum") {
		return true
	}
	if strings.HasSuffix(base, "sums") && !strings.Contains(base, "arpa") {
		return true
	}
	return false
}

// IsReverseZoneName reports a RIR reverse zone filename (optional -RIR suffix).
func IsReverseZoneName(name string) bool {
	base := strings.ToLower(strings.TrimSpace(path.Base(name)))
	base = stripZoneSourceSuffix(base)
	return strings.HasSuffix(base, ".in-addr.arpa") || strings.HasSuffix(base, ".ip6.arpa") ||
		base == "in-addr.arpa" || base == "ip6.arpa"
}

func stripZoneSourceSuffix(base string) string {
	i := strings.LastIndex(base, "-")
	if i <= 0 {
		return base
	}
	head, tail := base[:i], base[i+1:]
	if tail == "" {
		return base
	}
	for _, c := range tail {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return base
		}
	}
	if strings.Contains(head, "in-addr.arpa") || strings.Contains(head, "ip6.arpa") {
		return head
	}
	return base
}

// ZoneFileOrigin returns the DNS origin for a RIR zone filename
// (193.in-addr.arpa-RIPE → 193.in-addr.arpa.).
func ZoneFileOrigin(filename string) (string, bool) {
	base := strings.ToLower(strings.TrimSpace(path.Base(filename)))
	if IsChecksumName(base) || !IsReverseZoneName(base) {
		return "", false
	}
	origin := stripZoneSourceSuffix(base)
	if origin == "" {
		return "", false
	}
	return canonicalZone(origin), true
}

func canonicalZone(z string) string {
	z = strings.ToLower(strings.TrimSpace(z))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return ""
	}
	return z + "."
}

// ParseZoneListing extracts same-host reverse zone file URLs from an HTML
// (or plain-text) directory listing. Checksums, directories, and README are skipped.
func ParseZoneListing(listURL, body string) []string {
	base, err := url.Parse(listURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "javascript:") {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		res := base.ResolveReference(u)
		if res.Host != "" && base.Host != "" && !strings.EqualFold(res.Host, base.Host) {
			return
		}
		name := path.Base(res.Path)
		if name == "" || name == "." || name == ".." {
			return
		}
		if strings.HasSuffix(res.Path, "/") {
			return
		}
		if IsChecksumName(name) || !IsReverseZoneName(name) {
			return
		}
		s := res.String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	if hrefRe.MatchString(body) {
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			href := m[2]
			if href == "" {
				href = m[3]
			}
			if href == "" {
				href = m[4]
			}
			add(href)
		}
		return out
	}

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		add(fields[len(fields)-1])
	}
	return out
}

// PreferRIRZoneFiles keeps one file per DNS origin. When a listing has both
// an unsuffixed name and *-{RIR} (AFRINIC publishes 41.in-addr.arpa and
// 41.in-addr.arpa-AFRINIC), the RIR-suffixed file wins so upsert cannot
// steal source_url on UNIQUE (zone, source).
func PreferRIRZoneFiles(source string, urls []string) []string {
	source = strings.ToLower(strings.TrimSpace(source))
	type group struct {
		urls []string
	}
	byOrigin := make(map[string]*group)
	var order []string
	for _, u := range urls {
		origin, ok := ZoneFileOrigin(u)
		if !ok {
			continue
		}
		g, ok := byOrigin[origin]
		if !ok {
			g = &group{}
			byOrigin[origin] = g
			order = append(order, origin)
		}
		g.urls = append(g.urls, u)
	}
	out := make([]string, 0, len(order))
	for _, origin := range order {
		list := byOrigin[origin].urls
		var preferred []string
		for _, u := range list {
			if zoneFileHasRIRSuffix(u, source) {
				preferred = append(preferred, u)
			}
		}
		if len(preferred) > 0 {
			out = append(out, preferred[0])
			continue
		}
		out = append(out, list[0])
	}
	return out
}

func zoneFileHasRIRSuffix(fileURL, source string) bool {
	if source == "" {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(path.Base(fileURL)))
	stripped := stripZoneSourceSuffix(base)
	if stripped == base || len(base) <= len(stripped)+1 {
		return false
	}
	return base[len(stripped)+1:] == source
}

// ListingHasHrefs reports an HTML directory listing (vs a plain-text index).
func ListingHasHrefs(body string) bool {
	return hrefRe.MatchString(body)
}
