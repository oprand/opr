package geofeeds

import (
	"net"
	"net/url"
	"strings"
)

// CanonicalizeURL returns a stable catalog key for an http(s) geofeed URL, or
// "" if the input is not a usable http(s) URL (ftp, empty host, empty string).
//
// Rules: scheme and host are lowercased; default ports (:80 / :443) are
// stripped; fragments are dropped; path case is preserved; a missing path
// becomes "/". Query and userinfo are kept.
func CanonicalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}
	u.Scheme = scheme
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "" && u.Opaque == "" {
		u.Path = "/"
	}
	return u.String()
}
