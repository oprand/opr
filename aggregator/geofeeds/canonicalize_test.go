package geofeeds

import "testing"

func TestCanonicalizeURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "scheme and host lowercased path preserved", in: "HTTP://Example.COM/Feed.csv", want: "http://example.com/Feed.csv"},
		{name: "https default port stripped", in: "https://x.com:443/a", want: "https://x.com/a"},
		{name: "fragment dropped", in: "https://x.com/a#frag", want: "https://x.com/a"},
		{name: "empty path becomes slash", in: "https://x.com", want: "https://x.com/"},
		{name: "ftp rejected", in: "ftp://example.com/feed.csv", want: ""},
		{name: "empty rejected", in: "", want: ""},
		{name: "whitespace only rejected", in: "   ", want: ""},
		{name: "empty host rejected", in: "https://", want: ""},
		{name: "http default port stripped", in: "http://example.com:80/Feed.csv", want: "http://example.com/Feed.csv"},
		{name: "https non-default port kept", in: "https://example.com:8443/a", want: "https://example.com:8443/a"},
		{name: "http port 443 kept", in: "http://example.com:443/a", want: "http://example.com:443/a"},
		{name: "slash path unchanged", in: "https://x.com/", want: "https://x.com/"},
		{name: "query preserved", in: "https://Example.COM/a?b=C", want: "https://example.com/a?b=C"},
		{name: "file rejected", in: "file:///tmp/feed.csv", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CanonicalizeURL(tc.in); got != tc.want {
				t.Fatalf("CanonicalizeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
