package whoisdb

import "testing"

func TestExtractGeofeedURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		line string
		want string
	}{
		{name: "ripe geofeed attr", line: "geofeed: https://example.com/ripe.csv", want: "https://example.com/ripe.csv"},
		{name: "apnic geofeed attr padded", line: "geofeed:        https://example.com/apnic.csv", want: "https://example.com/apnic.csv"},
		{name: "remarks Geofeed rfc9632", line: "remarks: Geofeed https://example.com/rfc.csv", want: "https://example.com/rfc.csv"},
		{name: "remarks geofeed loose", line: "remarks: geofeed https://example.com/loose.csv", want: "https://example.com/loose.csv"},
		{name: "remarks geofeed colon loose", line: "remarks: geofeed: https://example.com/loose2.csv", want: "https://example.com/loose2.csv"},
		{name: "comment Geofeed", line: "Comment: Geofeed https://example.com/arin.csv", want: "https://example.com/arin.csv"},
		{name: "comment geofeed loose", line: "Comment: geofeed https://example.com/arin2.csv", want: "https://example.com/arin2.csv"},
		{name: "comment geofeed colon loose", line: "Comment: geofeed: https://example.com/arin3.csv", want: "https://example.com/arin3.csv"},
		{name: "descr Geofeed", line: "descr: Geofeed https://example.com/descr.csv", want: "https://example.com/descr.csv"},
		{name: "descr geofeed colon", line: "descr: geofeed: https://example.com/descr2.csv", want: "https://example.com/descr2.csv"},
		{name: "continuation url only", line: "https://example.com/wrap.csv", want: "https://example.com/wrap.csv"},
		{name: "continuation Geofeed", line: "Geofeed https://example.com/wrap2.csv", want: "https://example.com/wrap2.csv"},
		{name: "continuation indented url", line: "        https://example.com/wrap3.csv", want: "https://example.com/wrap3.csv"},
		{name: "HTTP scheme and host canonicalized", line: "geofeed: HTTP://Example.COM/Feed.csv", want: "http://example.com/Feed.csv"},
		{name: "https default port stripped", line: "geofeed: https://example.com:443/feed.csv", want: "https://example.com/feed.csv"},
		{name: "https empty path slash", line: "geofeed: https://example.com", want: "https://example.com/"},
		{name: "http kept", line: "geofeed: http://example.com/insecure.csv", want: "http://example.com/insecure.csv"},
		{name: "quoted url", line: `geofeed: "https://example.com/q.csv"`, want: "https://example.com/q.csv"},
		{name: "trailing junk", line: "geofeed: https://example.com/j.csv,;.)>", want: "https://example.com/j.csv"},
		{name: "hash comment", line: "geofeed: https://example.com/c.csv # self-published", want: "https://example.com/c.csv"},
		{name: "trailing period", line: "remarks: Geofeed https://example.com/p.csv.", want: "https://example.com/p.csv"},
		{name: "rfc-editor no token", line: "remarks: See https://www.rfc-editor.org/rfc/rfc9632.html", want: ""},
		{name: "rfc-editor then geofeed word", line: "remarks: https://www.rfc-editor.org/info/rfc8805 discusses geofeed", want: ""},
		{name: "geofeed rfc then url", line: "remarks: See geofeed RFC at https://www.rfc-editor.org/rfc/rfc9632.html", want: ""},
		{name: "no url", line: "remarks: Geofeed self-published file", want: ""},
		{name: "non-geofeed comment", line: "Comment: Customer allocation", want: ""},
		{name: "descr bare url", line: "descr: https://example.com/bare.csv", want: ""},
		{name: "empty", line: "", want: ""},
		{name: "unrelated attr", line: "country: NL", want: ""},
		{name: "ftp dropped", line: "geofeed: ftp://example.com/feed.csv", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractGeofeedURL(tc.line); got != tc.want {
				t.Fatalf("extractGeofeedURL(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}
