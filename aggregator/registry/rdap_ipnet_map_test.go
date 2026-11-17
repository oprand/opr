package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

type rdapIpnetFixtureWant struct {
	queried       string
	v4            []string
	v6            []string
	netname       string
	orgHandle     string
	abuseNicHdl   string
	geofeed       string
	countryCode   string
	preferFirst   string
	cidr0Siblings bool
}

var rdapIpnetFixtures = []struct {
	file string
	want rdapIpnetFixtureWant
}{
	{
		file: "NET-192-0-2-0-1.json",
		want: rdapIpnetFixtureWant{
			queried:     "192.0.2.0/24",
			v4:          []string{"192.0.2.0/24"},
			netname:     "TEST-NET-1",
			orgHandle:   "GOGL",
			abuseNicHdl: "ABUSE5250-ARIN",
		},
	},
	{
		file: "LACNIC-2804-14d.json",
		want: rdapIpnetFixtureWant{
			queried:     "2804:14d::/32",
			v6:          []string{"2804:14d::/32"},
			netname:     "NIC-BR",
			orgHandle:   "BR-NIC-LACNIC",
			abuseNicHdl: "ABU123",
			countryCode: "BR",
		},
	},
	{
		file: "NET-203-0-113-0-geofeed.json",
		want: rdapIpnetFixtureWant{
			queried:   "203.0.113.0/24",
			v4:        []string{"203.0.113.0/24"},
			netname:   "TEST-NET-3-GEOFEED",
			orgHandle: "ORG-EX-1",
			geofeed:   "https://example.com/geofeed.csv",
		},
	},
	{
		file: "NET-192-0-2-cidr0.json",
		want: rdapIpnetFixtureWant{
			queried:       "192.0.2.0/25",
			v4:            []string{"192.0.2.0/25", "192.0.2.128/25"},
			netname:       "CIDR0-ONLY",
			preferFirst:   "192.0.2.0/25",
			cidr0Siblings: true,
		},
	},
}

func TestMapIpnetFromRDAPFixtures(t *testing.T) {
	aggr := &RegistryAggregator{Logger: zap.NewNop()}

	for _, tc := range rdapIpnetFixtures {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			resp := decodeIPNetworkFixture(t, tc.file)
			inet4, inet6, roles, orgs := mapIpnetFromRDAP(aggr, tc.want.queried, resp, opconst.ARIN, opconst.ARIN)
			stampIpnetRDAPFetch(inet4, inet6, roles, orgs)

			got4 := inetnumCIDRs(inet4)
			got6 := inet6numCIDRs(inet6)
			if !stringSlicesEqual(got4, tc.want.v4) {
				t.Errorf("v4 prefixes: got %v want %v", got4, tc.want.v4)
			}
			if !stringSlicesEqual(got6, tc.want.v6) {
				t.Errorf("v6 prefixes: got %v want %v", got6, tc.want.v6)
			}
			if tc.want.preferFirst != "" && len(inet4) > 0 && inet4[0].Netblock.String() != tc.want.preferFirst {
				t.Errorf("preferred first cidr: got %s want %s", inet4[0].Netblock.String(), tc.want.preferFirst)
			}

			rows := inetnumRows(inet4)
			if len(inet4) == 0 {
				rows = inet6Rows(inet6)
			}
			if tc.want.netname != "" && rows.netname != tc.want.netname {
				t.Errorf("netname: got %q want %q", rows.netname, tc.want.netname)
			}
			if ptrStr(rows.fetchMethod) != whoisdb.FetchMethodRDAP {
				t.Errorf("fetch_method: got %q want %q", ptrStr(rows.fetchMethod), whoisdb.FetchMethodRDAP)
			}
			if ptrStr(rows.fetchMethod) == whoisdb.FetchMethodOriginas {
				t.Error("must never write FetchMethodOriginas")
			}
			if rows.lastFetchedAt == nil || rows.lastSeen == nil {
				t.Error("missing last_fetched_at / last_seen_in_source_at")
			}
			if tc.want.geofeed != "" && ptrStr(rows.geofeed) != tc.want.geofeed {
				t.Errorf("geofeed: got %q want %q", ptrStr(rows.geofeed), tc.want.geofeed)
			}
			if tc.want.countryCode != "" && ptrStr(rows.countryCode) != tc.want.countryCode {
				t.Errorf("country_code: got %q want %q", ptrStr(rows.countryCode), tc.want.countryCode)
			}

			if tc.want.orgHandle != "" {
				org := orgByHandle(orgs, tc.want.orgHandle)
				if org == nil {
					t.Fatalf("missing org %q (got %v)", tc.want.orgHandle, orgHandles(orgs))
				}
				if ptrStr(org.FetchMethod) != whoisdb.FetchMethodRDAP {
					t.Errorf("org.fetch_method: got %q want %q", ptrStr(org.FetchMethod), whoisdb.FetchMethodRDAP)
				}
			}
			if tc.want.abuseNicHdl != "" {
				abuse := roleByHandle(roles, tc.want.abuseNicHdl)
				if abuse == nil {
					t.Fatalf("missing abuse role %q (got %v)", tc.want.abuseNicHdl, roleHandles(roles))
				}
				if abuse.NestingLevel != 1 {
					t.Errorf("abuse NestingLevel: got %d want 1", abuse.NestingLevel)
				}
				if ptrStr(abuse.FetchMethod) != whoisdb.FetchMethodRDAP {
					t.Errorf("abuse.fetch_method: got %q want %q", ptrStr(abuse.FetchMethod), whoisdb.FetchMethodRDAP)
				}
			}

			for _, r := range roles {
				if r != nil && ptrStr(r.FetchMethod) == whoisdb.FetchMethodOriginas {
					t.Errorf("role %q fetch_method originas", r.NicHdl)
				}
			}

			if tc.want.cidr0Siblings {
				if len(inet4) != 2 {
					t.Fatalf("cidr0 siblings: got %d inetnum rows, want 2 (same object, not child jobs)", len(inet4))
				}
				// persistIpnet only SaveWhois*; extra cidr0 prefixes must not
				// become crawl_target inserts. Mapping returns whois rows only.
				if len(got4) != 2 {
					t.Fatalf("cidr0 must persist both prefixes as whois rows, got %v", got4)
				}
			}
		})
	}
}

func TestMapIpnetFromRDAPPrefersQueriedCidr0(t *testing.T) {
	aggr := &RegistryAggregator{Logger: zap.NewNop()}
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-cidr0.json")
	inet4, _, _, _ := mapIpnetFromRDAP(aggr, "192.0.2.128/25", resp, opconst.ARIN, opconst.ARIN)
	if len(inet4) != 2 {
		t.Fatalf("got %d rows, want 2", len(inet4))
	}
	if inet4[0].Netblock.String() != "192.0.2.128/25" {
		t.Fatalf("preferred first: got %s want 192.0.2.128/25", inet4[0].Netblock.String())
	}
	if inet4[1].Netblock.String() != "192.0.2.0/25" {
		t.Fatalf("sibling: got %s want 192.0.2.0/25", inet4[1].Netblock.String())
	}
}

func TestIpnetPrefixesFromRDAPCidr0DoesNotDropQueried(t *testing.T) {
	t.Parallel()
	resp := decodeIPNetworkFixture(t, "NET-192-0-2-cidr0.json")
	got := ipnetPrefixesFromRDAP("192.0.2.0/25", resp)
	if len(got) != 2 {
		t.Fatalf("prefixes = %d, want 2 (no crawl_target enqueue; both stay whois siblings)", len(got))
	}
}

func decodeIPNetworkFixture(t *testing.T, file string) *rdap.IPNetwork {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rdap", file))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	obj, err := rdap.NewDecoder(raw).Decode()
	if err != nil {
		t.Fatalf("decode RDAP JSON: %v", err)
	}
	resp, ok := obj.(*rdap.IPNetwork)
	if !ok || resp == nil {
		t.Fatalf("decoded %T, want *rdap.IPNetwork", obj)
	}
	return resp
}

func inetnumCIDRs(rows []*whoisdb.WhoisInetNum) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r != nil && r.Netblock != nil {
			out = append(out, r.Netblock.String())
		}
	}
	return out
}

func inet6numCIDRs(rows []*whoisdb.WhoisInet6Num) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r != nil && r.Netblock != nil {
			out = append(out, r.Netblock.String())
		}
	}
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if a == nil && len(b) == 0 || b == nil && len(a) == 0 {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type mappedInetMeta struct {
	netname       string
	fetchMethod   *string
	geofeed       *string
	countryCode   *string
	lastFetchedAt interface{}
	lastSeen      interface{}
}

func inetnumRows(rows []*whoisdb.WhoisInetNum) mappedInetMeta {
	if len(rows) == 0 || rows[0] == nil {
		return mappedInetMeta{}
	}
	r := rows[0]
	return mappedInetMeta{
		netname:       ptrStr(r.Netname),
		fetchMethod:   r.FetchMethod,
		geofeed:       r.Geofeed,
		countryCode:   r.CountryCode,
		lastFetchedAt: r.LastFetchedAt,
		lastSeen:      r.LastSeenInSourceAt,
	}
}

func inet6Rows(rows []*whoisdb.WhoisInet6Num) mappedInetMeta {
	if len(rows) == 0 || rows[0] == nil {
		return mappedInetMeta{}
	}
	r := rows[0]
	return mappedInetMeta{
		netname:       ptrStr(r.Netname),
		fetchMethod:   r.FetchMethod,
		geofeed:       r.Geofeed,
		countryCode:   r.CountryCode,
		lastFetchedAt: r.LastFetchedAt,
		lastSeen:      r.LastSeenInSourceAt,
	}
}

func TestGeofeedFromRDAPCanonicalizes(t *testing.T) {
	t.Parallel()
	resp := &rdap.IPNetwork{
		Links: []rdap.Link{
			{Rel: "geofeed", Href: "HTTP://Example.COM/Feed.csv"},
		},
	}
	if got := geofeedFromRDAP(resp); got != "http://example.com/Feed.csv" {
		t.Fatalf("got %q, want canonical URL", got)
	}
}

func TestCatalogGeofeedURLs(t *testing.T) {
	t.Parallel()
	a := "HTTP://Example.COM/a.csv"
	b := "https://example.com/b.csv"
	dup := "http://example.com/a.csv"
	ftp := "ftp://example.com/x.csv"
	inet4 := []*whoisdb.WhoisInetNum{
		{Geofeed: &a},
		{Geofeed: &dup},
		{Geofeed: &ftp},
		nil,
	}
	inet6 := []*whoisdb.WhoisInet6Num{
		{Geofeed: &b},
		{Geofeed: nil},
	}
	got := catalogGeofeedURLs(inet4, inet6)
	want := map[string]bool{
		"http://example.com/a.csv":  true,
		"https://example.com/b.csv": true,
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 unique canonical urls", got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected %q", u)
		}
	}
}
