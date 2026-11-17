package registry

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oprand/opr/internal/opconst"
	"github.com/oprand/opr/pkg/openrdap/rdap"
	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"go.uber.org/zap"
)

// rdapAutnumFixtureWant is the mapped whoisdb shape we expect from an RDAP
// autnum JSON file in testdata/rdap/. Add another ASN by dropping ASNNNNN.json
// in that directory and appending a row here (or a small sidecar later).
type rdapAutnumFixtureWant struct {
	asNumber     uint32
	asName       string
	orgHandle    string
	abuseNicHdl  string
	abuseEmail   string
	adminHandles []string
	techHandles  []string
}

var rdapAutnumFixtures = []struct {
	file string
	want rdapAutnumFixtureWant
}{
	{
		file: "AS15169.json",
		want: rdapAutnumFixtureWant{
			asNumber:     15169,
			asName:       "GOOGLE",
			orgHandle:    "GOGL",
			abuseNicHdl:  "ABUSE5250-ARIN",
			abuseEmail:   "abuse@google.com",
			adminHandles: []string{"ZG39-ARIN"},
			techHandles:  []string{"ZG39-ARIN"},
		},
	},
	{
		file: "AS64255.json",
		want: rdapAutnumFixtureWant{
			asNumber:     64255,
			asName:       "EM-888",
			orgHandle:    "IE-217",
			abuseNicHdl:  "ABUSE5412-ARIN",
			abuseEmail:   "abuse@theice.com",
			adminHandles: []string{"INT8-ARIN"},
			techHandles:  []string{"INT8-ARIN"},
		},
	},
}

func TestMapAutnumFromRDAPFixtures(t *testing.T) {
	aggr := &RegistryAggregator{Logger: zap.NewNop()}

	for _, tc := range rdapAutnumFixtures {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "rdap", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			obj, err := rdap.NewDecoder(raw).Decode()
			if err != nil {
				t.Fatalf("decode RDAP JSON: %v", err)
			}
			resp, ok := obj.(*rdap.Autnum)
			if !ok || resp == nil {
				t.Fatalf("decoded %T, want *rdap.Autnum", obj)
			}

			autnum, roles, orgs := mapAutnumFromRDAP(aggr, tc.want.asNumber, resp, opconst.ARIN, opconst.ARIN)
			stampRDAPFetch(autnum, roles, orgs)

			if autnum.AutNum != tc.want.asNumber {
				t.Errorf("aut_num: got %d want %d", autnum.AutNum, tc.want.asNumber)
			}
			if autnum.ASName != tc.want.asName {
				t.Errorf("as_name: got %q want %q", autnum.ASName, tc.want.asName)
			}
			if ptrStr(autnum.Org) != tc.want.orgHandle {
				t.Errorf("autnum.org: got %q want %q", ptrStr(autnum.Org), tc.want.orgHandle)
			}
			if ptrStr(autnum.AbuseC) != tc.want.abuseNicHdl {
				t.Errorf("autnum.abuse_c: got %q want %q", ptrStr(autnum.AbuseC), tc.want.abuseNicHdl)
			}
			if ptrStr(autnum.FetchMethod) != whoisdb.FetchMethodRDAP {
				t.Errorf("autnum.fetch_method: got %q want %q", ptrStr(autnum.FetchMethod), whoisdb.FetchMethodRDAP)
			}
			if autnum.LastFetchedAt == nil || autnum.LastSeenInSourceAt == nil {
				t.Errorf("autnum missing last_fetched_at / last_seen_in_source_at")
			}

			org := orgByHandle(orgs, tc.want.orgHandle)
			if org == nil {
				t.Fatalf("missing org %q (got %v)", tc.want.orgHandle, orgHandles(orgs))
			}
			if ptrStr(org.FetchMethod) != whoisdb.FetchMethodRDAP {
				t.Errorf("org.fetch_method: got %q want %q", ptrStr(org.FetchMethod), whoisdb.FetchMethodRDAP)
			}

			abuse := roleByHandle(roles, tc.want.abuseNicHdl)
			if abuse == nil {
				t.Fatalf("missing abuse role %q (got %v)", tc.want.abuseNicHdl, roleHandles(roles))
			}
			if abuse.NestingLevel != 1 {
				t.Errorf("abuse NestingLevel: got %d want 1 (skipped registrant must not count)", abuse.NestingLevel)
			}
			if !slicePtrContains(abuse.Email, tc.want.abuseEmail) {
				t.Errorf("abuse email: got %v want %q", derefSlice(abuse.Email), tc.want.abuseEmail)
			}
			if !slicePtrContains(abuse.AbuseMailbox, tc.want.abuseEmail) {
				t.Errorf("abuse_mailbox: got %v want %q", derefSlice(abuse.AbuseMailbox), tc.want.abuseEmail)
			}
			if ptrStr(abuse.FetchMethod) != whoisdb.FetchMethodRDAP {
				t.Errorf("abuse.fetch_method: got %q want %q", ptrStr(abuse.FetchMethod), whoisdb.FetchMethodRDAP)
			}

			for _, hdl := range tc.want.adminHandles {
				if !slicePtrContains(autnum.AdminC, hdl) {
					t.Errorf("autnum.admin_c missing %q (got %v)", hdl, derefSlice(autnum.AdminC))
				}
			}
			for _, hdl := range tc.want.techHandles {
				if !slicePtrContains(autnum.TechC, hdl) {
					t.Errorf("autnum.tech_c missing %q (got %v)", hdl, derefSlice(autnum.TechC))
				}
			}

			for _, r := range roles {
				if r != nil && ptrStr(r.FetchMethod) != whoisdb.FetchMethodRDAP {
					t.Errorf("role %q fetch_method: got %q want rdap", r.NicHdl, ptrStr(r.FetchMethod))
				}
			}
			for _, o := range orgs {
				if o != nil && ptrStr(o.FetchMethod) != whoisdb.FetchMethodRDAP {
					t.Errorf("org %q fetch_method: got %q want rdap", o.Organization, ptrStr(o.FetchMethod))
				}
			}
		})
	}
}

func roleByHandle(roles []*whoisdb.WhoisRole, hdl string) *whoisdb.WhoisRole {
	for _, r := range roles {
		if r != nil && r.NicHdl == hdl {
			return r
		}
	}
	return nil
}

func orgByHandle(orgs []*whoisdb.WhoisOrganization, hdl string) *whoisdb.WhoisOrganization {
	for _, o := range orgs {
		if o != nil && o.Organization == hdl {
			return o
		}
	}
	return nil
}

func roleHandles(roles []*whoisdb.WhoisRole) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if r != nil {
			out = append(out, r.NicHdl)
		}
	}
	return out
}

func orgHandles(orgs []*whoisdb.WhoisOrganization) []string {
	out := make([]string, 0, len(orgs))
	for _, o := range orgs {
		if o != nil {
			out = append(out, o.Organization)
		}
	}
	return out
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefSlice(ss *[]string) []string {
	if ss == nil {
		return nil
	}
	return *ss
}

func slicePtrContains(ss *[]string, want string) bool {
	if ss == nil {
		return false
	}
	return slices.Contains(*ss, want)
}

func TestSafeRDAPResponseHeadersRedactsSecrets(t *testing.T) {
	h := map[string][]string{
		"Content-Type":        {"application/rdap+json"},
		"Retry-After":         {"120"},
		"Authorization":       {"Bearer secret"},
		"Set-Cookie":          {"sid=abc"},
		"Proxy-Authorization": {"Basic x"},
		"Connection":          {"keep-alive"},
	}
	got := safeRDAPResponseHeaders(h)
	if _, ok := got["Authorization"]; ok {
		t.Fatal("Authorization must not be logged")
	}
	if _, ok := got["Set-Cookie"]; ok {
		t.Fatal("Set-Cookie must not be logged")
	}
	if _, ok := got["Connection"]; ok {
		t.Fatal("hop-by-hop Connection must not be logged")
	}
	if got["Content-Type"][0] != "application/rdap+json" {
		t.Fatalf("Content-Type: %v", got["Content-Type"])
	}
	if !strings.Contains(strings.Join(got["Retry-After"], ","), "120") {
		t.Fatalf("Retry-After: %v", got["Retry-After"])
	}
}
