package rpki

import (
	"strings"
	"testing"
	"time"
)

const jsonextFixture = `{
  "metadata": {"generated": 1681829067, "generatedTime": "2023-04-18T14:44:27Z"},
  "roas": [{
    "asn": "AS196615",
    "prefix": "93.175.147.0/24",
    "maxLength": 24,
    "source": [{
      "type": "roa",
      "uri": "rsync://rpki.ripe.net/repository/older.roa",
      "tal": "ripe",
      "validity": {
        "notBefore": "2022-01-01T00:00:00Z",
        "notAfter": "2023-01-01T00:00:00Z"
      }
    }, {
      "type": "roa",
      "uri": "rsync://rpki.ripe.net/repository/example.roa",
      "tal": "ripe",
      "validity": {
        "notBefore": "2023-01-01T08:44:47Z",
        "notAfter": "2024-07-01T00:00:00Z"
      },
      "chainValidity": {"notBefore": "2023-04-18T14:32:13Z", "notAfter": "2023-04-20T00:00:00Z"},
      "stale": "2023-04-20T00:00:00Z"
    }]
  }],
  "routerKeys": [],
  "aspas": [{
    "customer": "AS64496",
    "afi": "ipv6",
    "providers": ["AS64499", "AS64511", "AS65551"],
    "source": [{
      "type": "aspa",
      "uri": "rsync://acmecorp.example.net/0/AS64496.asa",
      "tal": "ripe",
      "validity": {
        "notBefore": "2023-04-13T07:21:24Z",
        "notAfter": "2024-04-11T07:26:24Z"
      }
    }]
  }]
}`

func TestDecodeJSONExtROASourceAndASPA(t *testing.T) {
	t.Parallel()
	p, err := DecodeJSONExt(strings.NewReader(jsonextFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.VRPs) != 1 {
		t.Fatalf("vrps=%d, want 1", len(p.VRPs))
	}
	v := p.VRPs[0]
	if v.OriginASN != 196615 || v.MaxLength != 24 || v.TA != "ripe" {
		t.Fatalf("vrp=%+v", v)
	}
	if v.Prefix.String() != "93.175.147.0/24" {
		t.Fatalf("prefix=%s", v.Prefix.String())
	}
	if v.URI == nil || *v.URI != "rsync://rpki.ripe.net/repository/example.roa" {
		t.Fatalf("uri=%v, want latest notAfter source", v.URI)
	}
	wantAfter := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	if v.NotAfter == nil || !v.NotAfter.Equal(wantAfter) {
		t.Fatalf("notAfter=%v, want %s", v.NotAfter, wantAfter)
	}

	if len(p.ASPAs) != 1 {
		t.Fatalf("aspas=%d, want 1", len(p.ASPAs))
	}
	a := p.ASPAs[0]
	if a.CustomerASN != 64496 || a.AFI != "ipv6" || a.TA != "ripe" {
		t.Fatalf("aspa=%+v", a)
	}
	if len(a.Providers) != 3 || a.Providers[0] != 64499 {
		t.Fatalf("providers=%v", a.Providers)
	}
	if a.URI == nil || *a.URI != "rsync://acmecorp.example.net/0/AS64496.asa" {
		t.Fatalf("aspa uri=%v", a.URI)
	}
}

func TestDecodeJSONExtEmptyRoas(t *testing.T) {
	t.Parallel()
	p, err := DecodeJSONExt(strings.NewReader(`{"roas":[],"aspas":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.VRPs) != 0 || len(p.ASPAs) != 0 {
		t.Fatalf("payload=%+v", p)
	}
}

func TestDecodeJSONExtBadROAFails(t *testing.T) {
	t.Parallel()
	_, err := DecodeJSONExt(strings.NewReader(`{"roas":[{"asn":"AS1","prefix":"not-a-cidr","maxLength":24}]}`))
	if err == nil {
		t.Fatal("expected decode error for bad ROA prefix")
	}
}

func TestDecodeJSONExtBadASPAProviderFails(t *testing.T) {
	t.Parallel()
	_, err := DecodeJSONExt(strings.NewReader(`{"roas":[],"aspas":[{"customer":"AS1","afi":"ipv4","providers":["nope"]}]}`))
	if err == nil {
		t.Fatal("expected decode error for bad ASPA provider")
	}
}

const jsonextASPANoAFI = `{
  "roas": [],
  "aspas": [{
    "customer": "AS43",
    "providers": ["AS293"],
    "source": [{
      "type": "aspa",
      "uri": "rsync://rpki.ripe.net/repository/DEFAULT/AS43.asa",
      "tal": "ripe",
      "validity": {
        "notBefore": "2025-01-01T00:00:00Z",
        "notAfter": "2026-07-01T00:00:00Z"
      }
    }]
  }]
}`

func TestDecodeJSONExtASPAAfi(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantAFI string
		wantErr bool
	}{
		{
			name:    "routinator 0.15 missing afi is both",
			body:    jsonextASPANoAFI,
			wantAFI: "both",
		},
		{
			name:    "explicit both",
			body:    `{"roas":[],"aspas":[{"customer":"AS1","afi":"both","providers":["AS2"]}]}`,
			wantAFI: "both",
		},
		{
			name:    "IPv4 case",
			body:    `{"roas":[],"aspas":[{"customer":"AS1","afi":"IPv4","providers":["AS2"]}]}`,
			wantAFI: "ipv4",
		},
		{
			name:    "ipv6 kept",
			body:    jsonextFixture,
			wantAFI: "ipv6",
		},
		{
			name:    "ipv4 kept",
			body:    `{"roas":[],"aspas":[{"customer":"AS1","afi":"ipv4","providers":["AS2"]}]}`,
			wantAFI: "ipv4",
		},
		{
			name:    "junk afi fails",
			body:    `{"roas":[],"aspas":[{"customer":"AS1","afi":"ipv5","providers":["AS2"]}]}`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := DecodeJSONExt(strings.NewReader(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected decode error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(p.ASPAs) != 1 {
				t.Fatalf("aspas=%d, want 1", len(p.ASPAs))
			}
			if p.ASPAs[0].AFI != tc.wantAFI {
				t.Fatalf("afi=%q, want %q", p.ASPAs[0].AFI, tc.wantAFI)
			}
		})
	}
}
