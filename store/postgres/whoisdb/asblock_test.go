package whoisdb

import (
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestParseAsBlockRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        string
		wantStart uint32
		wantEnd   uint32
		wantOK    bool
	}{
		{name: "happy path spaces", in: "AS37945 - AS37950", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "no spaces", in: "AS147191-AS147290", wantStart: 147191, wantEnd: 147290, wantOK: true},
		{name: "extra spaces", in: "  AS37945  -  AS37950  ", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "lowercase as prefix", in: "as37945 - as37950", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "missing AS prefix", in: "37945 - 37950", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "mixed prefix", in: "AS37945-37950", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "comment suffix", in: "AS37945 - AS37950 # CNNIC", wantStart: 37945, wantEnd: 37950, wantOK: true},
		{name: "single ASN with prefix", in: "AS37945", wantStart: 37945, wantEnd: 37945, wantOK: true},
		{name: "single ASN missing prefix", in: "37945", wantStart: 37945, wantEnd: 37945, wantOK: true},
		{name: "equal range", in: "AS37945 - AS37945", wantStart: 37945, wantEnd: 37945, wantOK: true},
		{name: "inverted range", in: "AS37950 - AS37945", wantOK: false},
		{name: "junk text", in: "not-a-range", wantOK: false},
		{name: "as-set name", in: "AS-CLOUDFLARE", wantOK: false},
		{name: "incomplete", in: "AS37945 -", wantOK: false},
		{name: "empty", in: "", wantOK: false},
		{name: "asn zero", in: "AS0 - AS10", wantOK: false},
		{name: "three tokens", in: "AS1-AS2-AS3", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start, end, ok := ParseAsBlockRange(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ParseAsBlockRange(%q) ok=%v, want %v (start=%d end=%d)", tt.in, ok, tt.wantOK, start, end)
			}
			if !tt.wantOK {
				return
			}
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("ParseAsBlockRange(%q)=(%d,%d), want (%d,%d)", tt.in, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestHandleAsBlock(t *testing.T) {
	t.Parallel()

	t.Run("cnnic style", func(t *testing.T) {
		t.Parallel()
		var w WhoisAsBlock
		w.HandleAsBlock("as-block:       AS37945 - AS37950")
		w.HandleSource("source:         APNIC")
		if w.AsBlock != "AS37945 - AS37950" {
			t.Fatalf("AsBlock=%q", w.AsBlock)
		}
		if w.AsnStart != 37945 || w.AsnEnd != 37950 {
			t.Fatalf("range=%d-%d, want 37945-37950", w.AsnStart, w.AsnEnd)
		}
		if w.GetRecordType() != opconst.RecordTypeAsBlock {
			t.Fatalf("record type=%q", w.GetRecordType())
		}
	})
	t.Run("junk leaves zero range", func(t *testing.T) {
		t.Parallel()
		var w WhoisAsBlock
		w.HandleAsBlock("as-block:       not-a-range")
		if w.AsBlock != "not-a-range" {
			t.Fatalf("AsBlock=%q, want original dump text", w.AsBlock)
		}
		if w.AsnStart != 0 || w.AsnEnd != 0 {
			t.Fatalf("range=%d-%d, want 0-0", w.AsnStart, w.AsnEnd)
		}
	})
}

func TestWhoisAsBlockImplementsWhoisRecord(t *testing.T) {
	t.Parallel()
	var _ WhoisRecord = (*WhoisAsBlock)(nil)
}
