package whoisdb

import (
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestHandleAsSet(t *testing.T) {
	t.Parallel()

	var w WhoisAsSet
	w.HandleAsSet("as-set:         AS-CLOUDFLARE")
	w.HandleMembers("members:        AS13335")
	w.HandleMembers("members:        AS-FOO")
	w.HandleMbrsByRef("mbrs-by-ref:    MAINT-CLOUDFLARE")
	w.HandleSource("source:         APNIC # comment")

	if w.AsSet != "AS-CLOUDFLARE" {
		t.Fatalf("AsSet=%q", w.AsSet)
	}
	if w.Members == nil || len(*w.Members) != 2 || (*w.Members)[0] != "AS13335" || (*w.Members)[1] != "AS-FOO" {
		t.Fatalf("Members=%v", w.Members)
	}
	if w.MbrsByRef == nil || len(*w.MbrsByRef) != 1 || (*w.MbrsByRef)[0] != "MAINT-CLOUDFLARE" {
		t.Fatalf("MbrsByRef=%v", w.MbrsByRef)
	}
	if w.Source == nil || *w.Source != "APNIC" {
		t.Fatalf("Source=%v", w.Source)
	}
	if w.GetRecordType() != opconst.RecordTypeAsSet {
		t.Fatalf("record type=%q, want as-set", w.GetRecordType())
	}
}

func TestWhoisAsSetImplementsWhoisRecord(t *testing.T) {
	t.Parallel()
	var _ WhoisRecord = (*WhoisAsSet)(nil)
}
