package whoisdb

import (
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestHandleIrt(t *testing.T) {
	t.Parallel()

	var w WhoisIrt
	w.HandleIrt("irt:            IRT-APNICRANDNET-AU")
	w.HandleAbuseMailbox("abuse-mailbox:  abuse@example.net")
	w.HandleAuth("auth:           PGPKEY-23F0C2B5")
	w.HandleSource("source:         APNIC")

	if w.Irt != "IRT-APNICRANDNET-AU" {
		t.Fatalf("Irt=%q", w.Irt)
	}
	if w.AbuseMailbox == nil || len(*w.AbuseMailbox) != 1 || (*w.AbuseMailbox)[0] != "abuse@example.net" {
		t.Fatalf("AbuseMailbox=%v", w.AbuseMailbox)
	}
	if w.Auth == nil || len(*w.Auth) != 1 || (*w.Auth)[0] != "PGPKEY-23F0C2B5" {
		t.Fatalf("Auth=%v", w.Auth)
	}
	if w.Source == nil || *w.Source != "APNIC" {
		t.Fatalf("Source=%v", w.Source)
	}
	if w.GetRecordType() != opconst.RecordTypeIrt {
		t.Fatalf("record type=%q, want irt", w.GetRecordType())
	}
}

func TestWhoisIrtImplementsWhoisRecord(t *testing.T) {
	t.Parallel()
	var _ WhoisRecord = (*WhoisIrt)(nil)
}
