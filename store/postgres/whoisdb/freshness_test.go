package whoisdb

import (
	"github.com/oprand/opr/internal/opconst"
	"testing"
)

func TestStampFetchSetsBulkDumpFreshness(t *testing.T) {
	t.Parallel()

	assertStamped := func(t *testing.T, method *string, fetched, seen interface{}) {
		t.Helper()
		if method == nil || *method != FetchMethodBulkDump {
			t.Fatalf("fetch_method=%v, want %q", method, FetchMethodBulkDump)
		}
		if fetched == nil || seen == nil {
			t.Fatal("last_fetched_at and last_seen_in_source_at must be set")
		}
	}

	t.Run("autnum", func(t *testing.T) {
		var rec WhoisAutNum
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
		if rec.LastChangedAt != nil || rec.ContentHash != nil {
			t.Fatal("must not compute last_changed_at or content_hash")
		}
	})
	t.Run("org", func(t *testing.T) {
		var rec WhoisOrganization
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("role", func(t *testing.T) {
		var rec WhoisRole
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("inetnum", func(t *testing.T) {
		var rec WhoisInetNum
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("inet6num", func(t *testing.T) {
		var rec WhoisInet6Num
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("route", func(t *testing.T) {
		var rec WhoisRoute
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("route6", func(t *testing.T) {
		var rec WhoisRoute6
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("as-set", func(t *testing.T) {
		var rec WhoisAsSet
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("as-block", func(t *testing.T) {
		var rec WhoisAsBlock
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("irt", func(t *testing.T) {
		var rec WhoisIrt
		rec.StampFetch(FetchMethodBulkDump)
		assertStamped(t, rec.FetchMethod, rec.LastFetchedAt, rec.LastSeenInSourceAt)
	})
	t.Run("nil receiver", func(t *testing.T) {
		var rec *WhoisInetNum
		rec.StampFetch(FetchMethodBulkDump)
	})
}

func TestStampFetchASNames(t *testing.T) {
	t.Parallel()
	var rec WhoisAutNum
	rec.StampFetch(FetchMethodASNames)
	if rec.FetchMethod == nil || *rec.FetchMethod != FetchMethodASNames {
		t.Fatalf("fetch_method=%v, want %q", rec.FetchMethod, FetchMethodASNames)
	}
	if rec.LastFetchedAt == nil || rec.LastSeenInSourceAt == nil {
		t.Fatal("last_fetched_at and last_seen_in_source_at must be set")
	}
	if rec.Source != nil {
		t.Fatalf("StampFetch must not invent Source, got %v", *rec.Source)
	}
}

func TestHandlePersonMapsToRole(t *testing.T) {
	t.Parallel()
	var role WhoisRole
	role.HandlePerson("person:        Test Person")
	role.HandleNicHdl("nic-hdl:       TP1-AFRINIC")
	role.HandleSource("source:         AFRINIC")
	if role.Role == nil || *role.Role != "Test Person" {
		t.Fatalf("role name=%v, want Test Person", role.Role)
	}
	if role.NicHdl != "TP1-AFRINIC" {
		t.Fatalf("nic_hdl=%q", role.NicHdl)
	}
	if role.RdapKind == nil || *role.RdapKind != "individual" {
		t.Fatalf("rdap_kind=%v, want individual", role.RdapKind)
	}
	if role.GetRecordType() != opconst.RecordTypeRole {
		t.Fatalf("record type=%q, want role (same unique key as whoisdb_role)", role.GetRecordType())
	}
}
