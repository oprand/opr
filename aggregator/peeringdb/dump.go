package peeringdb

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"

	"github.com/jackc/pgx/v5"
)

// PublicVisible is the PeeringDB poc visibility that official dumps publish.
const PublicVisible = "Public"

// ShouldReplacePeeringDBDump is false for an empty data array so a blank
// dump cannot wipe a previous ingest.
func ShouldReplacePeeringDBDump(n int) bool {
	return n > 0
}

// MapDumpRow projects one API-shaped dump object onto existing columns for
// tag. Extra dump fields (info_types, social_media, campus, carrier, ...)
// are ignored. A missing or zero id skips the row.
func MapDumpRow(tag string, obj map[string]any) ([]any, bool) {
	id := dumpInt(obj, "id")
	if id <= 0 {
		return nil, false
	}
	switch tag {
	case postgres.PeeringDBDumpTagOrg:
		return mapOrganization(obj, id), true
	case postgres.PeeringDBDumpTagFac:
		return mapFacility(obj, id), true
	case postgres.PeeringDBDumpTagNet:
		return mapNetwork(obj, id), true
	case postgres.PeeringDBDumpTagIX:
		return mapIX(obj, id), true
	case postgres.PeeringDBDumpTagIXFac:
		return mapIXFacility(obj, id), true
	case postgres.PeeringDBDumpTagIXLAN:
		return mapIXLAN(obj, id), true
	case postgres.PeeringDBDumpTagIXPfx:
		return mapIXPrefix(obj, id), true
	case postgres.PeeringDBDumpTagPOC:
		if !IsPublicVisible(dumpString(obj, "visible")) {
			return nil, false
		}
		return mapContact(obj, id), true
	case postgres.PeeringDBDumpTagNetFac:
		return mapNetworkFacility(obj, id), true
	case postgres.PeeringDBDumpTagNetIXLAN:
		return mapNetworkIXLAN(obj, id), true
	default:
		return nil, false
	}
}

// MapOverlayRow is MapDumpRow without the Public-only poc filter so a keyed
// API overlay can add Users/Private contacts.
func MapOverlayRow(tag string, obj map[string]any) ([]any, bool) {
	id := dumpInt(obj, "id")
	if id <= 0 {
		return nil, false
	}
	switch tag {
	case postgres.PeeringDBDumpTagPOC:
		return mapContact(obj, id), true
	case postgres.PeeringDBDumpTagIXLAN:
		return mapIXLAN(obj, id), true
	default:
		return MapDumpRow(tag, obj)
	}
}

// IsPublicVisible reports PeeringDB poc rows the public dump is allowed to
// publish. Overlay (API key) may ingest other visibilities.
func IsPublicVisible(visible string) bool {
	return visible == PublicVisible
}

func mapOrganization(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "address1"), dumpString(obj, "address2"), dumpString(obj, "city"),
		dumpString(obj, "state"), dumpString(obj, "zipcode"), dumpString(obj, "country"),
		dumpString(obj, "name"), dumpString(obj, "website"), dumpString(obj, "notes"),
	}
}

func mapFacility(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "address1"), dumpString(obj, "address2"), dumpString(obj, "city"),
		dumpString(obj, "state"), dumpString(obj, "zipcode"), dumpString(obj, "country"),
		dumpString(obj, "name"), dumpString(obj, "website"), dumpString(obj, "clli"),
		dumpString(obj, "rencode"), dumpString(obj, "npanxx"), dumpString(obj, "notes"),
		dumpInt(obj, "org_id"),
	}
}

func mapNetwork(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpInt(obj, "asn"), dumpString(obj, "name"), dumpString(obj, "aka"),
		dumpString(obj, "irr_as_set"), dumpString(obj, "website"), dumpString(obj, "looking_glass"),
		dumpString(obj, "route_server"), dumpString(obj, "notes"), "",
		dumpString(obj, "info_traffic"), dumpString(obj, "info_ratio"),
		dumpString(obj, "info_scope"), dumpString(obj, "info_type"),
		dumpIntPtr(obj, "info_prefixes4"), dumpIntPtr(obj, "info_prefixes6"),
		dumpBool(obj, "info_unicast"), dumpBool(obj, "info_multicast"), dumpBool(obj, "info_ipv6"),
		dumpString(obj, "policy_url"), dumpString(obj, "policy_general"),
		dumpString(obj, "policy_locations"), dumpBool(obj, "policy_ratio"),
		dumpString(obj, "policy_contracts"), dumpInt(obj, "org_id"),
	}
}

func mapIX(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "name"), dumpString(obj, "name_long"), dumpString(obj, "city"),
		dumpString(obj, "country"), dumpString(obj, "notes"), dumpString(obj, "region_continent"),
		dumpString(obj, "media"), dumpBool(obj, "proto_unicast"), dumpBool(obj, "proto_multicast"),
		dumpBool(obj, "proto_ipv6"), dumpString(obj, "website"), dumpString(obj, "url_stats"),
		dumpString(obj, "tech_email"), dumpString(obj, "tech_phone"),
		dumpString(obj, "policy_email"), dumpString(obj, "policy_phone"),
		dumpInt(obj, "org_id"),
	}
}

func mapIXFacility(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpInt(obj, "ix_id"), dumpInt(obj, "fac_id"),
	}
}

func mapIXLAN(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "name"), dumpString(obj, "descr"),
		dumpIntPtr(obj, "mtu"), dumpIntPtr(obj, "vlan"),
		dumpBool(obj, "dot1q_support"), dumpIntPtr(obj, "rs_asn"),
		dumpStringPtr(obj, "arp_sponge"), dumpInt(obj, "ix_id"),
	}
}

func mapIXPrefix(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "notes"), dumpString(obj, "protocol"), dumpString(obj, "prefix"),
		dumpInt(obj, "ixlan_id"),
	}
}

func mapContact(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpString(obj, "role"), dumpString(obj, "visible"), dumpString(obj, "name"),
		dumpString(obj, "phone"), dumpString(obj, "email"), dumpString(obj, "url"),
		dumpInt(obj, "net_id"),
	}
}

func mapNetworkFacility(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpIntPtr(obj, "local_asn"), false, false, false,
		dumpInt(obj, "net_id"), dumpInt(obj, "fac_id"),
	}
}

func mapNetworkIXLAN(obj map[string]any, id int) []any {
	return []any{
		id, dumpString(obj, "status"), dumpTime(obj, "created"), dumpTime(obj, "updated"), 0,
		dumpInt(obj, "asn"), dumpStringPtr(obj, "ipaddr4"), dumpStringPtr(obj, "ipaddr6"),
		dumpBool(obj, "is_rs_peer"), dumpString(obj, "notes"), dumpInt(obj, "speed"),
		dumpInt(obj, "net_id"), dumpInt(obj, "ixlan_id"),
	}
}

func dumpString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return ""
	}
}

func dumpStringPtr(m map[string]any, key string) any {
	if _, ok := m[key]; !ok || m[key] == nil {
		return nil
	}
	s := dumpString(m, key)
	if s == "" {
		return nil
	}
	return s
}

func dumpBool(m map[string]any, key string) bool {
	v, ok := m[key].(bool)
	return ok && v
}

func dumpInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func dumpIntPtr(m map[string]any, key string) any {
	if _, ok := m[key]; !ok || m[key] == nil {
		return nil
	}
	return dumpInt(m, key)
}

func dumpTime(m map[string]any, key string) time.Time {
	s, _ := m[key].(string)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

// dumpCopySource streams {"data":[...]} objects into pgx.CopyFrom.
type dumpCopySource struct {
	dec   *json.Decoder
	mapFn func(map[string]any) ([]any, bool)
	row   []any
	err   error
	n     int
}

func newDumpCopySource(r io.Reader, mapFn func(map[string]any) ([]any, bool)) (*dumpCopySource, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("peeringdb dump: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("peeringdb dump: expected object")
	}
	found := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("peeringdb dump: %w", err)
		}
		key, _ := keyTok.(string)
		if key != "data" {
			var skip any
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("peeringdb dump: %w", err)
			}
			continue
		}
		arrTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("peeringdb dump data: %w", err)
		}
		arr, ok := arrTok.(json.Delim)
		if !ok || arr != '[' {
			return nil, fmt.Errorf("peeringdb dump: data is not an array")
		}
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("peeringdb dump: missing data array")
	}
	return &dumpCopySource{dec: dec, mapFn: mapFn}, nil
}

func (s *dumpCopySource) Next() bool {
	for {
		if !s.dec.More() {
			_, _ = s.dec.Token()
			return false
		}
		var obj map[string]any
		if err := s.dec.Decode(&obj); err != nil {
			s.err = err
			return false
		}
		row, ok := s.mapFn(obj)
		if !ok {
			continue
		}
		s.row = row
		s.n++
		return true
	}
}

func (s *dumpCopySource) Values() ([]any, error) { return s.row, nil }

func (s *dumpCopySource) Err() error { return s.err }

var _ pgx.CopyFromSource = (*dumpCopySource)(nil)
