package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	whoisdb "github.com/oprand/opr/store/postgres/whoisdb"

	"github.com/jackc/pgx/v5"
)

// copyIntoTempThenUpsert bulk-loads a buffer via COPY into a session TEMP table,
// then upserts into the live whoisdb_* table with one INSERT … SELECT ON CONFLICT.
//
// Per-row Exec is too slow for dump buffers (~5000 rows): N round-trips and N
// parse/plan cycles. COPY is binary and one round-trip; the follow-up INSERT
// applies the existing COALESCE / array-merge SET list.
//
// Do not COPY directly into live whoisdb_*: COPY has no ON CONFLICT, and these
// upserts must merge arrays (admin_c || EXCLUDED.admin_c) rather than overwrite.
// A kill mid-flush rolls back only this buffer — TEMP is ON COMMIT DROP, and
// callers must not wrap a whole dump file in one transaction.
//
// Callers must dedup on the unique key (last wins) before calling: Postgres
// errors if ON CONFLICT DO UPDATE would affect the same row twice in one INSERT.
//
// CREATE TEMP / CopyFrom / INSERT all run on the same tx because pgx pool
// connections are not sticky outside a transaction. TEMP names are fixed per
// table (e.g. whoisdb_autnum_stg): TEMP is per-session and SaveWhois* does not
// nest. LIKE INCLUDING DEFAULTS copies defaults (meta_added_at) but not
// indexes; CopyFrom lists only the live INSERT columns so serial/generated
// columns (id, ip_version) are not written.

type whoisUpsertSpec struct {
	live        string
	columns     []string
	selectExprs map[string]string // column -> SQL expr used in SELECT (default: column name)
	onConflict  string
}

func (s whoisUpsertSpec) stg() string {
	return s.live + "_stg"
}

func copyIntoTempThenUpsert(ctx context.Context, tx pgx.Tx, spec whoisUpsertSpec, n int, rowFn func(int) ([]any, error)) error {
	stg := spec.stg()
	create := fmt.Sprintf(
		`CREATE TEMP TABLE %s (LIKE %s INCLUDING DEFAULTS) ON COMMIT DROP`,
		stg, spec.live,
	)
	if _, err := tx.Exec(ctx, create); err != nil {
		return fmt.Errorf("create temp %s: %w", stg, err)
	}

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{stg}, spec.columns, pgx.CopyFromSlice(n, rowFn)); err != nil {
		return fmt.Errorf("copy into %s: %w", stg, err)
	}

	if _, err := tx.Exec(ctx, spec.insertSQL()); err != nil {
		return fmt.Errorf("upsert from %s into %s: %w", stg, spec.live, err)
	}
	return nil
}

func (s whoisUpsertSpec) insertSQL() string {
	colList := strings.Join(s.columns, ", ")
	sel := make([]string, len(s.columns))
	for i, c := range s.columns {
		if expr, ok := s.selectExprs[c]; ok {
			sel[i] = expr
		} else {
			sel[i] = c
		}
	}
	return fmt.Sprintf(
		"INSERT INTO %s (%s) SELECT %s FROM %s\n%s",
		s.live, colList, strings.Join(sel, ", "), s.stg(), s.onConflict,
	)
}

// dedupLastWins keeps the last item for each key and skips entries whose key
// func returns keep=false. Order is first-seen; later duplicates overwrite
// the value at that slot.
func dedupLastWins[T any](items []T, key func(T) (string, bool)) []T {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]int, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		k, keep := key(item)
		if !keep {
			continue
		}
		if i, ok := seen[k]; ok {
			out[i] = item
			continue
		}
		seen[k] = len(out)
		out = append(out, item)
	}
	return out
}

func sourceConflictKey(s *string) string {
	if s == nil {
		return "\x00"
	}
	return *s
}

func originConflictKey(o *uint32) string {
	if o == nil {
		return "\x00"
	}
	return strconv.FormatUint(uint64(*o), 10)
}

func dedupWhoisRoute6(items []*whoisdb.WhoisRoute6) []*whoisdb.WhoisRoute6 {
	return dedupLastWins(items, func(item *whoisdb.WhoisRoute6) (string, bool) {
		if item == nil {
			return "", false
		}
		return item.Route6 + "\x00" + sourceConflictKey(item.Source) + "\x00" + originConflictKey(item.Origin), true
	})
}

func dedupWhoisRoute(items []*whoisdb.WhoisRoute) []*whoisdb.WhoisRoute {
	return dedupLastWins(items, func(item *whoisdb.WhoisRoute) (string, bool) {
		if item == nil {
			return "", false
		}
		return item.Route + "\x00" + sourceConflictKey(item.Source) + "\x00" + originConflictKey(item.Origin), true
	})
}

func dedupWhoisRole(items []*whoisdb.WhoisRole) []*whoisdb.WhoisRole {
	return dedupLastWins(items, func(item *whoisdb.WhoisRole) (string, bool) {
		if item == nil {
			return "", false
		}
		return item.NicHdl + "\x00" + sourceConflictKey(item.Source), true
	})
}

func dedupWhoisOrganization(items []*whoisdb.WhoisOrganization) []*whoisdb.WhoisOrganization {
	return dedupLastWins(items, func(item *whoisdb.WhoisOrganization) (string, bool) {
		if item == nil || item.Organization == "" || item.Source == nil {
			return "", false
		}
		return item.Organization + "\x00" + *item.Source, true
	})
}

func dedupWhoisInet6Num(items []*whoisdb.WhoisInet6Num) []*whoisdb.WhoisInet6Num {
	return dedupLastWins(items, func(item *whoisdb.WhoisInet6Num) (string, bool) {
		if item == nil || item.Netblock == nil || item.Source == nil {
			return "", false
		}
		return item.Netblock.String() + "\x00" + *item.Source, true
	})
}

func dedupWhoisInetNum(items []*whoisdb.WhoisInetNum) []*whoisdb.WhoisInetNum {
	return dedupLastWins(items, func(item *whoisdb.WhoisInetNum) (string, bool) {
		if item == nil || item.Netblock == nil || item.Source == nil {
			return "", false
		}
		return item.Netblock.String() + "\x00" + *item.Source, true
	})
}

func dedupWhoisAutNum(items []*whoisdb.WhoisAutNum) []*whoisdb.WhoisAutNum {
	return dedupLastWins(items, func(item *whoisdb.WhoisAutNum) (string, bool) {
		if item == nil || item.AutNum == 0 || item.Source == nil {
			return "", false
		}
		return strconv.FormatUint(uint64(item.AutNum), 10), true
	})
}

func dedupWhoisAsSet(items []*whoisdb.WhoisAsSet) []*whoisdb.WhoisAsSet {
	return dedupLastWins(items, func(item *whoisdb.WhoisAsSet) (string, bool) {
		if item == nil || item.AsSet == "" || item.Source == nil {
			return "", false
		}
		return item.AsSet + "\x00" + *item.Source, true
	})
}

func dedupWhoisAsBlock(items []*whoisdb.WhoisAsBlock) []*whoisdb.WhoisAsBlock {
	return dedupLastWins(items, func(item *whoisdb.WhoisAsBlock) (string, bool) {
		if item == nil || item.Source == nil || item.AsnStart == 0 || item.AsnStart > item.AsnEnd {
			return "", false
		}
		return strconv.FormatUint(uint64(item.AsnStart), 10) + "\x00" +
			strconv.FormatUint(uint64(item.AsnEnd), 10) + "\x00" + *item.Source, true
	})
}

func dedupWhoisIrt(items []*whoisdb.WhoisIrt) []*whoisdb.WhoisIrt {
	return dedupLastWins(items, func(item *whoisdb.WhoisIrt) (string, bool) {
		if item == nil || item.Irt == "" || item.Source == nil {
			return "", false
		}
		return item.Irt + "\x00" + *item.Source, true
	})
}

// --- whoisdb_route6 ---
// Unique key: (route6, source, origin) as in the previous per-row ON CONFLICT.

var whoisRoute6Upsert = whoisUpsertSpec{
	live: "whoisdb_route6",
	columns: []string{
		"route6", "descr", "country_code", "origin", "holes",
		"member_of", "inject", "aggr_mtd", "aggr_bndry", "export_comps",
		"components", "remarks", "notify", "mnt_lower", "mnt_routes",
		"mnt_by", "last_modified", "source", "created", "city",
		"country", "domain", "changed", "tech_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (route6, source, origin)
			DO UPDATE SET
				descr = EXCLUDED.descr,
				country_code = EXCLUDED.country_code,
				origin = EXCLUDED.origin,
				holes = EXCLUDED.holes,
				member_of = EXCLUDED.member_of,
				inject = EXCLUDED.inject,
				aggr_mtd = EXCLUDED.aggr_mtd,
				aggr_bndry = EXCLUDED.aggr_bndry,
				export_comps = EXCLUDED.export_comps,
				components = EXCLUDED.components,
				remarks = EXCLUDED.remarks,
				notify = EXCLUDED.notify,
				mnt_lower = EXCLUDED.mnt_lower,
				mnt_routes = EXCLUDED.mnt_routes,
				mnt_by = EXCLUDED.mnt_by,
				last_modified = EXCLUDED.last_modified,
				source = EXCLUDED.source,
				created = EXCLUDED.created,
				city = EXCLUDED.city,
				country = EXCLUDED.country,
				domain = EXCLUDED.domain,
				changed = EXCLUDED.changed,
				tech_c = EXCLUDED.tech_c,
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_route6.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_route6.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_route6.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_route6.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_route6.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_route6.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisRoute6CopyRow(item *whoisdb.WhoisRoute6) []any {
	return []any{
		item.Route6, item.Descr, item.CountryCode, item.Origin, item.Holes,
		item.MemberOf, item.Inject, item.AggrMtd, item.AggrBndry, item.ExportComps,
		item.Components, item.Remarks, item.Notify, item.MntLower, item.MntRoutes,
		item.MntBy, item.LastModified, item.Source, item.Created, item.City,
		item.Country, item.Domain, item.Changed, item.TechC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_route ---
// Unique key: (route, source, origin) as in the previous per-row ON CONFLICT.

var whoisRouteUpsert = whoisUpsertSpec{
	live: "whoisdb_route",
	columns: []string{
		"route", "descr", "country_code", "origin", "holes",
		"member_of", "inject", "aggr_mtd", "aggr_bndry", "export_comps",
		"components", "remarks", "notify", "mnt_lower", "mnt_routes",
		"mnt_by", "last_modified", "source", "created", "city",
		"country", "domain", "changed", "tech_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (route, source, origin)
			DO UPDATE SET
				descr = EXCLUDED.descr,
				country_code = EXCLUDED.country_code,
				origin = EXCLUDED.origin,
				holes = EXCLUDED.holes,
				member_of = EXCLUDED.member_of,
				inject = EXCLUDED.inject,
				aggr_mtd = EXCLUDED.aggr_mtd,
				aggr_bndry = EXCLUDED.aggr_bndry,
				export_comps = EXCLUDED.export_comps,
				components = EXCLUDED.components,
				remarks = EXCLUDED.remarks,
				notify = EXCLUDED.notify,
				mnt_lower = EXCLUDED.mnt_lower,
				mnt_routes = EXCLUDED.mnt_routes,
				mnt_by = EXCLUDED.mnt_by,
				last_modified = EXCLUDED.last_modified,
				source = EXCLUDED.source,
				created = EXCLUDED.created,
				city = EXCLUDED.city,
				country = EXCLUDED.country,
				domain = EXCLUDED.domain,
				changed = EXCLUDED.changed,
				tech_c = EXCLUDED.tech_c,
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_route.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_route.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_route.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_route.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_route.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_route.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisRouteCopyRow(item *whoisdb.WhoisRoute) []any {
	return []any{
		item.Route, item.Descr, item.CountryCode, item.Origin, item.Holes,
		item.MemberOf, item.Inject, item.AggrMtd, item.AggrBndry, item.ExportComps,
		item.Components, item.Remarks, item.Notify, item.MntLower, item.MntRoutes,
		item.MntBy, item.LastModified, item.Source, item.Created, item.City,
		item.Country, item.Domain, item.Changed, item.TechC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_role ---
// Unique key: (nic_hdl, source)

var whoisRoleUpsert = whoisUpsertSpec{
	live: "whoisdb_role",
	columns: []string{
		"role", "nic_hdl", "address", "country_code", "phone",
		"fax_no", "email", "admin_c", "tech_c", "remarks",
		"notify", "abuse_mailbox", "mnt_by", "last_modified", "source",
		"changed", "created", "country", "domain", "rdap_kind",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (nic_hdl, source)
			DO UPDATE SET
				role = COALESCE(EXCLUDED.role, whoisdb_role.role),
				address = COALESCE(EXCLUDED.address, whoisdb_role.address),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_role.country_code),
				phone = COALESCE(EXCLUDED.phone, whoisdb_role.phone),
				fax_no = COALESCE(EXCLUDED.fax_no, whoisdb_role.fax_no),
				email = COALESCE(EXCLUDED.email, whoisdb_role.email),
				admin_c = COALESCE(EXCLUDED.admin_c, whoisdb_role.admin_c),
				tech_c = COALESCE(EXCLUDED.tech_c, whoisdb_role.tech_c),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_role.remarks),
				notify = COALESCE(EXCLUDED.notify, whoisdb_role.notify),
				abuse_mailbox = COALESCE(EXCLUDED.abuse_mailbox, whoisdb_role.abuse_mailbox),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_role.mnt_by),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_role.last_modified),
				source = COALESCE(EXCLUDED.source, whoisdb_role.source),
				changed = COALESCE(EXCLUDED.changed, whoisdb_role.changed),
				created = COALESCE(EXCLUDED.created, whoisdb_role.created),
				country = COALESCE(EXCLUDED.country, whoisdb_role.country),
				domain = COALESCE(EXCLUDED.domain, whoisdb_role.domain),
				rdap_kind = COALESCE(EXCLUDED.rdap_kind, whoisdb_role.rdap_kind),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_role.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_role.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_role.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_role.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_role.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_role.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisRoleCopyRow(item *whoisdb.WhoisRole) []any {
	return []any{
		item.Role, item.NicHdl, item.Address, item.CountryCode, item.Phone,
		item.FaxNo, item.Email, item.AdminC, item.TechC, item.Remarks,
		item.Notify, item.AbuseMailbox, item.MntBy, item.LastModified, item.Source,
		item.Changed, item.Created, item.Country, item.Domain, item.RdapKind,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_org ---
// Unique key: (organization, source)

var whoisOrgUpsert = whoisUpsertSpec{
	live: "whoisdb_org",
	columns: []string{
		"organization", "org_name", "descr", "country_code", "remarks",
		"address", "phone", "fax_no", "email", "org",
		"org_type", "admin_c", "tech_c", "ref_nfy", "mnt_ref",
		"notify", "mnt_by", "last_modified", "created", "source",
		"country", "domain", "noc_c", "abuse_c", "routing_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (organization, source)
			DO UPDATE SET
				org_name = COALESCE(EXCLUDED.org_name, whoisdb_org.org_name),
				descr = COALESCE(EXCLUDED.descr, whoisdb_org.descr),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_org.country_code),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_org.remarks),
				address = COALESCE(EXCLUDED.address, whoisdb_org.address),
				phone = COALESCE(EXCLUDED.phone, whoisdb_org.phone),
				fax_no = COALESCE(EXCLUDED.fax_no, whoisdb_org.fax_no),
				email = COALESCE(EXCLUDED.email, whoisdb_org.email),
				org = COALESCE(EXCLUDED.org, whoisdb_org.org),
				org_type = COALESCE(EXCLUDED.org_type, whoisdb_org.org_type),
				admin_c = ARRAY(SELECT DISTINCT UNNEST(EXCLUDED.admin_c || whoisdb_org.admin_c)),
				tech_c = ARRAY(SELECT DISTINCT UNNEST(EXCLUDED.tech_c || whoisdb_org.tech_c)),
				ref_nfy = COALESCE(EXCLUDED.ref_nfy, whoisdb_org.ref_nfy),
				mnt_ref = COALESCE(EXCLUDED.mnt_ref, whoisdb_org.mnt_ref),
				notify = COALESCE(EXCLUDED.notify, whoisdb_org.notify),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_org.mnt_by),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_org.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_org.created),
				source = COALESCE(EXCLUDED.source, whoisdb_org.source),
				country = COALESCE(EXCLUDED.country, whoisdb_org.country),
				domain = COALESCE(EXCLUDED.domain, whoisdb_org.domain),
				noc_c = ARRAY(SELECT DISTINCT UNNEST(EXCLUDED.noc_c || whoisdb_org.noc_c)),
				abuse_c = COALESCE(EXCLUDED.abuse_c, whoisdb_org.abuse_c),
				routing_c = ARRAY(SELECT DISTINCT UNNEST(EXCLUDED.routing_c || whoisdb_org.routing_c)),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_org.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_org.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_org.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_org.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_org.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_org.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisOrgCopyRow(item *whoisdb.WhoisOrganization) []any {
	return []any{
		item.Organization, item.OrgName, item.Descr, item.CountryCode, item.Remarks,
		item.Address, item.Phone, item.FaxNo, item.Email, item.Org,
		item.OrgType, item.AdminC, item.TechC, item.RefNfy, item.MntRef,
		item.Notify, item.MntBy, item.LastModified, item.Created, item.Source,
		item.Country, item.Domain, item.NocC, item.AbuseC, item.RoutingC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_inet6num ---
// Unique key: (netblock, source)

var whoisInet6NumUpsert = whoisUpsertSpec{
	live: "whoisdb_inet6num",
	columns: []string{
		"netblock", "inet6num", "netname", "descr", "country_code",
		"geofeed", "geoloc", "language", "org", "admin_c",
		"tech_c", "abuse_c", "status", "remarks", "notify",
		"mnt_by", "mnt_lower", "mnt_routes", "mnt_domains", "changed",
		"last_modified", "created", "source", "city", "country",
		"domain", "geoloc_lat", "geoloc_lon", "mnt_irt", "assignment_size",
		"start_addr", "end_addr", "type", "noc_c", "routing_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (netblock, source) DO
			UPDATE
			SET
				inet6num = COALESCE(EXCLUDED.inet6num, whoisdb_inet6num.inet6num),
				netname = COALESCE(EXCLUDED.netname, whoisdb_inet6num.netname),
				descr = COALESCE(EXCLUDED.descr, whoisdb_inet6num.descr),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_inet6num.country_code),
				geofeed = COALESCE(EXCLUDED.geofeed, whoisdb_inet6num.geofeed),
				geoloc = COALESCE(EXCLUDED.geoloc, whoisdb_inet6num.geoloc),
				language = COALESCE(EXCLUDED.language, whoisdb_inet6num.language),
				org = COALESCE(EXCLUDED.org, whoisdb_inet6num.org),
				admin_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inet6num.admin_c || EXCLUDED.admin_c)),
				tech_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inet6num.tech_c || EXCLUDED.tech_c)),
				abuse_c = COALESCE(EXCLUDED.abuse_c, whoisdb_inet6num.abuse_c),
				status = COALESCE(EXCLUDED.status, whoisdb_inet6num.status),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_inet6num.remarks),
				notify = COALESCE(EXCLUDED.notify, whoisdb_inet6num.notify),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_inet6num.mnt_by),
				mnt_lower = COALESCE(EXCLUDED.mnt_lower, whoisdb_inet6num.mnt_lower),
				mnt_routes = COALESCE(EXCLUDED.mnt_routes, whoisdb_inet6num.mnt_routes),
				mnt_domains = COALESCE(EXCLUDED.mnt_domains, whoisdb_inet6num.mnt_domains),
				changed = COALESCE(EXCLUDED.changed, whoisdb_inet6num.changed),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_inet6num.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_inet6num.created),
				source = COALESCE(EXCLUDED.source, whoisdb_inet6num.source),
				city = COALESCE(EXCLUDED.city, whoisdb_inet6num.city),
				country = COALESCE(EXCLUDED.country, whoisdb_inet6num.country),
				domain = COALESCE(EXCLUDED.domain, whoisdb_inet6num.domain),
				geoloc_lat = COALESCE(EXCLUDED.geoloc_lat, whoisdb_inet6num.geoloc_lat),
				geoloc_lon = COALESCE(EXCLUDED.geoloc_lon, whoisdb_inet6num.geoloc_lon),
				mnt_irt = COALESCE(EXCLUDED.mnt_irt, whoisdb_inet6num.mnt_irt),
				assignment_size = COALESCE(EXCLUDED.assignment_size, whoisdb_inet6num.assignment_size),
				start_addr = COALESCE(EXCLUDED.start_addr, whoisdb_inet6num.start_addr),
				end_addr = COALESCE(EXCLUDED.end_addr, whoisdb_inet6num.end_addr),
				meta_added_at = NOW(),
				type = COALESCE(EXCLUDED.type, whoisdb_inet6num.type),
				noc_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inet6num.noc_c || EXCLUDED.noc_c)),
				routing_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inet6num.routing_c || EXCLUDED.routing_c)),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_inet6num.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_inet6num.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_inet6num.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_inet6num.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_inet6num.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_inet6num.last_seen_in_source_at)`,
}

func whoisInet6NumCopyRow(item *whoisdb.WhoisInet6Num) []any {
	return []any{
		item.Netblock, item.Inet6num, item.Netname, item.Descr, item.CountryCode,
		item.Geofeed, item.Geoloc, item.Language, item.Org, item.AdminC,
		item.TechC, item.AbuseC, item.Status, item.Remarks, item.Notify,
		item.MntBy, item.MntLower, item.MntRoutes, item.MntDomains, item.Changed,
		item.LastModified, item.Created, item.Source, item.City, item.Country,
		item.Domain, item.GeolocLatitude, item.GeolocLongitude, item.MntIrt, item.AssignmentSize,
		item.StartAddr, item.EndAddr, item.Type, item.NocC, item.RoutingC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_inetnum ---
// Unique key: (netblock, source)

var whoisInetNumUpsert = whoisUpsertSpec{
	live: "whoisdb_inetnum",
	columns: []string{
		"netblock", "inetnum", "netname", "descr", "country_code",
		"geofeed", "geoloc", "language", "org", "admin_c",
		"tech_c", "abuse_c", "status", "remarks", "notify",
		"mnt_by", "mnt_lower", "mnt_routes", "mnt_domains", "changed",
		"last_modified", "created", "source", "city", "country", "domain",
		"geoloc_lat", "geoloc_lon", "mnt_irt", "start_addr", "end_addr",
		"type", "noc_c", "routing_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (netblock, source) DO
			UPDATE
			SET
				inetnum = COALESCE(EXCLUDED.inetnum, whoisdb_inetnum.inetnum),
				netname = COALESCE(EXCLUDED.netname, whoisdb_inetnum.netname),
				descr = COALESCE(EXCLUDED.descr, whoisdb_inetnum.descr),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_inetnum.country_code),
				geofeed = COALESCE(EXCLUDED.geofeed, whoisdb_inetnum.geofeed),
				geoloc = COALESCE(EXCLUDED.geoloc, whoisdb_inetnum.geoloc),
				language = COALESCE(EXCLUDED.language, whoisdb_inetnum.language),
				org = COALESCE(EXCLUDED.org, whoisdb_inetnum.org),
				admin_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inetnum.admin_c || EXCLUDED.admin_c)),
				tech_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inetnum.tech_c || EXCLUDED.tech_c)),
				abuse_c = COALESCE(EXCLUDED.abuse_c, whoisdb_inetnum.abuse_c),
				status = COALESCE(EXCLUDED.status, whoisdb_inetnum.status),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_inetnum.remarks),
				notify = COALESCE(EXCLUDED.notify, whoisdb_inetnum.notify),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_inetnum.mnt_by),
				mnt_lower = COALESCE(EXCLUDED.mnt_lower, whoisdb_inetnum.mnt_lower),
				mnt_routes = COALESCE(EXCLUDED.mnt_routes, whoisdb_inetnum.mnt_routes),
				mnt_domains = COALESCE(EXCLUDED.mnt_domains, whoisdb_inetnum.mnt_domains),
				changed = COALESCE(EXCLUDED.changed, whoisdb_inetnum.changed),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_inetnum.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_inetnum.created),
				source = COALESCE(EXCLUDED.source, whoisdb_inetnum.source),
				city = COALESCE(EXCLUDED.city, whoisdb_inetnum.city),
				country = COALESCE(EXCLUDED.country, whoisdb_inetnum.country),
				domain = COALESCE(EXCLUDED.domain, whoisdb_inetnum.domain),
				geoloc_lat = COALESCE(EXCLUDED.geoloc_lat, whoisdb_inetnum.geoloc_lat),
				geoloc_lon = COALESCE(EXCLUDED.geoloc_lon, whoisdb_inetnum.geoloc_lon),
				mnt_irt = COALESCE(EXCLUDED.mnt_irt, whoisdb_inetnum.mnt_irt),
				start_addr = COALESCE(EXCLUDED.start_addr, whoisdb_inetnum.start_addr),
				end_addr = COALESCE(EXCLUDED.end_addr, whoisdb_inetnum.end_addr),
				type = COALESCE(EXCLUDED.type, whoisdb_inetnum.type),
				noc_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inetnum.noc_c || EXCLUDED.noc_c)),
				routing_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_inetnum.routing_c || EXCLUDED.routing_c)),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_inetnum.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_inetnum.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_inetnum.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_inetnum.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_inetnum.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_inetnum.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisInetNumCopyRow(item *whoisdb.WhoisInetNum) []any {
	return []any{
		item.Netblock,
		item.Inetnum, item.Netname, item.Descr, item.CountryCode,
		item.Geofeed, item.Geoloc, item.Language, item.Org, item.AdminC,
		item.TechC, item.AbuseC, item.Status, item.Remarks, item.Notify,
		item.MntBy, item.MntLower, item.MntRoutes, item.MntDomains, item.Changed,
		item.LastModified, item.Created, item.Source, item.City, item.Country, item.Domain,
		item.GeolocLatitude, item.GeolocLongitude, item.MntIrt, item.StartAddr, item.EndAddr,
		item.Type, item.NocC, item.RoutingC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_autnum ---
// Unique key: aut_num. is_partial uses COALESCE(..., FALSE) on INSERT to match
// the previous VALUES ($39) wrapping.
//
// source uses NULLIF('', ...) on conflict so a sparse asnames row (empty
// string: whoisdb_autnum.source is NOT NULL and cannot store NULL) cannot wipe
// a dump/RDAP RIR source. Plain COALESCE(EXCLUDED.source, ...) would, because
// '' is not NULL.

var whoisAutNumUpsert = whoisUpsertSpec{
	live: "whoisdb_autnum",
	columns: []string{
		"aut_num", "as_name", "descr", "country_code",
		"status", "member_of", "import_via", "import", "mp_import",
		"export_via", "export", "mp_export", "default_net", "mp_default",
		"remarks", "org", "sponsoring_org", "admin_c", "tech_c",
		"abuse_c", "notify", "mnt_lower", "mnt_routes", "mnt_by",
		"mnt_irt", "changed", "last_modified", "created", "source",
		"city", "country", "domain", "noc_c", "routing_c",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (aut_num) DO
			UPDATE
			SET
				as_name = COALESCE(EXCLUDED.as_name, whoisdb_autnum.as_name),
				descr = COALESCE(EXCLUDED.descr, whoisdb_autnum.descr),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_autnum.country_code),
				status = COALESCE(EXCLUDED.status, whoisdb_autnum.status),
				member_of = COALESCE(EXCLUDED.member_of, whoisdb_autnum.member_of),
				import_via = COALESCE(EXCLUDED.import_via, whoisdb_autnum.import_via),
				import = COALESCE(EXCLUDED.import, whoisdb_autnum.import),
				mp_import = COALESCE(EXCLUDED.mp_import, whoisdb_autnum.mp_import),
				export_via = COALESCE(EXCLUDED.export_via, whoisdb_autnum.export_via),
				export = COALESCE(EXCLUDED.export, whoisdb_autnum.export),
				mp_export = COALESCE(EXCLUDED.mp_export, whoisdb_autnum.mp_export),
				default_net = COALESCE(EXCLUDED.default_net, whoisdb_autnum.default_net),
				mp_default = COALESCE(EXCLUDED.mp_default, whoisdb_autnum.mp_default),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_autnum.remarks),
				org = COALESCE(EXCLUDED.org, whoisdb_autnum.org),
				sponsoring_org = COALESCE(EXCLUDED.sponsoring_org, whoisdb_autnum.sponsoring_org),
				admin_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_autnum.admin_c || EXCLUDED.admin_c)),
				tech_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_autnum.tech_c || EXCLUDED.tech_c)),
				abuse_c = COALESCE(EXCLUDED.abuse_c, whoisdb_autnum.abuse_c),
				notify = COALESCE(EXCLUDED.notify, whoisdb_autnum.notify),
				mnt_lower = COALESCE(EXCLUDED.mnt_lower, whoisdb_autnum.mnt_lower),
				mnt_routes = COALESCE(EXCLUDED.mnt_routes, whoisdb_autnum.mnt_routes),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_autnum.mnt_by),
				mnt_irt = COALESCE(EXCLUDED.mnt_irt, whoisdb_autnum.mnt_irt),
				changed = COALESCE(EXCLUDED.changed, whoisdb_autnum.changed),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_autnum.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_autnum.created),
				source = COALESCE(NULLIF(EXCLUDED.source, ''), whoisdb_autnum.source),
				city = COALESCE(EXCLUDED.city, whoisdb_autnum.city),
				country = COALESCE(EXCLUDED.country, whoisdb_autnum.country),
				domain = COALESCE(EXCLUDED.domain, whoisdb_autnum.domain),
				noc_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_autnum.noc_c || EXCLUDED.noc_c)),
				routing_c = ARRAY( SELECT DISTINCT UNNEST(whoisdb_autnum.routing_c || EXCLUDED.routing_c)),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_autnum.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_autnum.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_autnum.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_autnum.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_autnum.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_autnum.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisAutNumCopyRow(item *whoisdb.WhoisAutNum) []any {
	return []any{
		item.AutNum, item.ASName, item.Descr, item.CountryCode,
		item.Status, item.MemberOf, item.ImportVia, item.Import, item.MpImport,
		item.ExportVia, item.Export, item.MpExport, item.DefaultNet, item.MpDefault,
		item.Remarks, item.Org, item.SponsoringOrg, item.AdminC, item.TechC,
		item.AbuseC, item.Notify, item.MntLower, item.MntRoutes, item.MntBy,
		item.MntIrt, item.Changed, item.LastModified, item.Created, item.Source,
		item.City, item.Country, item.Domain, item.NocC, item.RoutingC,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_as_set ---
// Unique key: (as_set, source). COALESCE matches whoisdb_role (prefer EXCLUDED
// when non-null; do not concat arrays).

var whoisAsSetUpsert = whoisUpsertSpec{
	live: "whoisdb_as_set",
	columns: []string{
		"as_set", "descr", "members", "mbrs_by_ref", "org",
		"tech_c", "admin_c", "mnt_by", "mnt_lower", "remarks",
		"notify", "last_modified", "created", "source",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (as_set, source)
			DO UPDATE SET
				descr = COALESCE(EXCLUDED.descr, whoisdb_as_set.descr),
				members = COALESCE(EXCLUDED.members, whoisdb_as_set.members),
				mbrs_by_ref = COALESCE(EXCLUDED.mbrs_by_ref, whoisdb_as_set.mbrs_by_ref),
				org = COALESCE(EXCLUDED.org, whoisdb_as_set.org),
				tech_c = COALESCE(EXCLUDED.tech_c, whoisdb_as_set.tech_c),
				admin_c = COALESCE(EXCLUDED.admin_c, whoisdb_as_set.admin_c),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_as_set.mnt_by),
				mnt_lower = COALESCE(EXCLUDED.mnt_lower, whoisdb_as_set.mnt_lower),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_as_set.remarks),
				notify = COALESCE(EXCLUDED.notify, whoisdb_as_set.notify),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_as_set.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_as_set.created),
				source = COALESCE(EXCLUDED.source, whoisdb_as_set.source),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_as_set.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_as_set.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_as_set.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_as_set.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_as_set.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_as_set.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisAsSetCopyRow(item *whoisdb.WhoisAsSet) []any {
	return []any{
		item.AsSet, item.Descr, item.Members, item.MbrsByRef, item.Org,
		item.TechC, item.AdminC, item.MntBy, item.MntLower, item.Remarks,
		item.Notify, item.LastModified, item.Created, item.Source,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_as_block ---
// Unique key: (asn_start, asn_end, source). COALESCE matches whoisdb_role.

var whoisAsBlockUpsert = whoisUpsertSpec{
	live: "whoisdb_as_block",
	columns: []string{
		"as_block", "asn_start", "asn_end", "descr", "country_code",
		"org", "admin_c", "tech_c", "mnt_by", "mnt_lower",
		"remarks", "last_modified", "created", "source",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (asn_start, asn_end, source)
			DO UPDATE SET
				as_block = COALESCE(EXCLUDED.as_block, whoisdb_as_block.as_block),
				descr = COALESCE(EXCLUDED.descr, whoisdb_as_block.descr),
				country_code = COALESCE(EXCLUDED.country_code, whoisdb_as_block.country_code),
				org = COALESCE(EXCLUDED.org, whoisdb_as_block.org),
				admin_c = COALESCE(EXCLUDED.admin_c, whoisdb_as_block.admin_c),
				tech_c = COALESCE(EXCLUDED.tech_c, whoisdb_as_block.tech_c),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_as_block.mnt_by),
				mnt_lower = COALESCE(EXCLUDED.mnt_lower, whoisdb_as_block.mnt_lower),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_as_block.remarks),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_as_block.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_as_block.created),
				source = COALESCE(EXCLUDED.source, whoisdb_as_block.source),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_as_block.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_as_block.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_as_block.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_as_block.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_as_block.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_as_block.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisAsBlockCopyRow(item *whoisdb.WhoisAsBlock) []any {
	return []any{
		item.AsBlock, item.AsnStart, item.AsnEnd, item.Descr, item.CountryCode,
		item.Org, item.AdminC, item.TechC, item.MntBy, item.MntLower,
		item.Remarks, item.LastModified, item.Created, item.Source,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}

// --- whoisdb_irt ---
// Unique key: (irt, source). COALESCE matches whoisdb_role.

var whoisIrtUpsert = whoisUpsertSpec{
	live: "whoisdb_irt",
	columns: []string{
		"irt", "address", "email", "abuse_mailbox", "phone",
		"fax_no", "admin_c", "tech_c", "auth", "mnt_by",
		"remarks", "last_modified", "created", "source",
		"last_fetched_at", "last_changed_at", "content_hash",
		"fetch_method", "is_partial", "last_seen_in_source_at",
	},
	selectExprs: map[string]string{
		"is_partial": "COALESCE(is_partial, FALSE)",
	},
	onConflict: `
			ON CONFLICT (irt, source)
			DO UPDATE SET
				address = COALESCE(EXCLUDED.address, whoisdb_irt.address),
				email = COALESCE(EXCLUDED.email, whoisdb_irt.email),
				abuse_mailbox = COALESCE(EXCLUDED.abuse_mailbox, whoisdb_irt.abuse_mailbox),
				phone = COALESCE(EXCLUDED.phone, whoisdb_irt.phone),
				fax_no = COALESCE(EXCLUDED.fax_no, whoisdb_irt.fax_no),
				admin_c = COALESCE(EXCLUDED.admin_c, whoisdb_irt.admin_c),
				tech_c = COALESCE(EXCLUDED.tech_c, whoisdb_irt.tech_c),
				auth = COALESCE(EXCLUDED.auth, whoisdb_irt.auth),
				mnt_by = COALESCE(EXCLUDED.mnt_by, whoisdb_irt.mnt_by),
				remarks = COALESCE(EXCLUDED.remarks, whoisdb_irt.remarks),
				last_modified = COALESCE(EXCLUDED.last_modified, whoisdb_irt.last_modified),
				created = COALESCE(EXCLUDED.created, whoisdb_irt.created),
				source = COALESCE(EXCLUDED.source, whoisdb_irt.source),
				last_fetched_at = COALESCE(EXCLUDED.last_fetched_at, whoisdb_irt.last_fetched_at),
				last_changed_at = COALESCE(EXCLUDED.last_changed_at, whoisdb_irt.last_changed_at),
				content_hash = COALESCE(EXCLUDED.content_hash, whoisdb_irt.content_hash),
				fetch_method = COALESCE(EXCLUDED.fetch_method, whoisdb_irt.fetch_method),
				is_partial = COALESCE(EXCLUDED.is_partial, whoisdb_irt.is_partial, FALSE),
				last_seen_in_source_at = COALESCE(EXCLUDED.last_seen_in_source_at, whoisdb_irt.last_seen_in_source_at),
				meta_added_at = NOW()`,
}

func whoisIrtCopyRow(item *whoisdb.WhoisIrt) []any {
	return []any{
		item.Irt, item.Address, item.Email, item.AbuseMailbox, item.Phone,
		item.FaxNo, item.AdminC, item.TechC, item.Auth, item.MntBy,
		item.Remarks, item.LastModified, item.Created, item.Source,
		item.LastFetchedAt, item.LastChangedAt, item.ContentHash,
		item.FetchMethod, item.IsPartial, item.LastSeenInSourceAt,
	}
}
