package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// ErrPeeringDBEmptyDump is returned when COPY found no rows. Callers must
// not treat this as a successful replace; the live table is left intact.
var ErrPeeringDBEmptyDump = errors.New("peeringdb: empty dump must not wipe")

type peeringDBSwapRename struct {
	stg  string
	live string
}

type peeringDBSwapSpec struct {
	live    string
	columns []string
	// constraintRenames maps LIKE-generated index names on staging to the
	// live names after swap. INCLUDING CONSTRAINTS copies CHECK/NOT NULL
	// only; PRIMARY KEY and UNIQUE require INCLUDING INDEXES. Postgres
	// then names those {staging}_pkey / {staging}_{cols}_key (default
	// rules, not the live names). Secondary indexes are also copied as
	// {staging}_{cols}_idx — do not CREATE INDEX them again.
	constraintRenames []peeringDBSwapRename
}

func peeringDBStaging(live string) string { return live + "_new" }

func peeringDBOld(live string) string { return live + "_old" }

// peeringDBCreateStagingSQL is the COPY-swap CREATE TABLE LIKE.
// INCLUDING INDEXES is required: INCLUDING CONSTRAINTS does not copy
// PRIMARY KEY or UNIQUE. After LIKE, pg_indexes on {live}_new shows
// {live}_new_pkey, {live}_new_{cols}_key, and {live}_new_{cols}_idx.
func peeringDBCreateStagingSQL(stg, live string) string {
	return fmt.Sprintf(
		"CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES INCLUDING COMMENTS)",
		stg, live,
	)
}

// ReplacePeeringDBTable COPY-swaps one peeringdb_* table. An empty source
// drops the staging table and returns ErrPeeringDBEmptyDump so a blank dump
// cannot wipe a previous ingest. There are no FKs between these tables.
func (st *Store) ReplacePeeringDBTable(ctx context.Context, table string, src pgx.CopyFromSource) (int64, error) {
	spec, ok := peeringDBSwapByTable[table]
	if !ok {
		return 0, fmt.Errorf("peeringdb copy-swap: unknown table %s", table)
	}
	return st.copyReplacePeeringDB(ctx, spec, src)
}

func (st *Store) copyReplacePeeringDB(ctx context.Context, spec peeringDBSwapSpec, src pgx.CopyFromSource) (int64, error) {
	stg := peeringDBStaging(spec.live)
	if _, err := st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg); err != nil {
		return 0, fmt.Errorf("drop stale %s: %w", stg, err)
	}
	if _, err := st.DB.Exec(ctx, peeringDBCreateStagingSQL(stg, spec.live)); err != nil {
		return 0, fmt.Errorf("create %s: %w", stg, err)
	}

	copied, err := st.DB.CopyFrom(ctx, pgx.Identifier{stg}, spec.columns, src)
	if err != nil {
		_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return 0, fmt.Errorf("copy %s: %w", stg, err)
	}
	if copied == 0 {
		_, _ = st.DB.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return 0, fmt.Errorf("copy replace %s: %w", spec.live, ErrPeeringDBEmptyDump)
	}

	tx, err := st.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())

	old := peeringDBOld(spec.live)
	swapStmts := []string{
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", spec.live, old),
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", stg, spec.live),
		fmt.Sprintf("DROP TABLE %s", old),
	}
	for _, r := range spec.constraintRenames {
		swapStmts = append(swapStmts, fmt.Sprintf("ALTER INDEX %s RENAME TO %s", r.stg, r.live))
	}
	for _, s := range swapStmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return 0, fmt.Errorf("swap %s (%q): %w", spec.live, s, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	st.logger.Info("replaced peeringdb table via copy-swap",
		zap.String("table", spec.live),
		zap.Int64("rows", copied))
	return copied, nil
}

// PeeringDBTableColumns is the COPY column order for one base table.
func PeeringDBTableColumns(table string) []string {
	spec, ok := peeringDBSwapByTable[table]
	if !ok {
		return nil
	}
	return spec.columns
}

var peeringDBSwapByTable = map[string]peeringDBSwapSpec{
	PeeringDBTableOrganization: {
		live:    PeeringDBTableOrganization,
		columns: peeringDBOrganizationColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_organization_new_pkey", "peeringdb_organization_pkey"},
			{"peeringdb_organization_new_name_key", "peeringdb_organization_name_key"},
		},
	},
	PeeringDBTableFacility: {
		live:    PeeringDBTableFacility,
		columns: peeringDBFacilityColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_facility_new_pkey", "peeringdb_facility_pkey"},
			{"peeringdb_facility_new_name_key", "peeringdb_facility_name_key"},
			{"peeringdb_facility_new_org_id_idx", "peeringdb_facility_org_id"},
		},
	},
	PeeringDBTableNetwork: {
		live:    PeeringDBTableNetwork,
		columns: peeringDBNetworkColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_network_new_pkey", "peeringdb_network_pkey"},
			{"peeringdb_network_new_asn_key", "peeringdb_network_asn_key"},
			{"peeringdb_network_new_name_key", "peeringdb_network_name_key"},
			{"peeringdb_network_new_org_id_idx", "peeringdb_network_org_id"},
		},
	},
	PeeringDBTableIX: {
		live:    PeeringDBTableIX,
		columns: peeringDBIXColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_ix_new_pkey", "peeringdb_ix_pkey"},
			{"peeringdb_ix_new_name_key", "peeringdb_ix_name_key"},
			{"peeringdb_ix_new_org_id_idx", "peeringdb_ix_org_id"},
		},
	},
	PeeringDBTableIXFacility: {
		live:    PeeringDBTableIXFacility,
		columns: peeringDBIXFacilityColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_ix_facility_new_pkey", "peeringdb_ix_facility_pkey"},
			{"peeringdb_ix_facility_new_ix_id_fac_id_key", "peeringdb_ix_facility_ix_id_fac_id_key"},
			{"peeringdb_ix_facility_new_ix_id_idx", "peeringdb_ix_facility_ix_id"},
			{"peeringdb_ix_facility_new_fac_id_idx", "peeringdb_ix_facility_fac_id"},
		},
	},
	PeeringDBTableIXLAN: {
		live:    PeeringDBTableIXLAN,
		columns: peeringDBIXLANColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_ixlan_new_pkey", "peeringdb_ixlan_pkey"},
			{"peeringdb_ixlan_new_ix_id_idx", "peeringdb_ixlan_ix_id"},
		},
	},
	PeeringDBTableIXLANPrefix: {
		live:    PeeringDBTableIXLANPrefix,
		columns: peeringDBIXLANPrefixColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_ixlan_prefix_new_pkey", "peeringdb_ixlan_prefix_pkey"},
			{"peeringdb_ixlan_prefix_new_prefix_key", "peeringdb_ixlan_prefix_prefix_key"},
			{"peeringdb_ixlan_prefix_new_ixlan_id_idx", "peeringdb_ixlan_prefix_ixlan_id"},
		},
	},
	PeeringDBTableNetworkContact: {
		live:    PeeringDBTableNetworkContact,
		columns: peeringDBNetworkContactColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_network_contact_new_pkey", "peeringdb_network_contact_pkey"},
			{"peeringdb_network_contact_new_net_id_idx", "peeringdb_network_contact_net_id"},
		},
	},
	PeeringDBTableNetworkFacility: {
		live:    PeeringDBTableNetworkFacility,
		columns: peeringDBNetworkFacilityColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_network_facility_new_pkey", "peeringdb_network_facility_pkey"},
			{"peeringdb_network_facility_new_net_id_fac_id_local_asn_key", "peeringdb_network_facility_net_id_fac_id_local_asn_key"},
			{"peeringdb_network_facility_new_net_id_idx", "peeringdb_network_facility_net_id"},
			{"peeringdb_network_facility_new_fac_id_idx", "peeringdb_network_facility_fac_id"},
		},
	},
	PeeringDBTableNetworkIXLAN: {
		live:    PeeringDBTableNetworkIXLAN,
		columns: peeringDBNetworkIXLANColumns,
		constraintRenames: []peeringDBSwapRename{
			{"peeringdb_network_ixlan_new_pkey", "peeringdb_network_ixlan_pkey"},
			{"peeringdb_network_ixlan_new_ixlan_id_idx", "peeringdb_network_ixlan_ixlan_id"},
			{"peeringdb_network_ixlan_new_net_id_idx", "peeringdb_network_ixlan_net_id"},
		},
	},
}

var (
	peeringDBOrganizationColumns = []string{
		"id", "status", "created", "updated", "version",
		"address1", "address2", "city", "state", "zipcode", "country",
		"name", "website", "notes",
	}
	peeringDBFacilityColumns = []string{
		"id", "status", "created", "updated", "version",
		"address1", "address2", "city", "state", "zipcode", "country",
		"name", "website", "clli", "rencode", "npanxx", "notes", "org_id",
	}
	peeringDBNetworkColumns = []string{
		"id", "status", "created", "updated", "version",
		"asn", "name", "aka", "irr_as_set", "website", "looking_glass",
		"route_server", "notes", "notes_private", "info_traffic", "info_ratio",
		"info_scope", "info_type", "info_prefixes4", "info_prefixes6",
		"info_unicast", "info_multicast", "info_ipv6", "policy_url",
		"policy_general", "policy_locations", "policy_ratio",
		"policy_contracts", "org_id",
	}
	peeringDBIXColumns = []string{
		"id", "status", "created", "updated", "version",
		"name", "name_long", "city", "country", "notes", "region_continent",
		"media", "proto_unicast", "proto_multicast", "proto_ipv6", "website",
		"url_stats", "tech_email", "tech_phone", "policy_email",
		"policy_phone", "org_id",
	}
	peeringDBIXFacilityColumns = []string{
		"id", "status", "created", "updated", "version", "ix_id", "fac_id",
	}
	peeringDBIXLANColumns = []string{
		"id", "status", "created", "updated", "version",
		"name", "descr", "mtu", "vlan", "dot1q_support", "rs_asn",
		"arp_sponge", "ix_id",
	}
	peeringDBIXLANPrefixColumns = []string{
		"id", "status", "created", "updated", "version",
		"notes", "protocol", "prefix", "ixlan_id",
	}
	peeringDBNetworkContactColumns = []string{
		"id", "status", "created", "updated", "version",
		"role", "visible", "name", "phone", "email", "url", "net_id",
	}
	peeringDBNetworkFacilityColumns = []string{
		"id", "status", "created", "updated", "version",
		"local_asn", "avail_sonet", "avail_ethernet", "avail_atm",
		"net_id", "fac_id",
	}
	peeringDBNetworkIXLANColumns = []string{
		"id", "status", "created", "updated", "version",
		"asn", "ipaddr4", "ipaddr6", "is_rs_peer", "notes", "speed",
		"net_id", "ixlan_id",
	}
)

const (
	peeringDBUpsertContactSQL = `
INSERT INTO peeringdb_network_contact (
	id, status, created, updated, version,
	role, visible, name, phone, email, url, net_id
) VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8, $9, $10, $11, $12
)
ON CONFLICT (id) DO UPDATE SET
	status = EXCLUDED.status,
	created = EXCLUDED.created,
	updated = EXCLUDED.updated,
	version = EXCLUDED.version,
	role = EXCLUDED.role,
	visible = EXCLUDED.visible,
	name = EXCLUDED.name,
	phone = EXCLUDED.phone,
	email = EXCLUDED.email,
	url = EXCLUDED.url,
	net_id = EXCLUDED.net_id`

	peeringDBUpsertIXLANSQL = `
INSERT INTO peeringdb_ixlan (
	id, status, created, updated, version,
	name, descr, mtu, vlan, dot1q_support, rs_asn, arp_sponge, ix_id
) VALUES (
	$1, $2, $3, $4, $5,
	$6, $7, $8, $9, $10, $11, $12, $13
)
ON CONFLICT (id) DO UPDATE SET
	status = EXCLUDED.status,
	created = EXCLUDED.created,
	updated = EXCLUDED.updated,
	version = EXCLUDED.version,
	name = EXCLUDED.name,
	descr = EXCLUDED.descr,
	mtu = EXCLUDED.mtu,
	vlan = EXCLUDED.vlan,
	dot1q_support = EXCLUDED.dot1q_support,
	rs_asn = EXCLUDED.rs_asn,
	arp_sponge = EXCLUDED.arp_sponge,
	ix_id = EXCLUDED.ix_id`

	peeringDBDeleteStalePrivateContactsSQL = `
DELETE FROM peeringdb_network_contact
WHERE visible <> 'Public' AND NOT (id = ANY($1))`
)

// UpsertPeeringDBNetworkContact writes one poc row (dump or private overlay).
func (st *Store) UpsertPeeringDBNetworkContact(ctx context.Context, values []any) error {
	if len(values) != len(peeringDBNetworkContactColumns) {
		return fmt.Errorf("peeringdb poc upsert: want %d values, got %d", len(peeringDBNetworkContactColumns), len(values))
	}
	_, err := st.DB.Exec(ctx, peeringDBUpsertContactSQL, values...)
	return err
}

// UpsertPeeringDBIXLAN writes one ixlan row (private overlay after dumps).
func (st *Store) UpsertPeeringDBIXLAN(ctx context.Context, values []any) error {
	if len(values) != len(peeringDBIXLANColumns) {
		return fmt.Errorf("peeringdb ixlan upsert: want %d values, got %d", len(peeringDBIXLANColumns), len(values))
	}
	_, err := st.DB.Exec(ctx, peeringDBUpsertIXLANSQL, values...)
	return err
}

// DeleteStalePrivatePeeringDBContacts removes non-Public contacts that the
// authenticated overlay did not return. Public dump rows are left alone.
func (st *Store) DeleteStalePrivatePeeringDBContacts(ctx context.Context, keepIDs []int) error {
	if keepIDs == nil {
		keepIDs = []int{}
	}
	_, err := st.DB.Exec(ctx, peeringDBDeleteStalePrivateContactsSQL, keepIDs)
	return err
}
