package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestPeeringDBTableColumnsMatchSwapSpecs(t *testing.T) {
	t.Parallel()
	if PeeringDBTableColumns("campus") != nil {
		t.Fatal("unknown table has no columns")
	}
	for _, d := range PeeringDBDumps {
		cols := PeeringDBTableColumns(d.Table)
		if len(cols) == 0 {
			t.Fatalf("%s: no columns", d.Table)
		}
		if cols[0] != "id" {
			t.Fatalf("%s: first column must be id", d.Table)
		}
		spec := peeringDBSwapByTable[d.Table]
		if spec.live != d.Table {
			t.Fatalf("%s: swap spec live = %q", d.Table, spec.live)
		}
	}
}

func TestErrPeeringDBEmptyDump(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrPeeringDBEmptyDump, ErrPeeringDBEmptyDump) {
		t.Fatal("sentinel")
	}
	if ErrPeeringDBEmptyDump.Error() == "" {
		t.Fatal("empty dump error must explain the wipe guard")
	}
}

func TestPeeringDBCreateStagingSQLIncludesIndexes(t *testing.T) {
	t.Parallel()
	sql := peeringDBCreateStagingSQL("peeringdb_organization_new", "peeringdb_organization")
	for _, want := range []string{
		"CREATE TABLE peeringdb_organization_new",
		"LIKE peeringdb_organization",
		"INCLUDING DEFAULTS",
		"INCLUDING CONSTRAINTS",
		"INCLUDING INDEXES",
		"INCLUDING COMMENTS",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("staging SQL missing %q\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "CREATE INDEX") {
		t.Fatal("LIKE already copies indexes; do not CREATE INDEX in staging SQL")
	}
}

func TestPeeringDBSwapRenamesLikeGeneratedIndexes(t *testing.T) {
	t.Parallel()
	// Postgres LIKE INCLUDING INDEXES names copied indexes from the new
	// table (ChooseIndexName): {staging}_pkey, {staging}_{cols}_key,
	// {staging}_{cols}_idx. After swap those become the live names.
	// SELECT indexname FROM pg_indexes WHERE tablename = '{live}_new';
	want := map[string][]peeringDBSwapRename{
		PeeringDBTableOrganization: {
			{"peeringdb_organization_new_pkey", "peeringdb_organization_pkey"},
			{"peeringdb_organization_new_name_key", "peeringdb_organization_name_key"},
		},
		PeeringDBTableFacility: {
			{"peeringdb_facility_new_pkey", "peeringdb_facility_pkey"},
			{"peeringdb_facility_new_name_key", "peeringdb_facility_name_key"},
			{"peeringdb_facility_new_org_id_idx", "peeringdb_facility_org_id"},
		},
		PeeringDBTableNetwork: {
			{"peeringdb_network_new_pkey", "peeringdb_network_pkey"},
			{"peeringdb_network_new_asn_key", "peeringdb_network_asn_key"},
			{"peeringdb_network_new_name_key", "peeringdb_network_name_key"},
			{"peeringdb_network_new_org_id_idx", "peeringdb_network_org_id"},
		},
		PeeringDBTableIX: {
			{"peeringdb_ix_new_pkey", "peeringdb_ix_pkey"},
			{"peeringdb_ix_new_name_key", "peeringdb_ix_name_key"},
			{"peeringdb_ix_new_org_id_idx", "peeringdb_ix_org_id"},
		},
		PeeringDBTableIXFacility: {
			{"peeringdb_ix_facility_new_pkey", "peeringdb_ix_facility_pkey"},
			{"peeringdb_ix_facility_new_ix_id_fac_id_key", "peeringdb_ix_facility_ix_id_fac_id_key"},
			{"peeringdb_ix_facility_new_ix_id_idx", "peeringdb_ix_facility_ix_id"},
			{"peeringdb_ix_facility_new_fac_id_idx", "peeringdb_ix_facility_fac_id"},
		},
		PeeringDBTableIXLAN: {
			{"peeringdb_ixlan_new_pkey", "peeringdb_ixlan_pkey"},
			{"peeringdb_ixlan_new_ix_id_idx", "peeringdb_ixlan_ix_id"},
		},
		PeeringDBTableIXLANPrefix: {
			{"peeringdb_ixlan_prefix_new_pkey", "peeringdb_ixlan_prefix_pkey"},
			{"peeringdb_ixlan_prefix_new_prefix_key", "peeringdb_ixlan_prefix_prefix_key"},
			{"peeringdb_ixlan_prefix_new_ixlan_id_idx", "peeringdb_ixlan_prefix_ixlan_id"},
		},
		PeeringDBTableNetworkContact: {
			{"peeringdb_network_contact_new_pkey", "peeringdb_network_contact_pkey"},
			{"peeringdb_network_contact_new_net_id_idx", "peeringdb_network_contact_net_id"},
		},
		PeeringDBTableNetworkFacility: {
			{"peeringdb_network_facility_new_pkey", "peeringdb_network_facility_pkey"},
			{"peeringdb_network_facility_new_net_id_fac_id_local_asn_key", "peeringdb_network_facility_net_id_fac_id_local_asn_key"},
			{"peeringdb_network_facility_new_net_id_idx", "peeringdb_network_facility_net_id"},
			{"peeringdb_network_facility_new_fac_id_idx", "peeringdb_network_facility_fac_id"},
		},
		PeeringDBTableNetworkIXLAN: {
			{"peeringdb_network_ixlan_new_pkey", "peeringdb_network_ixlan_pkey"},
			{"peeringdb_network_ixlan_new_ixlan_id_idx", "peeringdb_network_ixlan_ixlan_id"},
			{"peeringdb_network_ixlan_new_net_id_idx", "peeringdb_network_ixlan_net_id"},
		},
	}
	for table, spec := range peeringDBSwapByTable {
		got := spec.constraintRenames
		exp, ok := want[table]
		if !ok {
			t.Fatalf("%s: unexpected swap spec", table)
		}
		if len(got) != len(exp) {
			t.Fatalf("%s: %d renames, want %d", table, len(got), len(exp))
		}
		for i, r := range got {
			if r != exp[i] {
				t.Errorf("%s[%d] = %+v, want %+v", table, i, r, exp[i])
			}
			if !strings.HasPrefix(r.stg, table+"_new_") {
				t.Errorf("%s: staging name %q must start with %s_new_", table, r.stg, table)
			}
			if strings.HasSuffix(r.stg, "_stg") {
				t.Errorf("%s: LIKE names indexes; do not use _stg create path (%q)", table, r.stg)
			}
		}
	}
}
