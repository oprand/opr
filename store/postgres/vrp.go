package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// ErrEmptyVRPSnapshot is returned when jsonext has no ROAs. Callers must
// not COPY-swap; the live vrp/aspa tables stay intact.
var ErrEmptyVRPSnapshot = errors.New("rpki: empty roas must not wipe vrp snapshot")

// vrpIngestAdvisoryLock serializes persist so two ingests cannot clobber
// the shared vrp_new/aspa_new staging tables. Session-level; held on one
// pool connection for COPY (autocommit) plus the rename swap transaction.
const vrpIngestAdvisoryLock int64 = 87275009

// VRP is one validated ROA payload row from Routinator jsonext.
type VRP struct {
	Prefix    net.IPNet
	MaxLength int32
	OriginASN int64
	TA        string
	URI       *string
	NotBefore *time.Time
	NotAfter  *time.Time
}

// ASPA is one ASPA assertion row from Routinator jsonext.
type ASPA struct {
	CustomerASN int64
	AFI         string
	Providers   []int64
	TA          string
	URI         *string
	NotBefore   *time.Time
	NotAfter    *time.Time
}

// VRPIngest is the last successful jsonext snapshot clock.
type VRPIngest struct {
	FetchedAt time.Time
	SourceURL string
	VRPCount  int64
	ASPACount int64
}

var vrpCopyColumns = []string{
	"prefix", "max_length", "origin_asn", "ta", "uri", "not_before", "not_after",
}

var aspaCopyColumns = []string{
	"customer_asn", "afi", "providers", "ta", "uri", "not_before", "not_after",
}

type rpkiSwapRename struct {
	stg  string
	live string
}

// Postgres LIKE INCLUDING INDEXES names copied indexes from the staging
// table (ChooseIndexName): {staging}_{cols}_key and {staging}_{cols}_idx.
var vrpIndexRenames = []rpkiSwapRename{
	{"vrp_new_prefix_max_length_origin_asn_ta_key", "vrp_prefix_max_length_origin_asn_ta_key"},
	{"vrp_new_prefix_idx", "vrp_prefix_gist_idx"},
}

var aspaIndexRenames = []rpkiSwapRename{
	{"aspa_new_customer_asn_afi_ta_key", "aspa_customer_asn_afi_ta_key"},
	{"aspa_new_customer_asn_idx", "aspa_customer_asn_idx"},
}

func rpkiCreateStagingSQL(stg, live string) string {
	return fmt.Sprintf(
		"CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES INCLUDING COMMENTS)",
		stg, live,
	)
}

// LatestVRPIngest returns the current snapshot clock, or nil if none.
func (st *Store) LatestVRPIngest(ctx context.Context) (*VRPIngest, error) {
	var m VRPIngest
	err := st.DB.QueryRow(ctx, `
		SELECT fetched_at, source_url, vrp_count, aspa_count
		FROM vrp_ingest
		ORDER BY fetched_at DESC
		LIMIT 1`).Scan(&m.FetchedAt, &m.SourceURL, &m.VRPCount, &m.ASPACount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest vrp_ingest: %w", err)
	}
	return &m, nil
}

// ReplaceRPKISnapshot COPY-swaps vrp (and aspa unless keepASPA) under a
// session advisory lock. COPY and index creation autocommit on the locked
// connection; only the rename lives in a transaction. Empty VRPs return
// ErrEmptyVRPSnapshot before any staging work. keepASPA leaves the live
// aspa table in place when jsonext had VRPs but no ASPAs.
func (st *Store) ReplaceRPKISnapshot(ctx context.Context, vrps []VRP, aspas []ASPA, meta VRPIngest, keepASPA bool) error {
	if len(vrps) == 0 {
		return ErrEmptyVRPSnapshot
	}
	if st.DB == nil {
		return fmt.Errorf("rpki copy-swap: nil db")
	}

	conn, err := st.DB.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("rpki copy-swap acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", vrpIngestAdvisoryLock); err != nil {
		return fmt.Errorf("rpki advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", vrpIngestAdvisoryLock)
	}()

	if err := copyRPKIStaging(ctx, conn, "vrp", vrpCopyColumns, pgx.CopyFromSlice(len(vrps), func(i int) ([]any, error) {
		v := vrps[i]
		return []any{
			v.Prefix.String(), v.MaxLength, v.OriginASN, v.TA, v.URI, v.NotBefore, v.NotAfter,
		}, nil
	})); err != nil {
		return err
	}

	if !keepASPA {
		if err := copyRPKIStaging(ctx, conn, "aspa", aspaCopyColumns, pgx.CopyFromSlice(len(aspas), func(i int) ([]any, error) {
			a := aspas[i]
			providers := a.Providers
			if providers == nil {
				providers = []int64{}
			}
			return []any{
				a.CustomerASN, a.AFI, providers, a.TA, a.URI, a.NotBefore, a.NotAfter,
			}, nil
		})); err != nil {
			_, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS vrp_new")
			return err
		}
		if err := ensureAspaAFICheck(ctx, conn, "aspa_new"); err != nil {
			_, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS vrp_new")
			_, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS aspa_new")
			return err
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	swapStmts := []string{
		"ALTER TABLE vrp RENAME TO vrp_old",
		"ALTER TABLE vrp_new RENAME TO vrp",
		"DROP TABLE vrp_old",
	}
	if !keepASPA {
		swapStmts = append(swapStmts,
			"ALTER TABLE aspa RENAME TO aspa_old",
			"ALTER TABLE aspa_new RENAME TO aspa",
			"DROP TABLE aspa_old",
		)
	}
	for _, s := range swapStmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("swap rpki (%q): %w", s, err)
		}
	}
	for _, r := range vrpIndexRenames {
		stmt := fmt.Sprintf("ALTER INDEX IF EXISTS %s RENAME TO %s", r.stg, r.live)
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("rename index %s -> %s: %w", r.stg, r.live, err)
		}
	}
	if !keepASPA {
		for _, r := range aspaIndexRenames {
			stmt := fmt.Sprintf("ALTER INDEX IF EXISTS %s RENAME TO %s", r.stg, r.live)
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("rename index %s -> %s: %w", r.stg, r.live, err)
			}
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE aspa RENAME CONSTRAINT aspa_new_afi_ipv4_ipv6 TO aspa_afi_ipv4_ipv6`); err != nil {
			st.logger.Debug("aspa AFI check constraint rename skipped", zap.Error(err))
		}
	}

	if _, err := tx.Exec(ctx, "TRUNCATE vrp_ingest"); err != nil {
		return fmt.Errorf("truncate vrp_ingest: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vrp_ingest (fetched_at, source_url, vrp_count, aspa_count)
		VALUES ($1, $2, $3, $4)`,
		meta.FetchedAt, meta.SourceURL, meta.VRPCount, meta.ASPACount,
	); err != nil {
		return fmt.Errorf("insert vrp_ingest: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	st.logger.Info("replaced vrp snapshot via copy-swap",
		zap.String("source_url", meta.SourceURL),
		zap.Int("vrp_count", len(vrps)),
		zap.Int("aspa_count", len(aspas)),
		zap.Bool("kept_previous_aspa", keepASPA))
	return nil
}

func copyRPKIStaging(ctx context.Context, conn *pgxpool.Conn, live string, columns []string, src pgx.CopyFromSource) error {
	stg := live + "_new"
	if _, err := conn.Exec(ctx, "DROP TABLE IF EXISTS "+stg); err != nil {
		return fmt.Errorf("drop stale %s: %w", stg, err)
	}
	if _, err := conn.Exec(ctx, rpkiCreateStagingSQL(stg, live)); err != nil {
		return fmt.Errorf("create %s: %w", stg, err)
	}
	if _, err := conn.CopyFrom(ctx, pgx.Identifier{stg}, columns, src); err != nil {
		_, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
		return fmt.Errorf("copy %s: %w", stg, err)
	}
	return nil
}

func ensureAspaAFICheck(ctx context.Context, conn *pgxpool.Conn, stg string) error {
	drops := []string{
		"ALTER TABLE " + stg + " DROP CONSTRAINT IF EXISTS aspa_afi_ipv4_ipv6",
		"ALTER TABLE " + stg + " DROP CONSTRAINT IF EXISTS aspa_new_afi_ipv4_ipv6",
	}
	for _, s := range drops {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("drop aspa afi check: %w", err)
		}
	}
	add := "ALTER TABLE " + stg + " ADD CONSTRAINT aspa_new_afi_ipv4_ipv6 CHECK (afi IN ('ipv4', 'ipv6', 'both'))"
	if _, err := conn.Exec(ctx, add); err != nil {
		return fmt.Errorf("add aspa afi check: %w", err)
	}
	return nil
}
