package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func TestReplaceRPKISnapshotEmptyDoesNotTouchDB(t *testing.T) {
	t.Parallel()
	st := &Store{logger: zap.NewNop()}
	err := st.ReplaceRPKISnapshot(context.Background(), nil, nil, VRPIngest{}, false)
	if !errors.Is(err, ErrEmptyVRPSnapshot) {
		t.Fatalf("err=%v, want ErrEmptyVRPSnapshot", err)
	}
}

func TestRPKICreateStagingSQLIncludesConstraintsAndIndexes(t *testing.T) {
	t.Parallel()
	sql := rpkiCreateStagingSQL("aspa_new", "aspa")
	for _, want := range []string{
		"CREATE TABLE aspa_new",
		"LIKE aspa",
		"INCLUDING DEFAULTS",
		"INCLUDING CONSTRAINTS",
		"INCLUDING INDEXES",
		"INCLUDING COMMENTS",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("staging SQL missing %q\n%s", want, sql)
		}
	}
}

func TestReplaceRPKISnapshotEmptyLeavesLiveCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := rpkiTestStore(t)
	ctx := context.Background()

	var vrpN, aspaN int64
	if err := st.DB.QueryRow(ctx, "SELECT count(*) FROM vrp").Scan(&vrpN); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, "SELECT count(*) FROM aspa").Scan(&aspaN); err != nil {
		t.Fatal(err)
	}

	err := st.ReplaceRPKISnapshot(ctx, nil, nil, VRPIngest{FetchedAt: time.Now()}, false)
	if !errors.Is(err, ErrEmptyVRPSnapshot) {
		t.Fatalf("err=%v, want ErrEmptyVRPSnapshot", err)
	}

	var vrpAfter, aspaAfter int64
	if err := st.DB.QueryRow(ctx, "SELECT count(*) FROM vrp").Scan(&vrpAfter); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, "SELECT count(*) FROM aspa").Scan(&aspaAfter); err != nil {
		t.Fatal(err)
	}
	if vrpAfter != vrpN || aspaAfter != aspaN {
		t.Fatalf("empty persist wiped tables: vrp %d->%d aspa %d->%d", vrpN, vrpAfter, aspaN, aspaAfter)
	}
}

func rpkiTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("OPR_TEST_DSN")
	if dsn == "" {
		dsn = "postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres ping: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'vrp'`).Scan(&n); err != nil || n == 0 {
		t.Skip("vrp table missing (run migrations)")
	}
	return &Store{DB: pool, logger: zap.NewNop()}
}
