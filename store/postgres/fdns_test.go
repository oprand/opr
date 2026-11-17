package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func TestHostNameUpsertSQLMergesSourceAndRanks(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(hostNameUpsert.insertSQL())
	if !strings.Contains(sql, "insert into fdns_host_name") {
		t.Fatal("expected INSERT INTO fdns_host_name")
	}
	if !strings.Contains(sql, "on conflict (name)") {
		t.Fatal("upsert must conflict on name")
	}
	if !strings.Contains(sql, "unnest(fdns_host_name.source || excluded.source)") {
		t.Fatal("conflict must union source arrays")
	}
	if !strings.Contains(sql, "rank_tranco = coalesce(excluded.rank_tranco, fdns_host_name.rank_tranco)") {
		t.Fatal("tranco rank must fill only when the new row has it")
	}
	if !strings.Contains(sql, "rank_umbrella = coalesce(excluded.rank_umbrella, fdns_host_name.rank_umbrella)") {
		t.Fatal("umbrella rank must fill only when the new row has it")
	}
	if !strings.Contains(sql, "rank_crux = coalesce(excluded.rank_crux, fdns_host_name.rank_crux)") {
		t.Fatal("crux rank must fill only when the new row has it")
	}
	if !strings.Contains(sql, "last_seen = excluded.last_seen") {
		t.Fatal("last_seen must bump on ingest")
	}
	if strings.Contains(sql, "first_seen =") {
		t.Fatal("first_seen must stay on the existing row")
	}
	if strings.Contains(sql, "resolved_at") {
		t.Fatal("list upsert must not write resolved_at")
	}
	if strings.Contains(sql, "truncate") {
		t.Fatal("must not TRUNCATE fdns_host_name")
	}
	if strings.Contains(sql, "delete from") {
		t.Fatal("must not DELETE fdns_host_name (empty ingest must not wipe source=cc)")
	}
}

func TestHostNameSourceIncludesCC(t *testing.T) {
	t.Parallel()
	if HostNameSourceCC != "cc" || HostIPSourceCC != "cc" {
		t.Fatalf("cc constants: name=%q ip=%q", HostNameSourceCC, HostIPSourceCC)
	}
	if HostIndexPathsURL == "" || !strings.Contains(HostIndexPathsURL, "host-index-testing") {
		t.Fatalf("Host Index paths url=%s", HostIndexPathsURL)
	}
	if FDNSCCCrawlMetadataURL != "fdns:cc-crawl" {
		t.Fatalf("crawl metadata url=%s", FDNSCCCrawlMetadataURL)
	}
	if FDNSCCSeedCursorURL != "fdns:cc-seed-cursor" {
		t.Fatalf("seed cursor url=%s", FDNSCCSeedCursorURL)
	}
}

func TestEnqueueResolveQueueSQLSkipsFreshResolved(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(enqueueResolveQueueSQL)
	if !strings.Contains(sql, "insert into fdns_resolve_queue (name, priority)") {
		t.Fatal("expected INSERT INTO fdns_resolve_queue (name, priority)")
	}
	if !strings.Contains(sql, "from fdns_host_name_stg") {
		t.Fatal("enqueue must read the host-name staging table")
	}
	if !strings.Contains(sql, "$2::smallint") {
		t.Fatal("priority must be a bound parameter (list=1, CC seed=0)")
	}
	if strings.Contains(sql, "on conflict do nothing") {
		t.Fatal("list ingest must be able to bump a CC-seeded row's priority")
	}
	if !strings.Contains(sql, "on conflict (name) do update set") {
		t.Fatal("re-seed must not insert a second queue row")
	}
	if !strings.Contains(sql, "priority = excluded.priority") {
		t.Fatal("conflict must only write priority")
	}
	if strings.Contains(sql, "locked_at") {
		t.Fatal("re-seed must not reset an in-flight lease")
	}
	if !strings.Contains(sql, "fdns_resolve_queue.priority < excluded.priority") {
		t.Fatal("priority-0 re-seed must not bump or count as a write")
	}
	if !strings.Contains(sql, "resolved_at is not null") {
		t.Fatal("must skip names already resolved and still fresh")
	}
	if !strings.Contains(sql, "interval '1 second'") {
		t.Fatal("stale window must be an interval")
	}
	if ResolveQueuePriorityList <= ResolveQueuePriorityCC {
		t.Fatal("list ingest priority must be > CC seed")
	}
}

func TestClaimDueResolveQueueSQLSkipLocked(t *testing.T) {
	t.Parallel()
	for _, sql := range []string{claimUnlockedResolveQueueSQL, claimStaleResolveQueueSQL} {
		s := strings.ToLower(sql)
		if !strings.Contains(s, "update fdns_resolve_queue") {
			t.Fatal("claim must UPDATE fdns_resolve_queue so the lease survives commit")
		}
		if !strings.Contains(s, "for update skip locked") {
			t.Fatal("concurrent claimers must SKIP LOCKED")
		}
		if !strings.Contains(s, "locked_at = now()") {
			t.Fatal("claim must set locked_at")
		}
		if !strings.Contains(s, "locked_by = $1") {
			t.Fatal("claim must set locked_by")
		}
		if !strings.Contains(s, "attempts = q.attempts + 1") {
			t.Fatal("claim must increment attempts")
		}
		if !strings.Contains(s, "returning q.name") {
			t.Fatal("UPDATE must RETURNING claimed names")
		}
		if strings.Contains(s, "locked_at is null or") || strings.Contains(s, "or locked_at is null") {
			t.Fatal("do not OR unlocked and stale in one SELECT (due_idx cannot be used)")
		}
	}

	unlocked := strings.ToLower(claimUnlockedResolveQueueSQL)
	if !strings.Contains(unlocked, "locked_at is null") {
		t.Fatal("hot path must be locked_at IS NULL (fdns_resolve_queue_due_idx)")
	}
	if strings.Contains(unlocked, "locked_at <") {
		t.Fatal("unlocked claim must not OR stale leases")
	}
	if !strings.Contains(unlocked, "order by priority desc, enqueued_at, name") {
		t.Fatal("due index order is priority DESC, enqueued_at, name")
	}

	stale := strings.ToLower(claimStaleResolveQueueSQL)
	if !strings.Contains(stale, "locked_at is not null") {
		t.Fatal("stale claim must require an existing lease")
	}
	if !strings.Contains(stale, "locked_at < now() - ($2 * interval '1 second')") {
		t.Fatal("stale locked_at must be reclaimable after --lease")
	}
	if strings.Contains(stale, "order by priority") {
		t.Fatal("stale claim must not use due_idx ORDER BY (oldest lease first)")
	}
	if !strings.Contains(stale, "order by locked_at") {
		t.Fatal("stale claim order is locked_at ASC (fdns_resolve_queue_lease_idx)")
	}
}

func TestClaimDueResolveQueueGuards(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.ClaimDueResolveQueue(context.Background(), "", 1, time.Minute); err == nil {
		t.Fatal("empty locked_by must error")
	}
	if _, err := st.ClaimDueResolveQueue(context.Background(), "w", 0, time.Minute); err == nil {
		t.Fatal("batch < 1 must error")
	}
	if _, err := st.ClaimDueResolveQueue(context.Background(), "w", 1, 0); err == nil {
		t.Fatal("lease <= 0 must error")
	}
}

func TestUnlockResolveQueueSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(unlockResolveQueueSQL)
	if !strings.Contains(sql, "update fdns_resolve_queue") {
		t.Fatal("expected UPDATE fdns_resolve_queue")
	}
	if !strings.Contains(sql, "locked_at = null") {
		t.Fatal("SERVFAIL/timeout must clear locked_at")
	}
	if !strings.Contains(sql, "locked_by = $2") {
		t.Fatal("unlock must require locked_by so it cannot steal another worker's lease")
	}
	if !strings.Contains(sql, "locked_at is not null") {
		t.Fatal("unlock must only clear an active lease")
	}
	if strings.Contains(sql, "attempts =") {
		t.Fatal("unlock must keep attempts")
	}
}

func TestUnlockResolveQueueGuards(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.UnlockResolveQueue(context.Background(), []string{"example.com"}, ""); err == nil {
		t.Fatal("empty locked_by must error")
	}
}

func TestDeleteResolveQueueSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(deleteResolveQueueSQL)
	if !strings.Contains(sql, "delete from fdns_resolve_queue") {
		t.Fatal("success must DELETE from the queue")
	}
	if !strings.Contains(sql, "name = any") {
		t.Fatal("delete must take a name array")
	}
}

func TestCountResolveQueueSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(approxResolveQueueSQL)
	if !strings.Contains(sql, "pg_class") {
		t.Fatal("queue_approx must read pg_class.reltuples, not count(*)")
	}
	if !strings.Contains(sql, "reltuples") {
		t.Fatal("queue_approx uses reltuples (cheap planner estimate)")
	}
	if !strings.Contains(sql, "to_regclass('fdns_resolve_queue')") {
		t.Fatal("queue_approx must target fdns_resolve_queue (to_regclass so a missing table is 0)")
	}
	if strings.Contains(sql, "count(") {
		t.Fatal("queue_approx must not seq-scan with count(*)")
	}
	if strings.Contains(sql, "locked_at") {
		t.Fatal("reltuples is whole-table; it cannot apply the due predicate")
	}
}

func TestInitialMigrationCreatesResolveQueue(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("migrations/0001_initial.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(b))
	if !strings.Contains(sql, "create table public.fdns_resolve_queue") {
		t.Fatal("baseline must create fdns_resolve_queue")
	}
	if !strings.Contains(sql, "fdns_resolve_queue_due_idx") {
		t.Fatal("baseline must keep the due index the claim query uses")
	}
	if !strings.Contains(sql, "references public.fdns_host_name(name)") {
		t.Fatal("queue name must reference fdns_host_name")
	}
}

func TestUpsertHostNamesEmptyError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.UpsertHostNames(context.Background(), nil); err == nil {
		t.Fatal("empty rows must error instead of looking like a successful ingest")
	}
}

func TestDedupHostNamesLastWins(t *testing.T) {
	t.Parallel()
	r1, r2 := 1, 2
	got := dedupHostNames([]HostName{
		{Name: "example.com", RankTranco: &r2},
		{Name: "example.com", RankTranco: &r1},
		{Name: "", RankTranco: &r1},
	})
	if len(got) != 1 || got[0].RankTranco == nil || *got[0].RankTranco != 1 {
		t.Fatalf("got=%+v", got)
	}
}

func TestUpsertHostNamesIntegration(t *testing.T) {
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tranco, umbrella := 10, 20
	name := "fdns-test.example"

	if err := st.UpsertHostNames(ctx, []HostName{{
		Name:       name,
		Source:     []string{HostNameSourceTranco},
		RankTranco: &tranco,
		FirstSeen:  now,
		LastSeen:   now,
	}}); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if err := st.UpsertHostNames(ctx, []HostName{{
		Name:         name,
		Source:       []string{HostNameSourceUmbrella},
		RankUmbrella: &umbrella,
		FirstSeen:    later,
		LastSeen:     later,
	}}); err != nil {
		t.Fatal(err)
	}

	var src []string
	var rt, ru *int
	var first, last time.Time
	var resolved *time.Time
	err := st.DB.QueryRow(ctx, `
		SELECT source, rank_tranco, rank_umbrella, first_seen, last_seen, resolved_at
		FROM fdns_host_name WHERE name = $1`, name).Scan(&src, &rt, &ru, &first, &last, &resolved)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, name)
	})
	if !containsString(src, HostNameSourceTranco) || !containsString(src, HostNameSourceUmbrella) {
		t.Fatalf("source=%v, want union of tranco and umbrella", src)
	}
	if rt == nil || *rt != tranco {
		t.Fatalf("rank_tranco=%v", rt)
	}
	if ru == nil || *ru != umbrella {
		t.Fatalf("rank_umbrella=%v", ru)
	}
	if resolved != nil {
		t.Fatal("list ingest must leave resolved_at null")
	}
	if last.Before(first) || last.Sub(first) < 30*time.Second {
		t.Fatalf("last_seen should bump on the second upsert: first=%s last=%s", first, last)
	}

	if err := st.UpsertHostNames(ctx, []HostName{{
		Name:     name,
		Source:   []string{HostNameSourceCC},
		LastSeen: later.Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, `SELECT source FROM fdns_host_name WHERE name = $1`, name).Scan(&src); err != nil {
		t.Fatal(err)
	}
	if !containsString(src, HostNameSourceCC) || !containsString(src, HostNameSourceTranco) {
		t.Fatalf("source=%v, want union including cc", src)
	}
}

func TestHostIPUpsertSQLBumpsLastSeen(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(hostIPUpsert.insertSQL())
	if !strings.Contains(sql, "insert into fdns_host_ip") {
		t.Fatal("expected INSERT INTO fdns_host_ip")
	}
	if !strings.Contains(sql, "on conflict (name, ip, source)") {
		t.Fatal("upsert must conflict on (name, ip, source)")
	}
	if !strings.Contains(sql, "last_seen = excluded.last_seen") {
		t.Fatal("last_seen must bump on resolve")
	}
	if strings.Contains(sql, "first_seen =") {
		t.Fatal("first_seen must stay on the existing row")
	}
	if strings.Contains(sql, "truncate") {
		t.Fatal("must not TRUNCATE fdns_host_ip")
	}
}

func TestTouchResolvedAtSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(touchHostNameResolvedAtSQL)
	if !strings.Contains(sql, "update fdns_host_name") {
		t.Fatal("expected UPDATE fdns_host_name")
	}
	if !strings.Contains(sql, "resolved_at") {
		t.Fatal("must set resolved_at")
	}
	if strings.Contains(sql, "first_seen") || strings.Contains(sql, "last_seen") {
		t.Fatal("resolved_at touch must not rewrite first_seen/last_seen")
	}
	if strings.Contains(sql, "truncate") {
		t.Fatal("must not TRUNCATE")
	}
}

func TestListHostNamesToResolveSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(listHostNamesToResolveSQL)
	if !strings.Contains(sql, "from fdns_host_name") {
		t.Fatal("expected SELECT from fdns_host_name")
	}
	if !strings.Contains(sql, "resolved_at is null") {
		t.Fatal("must select never-resolved names")
	}
	if !strings.Contains(sql, "interval '1 second'") {
		t.Fatal("must apply --stale-after as an interval")
	}
	if !strings.Contains(sql, "limit nullif") {
		t.Fatal("LIMIT 0 must become NULL (uncapped)")
	}
	if strings.Contains(sql, "host_name") && !strings.Contains(sql, "fdns_host_name") {
		t.Fatal("must use fdns_host_name, not host_name")
	}
	if strings.Contains(sql, "truncate") {
		t.Fatal("must not TRUNCATE")
	}
}

func TestHostIPCopyRowNeverNilTimes(t *testing.T) {
	t.Parallel()
	row := hostIPCopyRow(&HostIP{Name: "example.com", IP: "192.0.2.1", Source: HostIPSourceDNS})
	if len(row) != 5 {
		t.Fatalf("len=%d", len(row))
	}
	first, ok := row[3].(time.Time)
	if !ok || first.IsZero() {
		t.Fatalf("first_seen=%#v (COPY into NOT NULL must not be nil/zero)", row[3])
	}
	last, ok := row[4].(time.Time)
	if !ok || last.IsZero() {
		t.Fatalf("last_seen=%#v (COPY into NOT NULL must not be nil/zero)", row[4])
	}

	seen := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	row = hostIPCopyRow(&HostIP{
		Name: "example.com", IP: "192.0.2.1", Source: HostIPSourceDNS, LastSeen: seen,
	})
	gotFirst, okFirst := row[3].(time.Time)
	gotLast, okLast := row[4].(time.Time)
	if !okFirst || !okLast || !gotFirst.Equal(seen) || !gotLast.Equal(seen) {
		t.Fatalf("only LastSeen set: first=%v last=%v, want %v (never nil)", row[3], row[4], seen)
	}

	row = hostIPCopyRow(&HostIP{
		Name: "example.com", IP: "192.0.2.1", Source: HostIPSourceDNS,
		FirstSeen: seen, LastSeen: seen,
	})
	if got, ok := row[3].(time.Time); !ok || !got.Equal(seen) {
		t.Fatalf("first_seen=%v, want preserved %v", row[3], seen)
	}
	if got, ok := row[4].(time.Time); !ok || !got.Equal(seen) {
		t.Fatalf("last_seen=%v, want preserved %v", row[4], seen)
	}
}

func TestHostNameCopyRowNeverNilTimes(t *testing.T) {
	t.Parallel()
	row := hostNameCopyRow(&HostName{Name: "example.com"})
	if len(row) != 7 {
		t.Fatalf("len=%d", len(row))
	}
	first, ok := row[5].(time.Time)
	if !ok || first.IsZero() {
		t.Fatalf("first_seen=%#v (COPY into NOT NULL must not be nil/zero)", row[5])
	}
	last, ok := row[6].(time.Time)
	if !ok || last.IsZero() {
		t.Fatalf("last_seen=%#v (COPY into NOT NULL must not be nil/zero)", row[6])
	}

	seen := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)
	row = hostNameCopyRow(&HostName{Name: "example.com", FirstSeen: seen, LastSeen: seen})
	if got, ok := row[5].(time.Time); !ok || !got.Equal(seen) {
		t.Fatalf("first_seen=%v, want preserved %v", row[5], seen)
	}
	if got, ok := row[6].(time.Time); !ok || !got.Equal(seen) {
		t.Fatalf("last_seen=%v, want preserved %v", row[6], seen)
	}
}

func TestDedupHostIPsLastWins(t *testing.T) {
	t.Parallel()
	got := dedupHostIPs([]HostIP{
		{Name: "example.com", IP: "1.1.1.1", Source: HostIPSourceDNS},
		{Name: "example.com", IP: "1.1.1.1", Source: HostIPSourceDNS, LastSeen: time.Unix(2, 0)},
		{Name: "example.com", IP: "not-an-ip", Source: HostIPSourceDNS},
		{Name: "", IP: "1.1.1.1", Source: HostIPSourceDNS},
	})
	if len(got) != 1 || got[0].LastSeen.Unix() != 2 {
		t.Fatalf("got=%+v", got)
	}
}

func TestApplyHostResolveEmptyNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.ApplyHostResolve(context.Background(), nil, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHostIPs(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchHostNamesResolvedAt(context.Background(), nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyHostResolveIntegration(t *testing.T) {
	st := fdnsTestStore(t)
	fdnsRequireHostIP(t, st)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	name := "fdns-resolve-test.example"
	now := time.Now().UTC().Truncate(time.Second)

	if err := st.UpsertHostNames(ctx, []HostName{{
		Name:      name,
		Source:    []string{HostNameSourceTranco},
		FirstSeen: now,
		LastSeen:  now,
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, name)
	})

	queued, err := st.ListHostNamesToResolve(ctx, HostNameResolveQuery{Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(queued, name) {
		t.Fatalf("never-resolved name missing from selection: %v", queued)
	}

	if err := st.ApplyHostResolve(ctx, []HostIP{{
		Name:     name,
		IP:       "192.0.2.1",
		Source:   HostIPSourceDNS,
		LastSeen: now,
	}}, []string{name}, now); err != nil {
		t.Fatal(err)
	}

	var ipCount int
	var resolved *time.Time
	var first, last time.Time
	if err := st.DB.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM fdns_host_ip WHERE name = $1 AND source = $2),
		       resolved_at
		FROM fdns_host_name WHERE name = $1`, name, HostIPSourceDNS).Scan(&ipCount, &resolved); err != nil {
		t.Fatal(err)
	}
	if ipCount != 1 {
		t.Fatalf("ip count=%d, want 1", ipCount)
	}
	if resolved == nil {
		t.Fatal("resolved_at must be stamped")
	}

	later := now.Add(time.Minute)
	if err := st.ApplyHostResolve(ctx, []HostIP{{
		Name:     name,
		IP:       "192.0.2.1",
		Source:   HostIPSourceDNS,
		LastSeen: later,
	}}, []string{name}, later); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, `
		SELECT first_seen, last_seen FROM fdns_host_ip
		WHERE name = $1 AND ip = $2 AND source = $3`,
		name, "192.0.2.1", HostIPSourceDNS).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	if last.Before(first) || last.Sub(first) < 30*time.Second {
		t.Fatalf("last_seen should bump: first=%s last=%s", first, last)
	}

	nxName := "fdns-nxdomain-test.example"
	if err := st.UpsertHostNames(ctx, []HostName{{
		Name:      nxName,
		Source:    []string{HostNameSourceTranco},
		FirstSeen: now,
		LastSeen:  now,
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, nxName)
	})
	if err := st.ApplyHostResolve(ctx, nil, []string{nxName}, now); err != nil {
		t.Fatal(err)
	}
	var nxIPs int
	var nxResolved *time.Time
	if err := st.DB.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM fdns_host_ip WHERE name = $1 AND source = $2),
		       resolved_at
		FROM fdns_host_name WHERE name = $1`, nxName, HostIPSourceDNS).Scan(&nxIPs, &nxResolved); err != nil {
		t.Fatal(err)
	}
	if nxIPs != 0 {
		t.Fatalf("NXDOMAIN must store zero dns IPs, got %d", nxIPs)
	}
	if nxResolved == nil {
		t.Fatal("NXDOMAIN must stamp resolved_at")
	}

	fresh, err := st.ListHostNamesToResolve(ctx, HostNameResolveQuery{StaleAfter: 0, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(fresh, name) || containsString(fresh, nxName) {
		t.Fatal("stamped names must not be selected when stale-after is 0")
	}

	if _, err := st.DB.Exec(ctx, `
		UPDATE fdns_host_name SET resolved_at = NOW() - INTERVAL '2 hours'
		WHERE name = ANY($1::text[])`, []string{name, nxName}); err != nil {
		t.Fatal(err)
	}
	stale, err := st.ListHostNamesToResolve(ctx, HostNameResolveQuery{StaleAfter: time.Hour, Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(stale, name) || !containsString(stale, nxName) {
		t.Fatalf("stale-after 1h should reselect names resolved 2h ago: %v", stale)
	}

	limited, err := st.ListHostNamesToResolve(ctx, HostNameResolveQuery{StaleAfter: time.Hour, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 {
		t.Fatalf("limit=1 got %d names: %v", len(limited), limited)
	}
}

func TestUpsertHostNamesEnqueuesResolveQueue(t *testing.T) {
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	fresh := "fdns-queue-fresh.example"
	due := "fdns-queue-due.example"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = ANY($1)`, []string{fresh, due})
	})

	if err := st.UpsertHostNames(ctx, []HostName{
		{Name: fresh, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
		{Name: due, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(ctx, `UPDATE fdns_host_name SET resolved_at = now() WHERE name = $1`, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(ctx, `DELETE FROM fdns_resolve_queue WHERE name = ANY($1)`, []string{fresh, due}); err != nil {
		t.Fatal(err)
	}

	queued, err := st.UpsertHostNamesAndEnqueue(ctx, []HostName{
		{Name: fresh, Source: []string{HostNameSourceCC}, LastSeen: now},
		{Name: due, Source: []string{HostNameSourceCC}, LastSeen: now},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("queued=%d, want 1 (fresh resolved name skipped)", queued)
	}
	var n int
	if err := st.DB.QueryRow(ctx, `SELECT count(*) FROM fdns_resolve_queue WHERE name = ANY($1)`, []string{fresh, due}).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("queue rows=%d, want 1", n)
	}
	var pri int16
	if err := st.DB.QueryRow(ctx, `SELECT priority FROM fdns_resolve_queue WHERE name = $1`, due).Scan(&pri); err != nil {
		t.Fatal(err)
	}
	if pri != ResolveQueuePriorityCC {
		t.Fatalf("seed-queue priority=%d, want %d", pri, ResolveQueuePriorityCC)
	}
	var src []string
	if err := st.DB.QueryRow(ctx, `SELECT source FROM fdns_host_name WHERE name = $1`, due).Scan(&src); err != nil {
		t.Fatal(err)
	}
	if !containsString(src, HostNameSourceTranco) || !containsString(src, HostNameSourceCC) {
		t.Fatalf("source=%v, want tranco∪cc (ranks/lists kept)", src)
	}
}

func TestClaimDueResolveQueuePostgresExclusive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	a := "fdns-claim-a.example"
	b := "fdns-claim-b.example"
	now := time.Now().UTC()
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = ANY($1)`, []string{a, b})
	})
	if err := st.UpsertHostNames(ctx, []HostName{
		{Name: a, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
		{Name: b, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatal(err)
	}
	fdnsPinResolveQueueHead(t, st, a, b)

	got := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			names, err := st.ClaimDueResolveQueue(ctx, "test", 1, time.Minute)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			if len(names) != 1 {
				t.Errorf("claimed %d, want 1", len(names))
				return
			}
			got <- names[0]
		}()
	}
	wg.Wait()
	close(got)
	seen := map[string]struct{}{}
	for name := range got {
		if _, dup := seen[name]; dup {
			t.Fatalf("two workers claimed %s", name)
		}
		seen[name] = struct{}{}
	}
	var stolen []string
	for name := range seen {
		if name != a && name != b {
			stolen = append(stolen, name)
		}
	}
	if len(stolen) > 0 {
		fdnsUnlockBorrowed(t, st, "test", stolen)
		t.Fatalf("claimed %v, want %s and %s", seen, a, b)
	}
	if _, ok := seen[a]; !ok {
		t.Fatalf("claimed %v, want %s", seen, a)
	}
	if _, ok := seen[b]; !ok {
		t.Fatalf("claimed %v, want %s", seen, b)
	}

	if err := st.UnlockResolveQueue(ctx, []string{a}, "test"); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := st.ClaimDueResolveQueue(ctx, "stale", 2, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	fdnsUnlockBorrowed(t, st, "stale", reclaimed, a, b)
	if !containsString(reclaimed, a) {
		t.Fatalf("stale/unlocked lease must be reclaimable: %v", reclaimed)
	}

	if err := st.ApplyHostResolve(ctx, nil, []string{b}, now); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := st.DB.QueryRow(ctx, `SELECT count(*) FROM fdns_resolve_queue WHERE name = $1`, b).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatal("ApplyHostResolve must DELETE stamped names from the queue")
	}
}

func TestUpsertHostNamesEnqueuesListPriority(t *testing.T) {
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	now := time.Now().UTC()
	name := "fdns-list-priority.example"
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, name)
	})
	if err := st.UpsertHostNames(ctx, []HostName{{
		Name: name, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatal(err)
	}
	var pri int16
	if err := st.DB.QueryRow(ctx, `SELECT priority FROM fdns_resolve_queue WHERE name = $1`, name).Scan(&pri); err != nil {
		t.Fatal(err)
	}
	if pri != ResolveQueuePriorityList {
		t.Fatalf("list ingest priority=%d, want %d", pri, ResolveQueuePriorityList)
	}
}

func TestClaimDueResolveQueueReclaimsExpiredLeaseWithoutUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	name := "fdns-stale-lease.example"
	now := time.Now().UTC()
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, name)
	})
	if err := st.UpsertHostNames(ctx, []HostName{{
		Name: name, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatal(err)
	}
	fdnsPinResolveQueueHead(t, st, name)
	claimed, err := st.ClaimDueResolveQueue(ctx, "worker-a", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fdnsUnlockBorrowed(t, st, "worker-a", claimed, name)
	if len(claimed) != 1 || claimed[0] != name {
		t.Fatalf("claimed=%v", claimed)
	}
	fresh, err := st.ClaimDueResolveQueue(ctx, "worker-b", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(fresh, name) {
		t.Fatalf("fresh lease must not be reclaimable: %v", fresh)
	}
	fdnsUnlockBorrowed(t, st, "worker-b", fresh)

	if _, err := st.DB.Exec(ctx, `
		UPDATE fdns_resolve_queue SET locked_at = now() - interval '1 hour'
		WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}

	reclaimed, err := st.ClaimDueResolveQueue(ctx, "worker-b", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(reclaimed, name) {
		var lockedBy string
		if err := st.DB.QueryRow(ctx, `SELECT locked_by FROM fdns_resolve_queue WHERE name = $1`, name).Scan(&lockedBy); err != nil {
			t.Fatal(err)
		}
		if lockedBy != "worker-b" {
			t.Fatalf("locked_by=%s, want worker-b", lockedBy)
		}
		return
	}
	fdnsUnlockBorrowed(t, st, "worker-b", reclaimed)
	// Unlocked backlog filled the batch, so ClaimDue did not query stale
	// this round. The stale statement must still reclaim without Unlock.
	stale, err := st.queryResolveQueueNames(ctx, claimStaleResolveQueueSQL, "worker-b", time.Minute.Seconds(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0] != name {
		t.Fatalf("Claim must reclaim locked_at < now()-lease without Unlock: claimed=%v stale=%v", reclaimed, stale)
	}
}

func TestClaimDueResolveQueuePrefersUnlockedOverStale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	unlocked := "fdns-prefer-unlocked.example"
	stale := "fdns-prefer-stale.example"
	now := time.Now().UTC()
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = ANY($1)`, []string{unlocked, stale})
	})
	if err := st.UpsertHostNames(ctx, []HostName{
		{Name: unlocked, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
		{Name: stale, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now},
	}); err != nil {
		t.Fatal(err)
	}
	fdnsPinResolveQueueHead(t, st, unlocked, stale)
	if tag, err := st.DB.Exec(ctx, `
		UPDATE fdns_resolve_queue
		SET locked_at = now() - interval '1 hour',
		    locked_by = 'crashed',
		    attempts = 1
		WHERE name = $1`, stale); err != nil {
		t.Fatal(err)
	} else if tag.RowsAffected() != 1 {
		t.Fatalf("stale lease updated %d, want 1", tag.RowsAffected())
	}

	got, err := st.ClaimDueResolveQueue(ctx, "worker-b", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fdnsUnlockBorrowed(t, st, "worker-b", got, unlocked)
	if len(got) != 1 {
		t.Fatalf("claimed %v, want 1", got)
	}
	if got[0] == stale {
		t.Fatal("unlocked rows must be claimed before stale leases")
	}
	if got[0] != unlocked {
		t.Fatalf("claimed %q, want unlocked %q", got[0], unlocked)
	}
}

func TestUnlockResolveQueueIgnoresOtherWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	ctx := context.Background()
	name := "fdns-unlock-other.example"
	now := time.Now().UTC()
	t.Cleanup(func() {
		_, _ = st.DB.Exec(context.Background(), `DELETE FROM fdns_host_name WHERE name = $1`, name)
	})
	if err := st.UpsertHostNames(ctx, []HostName{{
		Name: name, Source: []string{HostNameSourceTranco}, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatal(err)
	}
	fdnsPinResolveQueueHead(t, st, name)
	claimed, err := st.ClaimDueResolveQueue(ctx, "worker-a", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fdnsUnlockBorrowed(t, st, "worker-a", claimed, name)
	if len(claimed) != 1 || claimed[0] != name {
		t.Fatalf("claimed=%v, want %s", claimed, name)
	}
	if err := st.UnlockResolveQueue(ctx, []string{name}, "worker-b"); err != nil {
		t.Fatal(err)
	}
	var lockedAt *time.Time
	var lockedBy *string
	if err := st.DB.QueryRow(ctx, `
		SELECT locked_at, locked_by FROM fdns_resolve_queue WHERE name = $1`, name).Scan(&lockedAt, &lockedBy); err != nil {
		t.Fatal(err)
	}
	if lockedAt == nil || lockedBy == nil || *lockedBy != "worker-a" {
		t.Fatalf("other worker must not unlock: locked_at=%v locked_by=%v", lockedAt, lockedBy)
	}
	if err := st.UnlockResolveQueue(ctx, []string{name}, "worker-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(ctx, `
		SELECT locked_at, locked_by FROM fdns_resolve_queue WHERE name = $1`, name).Scan(&lockedAt, &lockedBy); err != nil {
		t.Fatal(err)
	}
	if lockedAt != nil || lockedBy != nil {
		t.Fatalf("owner unlock must clear lease: locked_at=%v locked_by=%v", lockedAt, lockedBy)
	}
}

func TestCountResolveQueuePostgresApproximate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres")
	}
	st := fdnsTestStore(t)
	fdnsRequireResolveQueue(t, st)
	n, err := st.CountResolveQueue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n < 0 {
		t.Fatalf("queue_approx=%d, want >= 0 (missing/unanalyzed maps to 0)", n)
	}
}

func fdnsRequireHostIP(t *testing.T, st *Store) {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'fdns_host_ip'`).Scan(&n); err != nil || n == 0 {
		t.Skip("fdns_host_ip table missing (run migrations)")
	}
}

func fdnsRequireResolveQueue(t *testing.T, st *Store) {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'fdns_resolve_queue'`).Scan(&n); err != nil || n == 0 {
		t.Skip("fdns_resolve_queue table missing (run migrations)")
	}
}

func containsString(got []string, want string) bool {
	for _, s := range got {
		if s == want {
			return true
		}
	}
	return false
}

// fdnsPinResolveQueueHead puts names at the front of due_idx so ClaimDue on a
// shared catalog (hundreds of millions of CC/list rows) claims these, not 00.ru.
func fdnsPinResolveQueueHead(t *testing.T, st *Store, names ...string) {
	t.Helper()
	tag, err := st.DB.Exec(context.Background(), `
		UPDATE fdns_resolve_queue
		SET priority = 32767, enqueued_at = TIMESTAMPTZ '1970-01-01'
		WHERE name = ANY($1)`, names)
	if err != nil {
		t.Fatal(err)
	}
	if int(tag.RowsAffected()) != len(names) {
		t.Fatalf("pinned %d queue rows, want %d (upsert did not enqueue?)", tag.RowsAffected(), len(names))
	}
}

func fdnsUnlockBorrowed(t *testing.T, st *Store, lockedBy string, claimed []string, keep ...string) {
	t.Helper()
	var extra []string
	for _, n := range claimed {
		if !containsString(keep, n) {
			extra = append(extra, n)
		}
	}
	if len(extra) == 0 {
		return
	}
	if err := st.UnlockResolveQueue(context.Background(), extra, lockedBy); err != nil {
		t.Fatal(err)
	}
}

func fdnsTestStore(t *testing.T) *Store {
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
		WHERE table_schema = 'public' AND table_name = 'fdns_host_name'`).Scan(&n); err != nil || n == 0 {
		t.Skip("fdns_host_name table missing (run migrations)")
	}
	return &Store{DB: pool, logger: zap.NewNop()}
}
