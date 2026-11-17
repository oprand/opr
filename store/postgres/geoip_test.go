package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGetIPGeoItemSQLLookupRules(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)

	if !strings.Contains(sql, "anycast_prefix") {
		t.Fatal("anycast covering prefix must be consulted")
	}
	if !strings.Contains(sql, "'anycast'") {
		t.Fatal("anycast path must return source ANYCAST")
	}
	if !strings.Contains(sql, "whoisdb_inetnum") || !strings.Contains(sql, "whoisdb_inet6num") {
		t.Fatal("anycast HQ must join inetnum and inet6num")
	}
	if !strings.Contains(sql, "whoisdb_org") {
		t.Fatal("anycast HQ must join whoisdb_org")
	}
	if !strings.Contains(sql, "i.org = o.organization") || !strings.Contains(sql, "i.source = o.source") {
		t.Fatal("org join must be i.org = o.organization AND i.source = o.source")
	}
	if strings.Contains(sql, "prefix_consolidated") || strings.Contains(sql, "whoisdb_autnum") || strings.Contains(sql, "use_asn") {
		t.Fatal("anycast HQ must use inetnum org then geofeed, with no prefix_consolidated lookup")
	}
	if !strings.Contains(sql, "0.0.0.0/0") || !strings.Contains(sql, "::/0") {
		t.Fatal("inetnum HQ must exclude default routes")
	}

	anyAt := strings.Index(sql, "anycast_row")
	uniAt := strings.Index(sql, "unicast_row")
	if anyAt < 0 || uniAt < anyAt {
		t.Fatal("expected anycast_row CTE before unicast_row")
	}
	anycastPart := sql[anyAt:uniAt]
	if strings.Contains(anycastPart, "from geoip") {
		t.Fatal("anycast_row must not read geoip directly; GEOFEED HQ is a separate CTE")
	}
	if !strings.Contains(anycastPart, "null::numeric as latitude") ||
		!strings.Contains(anycastPart, "null::numeric as longitude") {
		t.Fatal("anycast must not copy IPmap lat/lon")
	}
	if !strings.Contains(anycastPart, "'anycast'") {
		t.Fatal("anycast_row must emit source ANYCAST")
	}

	unicast := sql[uniAt:]
	if !strings.Contains(unicast, "from geoip") {
		t.Fatal("non-anycast lookup still reads geoip")
	}
	if !strings.Contains(unicast, "not exists") {
		t.Fatal("unicast geoip must be skipped when anycast_cover exists")
	}
	geofeedAt := strings.Index(unicast, "when 'geofeed' then 0")
	lacnicAt := strings.Index(unicast, "when 'lacnic_db_csv' then 1")
	elseAt := strings.Index(unicast, "else 2")
	maskAt := strings.Index(unicast, "masklen(netblock) desc")
	addedAt := strings.Index(unicast, "meta_added_at desc")
	if geofeedAt < 0 || lacnicAt < geofeedAt || elseAt < lacnicAt {
		t.Fatal("GEOFEED must beat LACNIC must beat IPmap (ELSE 2)")
	}
	if maskAt < elseAt || addedAt < maskAt {
		t.Fatal("after source rank: masklen DESC then meta_added_at DESC")
	}
	if !strings.Contains(sql, "org_address") || !strings.Contains(sql, "org_name") {
		t.Fatal("SELECT must include org HQ fields")
	}
	if !strings.Contains(sql, "limit 1") {
		t.Fatal("expected LIMIT 1")
	}
}

func TestGetIPGeoItemSQLTable(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	uniAt := strings.Index(sql, "unicast_row")
	anyAt := strings.Index(sql, "anycast_row")
	if anyAt < 0 || uniAt < 0 {
		t.Fatal("expected anycast_row and unicast_row CTEs")
	}

	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "GEOFEED /24 beats IPmap /32",
			check: func(t *testing.T) {
				unicast := sql[uniAt:]
				geofeedAt := strings.Index(unicast, "when 'geofeed' then 0")
				elseAt := strings.Index(unicast, "else 2")
				maskAt := strings.Index(unicast, "masklen(netblock) desc")
				if geofeedAt < 0 || elseAt < geofeedAt || maskAt < elseAt {
					t.Fatal("source rank (GEOFEED=0 ... ELSE 2 IPmap) must precede masklen, so a GEOFEED /24 beats an IPmap /32")
				}
			},
		},
		{
			name: "anycast preferred over IPmap city",
			check: func(t *testing.T) {
				anycastPart := sql[anyAt:uniAt]
				if strings.Contains(anycastPart, "from geoip") {
					t.Fatal("anycast_row must not select IPmap city from geoip")
				}
				if !strings.Contains(sql, "not exists (select 1 from anycast_cover)") {
					t.Fatal("unicast IPmap must yield when a covering anycast_prefix exists")
				}
				if !strings.Contains(anycastPart, "'anycast'") {
					t.Fatal("covering anycast_prefix returns source ANYCAST")
				}
				if !strings.Contains(anycastPart, "null::numeric as latitude") ||
					!strings.Contains(anycastPart, "null::numeric as longitude") {
					t.Fatal("anycast_row must null IPmap coords on every branch")
				}
			},
		},
		{
			name: "IPmap-only unicast still IPmap",
			check: func(t *testing.T) {
				unicast := sql[uniAt:]
				if !strings.Contains(unicast, "from geoip") {
					t.Fatal("unicast still reads geoip")
				}
				if !strings.Contains(unicast, "else 2") {
					t.Fatal("RIPE_IPMAP is ELSE 2 and is still selected when no GEOFEED/LACNIC covers")
				}
				if !strings.Contains(unicast, "latitude") || !strings.Contains(unicast, "city") {
					t.Fatal("unicast IPmap still returns city/coords")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.check)
	}
}

// A covering RIR catch-all (RIPE publishes inetnum 0.0.0.0 - 255.255.255.255
// with org ORG-IANA1-RIPE) would otherwise win inet_org. inet_org excludes
// the default routes on both legs so that catch-all cannot supply HQ.
func TestGetIPGeoItemSQLInetOrgDefaultRouteGuard(t *testing.T) {
	t.Parallel()
	v4, v6 := inetOrgLegs(t)
	for _, leg := range []struct {
		name string
		sql  string
	}{{"inetnum", v4}, {"inet6num", v6}} {
		if !strings.Contains(leg.sql, "netblock != '0.0.0.0/0'") {
			t.Fatalf("%s leg must exclude 0.0.0.0/0: %s", leg.name, leg.sql)
		}
		if !strings.Contains(leg.sql, "netblock != '::/0'") {
			t.Fatalf("%s leg must exclude ::/0: %s", leg.name, leg.sql)
		}
	}
	if strings.Contains(strings.ToLower(getIPGeoItemSQL), "asn_org") {
		t.Fatal("inet_org is the anycast org source; asn_org must be gone")
	}
}

// (netblock, source) is the unique key on whoisdb_inetnum, so masklen alone
// leaves the winner up to the plan. Restrict to the five RIR sources and
// tie-break on source.
func TestGetIPGeoItemSQLInetOrgDeterministicTieBreak(t *testing.T) {
	t.Parallel()
	v4, v6 := inetOrgLegs(t)
	for _, leg := range []struct {
		name string
		sql  string
	}{{"inetnum", v4}, {"inet6num", v6}} {
		for _, rir := range []string{"'apnic'", "'lacnic'", "'ripe'", "'afrinic'", "'arin'"} {
			if !strings.Contains(leg.sql, rir) {
				t.Fatalf("%s leg missing RIR %s from the source allow-list", leg.name, rir)
			}
		}
	}
	sql := strings.ToLower(getIPGeoItemSQL)
	if !strings.Contains(sql, "order by masklen(i.netblock) desc, i.source") {
		t.Fatal("inet_org must tie-break on source so the winner is reproducible")
	}
}

// HQ precedence: covering inetnum org (whole row), else operator-declared
// GEOFEED. IPmap/LACNIC city and coords stay off the anycast path.
func TestGetIPGeoItemSQLAnycastHQPrecedence(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	gfAt := strings.Index(sql, "geofeed_hq as (")
	anyAt := strings.Index(sql, "anycast_row as (")
	uniAt := strings.Index(sql, "unicast_row as (")
	if gfAt < 0 || anyAt < gfAt || uniAt < anyAt {
		t.Fatal("expected geofeed_hq CTE before anycast_row before unicast_row")
	}

	anycastPart := sql[anyAt:uniAt]
	useInet := strings.Index(anycastPart, "when p.use_inet then p.io_")
	geofeedElse := strings.Index(anycastPart, "else p.gf_country_code")
	if useInet < 0 || geofeedElse < useInet {
		t.Fatal("inetnum org must be chosen before geofeed (CASE WHEN use_inet THEN io … ELSE gf)")
	}
	if strings.Contains(anycastPart, "use_asn") || strings.Contains(anycastPart, "prefix_consolidated") {
		t.Fatal("anycast HQ must not consult an ASN org or prefix_consolidated")
	}
	if !strings.Contains(anycastPart, "'anycast'") {
		t.Fatal("anycast_row still emits source ANYCAST")
	}
	if !strings.Contains(anycastPart, "null::numeric as latitude") ||
		!strings.Contains(anycastPart, "null::numeric as longitude") ||
		!strings.Contains(anycastPart, "null::numeric as score") ||
		!strings.Contains(anycastPart, "null::text as location_id") {
		t.Fatal("org and geofeed branches must null IPmap coords/score/location_id")
	}
	if !strings.Contains(anycastPart, "when p.use_inet then null::text") {
		t.Fatal("inetnum HQ must null city/region/zip; only geofeed ELSE may copy them")
	}
}

// GEOFEED is the only geoip source on the anycast path, and only when the
// inetnum org lacks HQ. Unicast still ranks GEOFEED > LACNIC > IPmap.
func TestGetIPGeoItemSQLAnycastGeofeedFallback(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	gfAt := strings.Index(sql, "geofeed_hq as (")
	anyAt := strings.Index(sql, "anycast_row as (")
	uniAt := strings.Index(sql, "unicast_row as (")
	if gfAt < 0 || anyAt < gfAt || uniAt < anyAt {
		t.Fatal("expected geofeed_hq CTE before anycast_row before unicast_row")
	}

	fallback := sql[gfAt:anyAt]
	if !strings.Contains(fallback, "from geoip") {
		t.Fatal("geofeed fallback may read geoip")
	}
	if !strings.Contains(fallback, "source = 'geofeed'") {
		t.Fatal("geofeed fallback must filter source = 'GEOFEED'")
	}
	if strings.Contains(fallback, "lacnic_db_csv") || strings.Contains(fallback, "else 2") {
		t.Fatal("geofeed fallback must not rank LACNIC or IPmap")
	}
	if strings.Contains(fallback, "latitude") || strings.Contains(fallback, "longitude") ||
		strings.Contains(fallback, "score") || strings.Contains(fallback, "location_id") {
		t.Fatal("geofeed fallback must not read IPmap coords from geoip")
	}
	if !strings.Contains(fallback, "city") || !strings.Contains(fallback, "region") ||
		!strings.Contains(fallback, "zipcode") {
		t.Fatal("geofeed fallback may copy operator-declared city/region/zip")
	}
	if !strings.Contains(fallback, "masklen(netblock) desc") ||
		!strings.Contains(fallback, "meta_added_at desc") {
		t.Fatal("geofeed fallback ranks most specific then newest")
	}

	anycastPart := sql[anyAt:uniAt]
	if !strings.Contains(anycastPart, "left join geofeed_hq gf on true") {
		t.Fatal("anycast_row must join the geofeed fallback")
	}
	if !strings.Contains(anycastPart, "else p.gf_country_code") ||
		!strings.Contains(anycastPart, "else p.gf_city") {
		t.Fatal("geofeed HQ is used only when the inetnum org is absent")
	}
}

// geoip.latitude/longitude/score are NUMERIC. NULL::double precision on the
// anycast side would make the UNION resolve to double precision and cast the
// unicast rows.
func TestGetIPGeoItemSQLNumericNullsMatchGeoIPColumns(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	if strings.Contains(sql, "double precision") {
		t.Fatal("anycast NULLs must be numeric so the UNION does not cast the geoip side")
	}
	for _, col := range []string{"latitude", "longitude", "score"} {
		if !strings.Contains(sql, "null::numeric as "+col) {
			t.Fatalf("expected NULL::numeric AS %s", col)
		}
	}
}

// The anycast branch emits the source literal; keep it tied to the exported
// const callers compare against.
func TestGetIPGeoItemSQLEmitsGeoIPSourceANYCAST(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	if !strings.Contains(sql, "'"+strings.ToLower(GeoIPSourceANYCAST)+"'::text as source") {
		t.Fatalf("lookup must emit %q as the source literal", GeoIPSourceANYCAST)
	}
	emitted := GeoIPSourceANYCAST
	if !IsAnycastGeoIPSource(&emitted) {
		t.Fatal("IsAnycastGeoIPSource must accept the emitted literal")
	}
	lower := "anycast"
	if !IsAnycastGeoIPSource(&lower) {
		t.Fatal("IsAnycastGeoIPSource must be case-insensitive")
	}
	other := GeoIPStatusSourceIPMAP
	if IsAnycastGeoIPSource(&other) || IsAnycastGeoIPSource(nil) {
		t.Fatal("only the ANYCAST literal is the anycast branch")
	}
}

// anycast_cover is read by four CTEs plus the final branches, and the whois /
// geofeed CTEs must not be evaluated for a unicast address.
func TestGetIPGeoItemSQLAnycastCoverMaterializedAndGating(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(getIPGeoItemSQL)
	if !strings.Contains(sql, "with anycast_cover as materialized (") {
		t.Fatal("anycast_cover is referenced repeatedly; MATERIALIZED keeps it a single scan")
	}
	if want, got := 3, strings.Count(sql, "exists (select 1 from anycast_cover)"); got < want {
		t.Fatalf("EXISTS gate count = %d, want at least %d (both inet legs, geofeed_hq)", got, want)
	}
	if !strings.Contains(sql, "not exists (select 1 from anycast_cover)") {
		t.Fatal("unicast_row must still yield to a covering anycast prefix")
	}
}

func inetOrgLegs(t *testing.T) (v4 string, v6 string) {
	t.Helper()
	sql := strings.ToLower(getIPGeoItemSQL)
	v4At := strings.Index(sql, "from whoisdb_inetnum")
	v6At := strings.Index(sql, "from whoisdb_inet6num")
	endAt := strings.Index(sql, ") i\n")
	if v4At < 0 || v6At < v4At || endAt < v6At {
		t.Fatalf("inet_org legs not found in:\n%s", sql)
	}
	return sql[v4At:v6At], sql[v6At:endAt]
}

func TestSaveGeoIPItemOnConflictNetblockSourceURL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(geoIPUpsert.insertSQL())
	if strings.Contains(sql, "on conflict (netblock)") && !strings.Contains(sql, "on conflict (netblock, source_url)") {
		t.Fatal("ON CONFLICT (netblock) would collapse LACNIC and GEOFEED")
	}
	if !strings.Contains(sql, "on conflict (netblock, source_url)") {
		t.Fatal("expected ON CONFLICT (netblock, source_url)")
	}
	if !containsColumn(geoIPUpsert.columns, "source_url") {
		t.Fatal("COPY must include source_url")
	}
	dummy := geoIPCopyRow(&GeoIPItem{Netblock: "192.0.2.0/24"})
	if len(dummy) != len(geoIPUpsert.columns) {
		t.Fatalf("copy row len %d != columns %d", len(dummy), len(geoIPUpsert.columns))
	}
}

func TestDedupGeoIPItemsLastWinsPerNetblockSourceURL(t *testing.T) {
	t.Parallel()
	lacnic := "LACNIC_DB_CSV"
	geofeed := "GEOFEED"
	urlA := "https://a.example/feed.csv"
	urlB := "https://b.example/feed.csv"
	ccUS := "US"
	ccBR := "BR"
	items := dedupGeoIPItems([]*GeoIPItem{
		{Netblock: "192.0.2.0/24", Source: &lacnic, CountryCode: &ccUS},
		{Netblock: "192.0.2.0/24", Source: &geofeed, SourceURL: &urlA, CountryCode: &ccUS},
		{Netblock: "192.0.2.0/24", Source: &geofeed, SourceURL: &urlA, CountryCode: &ccBR},
		{Netblock: "192.0.2.0/24", Source: &geofeed, SourceURL: &urlB, CountryCode: &ccUS},
		{Netblock: "", Source: &geofeed, SourceURL: &urlA},
		nil,
	})
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3 (LACNIC empty url + two geofeed urls)", len(items))
	}
	got := map[string]string{}
	for _, it := range items {
		got[it.Netblock+"|"+geoIPSourceURL(it)] = *it.CountryCode
	}
	if got["192.0.2.0/24|"] != "US" {
		t.Fatalf("LACNIC row = %q, want US", got["192.0.2.0/24|"])
	}
	if got["192.0.2.0/24|"+urlA] != "BR" {
		t.Fatalf("url A last-wins = %q, want BR", got["192.0.2.0/24|"+urlA])
	}
	if got["192.0.2.0/24|"+urlB] != "US" {
		t.Fatalf("url B = %q, want US", got["192.0.2.0/24|"+urlB])
	}
}

func TestSaveGeoIPItemEmptyError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.SaveGeoIPItem(nil); err == nil {
		t.Fatal("nil items must error")
	}
	if err := st.SaveGeoIPItem([]*GeoIPItem{{Netblock: ""}, nil}); err == nil {
		t.Fatal("empty netblocks must error")
	}
}

func TestReplaceGeoIPBySourceURLSQLScopedToURL(t *testing.T) {
	t.Parallel()
	stale := strings.ToLower(replaceGeoIPDeleteStaleSQL)
	if !strings.Contains(stale, "delete from geoip") {
		t.Fatal("expected DELETE FROM geoip")
	}
	if !strings.Contains(stale, "source_url = $1") {
		t.Fatal("replace must filter source_url = $1 so other feeds are kept")
	}
	if !strings.Contains(stale, "geoip_stg") {
		t.Fatal("stale delete must use the COPY temp set")
	}
	if strings.Contains(stale, "crawl_target") {
		t.Fatal("derived geoip replace must not touch crawl_target")
	}

	all := strings.ToLower(replaceGeoIPDeleteAllSQL)
	if !strings.Contains(all, "delete from geoip") {
		t.Fatal("empty parse must DELETE FROM geoip")
	}
	if !strings.Contains(all, "source_url = $1") {
		t.Fatal("empty parse must still scope to source_url")
	}
	if strings.Contains(all, "not in") || strings.Contains(all, "not exists") {
		t.Fatal("empty-set delete removes every row for that URL")
	}
}

func TestCountGeoIPBySourceURLSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(countGeoIPBySourceURLSQL)
	if !strings.Contains(sql, "select count(*) from geoip") {
		t.Fatal("expected SELECT COUNT(*) FROM geoip")
	}
	if !strings.Contains(sql, "source_url = $1") {
		t.Fatal("count must filter source_url = $1")
	}
	if strings.Contains(sql, "geofeeds") {
		t.Fatal("IPmap floor count is by dump URL, not the geofeeds catalog")
	}
}

func TestCountGeoIPBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.CountGeoIPBySourceURL(context.Background(), ""); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestReplaceGeoIPBySourceURLEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.ReplaceGeoIPBySourceURL(context.Background(), "", nil); err == nil {
		t.Fatal("empty source_url must error")
	}
}

func TestPruneOrphanGeoIPSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(pruneOrphanGeoIPSQL)
	if !strings.Contains(sql, "delete from geoip") {
		t.Fatal("expected DELETE FROM geoip")
	}
	if !strings.Contains(sql, "source = $1") {
		t.Fatal("prune must filter source so LACNIC rows survive a GEOFEED prune")
	}
	if !strings.Contains(sql, "not in (select url from geofeeds)") {
		t.Fatal("expected source_url NOT IN geofeeds catalog")
	}
	if !strings.Contains(sql, "source_url = ''") {
		t.Fatal("empty source_url is an orphan for GEOFEED")
	}
	if strings.Contains(sql, "crawl_target") {
		t.Fatal("orphan prune is catalog-vs-geoip, not crawl_target")
	}
}

func TestPruneOrphanGeoIPEmptySourceNoop(t *testing.T) {
	t.Parallel()
	var st *Store
	n, err := st.PruneOrphanGeoIP(context.Background(), "")
	if err != nil || n != 0 {
		t.Fatalf("empty source: n=%d err=%v", n, err)
	}
	n, err = st.CountOrphanGeoIP(context.Background(), "")
	if err != nil || n != 0 {
		t.Fatalf("count empty source: n=%d err=%v", n, err)
	}
	n, err = st.PruneOrphanGeoIPNonEmpty(context.Background(), "")
	if err != nil || n != 0 {
		t.Fatalf("nonempty prune empty source: n=%d err=%v", n, err)
	}
}

func TestCountOrphanGeoIPSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(countOrphanGeoIPSQL)
	if !strings.Contains(sql, "select count(*) from geoip") {
		t.Fatal("expected SELECT COUNT(*) FROM geoip")
	}
	if !strings.Contains(sql, "source = $1") {
		t.Fatal("count must filter source")
	}
	if !strings.Contains(sql, "not in (select url from geofeeds)") {
		t.Fatal("expected source_url NOT IN geofeeds")
	}
}

func TestPruneOrphanGeoIPNonEmptySQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(pruneOrphanGeoIPNonEmptySQL)
	if !strings.Contains(sql, "source_url <> ''") && !strings.Contains(sql, `source_url <> ''`) {
		t.Fatal("LACNIC prune must keep empty source_url")
	}
	if strings.Contains(sql, "source_url = ''") {
		t.Fatal("non-empty prune must not treat empty source_url as orphan")
	}
	if !strings.Contains(sql, "not in (select url from geofeeds)") {
		t.Fatal("expected NOT IN geofeeds")
	}
}

func TestClaimDueGeofeedsSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(claimDueGeofeedsSQL)
	if strings.Contains(sql, "crawl_target") {
		t.Fatal("geofeed crawl claims geofeeds, not crawl_target")
	}
	if !strings.Contains(sql, "update geofeeds") {
		t.Fatal("claim must UPDATE geofeeds so the lease survives commit")
	}
	if !strings.Contains(sql, "locked_at = now()") {
		t.Fatal("claim must set locked_at")
	}
	if !strings.Contains(sql, "for update skip locked") {
		t.Fatal("concurrent claimers must SKIP LOCKED")
	}
	if !strings.Contains(sql, "locked_at is null or locked_at < now() - ($3 * interval '1 second')") {
		t.Fatal("stale locked_at must be reclaimable")
	}
	if !strings.Contains(sql, "from geofeeds") {
		t.Fatal("expected FROM geofeeds")
	}
	if !strings.Contains(sql, "quarantined_until") {
		t.Fatal("must skip quarantined URLs")
	}
	if !strings.Contains(sql, "last_fetched_at is null") {
		t.Fatal("new URLs (last_fetched_at NULL) must be due")
	}
	if !strings.Contains(sql, "cache_until < now()") {
		t.Fatal("expired cache_until must be due")
	}
	if !strings.Contains(sql, "last_fetched_at < now() - ($1 * interval '1 second')") {
		t.Fatal("caller refresh interval must be due")
	}
	if !strings.Contains(sql, "order by last_fetched_at asc nulls first") {
		t.Fatal("new URLs must sort first")
	}
	if !strings.Contains(sql, "returning") {
		t.Fatal("UPDATE must RETURNING claimed rows")
	}
}

func TestClaimDueGeofeedsBatchGuard(t *testing.T) {
	t.Parallel()
	var st *Store
	if _, err := st.ClaimDueGeofeeds(context.Background(), 0, time.Hour, time.Minute); err == nil {
		t.Fatal("batch < 1 must error")
	}
}

func TestClaimDueGeofeedsLeaseGuard(t *testing.T) {
	t.Parallel()
	var st *Store
	for _, lease := range []time.Duration{0, -time.Second} {
		if _, err := st.ClaimDueGeofeeds(context.Background(), 1, time.Hour, lease); err == nil {
			t.Fatalf("lease %v must error", lease)
		}
	}
}

func TestStampGeofeedSQL(t *testing.T) {
	t.Parallel()
	sql := strings.ToLower(stampGeofeedSQL)
	if !strings.Contains(sql, "update geofeeds") {
		t.Fatal("expected UPDATE geofeeds")
	}
	for _, col := range []string{
		"etag", "last_modified", "cache_until", "last_checked_at",
		"last_fetched_at", "last_http_status", "item_count", "is_valid",
		"quarantined_until",
	} {
		if !strings.Contains(sql, col) {
			t.Fatalf("stamp missing column %s", col)
		}
	}
	if !strings.Contains(sql, "last_checked_at = now()") {
		t.Fatal("every stamp must set last_checked_at")
	}
	if !strings.Contains(sql, "coalesce($2, etag)") {
		t.Fatal("304 must keep etag via COALESCE")
	}
	if !strings.Contains(sql, "when $10::boolean then null") {
		t.Fatal("successful fetch must be able to clear quarantine")
	}
	if strings.Contains(sql, "locked_at") {
		t.Fatal("stamp must not clear locked_at; the claim lease skips re-claim until expiry")
	}
}

func TestStampGeofeedEmptyURLError(t *testing.T) {
	t.Parallel()
	var st *Store
	if err := st.StampGeofeed(context.Background(), GeofeedStamp{}); err == nil {
		t.Fatal("empty url must error")
	}
}
