CREATE TABLE public.anycast_prefix (
    netblock inet NOT NULL,
    example_host inet,
    source_url text NOT NULL,
    meta_added_at timestamp with time zone DEFAULT now()
);


CREATE TABLE public.asn_connectivity (
    asn numeric NOT NULL,
    peers numeric[],
    upstreams numeric[],
    downstreams numeric[],
    meta_updated_at timestamp with time zone NOT NULL
);


CREATE TABLE public.aspa (
    customer_asn bigint NOT NULL,
    afi text NOT NULL,
    providers bigint[] DEFAULT '{}'::bigint[] NOT NULL,
    ta text NOT NULL,
    uri text,
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    CONSTRAINT aspa_afi_ipv4_ipv6 CHECK ((afi = ANY (ARRAY['ipv4'::text, 'ipv6'::text, 'both'::text])))
);


CREATE TABLE public.aspop (
    asn numeric NOT NULL,
    country_code character varying(2) NOT NULL,
    user_count numeric NOT NULL,
    perc_country numeric NOT NULL,
    perc_internet numeric NOT NULL,
    sample_count numeric NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE public.country_code_remap (
    from_code text NOT NULL,
    to_code text NOT NULL
);


COMMENT ON TABLE public.country_code_remap IS 'Maps non-ISO / vendor country codes onto GeoNames country_info.iso.';


CREATE TABLE public.country_info (
    iso text NOT NULL,
    iso3 text,
    iso_numeric text,
    fips text,
    country text,
    capital text,
    area double precision,
    population integer,
    continent text,
    tld text,
    currency_code text,
    currency_name text,
    phone text,
    postal_code_format text,
    postal_code_regex text,
    languages text[],
    geoname_id integer,
    neighbours text[],
    equivalent_fips text,
    meta_added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


CREATE TABLE public.country_legal_flag (
    iso text NOT NULL,
    flag text NOT NULL,
    admin1_code text DEFAULT ''::text NOT NULL,
    source text NOT NULL,
    as_of date NOT NULL,
    notes text,
    CONSTRAINT country_legal_flag_admin1_upper CHECK ((admin1_code = upper(admin1_code))),
    CONSTRAINT country_legal_flag_flag_lower CHECK (((flag = lower(flag)) AND (flag <> ''::text))),
    CONSTRAINT country_legal_flag_iso_upper CHECK (((iso = upper(iso)) AND (length(iso) = 2)))
);


COMMENT ON TABLE public.country_legal_flag IS 'Legal / treaty flags per country, optionally narrowed to one ISO 3166-2 admin1 (empty admin1_code means the whole country). Superset clubs are separate flags so WHERE flag = ''five_eyes'' stays exact. Lists are refreshed by a new migration that rewrites source / as_of, not by a crawl.';


CREATE TABLE public.crawl_target (
    id bigint NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    registry text DEFAULT ''::text NOT NULL,
    priority smallint DEFAULT 0 NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    next_retry_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_fetched_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    last_status_code integer,
    last_error text,
    locked_at timestamp with time zone,
    locked_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON COLUMN public.crawl_target.registry IS 'Defaults to '''' (empty string, not NULL) so the UNIQUE (kind, key, registry) key dedups geofeed rows correctly - NULLs are considered distinct in Postgres UNIQUE constraints.';


CREATE SEQUENCE public.crawl_target_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.crawl_target_id_seq OWNED BY public.crawl_target.id;


CREATE TABLE public.delegated_stats (
    id integer NOT NULL,
    registry text NOT NULL,
    country_code text,
    resource_type text NOT NULL,
    range_start text NOT NULL,
    range_value numeric NOT NULL,
    asn_start bigint,
    asn_end bigint,
    ip_start inet,
    ip_end inet,
    status text NOT NULL,
    alloc_date date,
    opaque_id text,
    file_date date,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    ingested_at timestamp with time zone DEFAULT now()
);


COMMENT ON TABLE public.delegated_stats IS 'Daily FULL snapshot of the NRO extended delegated-stats file, reloaded via rename-swap. Source of truth for asn/prefix -> registry attribution. See migration 0062 for full column semantics.';


COMMENT ON COLUMN public.delegated_stats.range_value IS 'Raw value from the NRO file, kept verbatim. Meaning depends on resource_type: asn = count of ASNs, ipv4 = COUNT OF ADDRESSES (NOT a prefix length, and frequently not a power of 2, e.g. 196608), ipv6 = prefix length. Do NOT derive a CIDR from this value - use ip_start/ip_end (or asn_start/asn_end) for lookups.';


COMMENT ON COLUMN public.delegated_stats.asn_end IS 'Derived at ingest = asn_start + range_value - 1 (asn rows only, NULL for ip). Use $asn BETWEEN asn_start AND asn_end for asn -> registry lookup.';


COMMENT ON COLUMN public.delegated_stats.ip_end IS 'Derived at ingest = ip_start + range_value - 1 (ipv4/ipv6 rows only, NULL for asn). Exists so prefix -> registry containment is indexable WITHOUT CIDR decomposition: family(ip_start)=family($ip) AND $ip BETWEEN ip_start AND ip_end.';


COMMENT ON COLUMN public.delegated_stats.status IS 'allocated | assigned | reserved | available | iana. Only allocated/assigned are crawlable, reserved/available/iana rows MUST be skipped when seeding crawl_target.';


COMMENT ON COLUMN public.delegated_stats.opaque_id IS 'Opaque in-series holder id. Groups resources of the same holder WITHIN ONE registry only (always key on (registry, opaque_id)) - NOT comparable across RIRs and NOT an org name/handle. Only meaningful for allocated/assigned rows.';


CREATE SEQUENCE public.delegated_stats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.delegated_stats_id_seq OWNED BY public.delegated_stats.id;


CREATE TABLE public.fdns_host_ip (
    name text NOT NULL,
    ip inet NOT NULL,
    source text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fdns_host_ip_source_check CHECK ((source = ANY (ARRAY['dns'::text, 'cc'::text])))
);


COMMENT ON TABLE public.fdns_host_ip IS 'Forward name→IP. source is dns (A/AAAA) or cc (legacy, Host Index ingest does not write cc IPs). Same (name, ip) from two sources is two rows.';


COMMENT ON COLUMN public.fdns_host_ip.source IS 'dns = recursive A/AAAA, cc = reserved/legacy Common Crawl IP extract. Host Index path writes names only.';


CREATE TABLE public.fdns_host_name (
    name text NOT NULL,
    source text[] DEFAULT '{}'::text[] NOT NULL,
    rank_tranco integer,
    rank_umbrella integer,
    rank_crux integer,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolve_locked_at timestamp with time zone,
    resolve_locked_by text,
    CONSTRAINT fdns_host_name_source_check CHECK ((source <@ ARRAY['tranco'::text, 'umbrella'::text, 'crux'::text, 'cc'::text]))
);


COMMENT ON TABLE public.fdns_host_name IS 'Forward-DNS hostname catalog. name is a lowercased FQDN with no trailing dot. source is the union of list/CC membership {tranco,umbrella,crux,cc}. cc = Common Crawl Host Index names (not WARC-IP). List/CC upsert leave resolved_at NULL.';


COMMENT ON COLUMN public.fdns_host_name.name IS 'Lowercased FQDN with no trailing dot. Primary key.';


COMMENT ON COLUMN public.fdns_host_name.source IS 'Membership union on upsert: tranco, umbrella, crux, cc. cc is Host Index hostname membership.';


COMMENT ON COLUMN public.fdns_host_name.resolved_at IS 'Set when A/AAAA resolve writes fdns_host_ip. NULL means still queued.';


COMMENT ON COLUMN public.fdns_host_name.resolve_locked_at IS 'Lease timestamp for multi-worker A/AAAA resolve (ClaimDueHostNames). NULL = unlocked. Stale leases are reclaimable.';


COMMENT ON COLUMN public.fdns_host_name.resolve_locked_by IS 'Worker id holding resolve_locked_at. Ops/debug only until the claim loop lands.';


CREATE TABLE public.fdns_resolve_queue (
    name text NOT NULL,
    priority smallint DEFAULT 0 NOT NULL,
    enqueued_at timestamp with time zone DEFAULT now() NOT NULL,
    locked_at timestamp with time zone,
    locked_by text,
    attempts smallint DEFAULT 0 NOT NULL
);


COMMENT ON TABLE public.fdns_resolve_queue IS 'A/AAAA work queue. Seeded from ClickHouse (fdns seed-queue) and list ingest. resolve claims with SKIP LOCKED, success deletes the row. SERVFAIL/timeout clears locked_at.';


COMMENT ON COLUMN public.fdns_resolve_queue.name IS 'FQDN PK, FK to fdns_host_name. Catalog row must exist before resolve writes IPs.';


COMMENT ON COLUMN public.fdns_resolve_queue.priority IS 'Higher values are claimed first. 0 = CC seed-queue. 1 = list ingest (Tranco/Umbrella/CrUX).';


COMMENT ON COLUMN public.fdns_resolve_queue.locked_at IS 'Lease timestamp. NULL = due. Stale leases (locked_at older than --lease) are reclaimable.';


COMMENT ON COLUMN public.fdns_resolve_queue.locked_by IS 'Worker id holding locked_at (--worker-id). Ops/debug.';


COMMENT ON COLUMN public.fdns_resolve_queue.attempts IS 'Incremented on every claim, including stale-lease reclaim.';


CREATE TABLE public.geofeeds (
    internal_id integer NOT NULL,
    url text NOT NULL,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen_in_whois timestamp with time zone,
    last_http_status integer,
    item_count integer,
    is_valid boolean,
    quarantined_until timestamp with time zone,
    etag text,
    last_modified text,
    cache_until timestamp with time zone,
    last_checked_at timestamp with time zone,
    last_fetched_at timestamp with time zone,
    locked_at timestamp with time zone
);


CREATE SEQUENCE public.geofeeds_internal_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.geofeeds_internal_id_seq OWNED BY public.geofeeds.internal_id;


CREATE TABLE public.geoip (
    netblock inet NOT NULL,
    ip_version numeric GENERATED ALWAYS AS (family(netblock)) STORED,
    country_code text,
    country text,
    region_code text,
    region text,
    city text,
    zipcode text,
    source text,
    meta_added_at timestamp with time zone DEFAULT now() NOT NULL,
    location_id text,
    type text,
    latitude numeric,
    longitude numeric,
    score numeric,
    source_url text DEFAULT ''::text NOT NULL
);


CREATE TABLE public.geonames_admin1 (
    code text NOT NULL,
    country_code text NOT NULL,
    admin1_code text NOT NULL,
    name text NOT NULL,
    ascii_name text,
    name_norm text DEFAULT ''::text NOT NULL,
    geonameid bigint
);


CREATE TABLE public.geonames_admin2 (
    code text NOT NULL,
    country_code text NOT NULL,
    admin1_code text,
    admin2_code text,
    name text NOT NULL,
    ascii_name text,
    name_norm text DEFAULT ''::text NOT NULL,
    geonameid bigint
);


CREATE TABLE public.geonames_altname (
    altname_id bigint NOT NULL,
    geonameid bigint NOT NULL,
    isolanguage text,
    alternate_name text NOT NULL,
    alias_norm text DEFAULT ''::text NOT NULL,
    is_preferred boolean,
    is_short boolean,
    is_colloquial boolean,
    is_historic boolean
);


CREATE TABLE public.geonames_city (
    geonameid bigint NOT NULL,
    name text NOT NULL,
    ascii_name text,
    city_norm text DEFAULT ''::text NOT NULL,
    ascii_norm text,
    latitude double precision,
    longitude double precision,
    feature_class text,
    feature_code text,
    country_code text NOT NULL,
    cc2 text,
    admin1_code text,
    admin2_code text,
    admin3_code text,
    admin4_code text,
    population bigint,
    elevation integer,
    dem integer,
    timezone text,
    modification_date date,
    alternate_names text[],
    meta_added_at timestamp with time zone DEFAULT now() NOT NULL
);


CREATE TABLE public.geonames_lookup (
    id bigint NOT NULL,
    country_code text NOT NULL,
    admin1_iso text,
    city_norm text,
    zipcode text,
    alias_norm text,
    geonameid bigint,
    lat double precision,
    lon double precision,
    timezone text,
    population bigint,
    zip_for_display text,
    admin_name_1 text,
    match_kind text NOT NULL
);


CREATE SEQUENCE public.geonames_lookup_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.geonames_lookup_id_seq OWNED BY public.geonames_lookup.id;


CREATE TABLE public.geonames_postal (
    id bigint NOT NULL,
    country_code text NOT NULL,
    postal_code text NOT NULL,
    place_name text NOT NULL,
    city_norm text DEFAULT ''::text NOT NULL,
    admin_name_1 text,
    admin_code_1 text,
    admin_name_2 text,
    admin_code_2 text,
    admin_name_3 text,
    admin_code_3 text,
    latitude double precision,
    longitude double precision,
    accuracy integer,
    meta_added_at timestamp with time zone DEFAULT now() NOT NULL
);


CREATE SEQUENCE public.geonames_postal_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.geonames_postal_id_seq OWNED BY public.geonames_postal.id;


CREATE TABLE public.geonames_timezone (
    timezone_id text NOT NULL,
    country_code text,
    gmt_offset double precision,
    dst_offset double precision,
    raw_offset double precision
);


CREATE TABLE public.host_ip (
    name text NOT NULL,
    ip inet NOT NULL,
    source text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_ip_source_check CHECK ((source = ANY (ARRAY['dns'::text, 'cc'::text])))
);


COMMENT ON TABLE public.host_ip IS 'Forward name→IP. source is dns (A/AAAA) or cc (Common Crawl WARC-IP-Address). Same (name, ip) from two sources is two rows.';


COMMENT ON COLUMN public.host_ip.source IS 'dns = recursive A/AAAA, cc = Common Crawl extract. Not list names.';


CREATE TABLE public.host_name (
    name text NOT NULL,
    source text[] DEFAULT '{}'::text[] NOT NULL,
    rank_tranco integer,
    rank_umbrella integer,
    rank_crux integer,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone
);


COMMENT ON TABLE public.host_name IS 'Forward-DNS hostname catalog. name is a lowercased FQDN with no trailing dot. source is the union of list membership {tranco,umbrella,crux}. List ingest leaves resolved_at NULL.';


COMMENT ON COLUMN public.host_name.name IS 'Lowercased FQDN with no trailing dot. Primary key.';


COMMENT ON COLUMN public.host_name.source IS 'List membership union on upsert: tranco, umbrella, crux.';


COMMENT ON COLUMN public.host_name.resolved_at IS 'Set when A/AAAA resolve writes host_ip. NULL means still queued.';


CREATE TABLE public.peeringdb_facility (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    address1 character varying(255) NOT NULL,
    address2 character varying(255) NOT NULL,
    city character varying(255) NOT NULL,
    state character varying(255) NOT NULL,
    zipcode character varying(48) NOT NULL,
    country character varying(2) NOT NULL,
    name character varying(255) NOT NULL,
    website character varying(255) NOT NULL,
    clli character varying(18) NOT NULL,
    rencode character varying(18) NOT NULL,
    npanxx character varying(21) NOT NULL,
    notes text NOT NULL,
    org_id integer NOT NULL
);


CREATE TABLE public.peeringdb_ix (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    name character varying(64) NOT NULL,
    name_long character varying(254) NOT NULL,
    city character varying(192) NOT NULL,
    country character varying(2) NOT NULL,
    notes text NOT NULL,
    region_continent character varying(255) NOT NULL,
    media character varying(128) NOT NULL,
    proto_unicast boolean NOT NULL,
    proto_multicast boolean NOT NULL,
    proto_ipv6 boolean NOT NULL,
    website character varying(255) NOT NULL,
    url_stats character varying(255) NOT NULL,
    tech_email character varying(254) NOT NULL,
    tech_phone character varying(192) NOT NULL,
    policy_email character varying(254) NOT NULL,
    policy_phone character varying(192) NOT NULL,
    org_id integer NOT NULL
);


CREATE TABLE public.peeringdb_ix_facility (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    ix_id integer NOT NULL,
    fac_id integer NOT NULL
);


CREATE TABLE public.peeringdb_ixlan (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    name character varying(255) NOT NULL,
    descr text NOT NULL,
    mtu integer,
    vlan integer,
    dot1q_support boolean NOT NULL,
    rs_asn integer,
    arp_sponge character varying(17),
    ix_id integer NOT NULL
);


CREATE TABLE public.peeringdb_ixlan_prefix (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    notes character varying(255) NOT NULL,
    protocol character varying(64) NOT NULL,
    prefix character varying(43) NOT NULL,
    ixlan_id integer NOT NULL
);


CREATE TABLE public.peeringdb_network (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    asn integer NOT NULL,
    name character varying(255) NOT NULL,
    aka character varying(255) NOT NULL,
    irr_as_set character varying(255) NOT NULL,
    website character varying(255) NOT NULL,
    looking_glass character varying(255) NOT NULL,
    route_server character varying(255) NOT NULL,
    notes text NOT NULL,
    notes_private text NOT NULL,
    info_traffic character varying(39) NOT NULL,
    info_ratio character varying(45) NOT NULL,
    info_scope character varying(39) NOT NULL,
    info_type character varying(60) NOT NULL,
    info_prefixes4 integer,
    info_prefixes6 integer,
    info_unicast boolean NOT NULL,
    info_multicast boolean NOT NULL,
    info_ipv6 boolean NOT NULL,
    policy_url character varying(255) NOT NULL,
    policy_general character varying(72) NOT NULL,
    policy_locations character varying(72) NOT NULL,
    policy_ratio boolean NOT NULL,
    policy_contracts character varying(36) NOT NULL,
    org_id integer NOT NULL
);


CREATE TABLE public.peeringdb_network_contact (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    role character varying(27) NOT NULL,
    visible character varying(64) NOT NULL,
    name character varying(254) NOT NULL,
    phone character varying(100) NOT NULL,
    email character varying(254) NOT NULL,
    url character varying(255) NOT NULL,
    net_id integer NOT NULL
);


CREATE TABLE public.peeringdb_network_facility (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    local_asn integer,
    avail_sonet boolean NOT NULL,
    avail_ethernet boolean NOT NULL,
    avail_atm boolean NOT NULL,
    net_id integer NOT NULL,
    fac_id integer NOT NULL
);


CREATE TABLE public.peeringdb_network_ixlan (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    asn integer NOT NULL,
    ipaddr4 character varying(39),
    ipaddr6 character varying(39),
    is_rs_peer boolean NOT NULL,
    notes character varying(255) NOT NULL,
    speed integer NOT NULL,
    net_id integer NOT NULL,
    ixlan_id integer NOT NULL
);


CREATE TABLE public.peeringdb_organization (
    id integer NOT NULL,
    status character varying(255) NOT NULL,
    created timestamp with time zone NOT NULL,
    updated timestamp with time zone NOT NULL,
    version integer NOT NULL,
    address1 character varying(255) NOT NULL,
    address2 character varying(255) NOT NULL,
    city character varying(255) NOT NULL,
    state character varying(255) NOT NULL,
    zipcode character varying(48) NOT NULL,
    country character varying(2) NOT NULL,
    name character varying(255) NOT NULL,
    website character varying(255) NOT NULL,
    notes text NOT NULL
);


CREATE TABLE public.rdns_delegation (
    zone text NOT NULL,
    prefix inet NOT NULL,
    nservers text[] DEFAULT '{}'::text[] NOT NULL,
    ds text[] DEFAULT '{}'::text[] NOT NULL,
    cname_target text,
    source text NOT NULL,
    source_url text NOT NULL,
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone,
    org text,
    admin_c text[] DEFAULT '{}'::text[] NOT NULL,
    tech_c text[] DEFAULT '{}'::text[] NOT NULL,
    mnt_by text[] DEFAULT '{}'::text[] NOT NULL,
    delegated_rir text
);


COMMENT ON TABLE public.rdns_delegation IS 'Reverse-DNS delegations from RIR zone files. source is the RIR, the same /8 may appear at more than one RIR (ERX).';


COMMENT ON COLUMN public.rdns_delegation.zone IS 'Absolute reverse name (trailing dot), e.g. 0.0.193.in-addr.arpa.';


COMMENT ON COLUMN public.rdns_delegation.prefix IS 'Address prefix implied by zone (193.in-addr.arpa → 193.0.0.0/8, nibble ip6.arpa → IPv6).';


COMMENT ON COLUMN public.rdns_delegation.org IS 'WHOIS domain:/inetnum org. Enriched onto the matching (zone, source) row, not a second table.';


COMMENT ON COLUMN public.rdns_delegation.admin_c IS 'WHOIS admin-c handles for the reverse zone.';


COMMENT ON COLUMN public.rdns_delegation.tech_c IS 'WHOIS tech-c handles for the reverse zone.';


COMMENT ON COLUMN public.rdns_delegation.mnt_by IS 'WHOIS mnt-by for the reverse zone.';


COMMENT ON COLUMN public.rdns_delegation.delegated_rir IS 'RIR this IANA parent cut is delegated to (source=IANA). NULL on RIR zone-file rows. Mixed NS: majority RIR, else NULL, status still infers all RIRs from nservers.';


CREATE TABLE public.rdns_ptr (
    ip inet NOT NULL,
    ptr text,
    queried_ns text DEFAULT ''::text NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    rcode text NOT NULL,
    source_prefix inet
);


COMMENT ON TABLE public.rdns_ptr IS 'PTR lookup results at delegated nservers. Unique (ip): one outcome per address, NXDOMAIN/NODATA stored as a row with ptr NULL.';


COMMENT ON COLUMN public.rdns_ptr.ip IS 'Address that was queried (reverse name derived from this IP).';


COMMENT ON COLUMN public.rdns_ptr.ptr IS 'PTR target hostname. NULL when NXDOMAIN, NODATA, or error rcode.';


COMMENT ON COLUMN public.rdns_ptr.queried_ns IS 'Delegated nameserver that produced this outcome (host:port or name).';


COMMENT ON COLUMN public.rdns_ptr.rcode IS 'NOERROR / NXDOMAIN / NODATA / SERVFAIL / TIMEOUT / REFUSED / …';


COMMENT ON COLUMN public.rdns_ptr.source_prefix IS 'Delegated prefix that produced this outcome. Upsert keeps the more-specific observation, a coarser NODATA/NXDOMAIN cannot replace a stored PTR name.';


CREATE TABLE public.rdns_ptr_block (
    prefix inet NOT NULL,
    zone text DEFAULT ''::text NOT NULL,
    nservers text[] DEFAULT '{}'::text[] NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    locked_at timestamp with time zone,
    locked_by text DEFAULT ''::text NOT NULL,
    seeded_at timestamp with time zone DEFAULT now() NOT NULL,
    done_at timestamp with time zone
);


COMMENT ON TABLE public.rdns_ptr_block IS 'PTR crawl queue: one expandable prefix per row (IPv4 /24–/32, IPv6 /120+). pending → leased → done|failed, SKIP LOCKED resume. failed is re-queued on next seed.';


COMMENT ON COLUMN public.rdns_ptr_block.prefix IS 'Delegated block to walk (unique). Not a leftover /8 or IPv6 /32.';


COMMENT ON COLUMN public.rdns_ptr_block.state IS 'pending, leased, done, or failed. done = flushed walk that was not all TIMEOUT/SERVFAIL/ERROR (RFC 8020 NXDOMAIN skip is done). failed = retry on next seed.';


CREATE TABLE public.remote_files_metadata (
    internal_id integer NOT NULL,
    url text NOT NULL,
    etag text,
    last_modified timestamp with time zone,
    content_length numeric,
    meta_added_at timestamp with time zone,
    charset text,
    content_type text
);


CREATE SEQUENCE public.remote_files_metadata_internal_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.remote_files_metadata_internal_id_seq OWNED BY public.remote_files_metadata.internal_id;


CREATE TABLE public.vrp (
    prefix inet NOT NULL,
    max_length integer NOT NULL,
    origin_asn bigint NOT NULL,
    ta text NOT NULL,
    uri text,
    not_before timestamp with time zone,
    not_after timestamp with time zone
);


CREATE TABLE public.vrp_ingest (
    fetched_at timestamp with time zone NOT NULL,
    source_url text NOT NULL,
    vrp_count bigint NOT NULL,
    aspa_count bigint NOT NULL
);


CREATE TABLE public.whoisdb_as_block (
    as_block text,
    asn_start bigint NOT NULL,
    asn_end bigint NOT NULL,
    descr text[],
    country_code text,
    org text,
    admin_c text[],
    tech_c text[],
    mnt_by text[],
    mnt_lower text[],
    remarks text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_as_set (
    as_set text NOT NULL,
    descr text[],
    members text[],
    mbrs_by_ref text[],
    org text,
    tech_c text[],
    admin_c text[],
    mnt_by text[],
    mnt_lower text[],
    remarks text[],
    notify text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_autnum (
    aut_num numeric NOT NULL,
    as_name text,
    descr text[],
    country_code text,
    status text,
    member_of text[],
    import_via text[],
    import text[],
    mp_import text[],
    export_via text[],
    export text[],
    mp_export text[],
    default_net text[],
    mp_default text[],
    remarks text[],
    org text,
    sponsoring_org text,
    admin_c text[],
    tech_c text[],
    abuse_c text,
    notify text[],
    mnt_lower text[],
    mnt_routes text[],
    mnt_by text[],
    mnt_irt text[],
    changed text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    city text,
    country text,
    domain text,
    meta_added_at timestamp with time zone DEFAULT now(),
    noc_c text[],
    routing_c text[],
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_inet6num (
    netblock inet,
    inet6num text NOT NULL,
    ip_version numeric GENERATED ALWAYS AS (family(netblock)) STORED,
    start_addr text,
    end_addr text,
    netname text,
    descr text[],
    assignment_size text,
    country_code text,
    geofeed text,
    geoloc text,
    language text[],
    org text,
    admin_c text[],
    tech_c text[],
    abuse_c text,
    status text,
    remarks text[],
    notify text[],
    mnt_by text[],
    mnt_lower text[],
    mnt_routes text[],
    mnt_domains text[],
    mnt_irt text[],
    changed text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    city text,
    country text,
    domain text,
    geoloc_lat double precision,
    geoloc_lon double precision,
    meta_added_at timestamp with time zone DEFAULT now(),
    type text,
    routing_c text[],
    noc_c text[],
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_inetnum (
    netblock inet,
    ip_version numeric GENERATED ALWAYS AS (family(netblock)) STORED,
    start_addr text,
    end_addr text,
    inetnum text NOT NULL,
    netname text,
    descr text[],
    country_code text,
    geofeed text,
    geoloc text,
    language text[],
    org text,
    admin_c text[],
    tech_c text[],
    abuse_c text,
    status text,
    remarks text[],
    notify text[],
    mnt_by text[],
    mnt_lower text[],
    mnt_routes text[],
    mnt_domains text[],
    mnt_irt text[],
    changed text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    city text,
    country text,
    domain text,
    geoloc_lat double precision,
    geoloc_lon double precision,
    meta_added_at timestamp with time zone DEFAULT now(),
    type text,
    routing_c text[],
    noc_c text[],
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_irt (
    irt text NOT NULL,
    address text[],
    email text[],
    abuse_mailbox text[],
    phone text[],
    fax_no text[],
    admin_c text[],
    tech_c text[],
    auth text[],
    mnt_by text[],
    remarks text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_org (
    organization text NOT NULL,
    org_name text,
    descr text[],
    country_code text,
    remarks text[],
    address text[],
    phone text[],
    fax_no text[],
    email text[],
    org text[],
    org_type text,
    admin_c text[],
    tech_c text[],
    ref_nfy text[],
    mnt_ref text[],
    notify text[],
    mnt_by text[],
    last_modified timestamp with time zone,
    created timestamp with time zone,
    source text NOT NULL,
    city text,
    country text,
    domain text,
    meta_added_at timestamp with time zone DEFAULT now(),
    noc_c text[],
    abuse_c text,
    routing_c text[],
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_role (
    nic_hdl text NOT NULL,
    role text,
    address text[],
    country text,
    country_code text,
    phone text[],
    fax_no text[],
    email text[],
    admin_c text[],
    tech_c text[],
    remarks text[],
    notify text[],
    abuse_mailbox text[],
    mnt_by text[],
    last_modified text,
    changed text[],
    created timestamp with time zone,
    source text NOT NULL,
    domain text,
    meta_added_at timestamp with time zone DEFAULT now(),
    rdap_kind text,
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_route (
    route inet NOT NULL,
    descr text[],
    country_code text,
    origin numeric,
    holes text[],
    member_of text[],
    tech_c text[],
    inject text[],
    aggr_mtd text,
    aggr_bndry text,
    export_comps text,
    components text,
    remarks text[],
    notify text[],
    mnt_lower text[],
    mnt_routes text[],
    mnt_by text[],
    last_modified text,
    created text,
    domain text,
    city text,
    country text,
    source text,
    changed text[],
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


CREATE TABLE public.whoisdb_route6 (
    route6 inet NOT NULL,
    descr text[],
    country_code text,
    origin numeric,
    holes text[],
    member_of text[],
    tech_c text[],
    inject text[],
    aggr_mtd text,
    aggr_bndry text,
    export_comps text,
    components text,
    remarks text[],
    notify text[],
    mnt_lower text[],
    mnt_routes text[],
    mnt_by text[],
    last_modified text,
    created text,
    domain text,
    city text,
    country text,
    source text,
    changed text[],
    meta_added_at timestamp with time zone DEFAULT now(),
    last_fetched_at timestamp with time zone,
    last_changed_at timestamp with time zone,
    content_hash text,
    fetch_method text,
    is_partial boolean DEFAULT false,
    last_seen_in_source_at timestamp with time zone
);


ALTER TABLE ONLY public.crawl_target ALTER COLUMN id SET DEFAULT nextval('public.crawl_target_id_seq'::regclass);


ALTER TABLE ONLY public.delegated_stats ALTER COLUMN id SET DEFAULT nextval('public.delegated_stats_id_seq'::regclass);


ALTER TABLE ONLY public.geofeeds ALTER COLUMN internal_id SET DEFAULT nextval('public.geofeeds_internal_id_seq'::regclass);


ALTER TABLE ONLY public.geonames_lookup ALTER COLUMN id SET DEFAULT nextval('public.geonames_lookup_id_seq'::regclass);


ALTER TABLE ONLY public.geonames_postal ALTER COLUMN id SET DEFAULT nextval('public.geonames_postal_id_seq'::regclass);



ALTER TABLE ONLY public.remote_files_metadata ALTER COLUMN internal_id SET DEFAULT nextval('public.remote_files_metadata_internal_id_seq'::regclass);


ALTER TABLE ONLY public.anycast_prefix
    ADD CONSTRAINT anycast_prefix_netblock_key UNIQUE (netblock);


ALTER TABLE ONLY public.aspa
    ADD CONSTRAINT aspa_customer_asn_afi_ta_key UNIQUE (customer_asn, afi, ta);


ALTER TABLE ONLY public.country_code_remap
    ADD CONSTRAINT country_code_remap_pkey PRIMARY KEY (from_code);


ALTER TABLE ONLY public.country_legal_flag
    ADD CONSTRAINT country_legal_flag_iso_flag_admin1_key UNIQUE (iso, flag, admin1_code);


ALTER TABLE ONLY public.crawl_target
    ADD CONSTRAINT crawl_target_kind_key_registry_key UNIQUE (kind, key, registry);


ALTER TABLE ONLY public.crawl_target
    ADD CONSTRAINT crawl_target_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.delegated_stats
    ADD CONSTRAINT delegated_stats_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.fdns_host_ip
    ADD CONSTRAINT fdns_host_ip_pkey PRIMARY KEY (name, ip, source);


ALTER TABLE ONLY public.fdns_host_name
    ADD CONSTRAINT fdns_host_name_pkey PRIMARY KEY (name);


ALTER TABLE ONLY public.fdns_resolve_queue
    ADD CONSTRAINT fdns_resolve_queue_pkey PRIMARY KEY (name);


ALTER TABLE ONLY public.geofeeds
    ADD CONSTRAINT geofeeds_pkey PRIMARY KEY (internal_id);


ALTER TABLE ONLY public.geofeeds
    ADD CONSTRAINT geofeeds_url_key UNIQUE (url);


ALTER TABLE ONLY public.geoip
    ADD CONSTRAINT geoip_netblock_source_url_key UNIQUE (netblock, source_url);


ALTER TABLE ONLY public.geonames_admin1
    ADD CONSTRAINT geonames_admin1_pkey PRIMARY KEY (code);


ALTER TABLE ONLY public.geonames_admin2
    ADD CONSTRAINT geonames_admin2_pkey PRIMARY KEY (code);


ALTER TABLE ONLY public.geonames_altname
    ADD CONSTRAINT geonames_altname_pkey PRIMARY KEY (altname_id);


ALTER TABLE ONLY public.geonames_city
    ADD CONSTRAINT geonames_city_pkey PRIMARY KEY (geonameid);


ALTER TABLE ONLY public.geonames_lookup
    ADD CONSTRAINT geonames_lookup_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.geonames_postal
    ADD CONSTRAINT geonames_postal_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.geonames_timezone
    ADD CONSTRAINT geonames_timezone_pkey PRIMARY KEY (timezone_id);


ALTER TABLE ONLY public.host_ip
    ADD CONSTRAINT host_ip_pkey PRIMARY KEY (name, ip, source);


ALTER TABLE ONLY public.host_name
    ADD CONSTRAINT host_name_pkey PRIMARY KEY (name);


ALTER TABLE ONLY public.peeringdb_facility
    ADD CONSTRAINT peeringdb_facility_name_key UNIQUE (name);


ALTER TABLE ONLY public.peeringdb_facility
    ADD CONSTRAINT peeringdb_facility_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_ix_facility
    ADD CONSTRAINT peeringdb_ix_facility_ix_id_fac_id_key UNIQUE (ix_id, fac_id);


ALTER TABLE ONLY public.peeringdb_ix_facility
    ADD CONSTRAINT peeringdb_ix_facility_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_ix
    ADD CONSTRAINT peeringdb_ix_name_key UNIQUE (name);


ALTER TABLE ONLY public.peeringdb_ix
    ADD CONSTRAINT peeringdb_ix_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_ixlan
    ADD CONSTRAINT peeringdb_ixlan_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_ixlan_prefix
    ADD CONSTRAINT peeringdb_ixlan_prefix_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_ixlan_prefix
    ADD CONSTRAINT peeringdb_ixlan_prefix_prefix_key UNIQUE (prefix);


ALTER TABLE ONLY public.peeringdb_network
    ADD CONSTRAINT peeringdb_network_asn_key UNIQUE (asn);


ALTER TABLE ONLY public.peeringdb_network_contact
    ADD CONSTRAINT peeringdb_network_contact_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_network_facility
    ADD CONSTRAINT peeringdb_network_facility_net_id_fac_id_local_asn_key UNIQUE (net_id, fac_id, local_asn);


ALTER TABLE ONLY public.peeringdb_network_facility
    ADD CONSTRAINT peeringdb_network_facility_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_network_ixlan
    ADD CONSTRAINT peeringdb_network_ixlan_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_network
    ADD CONSTRAINT peeringdb_network_name_key UNIQUE (name);


ALTER TABLE ONLY public.peeringdb_network
    ADD CONSTRAINT peeringdb_network_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.peeringdb_organization
    ADD CONSTRAINT peeringdb_organization_name_key UNIQUE (name);


ALTER TABLE ONLY public.peeringdb_organization
    ADD CONSTRAINT peeringdb_organization_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.rdns_delegation
    ADD CONSTRAINT rdns_delegation_zone_source_key UNIQUE (zone, source);


ALTER TABLE ONLY public.rdns_ptr_block
    ADD CONSTRAINT rdns_ptr_block_pkey PRIMARY KEY (prefix);


ALTER TABLE ONLY public.rdns_ptr
    ADD CONSTRAINT rdns_ptr_ip_key UNIQUE (ip);


ALTER TABLE ONLY public.remote_files_metadata
    ADD CONSTRAINT remote_files_metadata_pkey PRIMARY KEY (internal_id);


ALTER TABLE ONLY public.remote_files_metadata
    ADD CONSTRAINT remote_files_metadata_url_key UNIQUE (url);


ALTER TABLE ONLY public.vrp
    ADD CONSTRAINT vrp_prefix_max_length_origin_asn_ta_key UNIQUE (prefix, max_length, origin_asn, ta);


ALTER TABLE ONLY public.whoisdb_as_block
    ADD CONSTRAINT whoisdb_as_block_asn_start_asn_end_source_key UNIQUE (asn_start, asn_end, source);


ALTER TABLE ONLY public.whoisdb_as_set
    ADD CONSTRAINT whoisdb_as_set_as_set_source_key UNIQUE (as_set, source);


ALTER TABLE ONLY public.whoisdb_inet6num
    ADD CONSTRAINT whoisdb_inet6num_netblock_source_uniq UNIQUE (netblock, source);


ALTER TABLE ONLY public.whoisdb_inet6num
    ADD CONSTRAINT whoisdb_inet6num_uniq UNIQUE (netblock, source);


ALTER TABLE ONLY public.whoisdb_inetnum
    ADD CONSTRAINT whoisdb_inetnum_uniq UNIQUE (netblock, source);


ALTER TABLE ONLY public.whoisdb_irt
    ADD CONSTRAINT whoisdb_irt_irt_source_key UNIQUE (irt, source);


ALTER TABLE ONLY public.whoisdb_org
    ADD CONSTRAINT whoisdb_org_organization_source_key UNIQUE (organization, source);


ALTER TABLE ONLY public.whoisdb_role
    ADD CONSTRAINT whoisdb_role_nic_hdl_source_key UNIQUE (nic_hdl, source);


ALTER TABLE ONLY public.whoisdb_route6
    ADD CONSTRAINT whoisdb_route6_uniq UNIQUE (route6, origin, source);


ALTER TABLE ONLY public.whoisdb_route
    ADD CONSTRAINT whoisdb_route_uniq UNIQUE (route, origin, source);


CREATE INDEX anycast_prefix_netblock_gist_idx ON public.anycast_prefix USING gist (netblock inet_ops);


CREATE INDEX anycast_prefix_source_url_idx ON public.anycast_prefix USING btree (source_url);


CREATE INDEX asn_connectivity_asn ON public.asn_connectivity USING btree (asn);


CREATE INDEX aspa_customer_asn_idx ON public.aspa USING btree (customer_asn);


CREATE INDEX crawl_target_due_idx ON public.crawl_target USING btree (priority DESC, last_success_at NULLS FIRST) WHERE (state = ANY (ARRAY['pending'::text, 'failed'::text]));


CREATE INDEX crawl_target_due_kind_reg_idx ON public.crawl_target USING btree (kind, registry, priority DESC, last_success_at NULLS FIRST) WHERE (state = ANY (ARRAY['pending'::text, 'failed'::text]));


CREATE INDEX crawl_target_lease_idx ON public.crawl_target USING btree (kind, locked_at) WHERE (state = 'in_progress'::text);


CREATE INDEX crawl_target_retry_idx ON public.crawl_target USING btree (next_retry_at) WHERE (state = 'failed'::text);


CREATE UNIQUE INDEX delegated_stats_registry_resource_type_range_start_key ON public.delegated_stats USING btree (registry, resource_type, range_start);


CREATE INDEX fdns_host_ip_ip_gist_idx ON public.fdns_host_ip USING gist (ip inet_ops);


CREATE INDEX fdns_host_name_resolve_lease_idx ON public.fdns_host_name USING btree (resolve_locked_at) WHERE (resolve_locked_at IS NOT NULL);


CREATE INDEX fdns_resolve_queue_due_idx ON public.fdns_resolve_queue USING btree (priority DESC, enqueued_at, name) WHERE (locked_at IS NULL);


CREATE INDEX fdns_resolve_queue_lease_idx ON public.fdns_resolve_queue USING btree (locked_at) WHERE (locked_at IS NOT NULL);


CREATE INDEX geofeeds_due_idx ON public.geofeeds USING btree (last_fetched_at NULLS FIRST) WHERE (quarantined_until IS NULL);


CREATE INDEX geofeeds_lease_idx ON public.geofeeds USING btree (locked_at) WHERE (locked_at IS NOT NULL);


CREATE INDEX geoip_netblock_gist_idx ON public.geoip USING gist (netblock inet_ops);


CREATE INDEX geoip_source_url_idx ON public.geoip USING btree (source_url);


CREATE INDEX host_ip_ip_gist_idx ON public.host_ip USING gist (ip inet_ops);


CREATE INDEX idx_country_info_iso ON public.country_info USING btree (iso);


CREATE INDEX idx_country_info_meta_added_at ON public.country_info USING btree (meta_added_at);


CREATE INDEX idx_country_legal_flag_flag ON public.country_legal_flag USING btree (flag);


CREATE INDEX idx_delegated_stats_asn_range ON public.delegated_stats USING btree (asn_start, asn_end) WHERE (resource_type = 'asn'::text);


CREATE INDEX idx_delegated_stats_ip_range ON public.delegated_stats USING btree (ip_start, ip_end) WHERE (resource_type = ANY (ARRAY['ipv4'::text, 'ipv6'::text]));


CREATE INDEX idx_delegated_stats_opaque ON public.delegated_stats USING btree (registry, opaque_id);


CREATE INDEX idx_delegated_stats_type_status ON public.delegated_stats USING btree (resource_type, status);


CREATE INDEX idx_geonames_admin1_cc_code ON public.geonames_admin1 USING btree (country_code, admin1_code);


CREATE INDEX idx_geonames_admin2_cc_codes ON public.geonames_admin2 USING btree (country_code, admin1_code, admin2_code);


CREATE INDEX idx_geonames_altname_geonameid ON public.geonames_altname USING btree (geonameid);


CREATE INDEX idx_geonames_city_cc_norm_admin1 ON public.geonames_city USING btree (country_code, city_norm, admin1_code);


CREATE INDEX idx_geonames_lookup_cc_alias_admin1 ON public.geonames_lookup USING btree (country_code, alias_norm, admin1_iso);


CREATE INDEX idx_geonames_lookup_cc_city_admin1 ON public.geonames_lookup USING btree (country_code, city_norm, admin1_iso);


CREATE INDEX idx_geonames_lookup_cc_zip ON public.geonames_lookup USING btree (country_code, zipcode) WHERE (zipcode IS NOT NULL);


CREATE INDEX idx_geonames_postal_cc_norm_admin1 ON public.geonames_postal USING btree (country_code, city_norm, admin_code_1);


CREATE INDEX idx_geonames_postal_cc_zip ON public.geonames_postal USING btree (country_code, postal_code);


CREATE INDEX idx_inet_prefixes ON public.whoisdb_inetnum USING gist (netblock inet_ops);


CREATE INDEX idx_whoisdb_as_block_meta_added_at ON public.whoisdb_as_block USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_as_set_meta_added_at ON public.whoisdb_as_set USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_autnum_meta_added_at ON public.whoisdb_autnum USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_inet6num_meta_added_at ON public.whoisdb_inet6num USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_inetnum_meta_added_at ON public.whoisdb_inetnum USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_irt_meta_added_at ON public.whoisdb_irt USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_org_meta_added_at ON public.whoisdb_org USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_role_meta_added_at ON public.whoisdb_role USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_route6_meta_added_at ON public.whoisdb_route6 USING btree (meta_added_at);


CREATE INDEX idx_whoisdb_route_meta_added_at ON public.whoisdb_route USING btree (meta_added_at);


CREATE INDEX ix_whoisdb_as_block_range ON public.whoisdb_as_block USING btree (asn_start, asn_end);


CREATE INDEX ix_whoisdb_as_set_as_set ON public.whoisdb_as_set USING btree (as_set);


CREATE INDEX ix_whoisdb_autnum_aut_num ON public.whoisdb_autnum USING btree (aut_num);


CREATE INDEX ix_whoisdb_inetnum_netblock ON public.whoisdb_inet6num USING btree (netblock);


CREATE INDEX ix_whoisdb_irt_irt ON public.whoisdb_irt USING btree (irt);


CREATE INDEX ix_whoisdb_org_organization ON public.whoisdb_org USING btree (organization);


CREATE INDEX ix_whoisdb_role_role ON public.whoisdb_role USING btree (nic_hdl);


CREATE INDEX ix_whoisdb_route6 ON public.whoisdb_route6 USING btree (route6);


CREATE INDEX ix_whoisdb_route_route ON public.whoisdb_route USING btree (route);


CREATE INDEX peeringdb_facility_org_id ON public.peeringdb_facility USING btree (org_id);


CREATE INDEX peeringdb_ix_facility_fac_id ON public.peeringdb_ix_facility USING btree (fac_id);


CREATE INDEX peeringdb_ix_facility_ix_id ON public.peeringdb_ix_facility USING btree (ix_id);


CREATE INDEX peeringdb_ix_org_id ON public.peeringdb_ix USING btree (org_id);


CREATE INDEX peeringdb_ixlan_ix_id ON public.peeringdb_ixlan USING btree (ix_id);


CREATE INDEX peeringdb_ixlan_prefix_ixlan_id ON public.peeringdb_ixlan_prefix USING btree (ixlan_id);


CREATE INDEX peeringdb_network_contact_net_id ON public.peeringdb_network_contact USING btree (net_id);


CREATE INDEX peeringdb_network_facility_fac_id ON public.peeringdb_network_facility USING btree (fac_id);


CREATE INDEX peeringdb_network_facility_net_id ON public.peeringdb_network_facility USING btree (net_id);


CREATE INDEX peeringdb_network_ixlan_ixlan_id ON public.peeringdb_network_ixlan USING btree (ixlan_id);


CREATE INDEX peeringdb_network_ixlan_net_id ON public.peeringdb_network_ixlan USING btree (net_id);


CREATE INDEX peeringdb_network_org_id ON public.peeringdb_network USING btree (org_id);


CREATE INDEX rdns_delegation_prefix_gist_idx ON public.rdns_delegation USING gist (prefix inet_ops);


CREATE INDEX rdns_delegation_ptr_masklen_idx ON public.rdns_delegation USING btree (masklen(prefix)) WHERE ((source <> 'IANA'::text) AND (cardinality(COALESCE(nservers, '{}'::text[])) > 0));


CREATE INDEX rdns_delegation_source_idx ON public.rdns_delegation USING btree (source);


CREATE INDEX rdns_delegation_source_url_idx ON public.rdns_delegation USING btree (source_url);


CREATE INDEX rdns_ptr_block_claim_idx ON public.rdns_ptr_block USING btree (state, locked_at) WHERE (state = ANY (ARRAY['pending'::text, 'leased'::text]));


CREATE INDEX rdns_ptr_fetched_at_idx ON public.rdns_ptr USING btree (fetched_at);


CREATE INDEX rdns_ptr_ip_gist_idx ON public.rdns_ptr USING gist (ip inet_ops);


CREATE INDEX vrp_prefix_gist_idx ON public.vrp USING gist (prefix inet_ops);


CREATE UNIQUE INDEX whoisdb_autnum_aut_num_idx ON public.whoisdb_autnum USING btree (aut_num);


CREATE INDEX whoisdb_inet6num_gist_idx ON public.whoisdb_inet6num USING gist (netblock inet_ops);


CREATE INDEX whoisdb_inet6num_host_idx ON public.whoisdb_inet6num USING btree (host(netblock));


CREATE INDEX whoisdb_inet6num_masklen_idx ON public.whoisdb_inet6num USING btree (masklen(netblock));


CREATE INDEX whoisdb_inet6num_masklen_idx1 ON public.whoisdb_inet6num USING btree (masklen(netblock) DESC);


CREATE INDEX whoisdb_inetnum_host_idx ON public.whoisdb_inetnum USING btree (host(netblock));


CREATE INDEX whoisdb_inetnum_masklen_idx ON public.whoisdb_inetnum USING btree (masklen(netblock));


CREATE INDEX whoisdb_inetnum_netblock_gist_idx ON public.whoisdb_inetnum USING gist (netblock inet_ops);


CREATE INDEX whoisdb_inetnum_netblock_idx ON public.whoisdb_inetnum USING btree (netblock);


CREATE INDEX whoisdb_inetnum_netblock_idx1 ON public.whoisdb_inetnum USING spgist (netblock);


CREATE INDEX whoisdb_route_route_idx ON public.whoisdb_route USING gist (route inet_ops);


ALTER TABLE ONLY public.fdns_host_ip
    ADD CONSTRAINT fdns_host_ip_name_fkey FOREIGN KEY (name) REFERENCES public.fdns_host_name(name) ON DELETE CASCADE;


ALTER TABLE ONLY public.fdns_resolve_queue
    ADD CONSTRAINT fdns_resolve_queue_name_fkey FOREIGN KEY (name) REFERENCES public.fdns_host_name(name) ON DELETE CASCADE;


ALTER TABLE ONLY public.host_ip
    ADD CONSTRAINT host_ip_name_fkey FOREIGN KEY (name) REFERENCES public.host_name(name) ON DELETE CASCADE;


