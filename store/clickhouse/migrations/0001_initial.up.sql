-- Common Crawl Host Index: host_name is un-SURTed at insert. The 42 physical
-- Parquet columns are copied verbatim. crawl is not in the file (it is a hive
-- path segment) and the loader injects it from the manifest id. Counters are
-- non-Nullable, so a NULL in Parquet lands as 0 (input_format_null_as_default).
-- ORDER BY (url_host_tld, host_name) gives TLD pruning for the seed filters
-- and a cursor key the seeder can page on.
CREATE TABLE IF NOT EXISTS fdns_cc_host
(
    host_name                   String CODEC(ZSTD(3)),
    surt_host_name              String CODEC(ZSTD(3)),
    crawl                       LowCardinality(String),
    url_host_tld                LowCardinality(String),
    url_host_registered_domain  String CODEC(ZSTD(3)),
    fetch_200                   Int64 CODEC(T64, ZSTD(1)),
    fetch_200_lote              Int64 CODEC(T64, ZSTD(1)),
    fetch_200_lote_pct          Int8,
    fetch_3xx                   Int64 CODEC(T64, ZSTD(1)),
    fetch_4xx                   Int64 CODEC(T64, ZSTD(1)),
    fetch_5xx                   Int64 CODEC(T64, ZSTD(1)),
    fetch_gone                  Int64 CODEC(T64, ZSTD(1)),
    `fetch_notModified`         Int64 CODEC(T64, ZSTD(1)),
    fetch_other                 Int64 CODEC(T64, ZSTD(1)),
    `fetch_redirPerm`           Int64 CODEC(T64, ZSTD(1)),
    `fetch_redirTemp`           Int64 CODEC(T64, ZSTD(1)),
    nutch_fetched               Int64 CODEC(T64, ZSTD(1)),
    nutch_fetched_pct           Int8,
    nutch_gone                  Int64 CODEC(T64, ZSTD(1)),
    nutch_gone_pct              Int8,
    `nutch_notModified`         Int64 CODEC(T64, ZSTD(1)),
    `nutch_notModified_pct`     Int8,
    `nutch_numRecords`          Int64 CODEC(T64, ZSTD(1)),
    `nutch_redirPerm`           Int64 CODEC(T64, ZSTD(1)),
    `nutch_redirPerm_pct`       Int8,
    `nutch_redirTemp`           Int64 CODEC(T64, ZSTD(1)),
    `nutch_redirTemp_pct`       Int8,
    nutch_unfetched             Int64 CODEC(T64, ZSTD(1)),
    nutch_unfetched_pct         Int8,
    robots_200                  Int64 CODEC(T64, ZSTD(1)),
    robots_3xx                  Int64 CODEC(T64, ZSTD(1)),
    robots_4xx                  Int64 CODEC(T64, ZSTD(1)),
    robots_5xx                  Int64 CODEC(T64, ZSTD(1)),
    robots_gone                 Int64 CODEC(T64, ZSTD(1)),
    `robots_notModified`        Int64 CODEC(T64, ZSTD(1)),
    robots_other                Int64 CODEC(T64, ZSTD(1)),
    `robots_redirPerm`          Int64 CODEC(T64, ZSTD(1)),
    `robots_redirTemp`          Int64 CODEC(T64, ZSTD(1)),
    warc_record_length_av       Int64 CODEC(T64, ZSTD(1)),
    warc_record_length_median   Int64 CODEC(T64, ZSTD(1)),
    hcrank                      Float64,
    hcrank10                    Float64,
    prank                       Float64,
    prank10                     Float64,
    ingested_at                 DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY crawl
ORDER BY (url_host_tld, host_name);

-- Staging twin of fdns_cc_host. ingest-cc fills it part by part and then
-- EXCHANGE TABLES swaps it with the live table, so there is no empty window.
CREATE TABLE IF NOT EXISTS fdns_cc_host_load AS fdns_cc_host;

-- Per-part ledger for an in-flight ingest-cc load: a failed run retries only
-- the parts that did not land. Truncated after the EXCHANGE TABLES swap.
CREATE TABLE IF NOT EXISTS fdns_cc_load_part
(
    crawl     LowCardinality(String),
    path      String,
    rows      UInt64,
    loaded_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (crawl, path);
