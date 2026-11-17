![CI](https://github.com/oprand/opr/actions/workflows/test.yml/badge.svg) ![Go Reference](https://pkg.go.dev/badge/github.com/oprand/opr.svg) ![License](https://img.shields.io/github/license/oprand/opr)

# `opr`: Internet Network Data Aggregator

`opr` fetches, augments and stores continuously updated network data from various sources.

Network data about these entities: Autonomous System Number (ASN), IP address, IP address prefix, domain name, DNS records, RPKI and Internet Exchange Points (IXP).

Its purpose is to provide data for a comprehensive and up-to-date view of the Internet plumbing, which is essential for network security, routing, and troubleshooting.

It can run as a daemon, or as a one-shot command, for a subset of the ingests or all of them.

The whole system can be setup using the Makefile at the root of the repository, dependencies are managed using docker compose.

## Commands

- `registry-crawl`
  - Purpose: Builds the ASN (Autonomous System Number) and IP-prefix registry — who is allocated which AS numbers and address blocks. Combines NRO delegated stats, RIR/NIR whois dumps, an RDAP (Registration Data Access Protocol) crawl, and RIPE ASN names.
  - Sources: Regional Internet Registries (RIRs: ARIN, RIPE NCC, APNIC, AFRINIC, LACNIC), National Internet Registries (NIRs: JPNIC, KRNIC, TWNIC, …), RouteViews RIBs, RIPE asnames
  - Store: Postgres
- `peeringdb`
  - Purpose: Loads networks, IXPs (Internet Exchange Points), facilities, and which networks peer where.
  - Sources: PeeringDB (`public.peeringdb.com`)
  - Store: Postgres
- `aspop`
  - Purpose: Estimates how many users sit behind each ASN, broken down by country.
  - Sources: APNIC Labs (`stats.labs.apnic.net`)
  - Store: Postgres
- `geonames`
  - Purpose: Loads places, cities, postal codes, and country metadata used later for geographic lookups.
  - Sources: GeoNames (`download.geonames.org`)
  - Store: Postgres
- `geoip`
  - Purpose: Maps IP prefixes to locations (where addresses are used), from operator geofeeds, RIR dumps, and anycast data.
  - Sources: Operator geofeeds (RFC 8805/9632), LACNIC CSV, RIPE IPmap, BGPTools anycast
  - Store: Postgres
- `rpki`
  - Purpose: Loads ROAs (Route Origin Authorizations) and ASPA (Autonomous System Provider Authorization) — RPKI objects that constrain which ASN may announce a given prefix.
  - Sources: Local Routinator (`/jsonext`; pulls from RIR RPKI trust anchors)
  - Store: Postgres
- `rdns`
  - Purpose: Ingests reverse-DNS zone delegations (`in-addr.arpa` / `ip6.arpa`) and looks up PTR (pointer) records at those nameservers.
  - Sources: RIR zone files, InterNIC, RIR whois domain objects
  - Store: Postgres
- `fdns`
  - Purpose: Collects popular hostnames and their A/AAAA answers from top lists plus Common Crawl, then resolves them over DNS.
  - Sources: Tranco, Cisco Umbrella, Chrome CrUX, Common Crawl Host Index
  - Store: Postgres (+ ClickHouse for Common Crawl ingest / seed)
- `run`
  - Purpose: Daemon that runs every ingest enabled in `opr.config.toml` (default: all) until stopped.
  - Sources: Same as the jobs above
  - Store: Postgres (+ ClickHouse when FDNS Common Crawl jobs are on)
- `postgres`
  - Purpose: Applies or reports the Postgres schema only; does not fetch network data.
  - Sources: —
  - Store: Postgres
- `clickhouse`
  - Purpose: Applies or reports the ClickHouse schema only; does not fetch network data.
  - Sources: —
  - Store: ClickHouse

Run `opr help` to see the help text for each command and `opr <command> --help` to see the help text for each command.

## Build

From this directory:

```sh
make build
```

That writes `bin/opr`. `make` with no target prints the Makefile help. `make test` runs `go test ./...`.

`Dockerfile` builds only the CLI (Alpine image, entrypoint `/app/opr`). It does not start Postgres, ClickHouse, Unbound, or Routinator. Pass `--dsn` and the subcommand at `docker run` time.

### Scale out with different configs

Several `opr run --config …` processes can share the same `OPR_DSN`. Each TOML turns jobs on/off with `enabled` (default true). Copy [opr.example.toml](opr.example.toml) and disable what that host should not run. Section names match CLI syntax (`[command]` or `[command.subcommand]`).

**Bulk/periodic jobs** (registry-crawl.bulk, registry-crawl.seed, geoip.*, peeringdb, aspop, geonames, rpki.ingest, fdns.ingest-lists / ingest-cc / seed-queue, rdns.ingest): one host only each — two owners duplicate downloads/writes.

**Queue jobs** (registry-crawl.worker, fdns.resolve, rdns.crawl-ptr, geoip.crawl-geofeeds): safe on multiple hosts (leases / `SKIP LOCKED`).

Side deps only where needed (ClickHouse for cc/seed-queue, Routinator for rpki, Unbound for resolve). This is role split, not ASN-range sharding; `only-registries` can further narrow registry-crawl worker/seed.

Registry bulk host (bulk + seed; disable the rest):

```toml
[registry-crawl.bulk]
enabled = true

[registry-crawl.seed]
enabled = true

[registry-crawl.worker]
enabled = false
# … disable geoip.*, peeringdb, aspop, geonames, rpki.ingest, fdns.*, rdns.*
```

RDAP worker host (bulk off; a second host can reuse the same file to scale the queue):

```toml
[registry-crawl.worker]
enabled = true
# ipnet = true  # if desired

[registry-crawl.bulk]
enabled = false

[registry-crawl.seed]
enabled = false
# … disable the other bulk jobs
```

```sh
opr run --config /etc/opr/whois.toml
opr run --config /etc/opr/rdap.toml
```

## Runtime Local dependencies

| Service | Required for | How to run it |
| --- | --- | --- |
| Postgres | Every command except `clickhouse`, `fdns ingest-cc`, and help | `make localdb`, `make stoplocaldb`, `make resetlocaldb`. See [store/README.md](store/README.md). |
| ClickHouse | `clickhouse`, `fdns ingest-cc`, `fdns seed-queue` | `make localdb`, `make stoplocaldb`, `make resetlocaldb`. See [store/README.md](store/README.md). |
| Routinator | `rpki ingest` | `make localroutinator`, `make stoproutinator`, `make resetroutinator`. See [store/README.md](store/README.md). |
| Unbound | Optional, preferred for `fdns resolve` | `make localunbound`, `make stopunbound`, `make resetunbound`. See [store/README.md](store/README.md). |

`make localdb` starts only Postgres and ClickHouse. Unbound (profile `dns`) and Routinator (profile `rpki`) stay stopped until their own targets. All four services are in `docker-compose.yml`.

## Security

Commits are signed and show as verified on GitHub. Release binaries are built with GoReleaser for deterministic, reproducible builds, published with SHA-256 checksums, and signed with the project release key. There is no auto-update mechanism.

Dependencies go through normal Go module hygiene (`go.sum` and CI). Secrets stay in the environment (`OPR_DSN`, `OPR_CLICKHOUSE_PASSWORD`, `OPR_PEERINGDB_APIKEY`), not in TOML.

opr contacts the public data sources you configure (RIR FTPs, RDAP, PeeringDB, Common Crawl, DNS) and any local Postgres, ClickHouse, Unbound, or Routinator you point it at. It has no telemetry or analytics remote reporting.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

### Verify a release

The release key is published at https://oprand.com/keys/release-key.pub. Import it, then check the checksum signature and hashes from a GitHub Release:

```sh
curl -O https://oprand.com/keys/release-key.pub
gpg --import release-key.pub
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check checksums.txt
```

## License

This repository work is licensed under the [Apache License 2.0](LICENSE). The vendored tree under `pkg/openrdap` remains MIT (see `pkg/openrdap/rdap/LICENSE`). Attribution is in [NOTICE](NOTICE).
