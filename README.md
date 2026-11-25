![CI](https://github.com/oprand/opr/actions/workflows/test.yml/badge.svg) ![Go Reference](https://pkg.go.dev/badge/github.com/oprand/opr.svg) ![License](https://img.shields.io/github/license/oprand/opr)

# `opr`: Internet Network Data Aggregator

`opr` fetches, enriches and stores continuously updated network data from various sources.

Network data about these entities: Autonomous System Number (ASN), IP address, IP address prefix, domain name, DNS records, RPKI and Internet Exchange Points (IXP).

Its purpose is to provide data for a comprehensive and up-to-date view of the Internet plumbing, which is essential for network security, routing, and troubleshooting.

It can run as a daemon, or as a one-shot command, for a subset of the ingests or all of them.

The whole system can be setup using the Makefile at the root of the repository, dependencies are managed using docker compose.


## Getting Started

### 1. Install the `opr` command

#### Install it as a Go binary:
```sh
go install github.com/oprand/opr/cmd/opr@latest
```
That writes `opr` to `$(go env GOPATH)/bin`. That directory has to be on your `PATH`.

#### Or build it from source:

```sh
git clone https://github.com/oprand/opr.git && \
cd opr && \
make build
```

That writes `./bin/opr`.

#### Or use the Dockerfile:

```sh
docker build -t opr .
```

That builds the `opr` image (Alpine image, entrypoint `/app/opr`). It does not start Postgres, ClickHouse, Unbound, or Routinator. Pass `--postgres-db` and the subcommand at `docker run` time.


### 2. Start PostgreSQL and ClickHouse
```sh
make startdb 
```
That starts PostgreSQL and ClickHouse with the provided [docker compose configuration](docker-compose.yml).
ClickHouse is optional, but recommended for the `fdns` command.

### 3. Run the `opr` command

The default Postgres connection string is the local compose database:

`postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable`

One-shot commands use it when `--postgres-db` is omitted. `opr run` uses it when `OPR_POSTGRES_DB` is unset. Pass `--postgres-db` or export `OPR_POSTGRES_DB` to use another database. `opr run` does not accept `--postgres-db`.

#### Get ASN population data
```sh
opr --postgres-db postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable aspop
```

#### Get PeeringDB data
```sh
opr --postgres-db postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable peeringdb
```

#### Get RPKI data
Use `make startroutinator` to start the Routinator dependency, then:
```sh
opr --postgres-db postgres://opr:opr@127.0.0.1:5432/opr?sslmode=disable rpki ingest 
```

#### Run multiple commands at once with the daemon mode

```sh
opr run --config config/opr.example.toml
```

The full [opr.example.toml](config/opr.example.toml) enables every ingest, turn off the ones you don't need.

3 other example configs are:
- [config/geoip-geonames.toml](config/geoip-geonames.toml) enables geoip and geonames.
- [config/registry-crawl.toml](config/registry-crawl.toml) enables registry-crawl seed and bulk, with the worker (rdap crawler for ARIN and LACNIC) off.
- [config/aspop-peeringdb.toml](config/aspop-peeringdb.toml) enables aspop and peeringdb.


### Scale out with different configs

Several `opr run --config …` processes can share the same `OPR_POSTGRES_DB`. Each TOML turns jobs on/off with `enabled` (default true). Start from a sample: [config/aspop-peeringdb.toml](config/aspop-peeringdb.toml), [config/geoip-geonames.toml](config/geoip-geonames.toml), or [config/registry-crawl.toml](config/registry-crawl.toml). Section names match CLI syntax (`[command]` or `[command.subcommand]`).

**Bulk/periodic jobs** (registry-crawl.bulk, registry-crawl.seed, geoip.*, peeringdb, aspop, geonames, rpki.ingest, fdns.ingest-lists / ingest-cc / seed-queue, rdns.ingest): one host only each — two owners duplicate downloads/writes.

**Queue jobs** (registry-crawl.worker, fdns.resolve, rdns.crawl-ptr, geoip.crawl-geofeeds): safe on multiple hosts (leases / `SKIP LOCKED`).

Side deps only where needed (ClickHouse for cc/seed-queue, Routinator for rpki, Unbound for resolve). This is role split, not ASN-range sharding; `only-registries` can further narrow registry-crawl worker/seed.

Registry bulk host (bulk + seed, worker off — [config/registry-crawl.toml](config/registry-crawl.toml); disable the rest):

```toml
[registry-crawl.bulk]
enabled = true

[registry-crawl.seed]
enabled = true

[registry-crawl.worker]
enabled = false
# … disable geoip.*, peeringdb, aspop, geonames, rpki.ingest, fdns.*, rdns.*
```

RDAP worker host (same file with `[registry-crawl.worker]` `enabled = true`; bulk off; a second host can reuse that file to scale the queue):

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
# worker off
opr run --config config/registry-crawl.toml

# [registry-crawl.worker] enabled = true
opr run --config config/registry-crawl.toml
```

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

Run `bin/opr help` for the command list and `bin/opr <command> --help` for one command.

## Runtime Local dependencies

| Service | Required for | How to run it |
| --- | --- | --- |
| Postgres | Every command except `clickhouse`, `fdns ingest-cc`, and help | `make startdb`, `make stopdb`, `make resetdb`. See [store/README.md](store/README.md). |
| ClickHouse | `clickhouse`, `fdns ingest-cc`, `fdns seed-queue` | `make startdb`, `make stopdb`, `make resetdb`. See [store/README.md](store/README.md). |
| Routinator | `rpki ingest` | `make startroutinator`, `make stoproutinator`, `make resetroutinator`. See [store/README.md](store/README.md). |
| Unbound | Optional, preferred for `fdns resolve` | `make startunbound`, `make stopunbound`, `make resetunbound`. See [store/README.md](store/README.md). |

`make startdb` starts only Postgres and ClickHouse. Unbound (profile `dns`) and Routinator (profile `rpki`) stay stopped until their own targets. All four services are in `docker-compose.yml`.

## Security

Commits are signed and show as verified on GitHub. Release binaries are built with GoReleaser for deterministic, reproducible builds, published with SHA-256 checksums, and signed with the project release key. There is no auto-update mechanism.

Dependencies go through normal Go module hygiene (`go.sum` and CI). Secrets stay in the environment (`OPR_POSTGRES_DB`, `OPR_CLICKHOUSE_PASSWORD`, `OPR_PEERINGDB_APIKEY`), not in TOML.

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
