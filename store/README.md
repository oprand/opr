# store

`postgres` and `clickhouse` are sibling engines. This directory is not a Go package. Import one engine or the other.

Current aggregators use Postgres (`store/postgres`). Future aggregators should import `store/clickhouse` only. This extract does not port existing aggregators off Postgres.

Postgres ships a single `0001_initial` baseline. `RunMigrations` applies it and records the version in `opr_migrations` (`x-migrations-table` on the DSN; callers do not set that parameter). ClickHouse ships a single `0001_initial` baseline and keeps its own `schema_migrations` table.

`0001_initial` is schema only. A fresh database gets `country_code_remap` rows only after `opr geonames`. The insert waits until the target ISO exists in `country_info`. The map is UK→GB, EL→GR, CV→PT, FX→FR, TP→TL, ZR→CD, DD→DE, BU→MM.

`country_legal_flag` rows are not in the migration. Apply them with `opr geonames flags --apply`, which runs `store/postgres/seed/country_legal_flag.sql`. That apply is idempotent.

## Local services

Postgres, ClickHouse, Unbound, and Routinator all run from the repo-root `docker-compose.yml`. Postgres and ClickHouse have no profile. Unbound is profile `dns`. Routinator is profile `rpki`. `docker compose up -d` and `make startdb` start only the two databases.

`restart: unless-stopped` brings a container back when Docker itself starts. That applies to a database, Unbound, or Routinator only after that service has been started once.

Data lives in Docker named volumes, not in the git repo. `docker volume ls` shows each volume with the compose project name as a prefix. A checkout named `opr` yields `opr_opr_postgres`, `opr_opr_clickhouse`, `opr_unbound-cache`, and `opr_rpki-cache`.

Do not reset with a bare `docker compose down -v`. That flag deletes every named volume in this file, including `unbound-cache` and `rpki-cache`. Each reset target below removes one set of volumes by name.

The compose file uses named volumes rather than a folder on the host. Database writes are many small fsyncs, and Docker Desktop's Mac file share is slow for that. The Postgres image also initializes its data directory as user `postgres`; a folder created on the Mac is owned by the host user, so the container often fails until that directory is chowned. A named volume is created empty inside the VM and the image owns it.

### Postgres and ClickHouse

Start both databases. Volumes are created on first start and kept after that:

```sh
make startdb
```

`docker compose up -d` from the repo root does the same thing. It does not start Unbound or Routinator. Data is kept across later starts, stops, and reboots.

Stop them. Volumes and data are kept. A running Unbound or Routinator is left alone:

```sh
make stopdb
```

That runs `docker compose stop postgres clickhouse`. A bare `docker compose stop` would also stop profile services that are already running. Do not use that when you only want the databases down.

`docker compose rm -f postgres clickhouse` (after a stop) removes those containers and keeps the volumes. The next `up -d` creates new containers on the same volumes.

Reset, which deletes the database files and nothing else:

```sh
make resetdb
```

That removes the Postgres and ClickHouse containers and deletes only the named volumes `opr_postgres` and `opr_clickhouse`. `unbound-cache` and `rpki-cache` are kept. The next database start is empty. Run the migrations again:

```sh
opr --postgres-db 'postgresql://opr:opr@127.0.0.1:5432/opr?sslmode=disable' postgres migrate
opr clickhouse migrate --clickhouse-password opr
```

Inside the Postgres container the files are at `/var/lib/postgresql/data`. Inside the ClickHouse container they are at `/var/lib/clickhouse`. On a Mac those files are on the Docker Desktop VM disk.

ClickHouse has `mem_limit: 16g` and `mem_reservation: 8g`. The 16g value is a ceiling on the container, not a reservation of the whole VM. `mem_reservation` is a soft 8g hint. Postgres has no memory limit. Docker Desktop's VM memory must be larger than 16GB. If it is not, Docker OOM-kills ClickHouse during `fdns ingest-cc`.

If a Postgres server is already listening on `127.0.0.1:5432`, this container cannot publish that port until that server is stopped.

