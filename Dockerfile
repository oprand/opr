# opr network data aggregator CLI.
#
# This image has no default Postgres DSN, no config file, and no API keys.
# One-shots take --postgres-db (or OPR_POSTGRES_DB). The daemon takes only --config and
# reads OPR_POSTGRES_DB, OPR_CLICKHOUSE_PASSWORD, OPR_PEERINGDB_APIKEY from the
# environment.
#
#   docker build -t opr .
#   docker run --rm opr --postgres-db "$DSN" --log-level=INFO aspop
#   docker run --rm -e OPR_POSTGRES_DB="$DSN" -e OPR_PEERINGDB_APIKEY="$KEY" \
#     -v ./opr.config.toml:/etc/opr/opr.config.toml:ro \
#     opr --log-console run --config /etc/opr/opr.config.toml
#
# ClickHouse commands take their own connection flags. See: opr clickhouse --help
#
# GoReleaser publishes the same Alpine runtime via --target=goreleaser,
# copying a pre-built multi-arch binary (no secrets, entrypoint /app/opr).

FROM golang:1.24.6-alpine AS build

RUN apk add --no-cache ca-certificates git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG GIT_COMMIT=dev
ARG GIT_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
	-ldflags="-buildid= -X github.com/oprand/opr/internal/version.GitCommitHash=${GIT_COMMIT} -X github.com/oprand/opr/internal/version.Version=${GIT_VERSION}" \
	-o /app/opr ./cmd/opr

FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates

COPY --from=build /app/opr /app/opr

ENTRYPOINT ["/app/opr"]

# Pre-built binary from GoReleaser dockers_v2 (context has $TARGETPLATFORM/opr).
FROM alpine:3.20 AS goreleaser

RUN apk add --no-cache ca-certificates

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/opr /app/opr

ENTRYPOINT ["/app/opr"]

# Default target for local `docker build`.
FROM runtime
