.DEFAULT_GOAL := help

.PHONY: build test help startdb stopdb resetdb startunbound stopunbound resetunbound startroutinator stoproutinator resetroutinator

GITHASH := $(shell if [ -d .git ]; then git rev-parse HEAD; else echo dev; fi)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/oprand/opr/internal/version.GitCommitHash=$(GITHASH) -X github.com/oprand/opr/internal/version.Version=$(VERSION)

# Port 53 is usually taken on macOS. Other hosts publish 53.
# Override on the command line: make startunbound UNBOUND_HOST_PORT=53
ifeq ($(shell uname -s),Darwin)
UNBOUND_HOST_PORT ?= 5353
else
UNBOUND_HOST_PORT ?= 53
endif

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build opr binary inside ./bin/
	go build -o bin/opr -ldflags "$(LDFLAGS)" ./cmd/opr

test: ## Run all tests
	go test ./...

startdb: ## Start local Postgres and ClickHouse (docker compose up -d, no profiles; volumes kept)
	docker compose up -d

stopdb: ## Stop local Postgres and ClickHouse only (running Unbound or Routinator is left alone; volumes and data kept)
	docker compose stop postgres clickhouse

resetdb: ## DESTRUCTIVE: remove Postgres and ClickHouse and delete only volumes opr_postgres and opr_clickhouse (database data lost; unbound-cache and rpki-cache are kept)
	docker compose rm -fs postgres clickhouse
	@project=$$(docker compose config --format json | awk -F'"' '/"name"/ { for (i = 1; i <= NF; i++) if ($$i == "name") { print $$(i+2); exit } }'); \
	if [ -z "$$project" ]; then echo "resetdb: could not read compose project name" >&2; exit 1; fi; \
	for key in opr_postgres opr_clickhouse; do \
		vol=$$(docker volume ls -q --filter "label=com.docker.compose.project=$$project" --filter "label=com.docker.compose.volume=$$key"); \
		if [ -n "$$vol" ]; then docker volume rm $$vol; fi; \
	done

startunbound: ## Start local Unbound (profile dns; Darwin publishes 127.0.0.1:5353, otherwise :53; unbound-cache volume kept)
	UNBOUND_HOST_PORT="$(UNBOUND_HOST_PORT)" docker compose --profile dns up -d unbound

stopunbound: ## Stop local Unbound (container stops; unbound-cache volume kept)
	docker compose --profile dns stop unbound

resetunbound: ## DESTRUCTIVE: remove Unbound and delete only the unbound-cache volume (resolver cache wiped; databases and RPKI cache kept)
	docker compose --profile dns rm -fs unbound
	@project=$$(docker compose config --format json | awk -F'"' '/"name"/ { for (i = 1; i <= NF; i++) if ($$i == "name") { print $$(i+2); exit } }'); \
	if [ -z "$$project" ]; then echo "resetunbound: could not read compose project name" >&2; exit 1; fi; \
	vol=$$(docker volume ls -q --filter "label=com.docker.compose.project=$$project" --filter "label=com.docker.compose.volume=unbound-cache"); \
	if [ -n "$$vol" ]; then docker volume rm $$vol; fi

startroutinator: ## Start local Routinator (profile rpki; HTTP 127.0.0.1:8323, RTR 3323; rpki-cache kept; first start downloads several GB)
	docker compose --profile rpki up -d routinator

stoproutinator: ## Stop local Routinator (container stops; rpki-cache volume kept)
	docker compose --profile rpki stop routinator

resetroutinator: ## DESTRUCTIVE: remove Routinator and delete only the rpki-cache volume (RPKI cache wiped; databases and Unbound cache kept)
	docker compose --profile rpki rm -fs routinator
	@project=$$(docker compose config --format json | awk -F'"' '/"name"/ { for (i = 1; i <= NF; i++) if ($$i == "name") { print $$(i+2); exit } }'); \
	if [ -z "$$project" ]; then echo "resetroutinator: could not read compose project name" >&2; exit 1; fi; \
	vol=$$(docker volume ls -q --filter "label=com.docker.compose.project=$$project" --filter "label=com.docker.compose.volume=rpki-cache"); \
	if [ -n "$$vol" ]; then docker volume rm $$vol; fi
