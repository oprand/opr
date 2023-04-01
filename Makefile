.DEFAULT_GOAL := help

GITHASH := $(shell git rev-parse HEAD)
LDFLAGS := -X main.GitCommitHash=$(GITHASH)

.PHONY: help build


help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[;1;m%-10s\033[0m %s\n", $$1, $$2}'


build: ## Build `opr` binary for local env (os/arch)
	go build -o ./bin/opr -ldflags "$(LDFLAGS)" ./cmd/opr/...


install: ## Install `opr` binary under `/usr/local/bin/`
	cp ./bin/opr /usr/local/bin/
