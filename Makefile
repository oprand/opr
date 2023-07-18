.DEFAULT_GOAL := help

GITHASH := $(shell git rev-parse HEAD)
VERSION := $(shell git describe --tags | tr -d 'v')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(GITHASH)

.PHONY: help build install


help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[;1;m%-10s\033[0m %s\n", $$1, $$2}'


build: ## Build `opr` binary for local env (os/arch)
	CGO_ENABLED=0 go build -o ./bin/opr -ldflags "$(LDFLAGS)" ./cmd/opr/main.go


install: ## Install `opr` binary under `/usr/local/bin/`
	cp ./bin/opr /usr/local/bin/
