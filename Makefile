BINARY        := zerotrust
BUILD_DIR     := build
MODULE        := github.com/hoangharry-tm/zerotrust
GO_PKGS       := ./cmd/... ./internal/... ./pkg/...
GOTESTSUM     := $(shell go env GOPATH)/bin/gotestsum
# Engine image registry — override for local dev forks
DOCKER_REGISTRY := ghcr.io/hoangharry-tm
DOCKER_TAG      := latest

# Joern version pin — update here when upgrading Joern.
# The integration test uses JOERN_BIN (env) or the resolved binary below.
JOERN_VERSION := v4.0.550
# Homebrew installs as "joern" (uses --server flag mode, not a separate joern-server binary).
JOERN_BIN     := $(shell command -v joern 2>/dev/null || echo "$(HOME)/bin/joern/joern")

# Scan target directory and Postgres connection for `make scan`.
SCAN_DIR    ?= .
DATABASE_URL ?= postgres://zerotrust:zerotrust@localhost:5432/zerotrust?sslmode=disable

.PHONY: build test test-integration joern-check lint scan scan-clean clean docker-build docker-push

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust

test:
	$(GOTESTSUM) --format testdox --format-icons codicons --format-hide-empty-pkg -- $(GO_PKGS)

# Run integration tests — requires a live Joern binary (Homebrew: brew install joern).
# Set JOERN_BIN to override the resolved joern path. Deliberately narrow: only
# confirms Joern starts and responds to a ping, no real CPG/taint query — see
# CLAUDE.md's "Known gaps" for why (fixture dependency was dropped).
test-integration:
	JOERN_BIN=$(JOERN_BIN) go test -v -race -timeout 10m -tags integration \
		./internal/cpg_engine/...

# Verify Joern installation and print version.
joern-check:
	@echo "Joern binary: $(JOERN_BIN)"
	@$(JOERN_BIN) --help 2>&1 | grep -i "REST server" || echo "ERROR: joern not found at $(JOERN_BIN)"
	@echo "Joern pinned version: $(JOERN_VERSION)"

lint:
	golangci-lint run $(GO_PKGS)

scan-clean:
	@lsof -ti:8080 2>/dev/null | xargs kill -9 2>/dev/null || true

# Run a scan against SCAN_DIR (default: repo root) with sane local defaults.
# Override any flag by appending SCAN_ARGS, e.g.:
#   make scan SCAN_DIR=~/some/project SCAN_ARGS="--patch --verify-poc --poe-artifact ./app.jar"
scan: scan-clean build
	@pgrep -f "ollama serve" > /dev/null || (ollama serve > /dev/null 2>&1 & sleep 3)
	./build/$(BINARY) scan $(SCAN_DIR) --db-url "$(DATABASE_URL)" --verbose $(SCAN_ARGS)

# Bundles Joern/OpenGrep/ast-grep into one deploy image for users who don't
# want to install those on PATH locally — not required for local dev, where
# the Go binary shells out to whatever's on PATH.
docker-build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust
	docker build \
		-f docker/engine/Dockerfile \
		-t $(DOCKER_REGISTRY)/zerotrust-engine:$(DOCKER_TAG) \
		--build-arg ENGINE_BINARY=build/$(BINARY) \
		.

docker-push:
	docker push $(DOCKER_REGISTRY)/zerotrust-engine:$(DOCKER_TAG)

clean:
	rm -rf $(BUILD_DIR)
