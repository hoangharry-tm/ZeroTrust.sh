BINARY        := zerotrust
BUILD_DIR     := build
MODULE        := github.com/hoangharry-tm/zerotrust
GOTESTSUM     := $(shell go env GOPATH)/bin/gotestsum
# Engine image registry — override for local dev forks
DOCKER_REGISTRY := ghcr.io/hoangharry-tm
DOCKER_TAG      := latest

# Joern version pin — update here when upgrading Joern.
# The integration tests use JOERN_BIN (env) or the resolved binary below.
JOERN_VERSION := v4.0.550
# Homebrew installs as "joern" (uses --server flag mode, not a separate joern-server binary).
JOERN_BIN     := $(shell command -v joern 2>/dev/null || echo "$(HOME)/bin/joern/joern")

.PHONY: build test test-rules test-integration joern-check lint worker-install demo clean docker-build docker-push

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust

test:
	$(GOTESTSUM) --format testdox --format-icons codicons --format-hide-empty-pkg -- ./...

test-rules:
	@echo "Running OpenGrep rule tests..."
	@./scripts/test_rules.sh

# Run integration tests — requires a live Joern binary (Homebrew: brew install joern).
# Set JOERN_BIN to override the resolved joern path.
test-integration:
	JOERN_BIN=$(JOERN_BIN) go test -v -race -timeout 10m -tags integration \
		./internal/pattern/joern/...

# Verify Joern installation and print version.
joern-check:
	@echo "Joern binary: $(JOERN_BIN)"
	@$(JOERN_BIN) --help 2>&1 | grep -i "REST server" || echo "ERROR: joern not found at $(JOERN_BIN)"
	@echo "Joern pinned version: $(JOERN_VERSION)"

lint:
	golangci-lint run ./...

worker-install:
	pip install -e "worker/[dev]"

demo:
	@./scripts/run_demo.sh

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
