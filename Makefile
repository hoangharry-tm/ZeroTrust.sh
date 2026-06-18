BINARY        := zerotrust
BUILD_DIR     := build
MODULE        := github.com/hoangharry-tm/zerotrust
GOTESTSUM     := $(shell go env GOPATH)/bin/gotestsum

# Joern version pin — update here when upgrading Joern.
# The integration tests use JOERN_BIN (env) or the resolved binary below.
JOERN_VERSION := v4.0.559
JOERN_BIN     := $(shell command -v joern-server 2>/dev/null || echo "$(HOME)/bin/joern/joern-server")

.PHONY: build test test-rules test-integration joern-check lint worker-install demo clean

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust

test:
	$(GOTESTSUM) --format testdox --format-icons codicons --format-hide-empty-pkg -- ./...

test-rules:
	@echo "Running OpenGrep rule tests..."
	@./scripts/test_rules.sh

# Run integration tests — requires a live Joern binary.
# Set JOERN_BIN to override the resolved joern-server path.
test-integration:
	JOERN_BIN=$(JOERN_BIN) go test -v -race -timeout 10m -tags integration \
		./internal/pattern/joern/...

# Verify Joern installation and print version.
joern-check:
	@echo "Joern binary: $(JOERN_BIN)"
	@$(JOERN_BIN) --version 2>/dev/null || echo "ERROR: joern-server not found at $(JOERN_BIN)"
	@echo "Joern pinned version: $(JOERN_VERSION)"

lint:
	golangci-lint run ./...

worker-install:
	pip install -e "worker/[dev]"

demo:
	@./scripts/run_demo.sh

clean:
	rm -rf $(BUILD_DIR)
