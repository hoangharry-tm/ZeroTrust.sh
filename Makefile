BINARY        := zerotrust
BUILD_DIR     := build
MODULE        := github.com/hoangharry-tm/zerotrust
GO_PKGS       := ./cmd/... ./internal/... ./pkg/...
GOTESTSUM     := $(shell go env GOPATH)/bin/gotestsum
# Engine image registry — override for local dev forks
DOCKER_REGISTRY := ghcr.io/hoangharry-tm
DOCKER_TAG      := latest

# Joern version pin — update here when upgrading Joern.
# The integration tests use JOERN_BIN (env) or the resolved binary below.
JOERN_VERSION := v4.0.550
# Homebrew installs as "joern" (uses --server flag mode, not a separate joern-server binary).
JOERN_BIN     := $(shell command -v joern 2>/dev/null || echo "$(HOME)/bin/joern/joern")

.PHONY: build test test-rules test-integration joern-check lint worker-install format-template demo demo-report demo-report-small demo-report-large clean docker-build docker-push

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust

test:
	$(GOTESTSUM) --format testdox --format-icons codicons --format-hide-empty-pkg -- $(GO_PKGS)

test-rules:
	@echo "Running OpenGrep rule tests..."
	@./scripts/rules/test_rules.sh


scan-webgoat: build
	rm -rf ~/mh_code/webgoat/.zerotrust && rm -f /tmp/zt-scan/scan.log /tmp/zt-scan/report.html && rm -rf ./workspace/
	@pgrep -f "ollama serve" > /dev/null || (ollama serve &> /tmp/zt-scan/ollama.log & sleep 2)
	./build/zerotrust ~/mh_code/webgoat --native --report /tmp/zt-scan/report.html --offline --verbose --joern-bin /opt/homebrew/bin/joern > /tmp/zt-scan/scan.log 2>&1 &

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
	golangci-lint run $(GO_PKGS)

worker-install:
	cd worker && uv sync --extra dev

format-template:
	node scripts/format_template.mjs

demo:
	@./scripts/pipeline/run_demo.sh

demo-report-small:
	go run ./cmd/zerotrust --mock --report $(BUILD_DIR)/report-small.html

demo-report-large:
	go run ./cmd/zerotrust --mock-large --report $(BUILD_DIR)/report-large.html
	cp $(BUILD_DIR)/report-large.html site/public/report.html

demo-report: demo-report-small

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

## Training pipeline
.PHONY: install
install: ## Sync the environment using uv
	@echo "🚀 Syncing environment with uv"
	uv sync

.PHONY: curate
curate: ## Run curation using uv
	uv run python -m worker.training.curate $(CURATE_ARGS)

.PHONY: finetune
finetune: ## Run finetuning using uv
	uv run python pipeline/train/finetune.py $(FINETUNE_ARGS)

.PHONY: train
train: curate finetune

.PHONY: clean
clean: ## Remove the virtual environment and build artifacts
	rm -rf .venv
	rm -rf $(BUILD_DIR)
