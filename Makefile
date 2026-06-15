BINARY    := zerotrust
BUILD_DIR := build
MODULE    := github.com/hoangharry-tm/zerotrust

.PHONY: build test test-rules lint worker-install demo clean

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/zerotrust

test:
	go test ./...

test-rules:
	@echo "Running OpenGrep rule tests..."
	@./scripts/test_rules.sh

lint:
	golangci-lint run ./...

worker-install:
	pip install -e "worker/[dev]"

demo:
	@./scripts/run_demo.sh

clean:
	rm -rf $(BUILD_DIR)
