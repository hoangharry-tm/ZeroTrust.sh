//go:build integration

// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Integration tests for the Joern client.
//
// These tests require a live Joern server. Run with:
//
//	make test-integration
//
// Prerequisites:
//  1. Joern installed: joern binary in PATH (Homebrew: brew install joern) (see Makefile JOERN_BIN).
//  2. Java 11+ available.
//  3. No other process bound on JOERN_TEST_PORT (default 18080).
//
// The tests spawn joern-server themselves; you do not need to pre-start it.
//
// The CPG-build/taint-analysis integration tests that depended on an external
// Spring Boot fixture codebase (tests/integration/spring-boot-app) were
// removed — that fixture isn't checked into this repo, so those tests always
// silently skipped here. Re-add them if/when a fixture is committed.
package cpg_engine

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

const (
	integrationPort    = 18080
	integrationBin     = "joern"         // Homebrew installs as "joern --server", not "joern-server"
	integrationTimeout = 5 * time.Minute // JVM cold-start can be slow
)

// startIntegrationClient starts a managed Joern client on integrationPort.
// The client is stopped via t.Cleanup.
func startIntegrationClient(t *testing.T) *Client {
	t.Helper()

	bin := os.Getenv("JOERN_BIN")
	if bin == "" {
		bin = integrationBin
	}

	c, err := New(
		WithServerURL("http://127.0.0.1:18080"),
		WithBinaryPath(bin),
		WithPort(integrationPort),
		WithBuildTimeout(integrationTimeout),
		WithQueryTimeout(2*time.Minute),
		WithPingRetries(120), // 60 s total at 500 ms intervals (Joern REPL init takes ~35 s cold)
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := c.Start(ctx); err != nil {
		if errors.Is(err, ErrPortInUse) {
			t.Skipf("port %d already in use — another Joern instance may be running", integrationPort)
		}
		t.Fatalf("Start: %v", err)
	}

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		_ = c.Stop(stopCtx)
	})
	return c
}

// TestIntegration_StartAndPing verifies that joern-server starts, binds to
// 127.0.0.1, and responds to the /ready health check.
func TestIntegration_StartAndPing(t *testing.T) {
	c := startIntegrationClient(t)

	// Joern REPL may still be processing queries after Start() returns;
	// use the same generous timeout as the integration client itself.
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping after Start: %v", err)
	}
}
