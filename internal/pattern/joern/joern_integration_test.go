//go:build integration

// Integration tests for the Joern client.
//
// These tests require a live Joern server and the Spring Boot test codebase.
// Run with:
//
//	make test-integration
//
// Prerequisites:
//  1. Joern installed: joern-server binary in PATH (see Makefile JOERN_BIN).
//  2. Java 11+ available.
//  3. No other process bound on JOERN_TEST_PORT (default 18080).
//
// The tests spawn joern-server themselves; you do not need to pre-start it.
// Each test that needs a CPG calls buildTestCPG as a sub-helper.
package joern

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

const (
	integrationPort    = 18080
	integrationBin     = "joern-server"
	integrationTimeout = 5 * time.Minute // JVM cold-start can be slow
)

// springBootDir returns the absolute path to the Spring Boot test codebase.
func springBootDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// Navigate from internal/pattern/joern/ up to the repo root, then into testdata.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
	dir := filepath.Join(root, "testdata", "spring-boot-app")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("spring-boot-app testdata not found at %s: %v", dir, err)
	}
	return dir
}

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
		WithPingRetries(60), // 30 s total at 500 ms intervals
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

// buildTestCPG imports the Spring Boot test codebase into the given client.
func buildTestCPG(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if err := c.BuildCPG(ctx, BuildConfig{
		Paths:    []string{springBootDir(t)},
		Language: "JAVASRC",
	}); err != nil {
		t.Fatalf("BuildCPG: %v", err)
	}
}

// ─── L1 Go/No-Go tests ───────────────────────────────────────────────────────
// These are the mandatory passing conditions for the L1 spike checkpoint.

// TestIntegration_StartAndPing verifies that joern-server starts, binds to
// 127.0.0.1, and responds to the /ready health check.
func TestIntegration_StartAndPing(t *testing.T) {
	c := startIntegrationClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping after Start: %v", err)
	}
}

// TestIntegration_BuildCPG_SpringBoot verifies that BuildCPG completes on the
// Spring Boot test codebase and produces a non-empty METHOD node set.
// This is the "CPG non-empty" assertion from the L1 golden-file checkpoint.
func TestIntegration_BuildCPG_SpringBoot(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	g := c.Graph()
	methods, err := g.QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes(METHOD): %v", err)
	}
	if len(methods) == 0 {
		t.Fatal("CPG contains no METHOD nodes — CPG build may have failed silently")
	}
	t.Logf("CPG contains %d METHOD nodes", len(methods))

	// Assert the known-vulnerable method is present.
	found := false
	for _, m := range methods {
		if m.Name == "getUser" {
			found = true
			t.Logf("Found getUser at %s:%d", m.File, m.Line)
			break
		}
	}
	if !found {
		t.Error("getUser method not found in CPG — expected from MainController.java")
	}
}

// TestIntegration_GetCallGraph_NonEmpty verifies that GetCallGraph returns a
// non-empty map after the CPG is built on the Spring Boot codebase.
func TestIntegration_GetCallGraph_NonEmpty(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	g := c.Graph()
	cg, err := g.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph: %v", err)
	}
	if len(cg) == 0 {
		t.Error("GetCallGraph: empty call graph — expected caller→callee edges from Spring Boot codebase")
	}
	t.Logf("Call graph contains %d caller entries", len(cg))
}

// TestIntegration_TaintPath_SQLInjection is the golden-file test for the L1 spike.
// It verifies that Joern detects the SQL injection taint path in MainController.java:
//   HTTP request parameter (@RequestParam id) → SQL sink (executeQuery / queryForList)
//
// Pass condition: at least one TaintPath is returned with source in getUser.
// This is the binary Go/No-Go test — if this fails, trigger the L1 fallback.
func TestIntegration_TaintPath_SQLInjection(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	g := c.Graph()

	// Locate the getUser method to use as taint source.
	methods, err := g.QueryNodesByFile("MainController.java", cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodesByFile: %v", err)
	}

	var getUserID string
	for _, m := range methods {
		if m.Name == "getUser" {
			getUserID = m.ID
			break
		}
	}
	if getUserID == "" {
		// Try full path as Joern may use absolute paths.
		methods, err = g.QueryNodes(cpg.NodeMethod)
		if err != nil {
			t.Fatalf("QueryNodes fallback: %v", err)
		}
		for _, m := range methods {
			if m.Name == "getUser" {
				getUserID = m.ID
				break
			}
		}
	}
	if getUserID == "" {
		t.Fatal("getUser method not found in CPG — cannot run taint test")
	}

	paths, err := g.TaintPaths(
		[]cpg.TaintSource{{NodeID: getUserID, Kind: "method_parameter", File: "MainController.java"}},
		[]cpg.TaintSink{{NodeID: getUserID, Kind: cpg.SinkSQL, File: "MainController.java"}},
	)
	if err != nil {
		t.Fatalf("TaintPaths: %v", err)
	}

	if len(paths) == 0 {
		t.Error("TaintPaths: no SQL injection taint path detected in getUser — " +
			"L1 Go/No-Go FAIL: Joern taint analysis is not working on this codebase")
	} else {
		t.Logf("L1 Go/No-Go PASS: detected %d taint path(s) in getUser", len(paths))
		for i, p := range paths {
			t.Logf("  path[%d]: %s:%d → %s:%d (%d intermediate nodes)",
				i, p.Source.File, p.Source.Line,
				p.Sink.File, p.Sink.Line,
				len(p.IntermediateNodes))
		}
	}
}

// TestIntegration_GetCallers_Callees_RoundTrip verifies that GetCallers and
// GetCallees are consistent: if A calls B, then A appears in B's callers.
func TestIntegration_GetCallers_CalleeRoundTrip(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	g := c.Graph()
	methods, err := g.QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(methods) == 0 {
		t.Skip("no methods in CPG")
	}

	// Pick the first method that has callees.
	for _, m := range methods {
		callees, err := g.GetCallees(m.ID)
		if err != nil {
			continue
		}
		if len(callees) == 0 {
			continue
		}

		// Verify at least one callee reports m as a caller.
		callee := callees[0]
		callers, err := g.GetCallers(callee.ID)
		if err != nil {
			t.Fatalf("GetCallers(%s): %v", callee.ID, err)
		}
		found := false
		for _, caller := range callers {
			if caller.ID == m.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetCallers(%s) does not include %s (which calls it)", callee.Name, m.Name)
		}
		t.Logf("Round-trip OK: %s → %s; callers of %s includes %s",
			m.Name, callee.Name, callee.Name, m.Name)
		return
	}
	t.Skip("no method with callees found in CPG")
}
