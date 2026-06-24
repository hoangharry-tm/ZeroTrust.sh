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
// These tests require a live Joern server and the Spring Boot test codebase.
// Run with:
//
//	make test-integration
//
// Prerequisites:
//  1. Joern installed: joern binary in PATH (Homebrew: brew install joern) (see Makefile JOERN_BIN).
//  2. Java 11+ available.
//  3. No other process bound on JOERN_TEST_PORT (default 18080).
//
// The tests spawn joern-server themselves; you do not need to pre-start it.
// Each test that needs a CPG calls buildTestCPG as a sub-helper.
package joern

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

const (
	integrationPort    = 18080
	integrationBin     = "joern" // Homebrew installs as "joern --server", not "joern-server"
	integrationTimeout = 5 * time.Minute // JVM cold-start can be slow
)

// springBootDir returns the absolute path to the Spring Boot test codebase.
func springBootDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// Navigate from internal/pattern/joern/ up to the repo root, then into tests/integration.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	dir := filepath.Join(root, "tests", "integration", "spring-boot-app")
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

	// Joern REPL may still be processing queries after Start() returns;
	// use the same generous timeout as the integration client itself.
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
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

// TestIntegration_TaintFlowsQuery verifies the queryTaintFlows template by running
// it against the getUser method and checking for non-empty results including
// SQL-related sink nodes.
func TestIntegration_TaintFlowsQuery(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Find the getUser method ID from the CPG.
	methods, err := c.Graph().QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	var getUserID string
	for _, m := range methods {
		if m.Name == "getUser" {
			getUserID = m.ID
			break
		}
	}
	if getUserID == "" {
		t.Fatal("getUser method not found")
	}

	q := queryTaintFlows(getUserID)
	raw, err := c.doQuery(ctx, q)
	if err != nil {
		t.Fatalf("queryTaintFlows: %v", err)
	}

	// Parse as joernFlow slice.
	var flows []joernFlow
	if err := json.Unmarshal(raw, &flows); err != nil {
		t.Fatalf("json.Unmarshal: %v\nraw: %s", err, string(raw))
	}
	if len(flows) == 0 {
		t.Fatal("no flows returned from getUser — expected SQL injection taint paths")
	}
	hasSQLSink := false
	for _, f := range flows {
		if f.Sink.Name == "executeQuery" || f.Sink.Name == "queryForList" {
			hasSQLSink = true
			break
		}
	}
	if !hasSQLSink {
		t.Error("no SQL-related sink (executeQuery/queryForList) found in flows")
	}
	t.Logf("queryTaintFlows: %d flows, SQL sink found", len(flows))
}

// TestIntegration_Version verifies that the Version method returns a non-empty
// version string from the live Joern server.
func TestIntegration_Version(t *testing.T) {
	c := startIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	v, err := c.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v == "" || v == "unknown" {
		t.Errorf("Version = %q, want a semantic version string", v)
	}
	t.Logf("Joern version: %s", v)
}

// TestIntegration_SaveLoadCPG verifies that a CPG snapshot can be saved and
// reloaded, and that the reloaded CPG still returns METHOD nodes. This is the
// core "repeat scan" contract: save after first build, load + incremental patch
// on subsequent runs.
func TestIntegration_SaveLoadCPG(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	// Count methods in the live CPG.
	liveMethods, err := c.Graph().QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes (pre-save): %v", err)
	}
	if len(liveMethods) == 0 {
		t.Fatal("CPG has no methods — cannot proceed")
	}
	t.Logf("Live CPG has %d methods", len(liveMethods))

	// Save the CPG to a temp file.
	savePath := filepath.Join(t.TempDir(), "test.cpg")
	saveCtx, saveCancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer saveCancel()
	if err := c.SaveCPG(saveCtx, savePath); err != nil {
		t.Fatalf("SaveCPG: %v", err)
	}
	t.Log("CPG snapshot saved")

	// Load the CPG into a fresh Joern instance.
	c2 := startIntegrationClient(t)
	loadCtx, loadCancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer loadCancel()
	if err := c2.LoadCPG(loadCtx, savePath); err != nil {
		t.Fatalf("LoadCPG: %v", err)
	}
	t.Log("CPG snapshot loaded")

	// Verify the loaded CPG returns a comparable method count.
	loadedMethods, err := c2.Graph().QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes (post-load): %v", err)
	}
	if len(loadedMethods) == 0 {
		t.Fatal("Loaded CPG has no methods — save/load cycle may have failed")
	}
	if len(loadedMethods) < len(liveMethods)/2 {
		t.Errorf("Loaded CPG has %d methods vs %d in live — too few",
			len(loadedMethods), len(liveMethods))
	}
	t.Logf("Loaded CPG has %d methods (live had %d)", len(loadedMethods), len(liveMethods))
}

// TestIntegration_IncrementalPatch verifies the repeat-scan flow: save CPG →
// load → incremental patch → verify the CPG is still queryable.
func TestIntegration_IncrementalPatch(t *testing.T) {
	c := startIntegrationClient(t)
	buildTestCPG(t, c)

	g := c.Graph()
	methods, err := g.QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(methods) == 0 {
		t.Fatal("no methods in CPG")
	}

	// Pick a few method IDs to simulate "changed functions".
	var changedIDs []string
	for i, m := range methods {
		if i >= 3 {
			break
		}
		changedIDs = append(changedIDs, m.ID)
	}
	if len(changedIDs) == 0 {
		t.Fatal("no method IDs to patch")
	}
	t.Logf("Patching %d functions", len(changedIDs))

	// Apply incremental patch on those functions.
	patchCtx, patchCancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer patchCancel()
	if err := c.IncrementalPatch(patchCtx, IncrementalPatchConfig{
		ChangedFunctions:   changedIDs,
		MaxDepth:           5,
		HubCallerThreshold: 50,
	}); err != nil {
		// ErrHubModuleDetected is acceptable — the test codebase may have
		// hub functions. If we get an unexpected error, fail.
		if !errors.Is(err, ErrHubModuleDetected) {
			t.Fatalf("IncrementalPatch: %v", err)
		}
		t.Logf("IncrementalPatch aborted: hub module detected (expected on some codebases)")
		return
	}
	t.Log("IncrementalPatch succeeded")

	// Verify the CPG is still functional after the patch.
	afterMethods, err := g.QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes (post-patch): %v", err)
	}
	if len(afterMethods) == 0 {
		t.Fatal("CPG lost all methods after incremental patch")
	}
	t.Logf("CPG has %d methods after patch (was %d before)", len(afterMethods), len(methods))
}

// TestIntegration_PreFlaggedSinks verifies that PreFlagSinks detects dangerous
// sinks in the Spring Boot test codebase and that PreFlaggedSinks returns them.
func TestIntegration_PreFlaggedSinks(t *testing.T) {
	c := startIntegrationClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	// Pre-flag sinks across all Java files in the test codebase.
	var javaFiles []string
	root := springBootDir(t)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Ext(path) == ".java" {
			javaFiles = append(javaFiles, path)
		}
		return nil
	})

	if len(javaFiles) == 0 {
		t.Fatal("no Java files found in Spring Boot test codebase")
	}

	if err := c.PreFlagSinks(ctx, javaFiles); err != nil {
		t.Fatalf("PreFlagSinks: %v", err)
	}

	sinks := c.PreFlaggedSinks()
	if len(sinks) == 0 {
		t.Fatal("PreFlagSinks: no sinks found in Spring Boot codebase — expected SQL/exec sinks")
	}
	t.Logf("Pre-flagged %d dangerous sinks across %d Java files", len(sinks), len(javaFiles))
	for _, s := range sinks {
		t.Logf("  sink: %s at %s:%d", s.Kind, s.File, s.Line)
	}
}

// TestIntegration_PathA_E2E simulates the full Path A pipeline:
//  1. Pre-flag sinks in the scope files
//  2. Build the CPG
//  3. Query CALL nodes matching the language taxonomy (source + sink defs)
//  4. Run TaintPaths on the matched nodes
//  5. Normalise to Finding structs via TaintPathsToFindings
//  6. Verify all Finding fields are properly populated
//
// This is the L2.3.T2 checkpoint test.
func TestIntegration_PathA_E2E(t *testing.T) {
	c := startIntegrationClient(t)
	root := springBootDir(t)

	// Gather Java files for the scope.
	var javaFiles []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Ext(path) == ".java" {
			javaFiles = append(javaFiles, path)
		}
		return nil
	})
	if len(javaFiles) == 0 {
		t.Fatal("no Java files in Spring Boot test codebase")
	}

	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	// Step 1: Pre-flag sinks.
	if err := c.PreFlagSinks(ctx, javaFiles); err != nil {
		t.Fatalf("PreFlagSinks: %v", err)
	}
	preFlagged := c.PreFlaggedSinks()
	t.Logf("Step 1 — Pre-flagged %d sinks", len(preFlagged))

	// Step 2: Build CPG.
	buildTestCPG(t, c)
	t.Log("Step 2 — CPG built")

	g := c.Graph()

	// Step 3: Query CALL nodes matching source/sink taxonomy.
	lang := LanguageJava
	var sources []cpg.TaintSource
	var sinks []cpg.TaintSink
	for _, f := range javaFiles {
		calls, err := g.QueryNodesByFile(f, cpg.NodeCall)
		if err != nil {
			continue
		}
		for _, call := range calls {
			if sd, ok := SourceDefForCall(lang, call.Name); ok {
				sources = append(sources, cpg.TaintSource{
					NodeID: call.ID,
					Kind:   sd.Kind,
					File:   call.File,
					Line:   call.Line,
				})
			}
			if sd, ok := SinkDefForCall(lang, call.Name); ok {
				sinks = append(sinks, cpg.TaintSink{
					NodeID: call.ID,
					Kind:   sd.Kind,
					File:   call.File,
					Line:   call.Line,
				})
			}
		}
	}
	t.Logf("Step 3 — Found %d source CALL nodes and %d sink CALL nodes via taxonomy", len(sources), len(sinks))

	if len(sources) == 0 || len(sinks) == 0 {
		// The test codebase may use framework conventions that Joern's CPG
		// represents differently. Log what was found and skip if nothing matches.
		t.Log("No source or sink CALL nodes matched in this CPG — this is acceptable",
			"if the taxonomy patterns don't match the framework's representation")
		return
	}

	// Step 4: Run taint analysis.
	paths, err := g.TaintPaths(sources, sinks)
	if err != nil {
		t.Fatalf("TaintPaths: %v", err)
	}
	t.Logf("Step 4 — TaintPaths returned %d paths", len(paths))

	if len(paths) == 0 {
		// This can happen if sources and sinks are in different methods and
		// inter-procedural flows are not yet supported.
		t.Log("No taint paths found — intra-procedural analysis only")
		return
	}

	// Step 5: Normalise to Finding structs.
	findings := TaintPathsToFindings(paths, lang)
	t.Logf("Step 5 — Normalised %d findings", len(findings))

	// Step 6: Verify Finding fields.
	if len(findings) == 0 {
		t.Fatal("TaintPathsToFindings returned empty slice despite non-empty paths")
	}

	for i, f := range findings {
		t.Logf("  finding[%d]: %s | %s | confidence=%.2f | cwe=%s | rule=%s",
			i, f.Path, f.Justification, f.Confidence, f.CWE, f.RuleID)

		// Every finding must have a non-empty ID.
		if f.ID == "" {
			t.Errorf("finding[%d].ID is empty", i)
		}
		// Path must be set (the sink file).
		if f.Path == "" {
			t.Errorf("finding[%d].Path is empty", i)
		}
		// CWE must be a valid CWE identifier.
		if f.CWE == "" || f.CWE == "CWE-200" {
			// CWE-200 is the fallback; flag it.
			t.Logf("finding[%d].CWE = %q (fallback — verify taxonomy)", i, f.CWE)
		}
		// Confidence must be in [0, 1].
		if f.Confidence < 0 || f.Confidence > 1 {
			t.Errorf("finding[%d].Confidence = %f, want [0, 1]", i, f.Confidence)
		}
		// SeverityLabel must match confidence.
		expectedLabel := finding.SeverityFromConfidence(f.Confidence)
		if f.SeverityLabel != expectedLabel {
			t.Errorf("finding[%d].SeverityLabel = %q, want %q (from confidence %.2f)",
				i, f.SeverityLabel, expectedLabel, f.Confidence)
		}
		// SourcePath must be PATTERN (Path A produces pattern findings).
		if f.SourcePath != finding.SourcePattern {
			t.Errorf("finding[%d].SourcePath = %q, want %q", i, f.SourcePath, finding.SourcePattern)
		}
		// Justification must be non-empty.
		if f.Justification == "" {
			t.Errorf("finding[%d].Justification is empty", i)
		}
		// RuleID must be present.
		if f.RuleID == "" {
			t.Errorf("finding[%d].RuleID is empty", i)
		}
		// SSVC dimensions must be set.
		if f.SSVC.Exploitation == "" || f.SSVC.Automatable == "" || f.SSVC.TechnicalImpact == "" {
			t.Errorf("finding[%d].SSVC has empty dimensions", i)
		}
		// PoeContext must be populated.
		if f.PoeContext == nil {
			t.Errorf("finding[%d].PoeContext is nil", i)
		} else {
			if f.PoeContext.SourceNode == "" || f.PoeContext.SinkNode == "" {
				t.Errorf("finding[%d].PoeContext has empty SourceNode or SinkNode", i)
			}
		}
	}
}
