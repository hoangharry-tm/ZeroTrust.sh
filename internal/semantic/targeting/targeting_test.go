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

package targeting

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// ── mock graph ───────────────────────────────────────────────────────────────

type mockGraph struct {
	nodes   []cpg.Node
	edges   []cpg.Edge
	callees map[string][]cpg.Node
	callers map[string][]cpg.Node
}

func (m *mockGraph) QueryNodes(nt cpg.NodeType) ([]cpg.Node, error) {
	var out []cpg.Node
	for _, n := range m.nodes {
		if n.Type == nt {
			out = append(out, n)
		}
	}
	return out, nil
}

func (m *mockGraph) QueryNodesByFile(relPath string, nt cpg.NodeType) ([]cpg.Node, error) {
	var out []cpg.Node
	for _, n := range m.nodes {
		if n.File == relPath && n.Type == nt {
			out = append(out, n)
		}
	}
	return out, nil
}

func (m *mockGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error) {
	var out []cpg.Edge
	for _, e := range m.edges {
		fromMatch := fromID == "" || e.FromID == fromID
		toMatch := toID == "" || e.ToID == toID
		if fromMatch && toMatch {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *mockGraph) GetCallGraph() (cpg.CallGraph, error) {
	cg := make(cpg.CallGraph)
	for id, callees := range m.callees {
		for _, c := range callees {
			cg[id] = append(cg[id], c.ID)
		}
	}
	return cg, nil
}

func (m *mockGraph) GetCallers(id string) ([]cpg.Node, error) { return m.callers[id], nil }
func (m *mockGraph) GetCallees(id string) ([]cpg.Node, error) { return m.callees[id], nil }
func (m *mockGraph) GetNeighboursAtDepth(_ string, _ int) ([]cpg.Node, error) { return nil, nil }
func (m *mockGraph) TaintPaths(_ []cpg.TaintSource, _ []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}
func (m *mockGraph) ProjectWideTaintPaths(_ []string, _ string) ([]cpg.TaintPath, error) {
	return nil, nil
}
func (m *mockGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return nil, nil }

// helpers

func method(id, name, file string) cpg.Node {
	return cpg.Node{ID: id, Type: cpg.NodeMethod, Name: name, File: file}
}

// writeTempFile creates path (relative to dir) with content.
func writeTempFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	abs := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o755))
	require.NoError(t, os.WriteFile(abs, []byte(content), 0o644))
	return abs
}

// ── T1: AnalyzeImports ───────────────────────────────────────────────────────

func TestAnalyzeImports_Java_SourceBoundary(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "Controller.java", "import org.springframework.web.bind.annotation.RestController;\n")
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	key := filepath.Join(dir, "Controller.java")
	require.Contains(t, classes, key)
	assert.True(t, classes[key].Bound&BoundarySource != 0, "spring controller should be source boundary")
}

func TestAnalyzeImports_Python_SinkBoundary(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "db.py", "import psycopg2\n")
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	key := filepath.Join(dir, "db.py")
	require.Contains(t, classes, key)
	assert.True(t, classes[key].Bound&BoundarySink != 0)
}

func TestAnalyzeImports_Go_AuthBoundary(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "auth.go", `package auth
import "github.com/golang-jwt/jwt"
`)
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	key := filepath.Join(dir, "auth.go")
	require.Contains(t, classes, key)
	assert.True(t, classes[key].Bound&BoundaryAuth != 0)
}

func TestAnalyzeImports_MultiBoundary(t *testing.T) {
	dir := t.TempDir()
	// A controller that also talks to the DB directly — both Source and Sink.
	writeTempFile(t, dir, "handler.py", "from flask import request\nimport sqlalchemy\n")
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	key := filepath.Join(dir, "handler.py")
	require.Contains(t, classes, key)
	assert.True(t, classes[key].Bound&BoundarySource != 0)
	assert.True(t, classes[key].Bound&BoundarySink != 0)
}

func TestAnalyzeImports_NoImports(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "util.go", `package util
func helper() {}
`)
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	assert.Empty(t, classes, "file with no recognised imports should not appear")
}

func TestAnalyzeImports_SkipsVendor(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "vendor/spring/Handler.java", "import org.springframework.web.bind.annotation.RestController;\n")
	classes, err := AnalyzeImports(context.Background(), dir)
	require.NoError(t, err)
	assert.Empty(t, classes, "vendor directory must be skipped")
}

// ── T2: bfsForward / buildReverseCG ─────────────────────────────────────────

func TestBfsForward_Basic(t *testing.T) {
	cg := cpg.CallGraph{
		"a": {"b", "c"},
		"b": {"d"},
	}
	reached := bfsForward(cg, []string{"a"})
	assert.True(t, reached["a"])
	assert.True(t, reached["b"])
	assert.True(t, reached["c"])
	assert.True(t, reached["d"])
	assert.False(t, reached["x"])
}

func TestBfsForward_Cycle(t *testing.T) {
	cg := cpg.CallGraph{
		"a": {"b"},
		"b": {"a"},
	}
	reached := bfsForward(cg, []string{"a"})
	assert.True(t, reached["a"])
	assert.True(t, reached["b"])
}

func TestBfsForward_EmptySeeds(t *testing.T) {
	cg := cpg.CallGraph{"a": {"b"}}
	reached := bfsForward(cg, nil)
	assert.Empty(t, reached)
}

func TestBuildReverseCG(t *testing.T) {
	cg := cpg.CallGraph{
		"a": {"b", "c"},
		"b": {"c"},
	}
	rev := buildReverseCG(cg)
	assert.ElementsMatch(t, []string{"a"}, rev["b"])
	assert.ElementsMatch(t, []string{"a", "b"}, rev["c"])
	assert.Nil(t, rev["a"])
}

// ── T3: identifyIDOR ─────────────────────────────────────────────────────────

func TestIdentifyIDOR_DetectsCandidate(t *testing.T) {
	surfaces := map[string]Surface{
		"h1": {ID: "h1", Kind: SurfaceExternalInput},
	}
	canReachAuth := map[string]bool{} // h1 cannot reach auth
	out := identifyIDOR(surfaces, canReachAuth)
	require.Len(t, out, 1)
	assert.True(t, out[0].IsIDORCandidate)
	assert.Equal(t, SurfaceIDORCandidate, out[0].Kind)
}

func TestIdentifyIDOR_ExcludesWhenAuthReachable(t *testing.T) {
	surfaces := map[string]Surface{
		"h2": {ID: "h2", Kind: SurfaceExternalInput},
	}
	canReachAuth := map[string]bool{"h2": true}
	out := identifyIDOR(surfaces, canReachAuth)
	assert.Empty(t, out)
}

func TestIdentifyIDOR_ExcludesAuthBoundarySurfaces(t *testing.T) {
	surfaces := map[string]Surface{
		"h3": {ID: "h3", Kind: SurfaceAuthBoundary},
	}
	out := identifyIDOR(surfaces, map[string]bool{})
	assert.Empty(t, out)
}

// ── T4: Targeter.Run integration ─────────────────────────────────────────────

// buildRunFixture sets up a temp dir with source/sink/auth files and a mock
// graph whose METHOD nodes reference those files (relative paths).
func buildRunFixture(t *testing.T) (root string, g *mockGraph) {
	t.Helper()
	dir := t.TempDir()

	// Source boundary: Spring controller
	writeTempFile(t, dir, "api/UserController.java",
		"import org.springframework.web.bind.annotation.RestController;\n")
	// Sink boundary: repository
	writeTempFile(t, dir, "repo/UserRepo.java",
		"import org.springframework.data.jpa.repository.JpaRepository;\n")
	// Auth boundary: JWT util
	writeTempFile(t, dir, "auth/JwtUtil.java",
		"import io.jsonwebtoken.Jwts;\n")

	g = &mockGraph{
		nodes: []cpg.Node{
			method("ctrl1", "getUser", "api/UserController.java"),
			method("repo1", "findById", "repo/UserRepo.java"),
			method("auth1", "validateToken", "auth/JwtUtil.java"),
			method("svc1", "userService", "service/UserService.java"), // no boundary
		},
		callees: map[string][]cpg.Node{
			"ctrl1": {{ID: "svc1"}},
			"svc1":  {{ID: "repo1"}},
		},
	}
	return dir, g
}

func TestRun_SelectsSurfaces(t *testing.T) {
	root, g := buildRunFixture(t)
	tk := New(g, root)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	// ctrl1 → svc1 → repo1: ctrl1 and svc1 should be surfaces (on source→sink path)
	ids := make(map[string]bool)
	for _, s := range surfaces {
		ids[s.ID] = true
	}
	assert.True(t, ids["ctrl1"], "controller should be a surface")
	assert.True(t, ids["svc1"], "service (intermediate) should be a surface")
}

func TestRun_IDORWhenNoAuth(t *testing.T) {
	root, g := buildRunFixture(t)
	// Remove auth node's callee — auth1 is never called by ctrl1/svc1.
	tk := New(g, root)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)

	// ctrl1 and svc1 cannot reach auth1 — both should be IDOR candidates.
	for _, s := range surfaces {
		if s.ID == "ctrl1" || s.ID == "svc1" {
			assert.Equal(t, SurfaceIDORCandidate, s.Kind,
				"%s should be IDOR candidate (no auth on path)", s.ID)
		}
	}
}

func TestRun_AuthBoundaryWhenAuthReachable(t *testing.T) {
	root, g := buildRunFixture(t)
	// Wire svc1 → auth1 so that ctrl1 transitively reaches auth.
	g.callees["svc1"] = append(g.callees["svc1"], cpg.Node{ID: "auth1"})
	tk := New(g, root)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)

	for _, s := range surfaces {
		if s.ID == "ctrl1" || s.ID == "svc1" {
			assert.NotEqual(t, SurfaceIDORCandidate, s.Kind,
				"%s calls auth — should not be IDOR", s.ID)
		}
	}
}

func TestRun_IDORRankedFirst(t *testing.T) {
	root, g := buildRunFixture(t)
	tk := New(g, root)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, surfaces)
	assert.Equal(t, SurfaceIDORCandidate, surfaces[0].Kind, "IDOR must be first")
}

func TestRun_EmptyCPG(t *testing.T) {
	dir := t.TempDir()
	g := &mockGraph{}
	tk := New(g, dir)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, surfaces)
}

// ── T5: AutoFlagCVESurfaces ──────────────────────────────────────────────────

func TestAutoFlagCVESurfaces_Block(t *testing.T) {
	s := Surface{HasCVEMatch: true, CVSSScore: 9.0}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s}, config.Default())
	require.Len(t, flagged, 1)
	assert.Empty(t, rem)
	assert.InEpsilon(t, 0.95, flagged[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_HighBoundary(t *testing.T) {
	s89 := Surface{HasCVEMatch: true, CVSSScore: 8.9}
	s90 := Surface{HasCVEMatch: true, CVSSScore: 9.0}
	f89, _ := AutoFlagCVESurfaces([]Surface{s89}, config.Default())
	f90, _ := AutoFlagCVESurfaces([]Surface{s90}, config.Default())
	assert.InEpsilon(t, 0.82, f89[0].ConfidenceScore, 1e-6)
	assert.InEpsilon(t, 0.95, f90[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_MissingCVSSDefaultsToFive(t *testing.T) {
	s := Surface{HasCVEMatch: true, CVSSScore: 0}
	flagged, _ := AutoFlagCVESurfaces([]Surface{s}, config.Default())
	require.Len(t, flagged, 1)
	assert.InEpsilon(t, 0.68, flagged[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_NoCVEMatch(t *testing.T) {
	s := Surface{HasCVEMatch: false, CVSSScore: 9.0}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s}, config.Default())
	assert.Empty(t, flagged)
	require.Len(t, rem, 1)
}

func TestAutoFlagCVESurfaces_BelowThreshold(t *testing.T) {
	s := Surface{HasCVEMatch: true, CVSSScore: 3.9}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s}, config.Default())
	assert.Empty(t, flagged)
	require.Len(t, rem, 1)
}

// ── T6: CallGraphDepth helper ────────────────────────────────────────────────

func TestCallGraphDepth_Reachable(t *testing.T) {
	cg := CallGraph{"root": {"child"}, "child": {}}
	assert.Equal(t, 0, cg.CallGraphDepth("child"))
}

func TestCallGraphDepth_Unreachable(t *testing.T) {
	cg := CallGraph{"root": {"child"}}
	assert.Equal(t, -1, cg.CallGraphDepth("orphan"))
}

// ── T7: DetectSecondOrder ───────────────────────────────────────────────────

func TestDetectSecondOrder_StorageInjection(t *testing.T) {
	// Scenario: req1 writes user input to DB; req2 reads it and outputs to response.
	// Graph: source1 → storage1 → sink1
	cg := cpg.CallGraph{
		"source1":  {"storage1"},   // external input calls storage
		"storage1": {"sink1"},      // storage method calls sink
		"sink1":    {},             // sink has no further calls
	}

	// Use absolute paths so they match fileClass keys.
	absAPI := "/project/controllers/api.java"
	absDB := "/project/db/repository.java"
	absIO := "/project/io/output.java"

	methods := []cpg.Node{
		{ID: "source1", Type: cpg.NodeMethod, Name: "handleRequest", File: absAPI},
		{ID: "storage1", Type: cpg.NodeMethod, Name: "save", File: absDB},
		{ID: "sink1", Type: cpg.NodeMethod, Name: "writeResponse", File: absIO},
	}

	fileClass := map[string]FileClass{
		absAPI: {Path: absAPI, Bound: BoundarySource},
		absDB:  {Path: absDB, Bound: BoundaryStorage},
		absIO:  {Path: absIO, Bound: BoundarySink},
	}

	sourceReachable := map[string]bool{
		"source1":  true,
		"storage1": true,
		"sink1":    true,
	}

	backwardReachable := map[string]bool{
		"source1":  true,
		"storage1": true,
		"sink1":    true,
	}

	surfaces := DetectSecondOrder(cg, methods, fileClass, sourceReachable, backwardReachable)

	// storage1 should be detected as second-order (reads from storage → sink).
	found := false
	for _, s := range surfaces {
		if s.ID == "storage1" && s.IsSecondOrder {
			found = true
			break
		}
	}
	assert.True(t, found, "storage method should be detected as second-order source")
}

func TestDetectSecondOrder_NoStorageBoundary(t *testing.T) {
	// No storage-boundary files: should return empty.
	cg := cpg.CallGraph{
		"a": {"b"},
		"b": {},
	}

	methods := []cpg.Node{
		method("a", "handleRequest", "api.java"),
		method("b", "sink", "output.java"),
	}

	fileClass := map[string]FileClass{
		"api.java":    {Path: "api.java", Bound: BoundarySource},
		"output.java": {Path: "output.java", Bound: BoundarySink},
	}

	sourceReachable := map[string]bool{"a": true, "b": true}
	backwardReachable := map[string]bool{"a": true, "b": true}

	surfaces := DetectSecondOrder(cg, methods, fileClass, sourceReachable, backwardReachable)
	assert.Empty(t, surfaces, "no storage boundary should yield no second-order surfaces")
}
