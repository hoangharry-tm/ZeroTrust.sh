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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// mockGraph implements cpg.Graph for unit tests.
type mockGraph struct {
	nodes    []cpg.Node
	edges    []cpg.Edge
	callees  map[string][]cpg.Node
	callers  map[string][]cpg.Node
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

func (m *mockGraph) GetCallGraph() (cpg.CallGraph, error) { return nil, nil }

func (m *mockGraph) GetCallers(id string) ([]cpg.Node, error) {
	return m.callers[id], nil
}

func (m *mockGraph) GetCallees(id string) ([]cpg.Node, error) {
	return m.callees[id], nil
}

func (m *mockGraph) GetNeighboursAtDepth(rootID string, depth int) ([]cpg.Node, error) {
	return nil, nil
}

func (m *mockGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}

func (m *mockGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return nil, nil }

// helpers

func method(id, name string) cpg.Node {
	return cpg.Node{ID: id, Type: cpg.NodeMethod, Name: name}
}

func pdgEdge(fromID, label string) cpg.Edge {
	return cpg.Edge{FromID: fromID, Type: cpg.EdgePDG, Label: label}
}

// T1: external-input node detection

func TestIsExternalInputNode_HTTP(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m1", "getParameter(id)")}}
	tk := New(g)
	ok, err := tk.IsExternalInputNode(context.Background(), method("m1", "handler"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsExternalInputNode_Env(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m2", "os.Getenv(\"SECRET\")")}}
	tk := New(g)
	ok, err := tk.IsExternalInputNode(context.Background(), method("m2", "loadConfig"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsExternalInputNode_File(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m3", "os.Open(path)")}}
	tk := New(g)
	ok, err := tk.IsExternalInputNode(context.Background(), method("m3", "readFile"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsExternalInputNode_Stdin(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m4", "os.Stdin.Read(buf)")}}
	tk := New(g)
	ok, err := tk.IsExternalInputNode(context.Background(), method("m4", "readInput"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsExternalInputNode_None(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m5", "fmt.Println(x)")}}
	tk := New(g)
	ok, err := tk.IsExternalInputNode(context.Background(), method("m5", "printResult"))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestQueryExternalInputNodes_Empty(t *testing.T) {
	g := &mockGraph{}
	tk := New(g)
	nodes, err := tk.queryExternalInputNodes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, nodes)
}

// T2: auth-boundary node detection

func TestIsAuthBoundaryNode_NamePattern(t *testing.T) {
	g := &mockGraph{}
	tk := New(g)
	cases := []string{"AuthUser", "loginHandler", "verifyToken", "checkPermission", "authorizeRequest"}
	for _, name := range cases {
		ok, err := tk.IsAuthBoundaryNode(context.Background(), method("x", name))
		require.NoError(t, err)
		assert.True(t, ok, "expected auth boundary for %q", name)
	}
}

func TestIsAuthBoundaryNode_JavaAnnotation(t *testing.T) {
	g := &mockGraph{
		edges: []cpg.Edge{pdgEdge("m6", "@PreAuthorize(\"hasRole('ADMIN')\")"),
		},
	}
	tk := New(g)
	ok, err := tk.IsAuthBoundaryNode(context.Background(), method("m6", "deleteUser"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsAuthBoundaryNode_GoMiddleware(t *testing.T) {
	g := &mockGraph{}
	tk := New(g)
	ok, err := tk.IsAuthBoundaryNode(context.Background(), method("m7", "jwtMiddleware"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsAuthBoundaryNode_NonMatching(t *testing.T) {
	g := &mockGraph{edges: []cpg.Edge{pdgEdge("m8", "fmt.Sprintf(x)")}}
	tk := New(g)
	ok, err := tk.IsAuthBoundaryNode(context.Background(), method("m8", "formatResponse"))
	require.NoError(t, err)
	assert.False(t, ok)
}

// T3: call graph building

func TestBuildCallGraph_Connected(t *testing.T) {
	g := &mockGraph{
		callees: map[string][]cpg.Node{
			"root": {{ID: "child1"}, {ID: "child2"}},
			"child1": {{ID: "leaf"}},
		},
	}
	tk := New(g)
	seeds := []cpg.Node{{ID: "root"}}
	cg, err := tk.buildCallGraph(context.Background(), seeds)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"child1", "child2"}, cg["root"])
	assert.ElementsMatch(t, []string{"leaf"}, cg["child1"])
}

func TestBuildCallGraph_Disconnected(t *testing.T) {
	g := &mockGraph{callees: map[string][]cpg.Node{}}
	tk := New(g)
	cg, err := tk.buildCallGraph(context.Background(), []cpg.Node{{ID: "isolated"}})
	require.NoError(t, err)
	assert.Empty(t, cg["isolated"])
}

func TestBuildCallGraph_Cycle(t *testing.T) {
	g := &mockGraph{
		callees: map[string][]cpg.Node{
			"a": {{ID: "b"}},
			"b": {{ID: "a"}}, // cycle
		},
	}
	tk := New(g)
	cg, err := tk.buildCallGraph(context.Background(), []cpg.Node{{ID: "a"}})
	require.NoError(t, err)
	// must terminate; both nodes present
	assert.Contains(t, cg, "a")
	assert.Contains(t, cg, "b")
}

// T5: AutoFlagCVESurfaces

func TestAutoFlagCVESurfaces_Block(t *testing.T) {
	s := Surface{HasCVEMatch: true, CVSSScore: 9.0}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s})
	require.Len(t, flagged, 1)
	assert.Empty(t, rem)
	assert.InEpsilon(t, 0.95, flagged[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_HighBoundary(t *testing.T) {
	// 8.9 → HIGH (0.82), 9.0 → BLOCK (0.95)
	s89 := Surface{HasCVEMatch: true, CVSSScore: 8.9}
	s90 := Surface{HasCVEMatch: true, CVSSScore: 9.0}
	f89, _ := AutoFlagCVESurfaces([]Surface{s89})
	f90, _ := AutoFlagCVESurfaces([]Surface{s90})
	assert.InEpsilon(t, 0.82, f89[0].ConfidenceScore, 1e-6)
	assert.InEpsilon(t, 0.95, f90[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_MissingCVSSDefaultsToFive(t *testing.T) {
	// CVSSScore == 0 → treated as 5.0 → medium (0.68)
	s := Surface{HasCVEMatch: true, CVSSScore: 0}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s})
	require.Len(t, flagged, 1)
	assert.Empty(t, rem)
	assert.InEpsilon(t, 0.68, flagged[0].ConfidenceScore, 1e-6)
}

func TestAutoFlagCVESurfaces_NoCVEMatchGoesToRemainder(t *testing.T) {
	s := Surface{HasCVEMatch: false, CVSSScore: 9.0}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s})
	assert.Empty(t, flagged)
	require.Len(t, rem, 1)
}

func TestAutoFlagCVESurfaces_BelowThresholdGoesToRemainder(t *testing.T) {
	s := Surface{HasCVEMatch: true, CVSSScore: 3.9}
	flagged, rem := AutoFlagCVESurfaces([]Surface{s})
	assert.Empty(t, flagged)
	require.Len(t, rem, 1)
}

// T6: queryIDORCandidates

func TestQueryIDORCandidates_DetectsFlow(t *testing.T) {
	g := &mockGraph{
		nodes: []cpg.Node{method("h1", "getUser")},
		edges: []cpg.Edge{
			{FromID: "h1", Type: cpg.EdgePDG, Label: "getParameter(userId)"},
			{FromID: "h1", Type: cpg.EdgeCall, Label: "db.QueryRow(id)"},
		},
		// TaintPaths stubbed via the mock — we need to override it.
	}
	// mockGraph.TaintPaths returns nil; inject a custom mock for this test.
	mg := &idorMockGraph{
		mockGraph: g,
		paths: []cpg.TaintPath{
			{
				Source:            cpg.TaintSource{NodeID: "h1", File: "api.go"},
				Sink:              cpg.TaintSink{NodeID: "h1"},
				IntermediateNodes: nil,
				Sanitized:         false,
			},
		},
	}
	tk := New(mg)
	cfg := DefaultIDORConfig()
	surfaces, err := tk.queryIDORCandidates(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, surfaces, 1)
	assert.True(t, surfaces[0].IsIDORCandidate)
	assert.Equal(t, SurfaceIDORCandidate, surfaces[0].Kind)
}

func TestQueryIDORCandidates_ExcludesOwnershipCheck(t *testing.T) {
	g := &mockGraph{
		nodes: []cpg.Node{method("h2", "getDoc")},
		edges: []cpg.Edge{
			{FromID: "h2", Type: cpg.EdgePDG, Label: "getParameter(docId)"},
			{FromID: "h2", Type: cpg.EdgeCall, Label: "db.QueryRow(id)"},
		},
	}
	mg := &idorMockGraph{
		mockGraph: g,
		paths: []cpg.TaintPath{
			{
				Source: cpg.TaintSource{NodeID: "h2"},
				Sink:   cpg.TaintSink{NodeID: "h2"},
				IntermediateNodes: []cpg.Node{
					{ID: "chk", Name: "getUserId", Code: "session.getUserId()"},
				},
				Sanitized: false,
			},
		},
	}
	tk := New(mg)
	surfaces, err := tk.queryIDORCandidates(context.Background(), DefaultIDORConfig())
	require.NoError(t, err)
	assert.Empty(t, surfaces, "ownership check present — should be excluded")
}

func TestQueryIDORCandidates_EmptyWhenNoSources(t *testing.T) {
	g := &mockGraph{nodes: []cpg.Node{method("m1", "helper")}}
	tk := New(g)
	surfaces, err := tk.queryIDORCandidates(context.Background(), DefaultIDORConfig())
	require.NoError(t, err)
	assert.Empty(t, surfaces)
}

// idorMockGraph extends mockGraph with controllable TaintPaths.
type idorMockGraph struct {
	*mockGraph
	paths []cpg.TaintPath
}

func (m *idorMockGraph) TaintPaths(_ []cpg.TaintSource, _ []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return m.paths, nil
}

// T7: Targeter.Run

func TestRun_RanksIDORFirst(t *testing.T) {
	// One external-input node + one IDOR candidate (different node).
	extNode := method("ext1", "readInput")
	idorNode := method("idor1", "getUser")

	g := &idorMockGraph{
		mockGraph: &mockGraph{
			nodes: []cpg.Node{extNode, idorNode},
			edges: []cpg.Edge{
				// ext1 has an external-input edge
				pdgEdge("ext1", "getParameter(x)"),
				// idor1 has P-API source and storage sink edges
				pdgEdge("idor1", "getParameter(userId)"),
				{FromID: "idor1", Type: cpg.EdgeCall, Label: "db.QueryRow(id)"},
			},
		},
		paths: []cpg.TaintPath{
			{
				Source:    cpg.TaintSource{NodeID: "idor1"},
				Sink:      cpg.TaintSink{NodeID: "idor1"},
				Sanitized: false,
			},
		},
	}

	tk := New(g)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, surfaces)
	assert.Equal(t, SurfaceIDORCandidate, surfaces[0].Kind, "IDOR surface must be first")
}

func TestRun_SortsbyCallGraphDepth(t *testing.T) {
	// Two external-input nodes; one is a callee of the other.
	parent := method("p1", "handler")
	child := method("c1", "helper")

	g := &idorMockGraph{
		mockGraph: &mockGraph{
			nodes: []cpg.Node{parent, child},
			edges: []cpg.Edge{
				pdgEdge("p1", "getParameter(x)"),
				pdgEdge("c1", "getParameter(y)"),
			},
			callees: map[string][]cpg.Node{
				"p1": {child},
			},
		},
		paths: nil,
	}

	tk := New(g)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	require.Len(t, surfaces, 2)
	assert.Equal(t, "p1", surfaces[0].ID, "shallower node first")
	assert.Equal(t, "c1", surfaces[1].ID)
}

func TestRun_DeduplicatesNodes(t *testing.T) {
	// Same node is both external-input and auth-boundary.
	n := method("m1", "authHandler")

	g := &idorMockGraph{
		mockGraph: &mockGraph{
			nodes: []cpg.Node{n},
			edges: []cpg.Edge{
				pdgEdge("m1", "getParameter(token)"),
			},
		},
		paths: nil,
	}

	tk := New(g)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	assert.Len(t, surfaces, 1, "duplicate node must appear once")
}

func TestRun_EmptyCPG(t *testing.T) {
	g := &idorMockGraph{mockGraph: &mockGraph{}}
	tk := New(g)
	surfaces, err := tk.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, surfaces)
}

// T3: CallGraphDepth

func TestCallGraphDepth_Reachable(t *testing.T) {
	cg := CallGraph{
		"root":   {"child"},
		"child":  {"leaf"},
		"leaf":   {},
	}
	// leaf is reachable from root at depth 0 from itself
	assert.Equal(t, 0, cg.CallGraphDepth("leaf"))
}

func TestCallGraphDepth_Unreachable(t *testing.T) {
	cg := CallGraph{"root": {"child"}}
	assert.Equal(t, -1, cg.CallGraphDepth("orphan"))
}
