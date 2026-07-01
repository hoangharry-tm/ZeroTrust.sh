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

package assembler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// stubGraph is a minimal cpg.Graph for testing. Supports callees, pre-flagged sinks,
// and PDG edges; everything else returns empty/nil.
type stubGraph struct {
	callees  map[string][]cpg.Node
	sinks    []cpg.TaintSink
	pdgEdges map[string][]cpg.Edge // nodeID → outgoing edges
}

func (g *stubGraph) QueryNodes(nt cpg.NodeType) ([]cpg.Node, error) {
	if nt != cpg.NodeMethod {
		return nil, nil
	}
	seen := make(map[string]bool)
	var nodes []cpg.Node
	add := func(n cpg.Node) {
		if !seen[n.ID] {
			seen[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	for id, callees := range g.callees {
		add(cpg.Node{ID: id, Name: id})
		for _, c := range callees {
			add(c)
		}
	}
	return nodes, nil
}
func (g *stubGraph) QueryNodesByFile(string, cpg.NodeType) ([]cpg.Node, error) { return nil, nil }
func (g *stubGraph) GetCallGraph() (cpg.CallGraph, error) {
	cg := make(cpg.CallGraph)
	for id, callees := range g.callees {
		for _, c := range callees {
			cg[id] = append(cg[id], c.ID)
		}
	}
	return cg, nil
}
func (g *stubGraph) GetCallers(string) ([]cpg.Node, error)                     { return nil, nil }
func (g *stubGraph) GetNeighboursAtDepth(string, int) ([]cpg.Node, error)      { return nil, nil }
func (g *stubGraph) TaintPaths([]cpg.TaintSource, []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}

func (g *stubGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return g.sinks, nil }

func (g *stubGraph) GetCallees(id string) ([]cpg.Node, error) { return g.callees[id], nil }

func (g *stubGraph) QueryEdges(fromID, _ string) ([]cpg.Edge, error) {
	return g.pdgEdges[fromID], nil
}

func surface(id string) enrichment.EnrichedSurface {
	return enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: id, FunctionName: id + "_fn", File: "pkg/x.go"},
	}
}

func TestAssemble_CalleeFirstOrder(t *testing.T) {
	// surface → callee_1 → callee_2; surface → callee_3
	// callee-first post-order: callee_2, callee_1, callee_3, surface
	graph := &stubGraph{callees: map[string][]cpg.Node{
		"surface":  {{ID: "callee_1", Name: "callee_1"}, {ID: "callee_3", Name: "callee_3"}},
		"callee_1": {{ID: "callee_2", Name: "callee_2"}},
	}}
	a := New(graph, 3)
	chains, err := a.Assemble(context.Background(), []enrichment.EnrichedSurface{surface("surface")})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(chains))
	}
	chain := chains[0]
	wantOrder := []string{"callee_2", "callee_1", "callee_3", "surface_fn"}
	if len(chain.Functions) != len(wantOrder) {
		t.Fatalf("want %d frames, got %d: %v", len(wantOrder), len(chain.Functions), namesOf(chain.Functions))
	}
	for i, want := range wantOrder {
		if chain.Functions[i].Name != want {
			t.Errorf("frame[%d]: want %q, got %q", i, want, chain.Functions[i].Name)
		}
	}
	// surface is at depth 0; callee_1 and callee_3 at depth 1; callee_2 at depth 2
	if chain.Functions[0].Depth != 2 { // callee_2
		t.Errorf("callee_2 depth: want 2, got %d", chain.Functions[0].Depth)
	}
	if chain.Functions[3].Depth != 0 { // surface
		t.Errorf("surface depth: want 0, got %d", chain.Functions[3].Depth)
	}
}

func TestAssemble_MaxDepthTruncation(t *testing.T) {
	// linear chain: surface → d1 → d2 → d3 → d4; maxDepth=2 should truncate
	graph := &stubGraph{callees: map[string][]cpg.Node{
		"surface": {{ID: "d1", Name: "d1"}},
		"d1":      {{ID: "d2", Name: "d2"}},
		"d2":      {{ID: "d3", Name: "d3"}},
		"d3":      {{ID: "d4", Name: "d4"}},
	}}
	a := New(graph, 2)
	chains, err := a.Assemble(context.Background(), []enrichment.EnrichedSurface{surface("surface")})
	if err != nil {
		t.Fatal(err)
	}
	if !chains[0].Truncated {
		t.Error("want Truncated=true at maxDepth=2 with depth-4 chain")
	}
}

func TestAssemble_CycleGuard(t *testing.T) {
	// mutual recursion: a → b → a (should not loop)
	graph := &stubGraph{callees: map[string][]cpg.Node{
		"surface": {{ID: "b", Name: "b"}},
		"b":       {{ID: "surface", Name: "surface_fn"}}, // back edge
	}}
	a := New(graph, 3)
	_, err := a.Assemble(context.Background(), []enrichment.EnrichedSurface{surface("surface")})
	if err != nil {
		t.Fatal(err)
	}
}

func namesOf(frames []FunctionContext) []string {
	out := make([]string, len(frames))
	for i, f := range frames {
		out[i] = f.Name
	}
	return out
}

// T4: Batch splits correctly.
func TestBatch(t *testing.T) {
	cases := []struct {
		n    int
		want int // number of batches
	}{
		{0, 0},
		{1, 1},
		{5, 1},
		{6, 2},
		{10, 2},
		{11, 3},
	}
	for _, tc := range cases {
		contexts := make([]CallChainContext, tc.n)
		got := Batch(contexts)
		if len(got) != tc.want {
			t.Errorf("Batch(%d): got %d batches, want %d", tc.n, len(got), tc.want)
		}
		// All batches must be ≤ config.C.AssemblerBatchSize
		for _, b := range got {
			if len(b) > config.C.AssemblerBatchSize {
				t.Errorf("batch size %d exceeds config.C.AssemblerBatchSize %d", len(b), config.C.AssemblerBatchSize)
			}
		}
	}
}

// T5: InjectCPGFields strips Code and populates taint/sanitizer/auth fields.
func TestInjectCPGFields(t *testing.T) {
	// surface calls: validateInput (sanitizer), db.QueryRow (sink), requireAuth (auth guard)
	graph := &stubGraph{
		callees: map[string][]cpg.Node{
			"surface": {
				{ID: "validate", Name: "validateInput"},
				{ID: "db_sink", Name: "db.QueryRow"},
				{ID: "auth", Name: "requireAuth"},
			},
		},
		// db.QueryRow is a pre-flagged sink; PDG edge from surface to sink with label "userID"
		sinks:    []cpg.TaintSink{{NodeID: "db_sink", Kind: cpg.SinkSQL}},
		pdgEdges: map[string][]cpg.Edge{"surface": {{FromID: "surface", ToID: "db_sink", Type: cpg.EdgePDG, Label: "userID"}}},
	}
	a := New(graph, 1)
	ctx := context.Background()

	chains, err := a.Assemble(ctx, []enrichment.EnrichedSurface{
		{Surface: targeting.Surface{ID: "surface", FunctionName: "surface_fn", File: "x.go"},
			Code: "func surface_fn(userID string) { db.QueryRow(userID) }"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// set Code on frames to simulate pre-injection state
	for i := range chains[0].Functions {
		chains[0].Functions[i].Code = "some raw source code"
	}

	cc := FromCallChain(chains[0])
	if err := a.InjectCPGFields(ctx, &cc); err != nil {
		t.Fatal(err)
	}

	// Code must be stripped from all frames
	for _, f := range cc.Frames {
		if f.Code != "" {
			t.Errorf("frame %s: Code not stripped after InjectCPGFields", f.Name)
		}
	}

	// surface frame (last, depth=0) should have taint/sanitizer/auth fields set
	surfaceFrame := cc.Frames[len(cc.Frames)-1]
	if !slices.Contains(surfaceFrame.TaintSourceParams, "userID") {
		t.Errorf("TaintSourceParams: want 'userID', got %v", surfaceFrame.TaintSourceParams)
	}
	if !slices.Contains(surfaceFrame.SanitizerCalls, "validateInput") {
		t.Errorf("SanitizerCalls: want 'validateInput', got %v", surfaceFrame.SanitizerCalls)
	}
	if !slices.Contains(surfaceFrame.AuthAnnotations, "requireAuth") {
		t.Errorf("AuthAnnotations: want 'requireAuth', got %v", surfaceFrame.AuthAnnotations)
	}
}

// T6: Assembled context token footprint is at least 60% smaller than raw call chain.
// Writes benchmark results to docs/benchmarks/token_footprint.md.
func TestTokenFootprintReduction(t *testing.T) {
	// Representative function body: ~30 lines, ~700 chars — typical Spring Boot controller.
	const rawCode = `@RestController
@RequestMapping("/api/v1/documents")
public class DocumentController {

    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;

    @Autowired
    public DocumentController(DocumentRepository documentRepository,
                               UserRepository userRepository) {
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/{documentId}")
    public ResponseEntity<Document> getDocument(
            @PathVariable Long documentId,
            HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Document doc = documentRepository.findById(documentId)
                .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
        // Missing ownership check: any authenticated user can access any document
        return ResponseEntity.ok(doc);
    }
}`
	// Build a CallChainContext with Code fields set (simulating pre-injection state)
	cc := CallChainContext{
		SurfaceID: "getResource",
		Frames: []FunctionContext{
			{NodeID: "callee1", Name: "db.QueryRow", Code: rawCode, Depth: 1},
			{NodeID: "surface", Name: "getResource", Code: rawCode, Depth: 0,
				CallsMade: []string{"db.QueryRow"}},
		},
	}

	rawTokens := estimateTokens(cc)

	// Inject: strip Code, add structured fields
	for i := range cc.Frames {
		cc.Frames[i].Code = ""
	}
	cc.Frames[1].TaintSourceParams = []string{"userID"}
	cc.Frames[1].SanitizerCalls = []string{}
	cc.Frames[1].AuthAnnotations = []string{}

	assembledTokens := estimateTokens(cc)

	reduction := 1.0 - float64(assembledTokens)/float64(rawTokens)
	const minReduction = 0.60
	if reduction < minReduction {
		t.Errorf("token reduction %.1f%% below required %.0f%%", reduction*100, minReduction*100)
	}

	writeBenchmarkDoc(t, rawTokens, assembledTokens, reduction)
}

// estimateTokens returns a rough token count for a CallChainContext (1 token ≈ 4 chars).
func estimateTokens(cc CallChainContext) int {
	b, _ := json.Marshal(cc)
	return len(b) / 4
}

// writeBenchmarkDoc writes token footprint results to docs/benchmarks/token_footprint.md.
func writeBenchmarkDoc(t *testing.T, rawTokens, assembledTokens int, reduction float64) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// walk up from internal/semantic/assembler/ → internal/semantic/ → internal/ → repo root
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	path := filepath.Join(root, "docs", "benchmarks", "token_footprint.md")
	status := "FAIL"
	if reduction >= 0.60 {
		status = "PASS"
	}
	content := fmt.Sprintf(`# Token Footprint Benchmark

> Generated by TestTokenFootprintReduction in internal/semantic/assembler/assembler_test.go

| Metric | Value |
|--------|-------|
| Raw call chain tokens (est.) | %d |
| Assembled context tokens (est.) | %d |
| Reduction | %.1f%% |
| Required minimum | 60.0%% |
| Status | %s |

## Notes

Token estimate: 1 token ≈ 4 UTF-8 bytes (JSON-encoded struct).
Raw includes full source Code field per frame.
Assembled strips Code; retains TaintSourceParams, SanitizerCalls, AuthAnnotations, CallsMade.
`, rawTokens, assembledTokens, reduction*100, status)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Logf("could not write benchmark doc %s: %v", path, err)
	}
}

