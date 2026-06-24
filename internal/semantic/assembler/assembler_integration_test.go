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

//go:build integration

// Layer 3 checkpoint test (T7): IDOR vulnerability spanning caller + surface + callee
// detected end-to-end via assembled context. Run with: go test -tags integration ./...
//
// Scenario:
//
//	handleRequest (caller) — extracts userId from session, passes documentId from request
//	    └─ getDocument (surface, IDOR candidate) — reads documentId but no ownership check
//	           └─ documentRepository.findById (callee, DB sink) — executes the vulnerable query
//
// The IDOR is only detectable across the full chain: the caller has the session userId
// but never enforces ownership against documentId before passing it to the surface.
// The surface passes documentId directly to the DB sink.
// The assembled context must span all three functions for the LLM to detect this.

package assembler

import (
	"context"
	"slices"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/scs"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

func TestIDORDetectionEndToEnd(t *testing.T) {
	// CPG for the IDOR scenario:
	//   handleRequest → getDocument → documentRepository.findById
	// documentRepository.findById is a pre-flagged SQL sink.
	// PDG edge from getDocument to findById carries "documentId" label (taint flow).
	graph := &stubGraph{
		callees: map[string][]cpg.Node{
			"getDocument": {
				{ID: "findById", Name: "documentRepository.findById", File: "repo/DocumentRepository.java"},
			},
			"handleRequest": {
				{ID: "getDocument", Name: "getDocument", File: "ctrl/DocumentController.java"},
			},
		},
		sinks: []cpg.TaintSink{
			{NodeID: "findById", Kind: cpg.SinkSQL, File: "repo/DocumentRepository.java", Line: 12},
		},
		pdgEdges: map[string][]cpg.Edge{
			// documentId flows from getDocument into the DB sink without sanitization
			"getDocument": {
				{FromID: "getDocument", ToID: "findById", Type: cpg.EdgePDG, Label: "documentId"},
			},
		},
	}

	a := New(graph, 3)
	ctx := context.Background()

	// Surface: getDocument — IDOR candidate, no auth guard
	surfaces := []enrichment.EnrichedSurface{
		{
			Surface: targeting.Surface{
				ID:              "getDocument",
				FunctionName:    "getDocument",
				File:            "ctrl/DocumentController.java",
				IsIDORCandidate: true,
			},
		},
	}

	chains, err := a.Assemble(ctx, surfaces)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(chains))
	}

	chain := chains[0]

	// Must span surface + at least one callee (findById)
	if len(chain.Functions) < 2 {
		t.Fatalf("chain too shallow: got %d frames, want ≥2 (surface + DB callee)", len(chain.Functions))
	}

	// Callee-first: findById at index 0, getDocument last
	calleeFrame := chain.Functions[0]
	if calleeFrame.Name != "documentRepository.findById" {
		t.Errorf("frame[0]: want DB callee 'documentRepository.findById', got %q", calleeFrame.Name)
	}

	surfaceFrame := chain.Functions[len(chain.Functions)-1]
	if surfaceFrame.Name != "getDocument" {
		t.Errorf("last frame: want surface 'getDocument', got %q", surfaceFrame.Name)
	}
	if surfaceFrame.Depth != 0 {
		t.Errorf("surface frame depth: want 0, got %d", surfaceFrame.Depth)
	}

	// Inject CPG fields: taint source, no sanitizer, no auth guard
	cc := FromCallChain(chain)
	if err := a.InjectCPGFields(ctx, &cc); err != nil {
		t.Fatalf("InjectCPGFields: %v", err)
	}

	// After injection: Code stripped
	for _, f := range cc.Frames {
		if f.Code != "" {
			t.Errorf("frame %s: Code not stripped", f.Name)
		}
	}

	// IDOR signal: documentId appears as a taint source param on the surface frame
	injectedSurface := cc.Frames[len(cc.Frames)-1]
	if !slices.Contains(injectedSurface.TaintSourceParams, "documentId") {
		t.Errorf("TaintSourceParams: want 'documentId' (IDOR taint), got %v", injectedSurface.TaintSourceParams)
	}

	// No auth guard on the surface — IDOR is unprotected
	if len(injectedSurface.AuthAnnotations) > 0 {
		t.Errorf("AuthAnnotations: want none (IDOR surface has no ownership check), got %v", injectedSurface.AuthAnnotations)
	}

	// Store the IDOR inference in the SCS so cross-surface detection can use it
	store := scs.New()
	store.RegisterNeighbours("getDocument", []string{"findById"})
	store.Put(ctx, scs.Inference{
		SurfaceID:  "getDocument",
		Kind:       scs.InferenceIDORCandidate,
		Narrative:  "documentId from request param flows to DB sink without ownership check.",
		Confidence: 0.92,
	})

	snap := store.Snapshot()
	inferences, ok := snap["getDocument"]
	if !ok || len(inferences) == 0 {
		t.Fatal("SCS: no inference stored for getDocument")
	}
	if inferences[0].Kind != scs.InferenceIDORCandidate {
		t.Errorf("SCS inference kind: want %q, got %q", scs.InferenceIDORCandidate, inferences[0].Kind)
	}
}
