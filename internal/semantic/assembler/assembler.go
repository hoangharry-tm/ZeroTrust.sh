// Package assembler implements the Call Chain Context Assembler (Path B Tier 2).
// For each uncertain surface it traces the call chain to depth 3 from the Joern CPG
// in callee-first (bottom-up) order, assembling multi-function context required for
// authorization and logic flaw detection.
package assembler

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// FunctionContext holds the CPG-derived context for one function in the chain.
type FunctionContext struct {
	NodeID      string
	Name        string
	File        string
	Line        int
	Parameters  []string
	CallsMade   []string
}

// CallChain is the ordered call chain assembled for one uncertain surface.
// Functions are ordered callee-first (bottom-up) so Scan Security Context Store
// inferences about callees are available when callers are analysed.
type CallChain struct {
	SurfaceID string
	Functions []FunctionContext // index 0 = deepest callee, last = entry-point caller
	Depth     int
}

// Assembler traces call chains from the CPG for uncertain surfaces.
type Assembler struct {
	graph cpg.Graph
	maxDepth int
}

// New returns an Assembler with the given CPG and traversal depth cap.
func New(graph cpg.Graph, maxDepth int) *Assembler {
	if maxDepth <= 0 {
		maxDepth = 3
	}
	return &Assembler{graph: graph, maxDepth: maxDepth}
}

// Assemble builds call chains for the given surfaces in callee-first order.
func (a *Assembler) Assemble(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]CallChain, error) {
	// implemented in G3.M3.3
	return nil, nil
}
