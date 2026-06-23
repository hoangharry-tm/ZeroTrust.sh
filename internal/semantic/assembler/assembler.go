// Copyright 2026 hoangharry-tm
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

// Package assembler implements the Call Chain Context Assembler (Path B Tier 2).
//
// For each uncertain surface the Assembler traces the call chain up to depth 3
// from the Joern CPG in callee-first (bottom-up) order. Callee-first ordering
// ensures that when a caller function is submitted to the Summarizer and LLM,
// inferences about its callees are already available in the Scan Security Context Store.
//
// Depth 3 is a token-budget constraint (not a taint-correctness bound — that is
// depth 5 for the CPG incremental patch). Going deeper than 3 at this stage
// would exceed the Semantic Function Summarizer's prompt budget for most models.
//
// Multi-function context enables detection of:
//   - IDOR / missing auth guards: auth check is in a parent caller, not the sink function.
//   - Business logic flaws: condition is set in one function, checked in another.
//
// Surfaces flagged LabelSafe by the classifier with high confidence do not reach
// this stage. Only uncertain or escalated surfaces are assembled.
package assembler

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// FunctionContext holds the CPG-derived context for one function in the call chain.
type FunctionContext struct {
	// NodeID is the Joern CPG METHOD node identifier.
	NodeID string
	// Name is the fully qualified function or method name.
	Name string
	// File is the source file path relative to the project root.
	File string
	// Line is the 1-based start line of the function definition.
	Line int
	// Parameters is the ordered list of parameter names for this function.
	Parameters []string
	// CallsMade is the list of function names directly called from this function.
	// Derived from CPG CALL edges; used by the Summarizer for sink identification.
	CallsMade []string
	// Code is the raw source snippet for this function (populated when available).
	Code string
	// TaintSourceParams lists parameters that carry untrusted data into this function.
	// Derived from CPG PDG edges from external-input nodes.
	TaintSourceParams []string
	// SanitizerCalls lists calls to functions identified as sanitizers on the taint path.
	SanitizerCalls []string
}

// CallChain is the ordered call chain assembled for one uncertain surface.
// Functions are ordered callee-first (bottom-up): index 0 is the deepest callee,
// the last element is the entry-point caller closest to the external input.
type CallChain struct {
	// SurfaceID matches the input enrichment.EnrichedSurface.ID.
	SurfaceID string
	// Functions is the ordered call chain (callee-first, depth ≤ maxDepth).
	Functions []FunctionContext
	// Depth is the actual traversal depth achieved (≤ Assembler.maxDepth).
	Depth int
	// Truncated is true when the chain reached maxDepth before the entry-point caller.
	Truncated bool
}

// Assembler traces call chains from the CPG for uncertain surfaces.
type Assembler struct {
	// graph is the shared Joern CPG.
	graph cpg.Graph
	// maxDepth is the maximum call chain traversal depth (default 3).
	maxDepth int
}

// New returns an Assembler with the given CPG and traversal depth cap.
// maxDepth ≤ 0 defaults to 3.
//
// Parameters:
//   - graph: the shared Joern CPG (must be built before Assemble is called).
//   - maxDepth: maximum call chain depth (token budget constraint; default 3).
func New(graph cpg.Graph, maxDepth int) *Assembler {
	if maxDepth <= 0 {
		maxDepth = 3
	}
	return &Assembler{graph: graph, maxDepth: maxDepth}
}

// Assemble builds call chains for the given surfaces in callee-first order.
//
// For each surface:
//  1. Query the CPG for caller functions up to maxDepth hops.
//  2. For each function in the chain, extract Parameters, CallsMade,
//     TaintSourceParams (PDG), and SanitizerCalls.
//  3. Return the chain ordered callee-first.
//
// Parameters:
//   - ctx: cancellation context.
//   - surfaces: uncertain/escalated surfaces from the classifier stage.
//
// Returns:
//   - []CallChain: one call chain per input surface, in the same order.
//   - error: non-nil if CPG queries fail.
func (a *Assembler) Assemble(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]CallChain, error) {
	// implemented in G3.M3.3
	return nil, nil
}

// buildFunctionContext queries the CPG for a single function node and constructs
// its FunctionContext, including parameters, call edges, and taint metadata.
//
// Parameters:
//   - ctx: cancellation context.
//   - nodeID: the Joern CPG METHOD node identifier.
func (a *Assembler) buildFunctionContext(ctx context.Context, nodeID string) (FunctionContext, error) {
	// implemented in G3.M3.3
	return FunctionContext{}, nil
}
