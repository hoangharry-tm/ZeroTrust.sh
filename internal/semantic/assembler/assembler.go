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
	"fmt"
	"log/slog"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
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
	// LineEnd is the 1-based end line; 0 if not available from the CPG.
	LineEnd int
	// Depth is the hop count from the surface node (surface = 0, direct callee = 1, …).
	Depth int
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
	// AuthAnnotations lists framework-level authorization annotations or guard calls
	// detected on this function (e.g. "@PreAuthorize", "requireAuth"). Populated by InjectCPGFields.
	AuthAnnotations []string
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
		maxDepth = tuning.AssemblerMaxDepth
	}
	return &Assembler{graph: graph, maxDepth: maxDepth}
}

// Assemble builds call chains for the given surfaces in callee-first order.
//
// For each surface, traverses callees depth-first up to maxDepth hops.
// Functions are appended in post-order so the deepest callee appears at index 0
// and the surface function appears last. This ordering satisfies the SCSS
// requirement: callee inferences are written to the store before the caller
// is processed.
//
// Parameters:
//   - ctx: cancellation context.
//   - surfaces: uncertain/escalated surfaces from the classifier stage.
//
// Returns:
//   - []CallChain: one call chain per input surface, in the same order.
//   - error: non-nil if CPG queries fail.
func (a *Assembler) Assemble(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]CallChain, error) {
	slog.Debug("assembling call chains", slog.Int("surfaces", len(surfaces)), slog.Int("max_depth", a.maxDepth))
	result := make([]CallChain, 0, len(surfaces))
	for i, s := range surfaces {
		slog.Debug("assembler: processing surface", slog.Int("idx", i), slog.String("id", s.ID), slog.String("function", s.FunctionName))
		chain, err := a.assembleOne(ctx, s)
		if err != nil {
			slog.Error("assemble surface failed", "err", err, slog.String("surface_id", s.ID))
			return nil, fmt.Errorf("assemble surface %s: %w", s.ID, err)
		}
		slog.Debug("assembler: chain done",
			slog.String("surface_id", s.ID),
			slog.Int("depth", chain.Depth),
			slog.Bool("truncated", chain.Truncated),
			slog.Int("functions", len(chain.Functions)),
		)
		result = append(result, chain)
	}
	slog.Info("call chains assembled", slog.Int("chains", len(result)))
	return result, nil
}

// assembleOne builds the callee-first call chain for a single surface.
func (a *Assembler) assembleOne(ctx context.Context, s enrichment.EnrichedSurface) (CallChain, error) {
	slog.Debug("assembler: assembleOne", slog.String("surface_id", s.ID), slog.String("function", s.FunctionName))
	root := cpg.Node{ID: s.ID, Name: s.FunctionName, File: s.File}
	frames := make([]FunctionContext, 0, a.maxDepth+1)
	visited := make(map[string]bool)
	truncated, err := a.dfsCallees(ctx, root, 0, &frames, visited)
	if err != nil {
		return CallChain{}, err
	}
	maxDepth := 0
	for _, f := range frames {
		if f.Depth > maxDepth {
			maxDepth = f.Depth
		}
	}
	return CallChain{
		SurfaceID: s.ID,
		Functions: frames,
		Depth:     maxDepth,
		Truncated: truncated,
	}, nil
}

// dfsCallees traverses callees depth-first and appends frames in post-order
// (deepest callee first, then the node itself). Returns true if truncated by maxDepth.
func (a *Assembler) dfsCallees(ctx context.Context, node cpg.Node, depth int, frames *[]FunctionContext, visited map[string]bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if depth > a.maxDepth {
		slog.Debug("assembler: dfs truncated at maxDepth", slog.Int("depth", depth), slog.Int("max_depth", a.maxDepth))
		return true, nil
	}
	visited[node.ID] = true

	callees, err := a.graph.GetCallees(node.ID)
	if err != nil {
		return false, fmt.Errorf("get callees %s: %w", node.ID, err)
	}

	callsMade := make([]string, 0, len(callees))
	truncated := false
	for _, callee := range callees {
		callsMade = append(callsMade, callee.Name)
		if visited[callee.ID] {
			continue
		}
		t, err := a.dfsCallees(ctx, callee, depth+1, frames, visited)
		if err != nil {
			return false, err
		}
		truncated = truncated || t
	}

	*frames = append(*frames, FunctionContext{
		NodeID:    node.ID,
		Name:      node.Name,
		File:      node.File,
		Line:      node.Line,
		Depth:     depth,
		Code:      node.Code,
		CallsMade: callsMade,
	})
	return truncated, nil
}
