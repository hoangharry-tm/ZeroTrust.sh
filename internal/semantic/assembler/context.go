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

// CallChainContext is the assembled multi-function context for one surface,
// used by the batch assembler (T4) and the LLM Semantic Scan. It carries the
// full caller → surface → callee chain with per-frame depth annotations.
//
// Frames are ordered callee-first (index 0 = deepest callee reached; last
// index = surface node at depth 0). This mirrors CallChain.Functions ordering
// and satisfies the SCSS callee-before-caller write requirement.
type CallChainContext struct {
	// SurfaceID matches the enrichment.EnrichedSurface.ID.
	SurfaceID string
	// Frames holds the call chain in callee-first order (deepest callee first).
	// Each frame carries its Depth relative to the surface (surface = 0).
	Frames []FunctionContext
	// Depth is the maximum traversal depth achieved across all frames.
	Depth int
	// Truncated is true when maxDepth was reached before all callees were explored.
	Truncated bool
}

// FromCallChain converts a CallChain into a CallChainContext for downstream consumers.
func FromCallChain(cc CallChain) CallChainContext {
	return CallChainContext{
		SurfaceID: cc.SurfaceID,
		Frames:    cc.Functions,
		Depth:     cc.Depth,
		Truncated: cc.Truncated,
	}
}
