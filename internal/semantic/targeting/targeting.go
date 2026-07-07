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

// Package targeting implements Path B Tier 1 surface selection.
//
// Surface selection is based on import-boundary analysis + call graph
// reachability. No method-name patterns are used; the only patterns are
// package import prefixes (~40 entries) which are stable across framework
// versions and custom wrapper libraries.
//
// Algorithm:
//  1. Walk source files, classify each by imported package category
//     (Source / Sink / Auth boundary) — pure Go, no Joern.
//  2. Tag METHOD nodes by their containing file's boundary class.
//  3. Forward BFS from source-boundary seeds.
//     Backward BFS (reverse call graph) from sink-boundary seeds.
//     Intersection = functions on a path from external input to a privileged sink.
//  4. IDOR candidates: surfaces that cannot transitively reach any auth-boundary
//     function before reaching the sink.
//
// Design reference: BolaRay (CCS 2024) for zero-trust resource ID model.
package targeting

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"sort"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// SurfaceKind classifies why a surface was selected.
type SurfaceKind string

const (
	SurfaceExternalInput SurfaceKind = "external_input"
	SurfaceAuthBoundary  SurfaceKind = "auth_boundary"
	SurfaceIDORCandidate SurfaceKind = "idor_candidate"
	SurfaceDangerousSink SurfaceKind = "dangerous_sink"
)

// Surface is a code location selected for deeper analysis.
type Surface struct {
	ID              string
	File            string
	FunctionName    string
	NodeType        cpg.NodeType
	Kind            SurfaceKind
	CallGraphDepth  int
	IsIDORCandidate bool
	IsSecondOrder   bool
	CVSSScore       float64
	HasCVEMatch     bool
	ConfidenceScore float64
}

// CallGraph maps each function node ID to the IDs of functions it directly calls.
type CallGraph map[string][]string

// CallGraphDepth returns 0 if id is in the call graph, -1 if not.
func (cg CallGraph) CallGraphDepth(id string) int {
	if _, ok := cg[id]; ok {
		return 0
	}
	return -1
}

// Targeter selects analysis surfaces from the CPG using import-boundary
// analysis and call graph reachability.
type Targeter struct {
	graph     cpg.Graph
	callGraph cpg.CallGraph
	fileClass map[string]FileClass // populated during Run()
	root      string                // absolute path to project root; used by AnalyzeImports
}

// New returns a Targeter. root is the absolute path to the project root,
// used for the import boundary walk.
func New(graph cpg.Graph, root string) *Targeter {
	return &Targeter{graph: graph, root: root}
}

// ── Graph traversal helpers ───────────────────────────────────────────────────

// bfsForward performs BFS from seeds following the forward direction of cg.
// Returns the set of all reachable node IDs (seeds included).
func bfsForward(cg cpg.CallGraph, seeds []string) map[string]bool {
	visited := make(map[string]bool, len(seeds)*4)
	queue := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if !visited[s] {
			visited[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, next := range cg[id] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	return visited
}

// buildReverseCG inverts the call graph: callee → []caller.
func buildReverseCG(cg cpg.CallGraph) cpg.CallGraph {
	rev := make(cpg.CallGraph, len(cg))
	for caller, callees := range cg {
		for _, callee := range callees {
			rev[callee] = append(rev[callee], caller)
		}
	}
	return rev
}

// bfsDepths returns the minimum hop distance from any seed for each reachable
// node ID. Unreachable nodes are absent from the map.
func bfsDepths(cg cpg.CallGraph, seeds []string) map[string]int {
	type entry struct {
		id    string
		depth int
	}
	depths := make(map[string]int, len(seeds)*4)
	queue := make([]entry, 0, len(seeds))
	for _, s := range seeds {
		if _, seen := depths[s]; !seen {
			depths[s] = 0
			queue = append(queue, entry{s, 0})
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range cg[cur.id] {
			if _, seen := depths[next]; !seen {
				depths[next] = cur.depth + 1
				queue = append(queue, entry{next, cur.depth + 1})
			}
		}
	}
	return depths
}

// ── Core selection ────────────────────────────────────────────────────────────

// Run queries the CPG and returns the ranked surface list.
//
// Selection: functions that lie on a call-graph path from a source-boundary
// file (imports an HTTP/IO package) to a sink-boundary file (imports a
// DB/exec/fs package). Auth-boundary and IDOR classification are derived
// structurally from the same call graph without any method-name matching.
//
// Sort order: IDOR > auth_boundary > external_input, then ascending
// CallGraphDepth (entry points first), then stable by ID.
func (t *Targeter) Run(ctx context.Context) ([]Surface, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Phase 1: classify files by import boundaries.
	fileClasses, err := AnalyzeImports(ctx, t.root)
	if err != nil {
		return nil, fmt.Errorf("targeting: import analysis: %w", err)
	}
	t.fileClass = fileClasses

	// Phase 2: bulk-fetch call graph from Joern (one HTTP round-trip).
	joernCG, err := t.graph.GetCallGraph()
	if err != nil {
		return nil, fmt.Errorf("targeting: GetCallGraph: %w", err)
	}
	t.callGraph = joernCG

	// Phase 3: fetch all METHOD nodes and seed them by file boundary.
	methods, err := t.graph.QueryNodes(cpg.NodeMethod)
	if err != nil {
		return nil, fmt.Errorf("targeting: QueryNodes: %w", err)
	}

	byID := make(map[string]cpg.Node, len(methods))
	var sourceSeeds, sinkSeeds, authSeeds []string

	for _, m := range methods {
		byID[m.ID] = m
		absFile := m.File
		if !filepath.IsAbs(absFile) {
			absFile = filepath.Join(t.root, m.File)
		}
		fc, ok := fileClasses[absFile]
		if !ok {
			continue
		}
		if fc.Bound&BoundarySource != 0 {
			sourceSeeds = append(sourceSeeds, m.ID)
		}
		if fc.Bound&BoundarySink != 0 {
			sinkSeeds = append(sinkSeeds, m.ID)
		}
		if fc.Bound&BoundaryAuth != 0 {
			authSeeds = append(authSeeds, m.ID)
		}
	}

	slog.Info("targeting: seeds identified",
		slog.Int("source", len(sourceSeeds)),
		slog.Int("sink", len(sinkSeeds)),
		slog.Int("auth", len(authSeeds)),
		slog.Int("total_methods", len(methods)))

	if len(sourceSeeds) == 0 || len(sinkSeeds) == 0 {
		slog.Warn("targeting: no source or sink seeds found — check import boundary tables",
			slog.Int("source_seeds", len(sourceSeeds)),
			slog.Int("sink_seeds", len(sinkSeeds)))
		return nil, nil
	}

	// Phase 4: bidirectional BFS.
	// Forward from source seeds: all functions reachable from external input.
	forwardReachable := bfsForward(joernCG, sourceSeeds)

	// Backward from sink seeds: all functions that can reach a privileged sink.
	reverseCG := buildReverseCG(joernCG)
	backwardReachable := bfsForward(reverseCG, sinkSeeds)

	// Reverse from auth seeds: all functions that can reach an auth check.
	canReachAuth := bfsForward(reverseCG, authSeeds)

	// Hop depths from source entry points (for prioritisation).
	depths := bfsDepths(joernCG, sourceSeeds)

	// Phase 5: intersection → surfaces.
	// A surface lies on a path: source_boundary → ... → surface → ... → sink_boundary.
	authSeedSet := make(map[string]bool, len(authSeeds))
	for _, id := range authSeeds {
		authSeedSet[id] = true
	}

	merged := make(map[string]Surface, len(forwardReachable))
	for id := range forwardReachable {
		if !backwardReachable[id] {
			continue
		}
		m, ok := byID[id]
		if !ok {
			continue
		}
		kind := SurfaceExternalInput
		if authSeedSet[id] || canReachAuth[id] {
			kind = SurfaceAuthBoundary
		}
		merged[id] = Surface{
			ID:             m.ID,
			File:           m.File,
			FunctionName:   m.Name,
			NodeType:       cpg.NodeMethod,
			Kind:           kind,
			CallGraphDepth: depths[id],
		}
	}

	// Phase 6: IDOR detection.
	idorSurfaces := identifyIDOR(merged, canReachAuth)
	for _, s := range idorSurfaces {
		merged[s.ID] = s
	}

	// Phase 7: second-order source detection.
	secondOrderSurfaces := DetectSecondOrder(joernCG, methods, fileClasses, forwardReachable, backwardReachable)
	for _, s := range secondOrderSurfaces {
		if _, exists := merged[s.ID]; !exists {
			merged[s.ID] = s
		}
	}

	out := make([]Surface, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}

	slog.Info("targeting complete",
		slog.Int("methods_queried", len(methods)),
		slog.Int("surfaces_selected", len(out)),
		slog.Int("idor_candidates", len(idorSurfaces)))

	kindPriority := map[SurfaceKind]int{
		SurfaceIDORCandidate: 3,
		SurfaceAuthBoundary:  2,
		SurfaceExternalInput: 1,
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi := kindPriority[out[i].Kind]
		pj := kindPriority[out[j].Kind]
		if pi != pj {
			return pi > pj
		}
		if out[i].CallGraphDepth != out[j].CallGraphDepth {
			return out[i].CallGraphDepth < out[j].CallGraphDepth
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SelectSurfaces is an alias for Run kept for API compatibility.
func (t *Targeter) SelectSurfaces(ctx context.Context) ([]Surface, error) {
	return t.Run(ctx)
}

// ── CVE auto-flagging (unchanged) ────────────────────────────────────────────

// AutoFlagCVESurfaces splits surfaces into auto-flagged (CVE match, CVSS ≥ 4.0)
// and remainder. Auto-flagged surfaces bypass the CodeT5+ classifier.
func AutoFlagCVESurfaces(surfaces []Surface, cal config.Config) (flagged []Surface, remaining []Surface) {
	slog.Debug("targeting: auto-flagging CVE surfaces", slog.Int("surfaces", len(surfaces)))
	for _, s := range surfaces {
		if !s.HasCVEMatch {
			remaining = append(remaining, s)
			continue
		}
		cvss := s.CVSSScore
		if cvss == 0 {
			cvss = config.C.CVSSMissingDefault
		}
		conf := cvssConfidence(cvss, cal)
		if conf == 0 {
			remaining = append(remaining, s)
			continue
		}
		s.ConfidenceScore = conf
		flagged = append(flagged, s)
	}
	return flagged, remaining
}

func cvssConfidence(cvss float64, cal config.Config) float64 {
	if cal.CVSSPlattSlope != 0 {
		// ponytail: Platt sigmoid from calibration; replaces band bucketing once labeled data is available
		p := 1.0 / (1.0 + math.Exp(-(cal.CVSSPlattSlope*cvss + cal.CVSSPlattIntercept)))
		if cvss < config.C.CVSSMedium {
			return 0
		}
		return p
	}
	switch {
	case cvss >= config.C.CVSSCritical:
		return config.C.ConfCVSSCritical
	case cvss >= config.C.CVSSHigh:
		return config.C.ConfCVSSHigh
	case cvss >= config.C.CVSSMedium:
		return config.C.ConfCVSSMedium
	default:
		return 0
	}
}
