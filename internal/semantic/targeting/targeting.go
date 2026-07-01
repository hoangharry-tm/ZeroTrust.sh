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

// Package targeting implements Path B Tier 1 Heuristic Targeting.
//
// The Targeter queries the Joern CPG for language-agnostic surface selection,
// targeting external-input nodes and auth-boundary nodes. Typically ~95% of
// files are eliminated at this tier (design target; pending CVEFixes benchmark).
//
// AI agent config file nodes are handled by Path A (instrscan) and are explicitly
// excluded from targeting output.
//
// IDOR candidate detection: the Targeter applies a lightweight zero-trust
// resource ID heuristic — any function that reads an external ID (URL path
// parameter, query parameter, request body field) and passes it to a database
// or storage layer is flagged as an IDOR candidate. All IDOR candidates bypass
// the CodeT5+ classifier and escalate directly to the LLM tier.
//
// Design reference: BolaRay (CCS 2024) for zero-trust resource ID model.
package targeting

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// SurfaceKind classifies why a surface was selected by Heuristic Targeting.
type SurfaceKind string

const (
	// SurfaceExternalInput marks a surface that receives data from an external source
	// (HTTP request, file read, env var, IPC message).
	SurfaceExternalInput SurfaceKind = "external_input"
	// SurfaceAuthBoundary marks a surface at an authorization decision point.
	SurfaceAuthBoundary SurfaceKind = "auth_boundary"
	// SurfaceIDORCandidate marks a surface that reads an external resource ID and
	// passes it to a storage layer without a confirmed ownership check.
	SurfaceIDORCandidate SurfaceKind = "idor_candidate"
	// SurfaceDangerousSink marks a surface that directly calls a dangerous sink
	// (pre-flagged by Tree-sitter; always in scope regardless of module segmentation).
	SurfaceDangerousSink SurfaceKind = "dangerous_sink"
)

// Surface is a code location selected by Heuristic Targeting for deeper analysis.
type Surface struct {
	// ID is the CPG function node identifier (Joern METHOD node ID).
	ID string
	// File is the source file path relative to the project root.
	File string
	// FunctionName is the human-readable function or method name.
	FunctionName string
	// NodeType is the primary CPG node type for this surface.
	NodeType cpg.NodeType
	// Kind classifies why this surface was selected.
	Kind SurfaceKind
	// CallGraphDepth is the hop count from the nearest external-input node.
	// Used by the Token Budget Controller's reachability_from_entry weight.
	CallGraphDepth int
	// IsIDORCandidate is true when the surface matches the zero-trust resource
	// ID heuristic. IDOR candidates always escalate to the LLM tier.
	IsIDORCandidate bool
	// CVSSScore is the highest CVSS score among CVE matches for this surface's
	// dependencies (0.0 if no CVE match; populated by the enrichment stage).
	CVSSScore float64
	// HasCVEMatch is true when at least one CVE was found for this surface's dependencies.
	HasCVEMatch bool
	// ConfidenceScore is the SSVC-inspired confidence set by AutoFlagCVESurfaces.
	ConfidenceScore float64
}

// CallGraph maps each function node ID to the IDs of functions it directly calls.
// Built by buildCallGraph from a seed set of external-input nodes.
type CallGraph map[string][]string

// CallGraphDepth returns 0 if id is present in the call graph, -1 if not.
// Use this to test reachability; actual hop depth is set in Surface.CallGraphDepth by Run.
func (cg CallGraph) CallGraphDepth(id string) int {
	if _, ok := cg[id]; ok {
		return 0
	}
	return -1
}

// Targeter selects analysis surfaces from the CPG.
type Targeter struct {
	graph     cpg.Graph
	callGraph cpg.CallGraph // bulk-fetched once per Run; used by buildCallGraph in-memory
}

// New returns a Targeter reading from graph.
// graph must be fully built (BuildCPG completed) before SelectSurfaces is called.
func New(graph cpg.Graph) *Targeter {
	return &Targeter{graph: graph}
}

// externalInputPatterns are PDG edge label substrings that indicate a function
// receives data from an external source (HTTP, env, file, stdin).
var externalInputPatterns = []string{
	// HTTP / web frameworks
	"getParameter", "pathVariable", "QueryParam", "PathParam",
	"getBody", "FormValue", "PostFormValue", "URL.Query",
	"r.URL", "r.Form", "r.Body", "r.Header",
	"Request.Body", "Context.Param", "Context.Query",
	"c.Param", "c.Query", "c.PostForm",
	// Environment
	"os.Getenv", "Getenv",
	// File I/O
	"os.Open", "os.ReadFile", "ioutil.ReadFile", "bufio.NewReader",
	// Stdin / CLI
	"os.Stdin", "os.Args", "flag.Parse",
}

// authBoundaryNamePatterns are substrings checked case-insensitively in function names.
var authBoundaryNamePatterns = []string{
	"auth", "login", "logout", "verify", "validate",
	"permission", "authorize", "acl", "policy", "role",
	"access", "middleware", "jwt", "oauth", "session",
	"credential", "check",
}

// authBoundaryEdgePatterns are PDG edge label substrings indicating a framework
// annotation or explicit guard call that constitutes an authorization boundary.
var authBoundaryEdgePatterns = []string{
	"@PreAuthorize", "@Secured", "@AuthenticationPrincipal",
	"@RolesAllowed", "requireAuth", "IsAuthenticated",
}

// IsExternalInputNode reports whether the given CPG node receives external data.
// Checks PDG edges from the node for patterns matching HTTP params, env vars,
// file reads, and stdin access.
func (t *Targeter) IsExternalInputNode(ctx context.Context, node cpg.Node) (bool, error) {
	edges, err := t.graph.QueryEdges(node.ID, "")
	if err != nil {
		return false, err
	}
	for _, e := range edges {
		if e.Type != cpg.EdgePDG {
			continue
		}
		if matchesAny(e.Label, externalInputPatterns) {
			return true, nil
		}
	}
	return false, nil
}

// IsAuthBoundaryNode reports whether the given CPG method node is an
// authorization decision point based on identifier name heuristics and
// the presence of framework-level annotation edges.
func (t *Targeter) IsAuthBoundaryNode(ctx context.Context, node cpg.Node) (bool, error) {
	nameLower := strings.ToLower(node.Name)
	for _, p := range authBoundaryNamePatterns {
		if strings.Contains(nameLower, p) {
			return true, nil
		}
	}
	edges, err := t.graph.QueryEdges(node.ID, "")
	if err != nil {
		return false, err
	}
	for _, e := range edges {
		if matchesAny(e.Label, authBoundaryEdgePatterns) {
			return true, nil
		}
	}
	return false, nil
}

// queryExternalInputNodes returns all METHOD nodes whose PDG edges indicate
// that they receive externally controlled data.
func (t *Targeter) queryExternalInputNodes(ctx context.Context) ([]cpg.Node, error) {
	methods, err := t.graph.QueryNodes(cpg.NodeMethod)
	if err != nil {
		return nil, err
	}
	out := make([]cpg.Node, 0, len(methods))
	for _, m := range methods {
		ok, err := t.IsExternalInputNode(ctx, m)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// buildCallGraph performs a BFS from the seed nodes, following callee edges
// via the in-memory CallGraph map (bulk-fetched once by Run). No HTTP queries
// are made — the full edge set is already in t.callGraph.
// Cycles are handled via a visited set — each node is expanded at most once.
func (t *Targeter) buildCallGraph(_ context.Context, seeds []cpg.Node) (CallGraph, error) {
	slog.Info("targeting: building call graph (in-memory)", slog.Int("seeds", len(seeds)))
	cg := make(CallGraph)
	visited := make(map[string]bool)
	queue := make([]string, len(seeds))
	for i, s := range seeds {
		queue[i] = s.ID
	}

	expanded := 0
	bfsStart := time.Now()
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		expanded++

		if expanded%50 == 0 {
			elapsed := time.Since(bfsStart)
			elapsedSec := elapsed.Seconds()
			rate := float64(expanded) / elapsedSec
			remaining := len(queue)
			eta := time.Duration(float64(remaining)/elapsedSec*float64(time.Second)) * time.Second
			slog.Info("targeting: call graph BFS",
				slog.Int("expanded", expanded),
				slog.Int("queued", len(queue)),
				slog.Float64("elapsed_seconds", elapsedSec),
				slog.Float64("throughput_ops_per_sec", rate),
				slog.String("eta", eta.Round(time.Second).String()),
			)
		}

		calleeIDs := t.callGraph[id]
		ids := make([]string, 0, len(calleeIDs))
		for _, cid := range calleeIDs {
			ids = append(ids, cid)
			if !visited[cid] {
				queue = append(queue, cid)
			}
		}
		cg[id] = ids
	}
	slog.Info("targeting: call graph built",
		slog.Int("nodes", expanded),
		slog.Duration("elapsed", time.Since(bfsStart)),
	)
	return cg, nil
}

// bfsHopDepths computes the minimum BFS hop distance from root nodes (seeds with
// no callers among other seeds) in the CallGraph. Returns a map of nodeID → depth.
// Nodes not reachable from any root get depth = maxInt (treated as unknown).
func bfsHopDepths(cg CallGraph, seeds []cpg.Node) map[string]int {
	// Find seed IDs called by other seeds — they are not root entries.
	seedSet := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedSet[s.ID] = true
	}
	calledByOtherSeed := make(map[string]bool)
	for _, s := range seeds {
		for _, calleeID := range cg[s.ID] {
			if seedSet[calleeID] {
				calledByOtherSeed[calleeID] = true
			}
		}
	}

	depths := make(map[string]int)
	type entry struct {
		id    string
		depth int
	}
	queue := make([]entry, 0, len(seeds))
	for _, s := range seeds {
		if !calledByOtherSeed[s.ID] {
			queue = append(queue, entry{s.ID, 0})
			depths[s.ID] = 0
		}
	}
	// Seeds with no root callers get depth 0 only if unreachable via BFS.
	// Handled after BFS below.

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, calleeID := range cg[cur.id] {
			if _, seen := depths[calleeID]; !seen {
				depths[calleeID] = cur.depth + 1
				queue = append(queue, entry{calleeID, cur.depth + 1})
			}
		}
	}
	// Seeds unreachable from any root seed (isolated entry points) get depth 0.
	for _, s := range seeds {
		if _, seen := depths[s.ID]; !seen {
			depths[s.ID] = 0
		}
	}
	return depths
}

// AutoFlagCVESurfaces splits surfaces into auto-flagged (CVE match with CVSS ≥ 4.0)
// and remainder. Auto-flagged surfaces have ConfidenceScore set and bypass the
// CodeT5+ classifier. Missing CVSS (0.0) is treated as 5.0.
//
// cal controls the confidence mapping: Platt sigmoid when calibrated, band
// bucketing otherwise. Use config.Default() when no file is loaded.
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

// cvssConfidence maps a CVSS score to a confidence value.
// When cal has non-zero Platt parameters, it applies σ(slope×cvss + intercept).
// Otherwise it falls back to the three-band step function.
// Returns 0 when the score is below the auto-flag threshold (4.0).
func cvssConfidence(cvss float64, cal config.Config) float64 {
	if cal.CVSSPlattSlope != 0 {
		// ponytail: Platt sigmoid from calibration; replaces band bucketing once labeled data is available
		p := 1.0 / (1.0 + math.Exp(-(cal.CVSSPlattSlope*cvss+cal.CVSSPlattIntercept)))
		if cvss < config.C.CVSSMedium {
			return 0
		}
		return p
	}
	// Band bucketing fallback (compile-time defaults).
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

// Run queries the CPG and returns the ranked list of surfaces for deeper analysis.
// AI agent config file nodes are excluded (handled by Path A).
//
// Selection order:
//  1. IDOR candidates (always first — mandatory LLM escalation).
//  2. Auth-boundary nodes.
//  3. External-input nodes, sorted by ascending CallGraphDepth (entry points first).
//
// Duplicate node IDs are collapsed: IDOR > auth_boundary > external_input.
func (t *Targeter) Run(ctx context.Context) ([]Surface, error) {
	// Phase-level deadline: abort if the whole targeting phase exceeds budget.
	ctx, cancel := context.WithTimeout(ctx, max(5*time.Minute, 10*time.Millisecond*time.Duration(1)))
	defer cancel()

	slog.Debug("targeting: querying CPG for method nodes")
	methods, err := t.graph.QueryNodes(cpg.NodeMethod)
	if err != nil {
		slog.Error("targeting: CPG QueryNodes failed", "err", err)
		return nil, err
	}

	total := len(methods)
	slog.Info("targeting: scanning methods", slog.Int("total", total))

	// Bulk-fetch the full call graph once; all downstream in-memory traversals
	// read from this map instead of issuing per-node HTTP calls to Joern.
	slog.Debug("targeting: fetching full call graph")
	cg, err := t.graph.GetCallGraph()
	if err != nil {
		return nil, fmt.Errorf("targeting: GetCallGraph: %w", err)
	}
	t.callGraph = cg

	type nodeResult struct {
		node cpg.Node
		kind SurfaceKind
	}

	// Concurrently classify every method using a fixed-size worker pool.
	// Each iteration fires QueryEdges (PDG lookups) which are I/O-bound HTTP
	// calls to Joern — the worker pool pipelines them for throughput.
	limit := runtime.GOMAXPROCS(0) * 2
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)

	var (
		mu           sync.Mutex
		extInputNodes []cpg.Node
		candidates   []nodeResult
	)
	loopStart := time.Now()
	done := 0

	for _, m := range methods {
		m := m
		g.Go(func() error {
			isExt, err := t.IsExternalInputNode(gctx, m)
			if err != nil {
				return err
			}
			isAuth, err := t.IsAuthBoundaryNode(gctx, m)
			if err != nil {
				return err
			}

			mu.Lock()
			done++
			if done%100 == 0 {
				elapsed := time.Since(loopStart)
				elapsedSec := elapsed.Seconds()
				rate := float64(done) / elapsedSec
				remaining := total - done
				eta := time.Duration(float64(remaining)/elapsedSec*float64(time.Second)) * time.Second
				slog.Info("targeting: progress",
					slog.Int("done", done),
					slog.Int("total", total),
					slog.Float64("pct", float64(done)/float64(total)*100),
					slog.Float64("elapsed_seconds", elapsedSec),
					slog.Float64("throughput_ops_per_sec", rate),
					slog.String("eta", eta.Round(time.Second).String()),
				)
			}
			if isExt {
				extInputNodes = append(extInputNodes, m)
				candidates = append(candidates, nodeResult{m, SurfaceExternalInput})
			} else if isAuth {
				candidates = append(candidates, nodeResult{m, SurfaceAuthBoundary})
			}
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	slog.Debug("targeting: candidates identified", slog.Int("external_input", len(extInputNodes)), slog.Int("total_candidates", len(candidates)))

	idorSurfaces, err := t.queryIDORCandidates(ctx, DefaultIDORConfig())
	if err != nil {
		return nil, err
	}
	slog.Debug("targeting: IDOR candidates", slog.Int("count", len(idorSurfaces)))

	// Build call graph and compute hop depths from entry-point seeds.
	// Uses the already-bulk-fetched t.callGraph — zero HTTP calls.
	subCg, err := t.buildCallGraph(ctx, extInputNodes)
	if err != nil {
		return nil, err
	}
	depths := bfsHopDepths(subCg, extInputNodes)

	// Merge into deduped map; IDOR > auth_boundary > external_input.
	kindPriority := map[SurfaceKind]int{
		SurfaceIDORCandidate: 3,
		SurfaceAuthBoundary:  2,
		SurfaceExternalInput: 1,
	}
	merged := make(map[string]Surface)

	for _, c := range candidates {
		s := Surface{
			ID:             c.node.ID,
			File:           c.node.File,
			FunctionName:   c.node.Name,
			NodeType:       cpg.NodeMethod,
			Kind:           c.kind,
			CallGraphDepth: depths[c.node.ID],
		}
		if existing, ok := merged[c.node.ID]; ok {
			if kindPriority[c.kind] > kindPriority[existing.Kind] {
				s.IsIDORCandidate = existing.IsIDORCandidate
				merged[c.node.ID] = s
			}
		} else {
			merged[c.node.ID] = s
		}
	}

	for _, s := range idorSurfaces {
		existing := merged[s.ID]
		s.CallGraphDepth = depths[s.ID]
		if existing.ID == "" || kindPriority[SurfaceIDORCandidate] > kindPriority[existing.Kind] {
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
		slog.Int("idor_candidates", len(idorSurfaces)),
	)

	// Sort: IDOR first, then ascending CallGraphDepth, then stable by ID.
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

// SelectSurfaces is an alias for Run, kept for API compatibility.
func (t *Targeter) SelectSurfaces(ctx context.Context) ([]Surface, error) {
	return t.Run(ctx)
}
