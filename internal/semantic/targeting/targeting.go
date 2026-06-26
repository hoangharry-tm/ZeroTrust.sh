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
// the UniXcoder classifier and escalate directly to the LLM tier.
//
// Design reference: BolaRay (CCS 2024) for zero-trust resource ID model.
package targeting

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/tuning"
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
	graph cpg.Graph
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

// buildCallGraph performs a BFS from the seed nodes, following callee edges,
// and returns a CallGraph mapping each visited node ID to its direct callee IDs.
// Cycles are handled via a visited set — each node is expanded at most once.
func (t *Targeter) buildCallGraph(_ context.Context, seeds []cpg.Node) (CallGraph, error) {
	slog.Debug("targeting: building call graph", slog.Int("seeds", len(seeds)))
	cg := make(CallGraph)
	visited := make(map[string]bool)
	queue := make([]cpg.Node, len(seeds))
	copy(queue, seeds)

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if visited[node.ID] {
			continue
		}
		visited[node.ID] = true

		callees, err := t.graph.GetCallees(node.ID)
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(callees))
		for _, c := range callees {
			ids = append(ids, c.ID)
			if !visited[c.ID] {
				queue = append(queue, c)
			}
		}
		cg[node.ID] = ids
	}
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
// UniXcoder classifier. Missing CVSS (0.0) is treated as 5.0.
func AutoFlagCVESurfaces(surfaces []Surface) (flagged []Surface, remaining []Surface) {
	slog.Debug("targeting: auto-flagging CVE surfaces", slog.Int("surfaces", len(surfaces)))
	for _, s := range surfaces {
		if !s.HasCVEMatch {
			remaining = append(remaining, s)
			continue
		}
		cvss := s.CVSSScore
		if cvss == 0 {
			cvss = tuning.CVSSMissingDefault
		}
		conf := cvssBandConfidence(cvss)
		if conf == 0 {
			remaining = append(remaining, s)
			continue
		}
		s.ConfidenceScore = conf
		flagged = append(flagged, s)
	}
	return flagged, remaining
}

// cvssBandConfidence maps a CVSS score to an SSVC-inspired confidence score.
// Returns 0 when the score is below the auto-flag threshold (4.0).
func cvssBandConfidence(cvss float64) float64 {
	switch {
	case cvss >= tuning.CVSSCritical:
		return tuning.ConfCVSSCritical
	case cvss >= tuning.CVSSHigh:
		return tuning.ConfCVSSHigh
	case cvss >= tuning.CVSSMedium:
		return tuning.ConfCVSSMedium
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
	slog.Debug("targeting: querying CPG for method nodes")
	methods, err := t.graph.QueryNodes(cpg.NodeMethod)
	if err != nil {
		slog.Error("targeting: CPG QueryNodes failed", "err", err)
		return nil, err
	}

	slog.Debug("targeting: methods from CPG", slog.Int("count", len(methods)))

	type nodeResult struct {
		node cpg.Node
		kind SurfaceKind
	}
	var extInputNodes []cpg.Node
	var candidates []nodeResult

	for _, m := range methods {
		isExt, err := t.IsExternalInputNode(ctx, m)
		if err != nil {
			return nil, err
		}
		isAuth, err := t.IsAuthBoundaryNode(ctx, m)
		if err != nil {
			return nil, err
		}
		if isExt {
			extInputNodes = append(extInputNodes, m)
			candidates = append(candidates, nodeResult{m, SurfaceExternalInput})
		} else if isAuth {
			candidates = append(candidates, nodeResult{m, SurfaceAuthBoundary})
		}
	}
	slog.Debug("targeting: candidates identified", slog.Int("external_input", len(extInputNodes)), slog.Int("total_candidates", len(candidates)))

	idorSurfaces, err := t.queryIDORCandidates(ctx, DefaultIDORConfig())
	if err != nil {
		return nil, err
	}
	slog.Debug("targeting: IDOR candidates", slog.Int("count", len(idorSurfaces)))

	// Build call graph and compute hop depths from entry-point seeds.
	cg, err := t.buildCallGraph(ctx, extInputNodes)
	if err != nil {
		return nil, err
	}
	depths := bfsHopDepths(cg, extInputNodes)

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
