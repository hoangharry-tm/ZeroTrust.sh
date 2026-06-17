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

// SelectSurfaces queries the CPG and returns the ranked list of surfaces for
// deeper analysis. AI agent config file nodes are excluded (handled by Path A).
//
// Selection criteria:
//  1. External-input nodes: METHOD nodes whose parameters originate from
//     HTTP, file, env, or IPC sources (detected via PDG edge from CALL nodes
//     such as http.Request, os.Getenv, etc.).
//  2. Auth-boundary nodes: METHOD nodes that contain authorization-related
//     identifiers (auth, permission, role, acl, policy) without a confirmed
//     framework annotation.
//  3. IDOR candidates: METHOD nodes that read an external ID and pass it
//     to a db.Query / db.Exec / ORM call without an intervening ownership check.
//  4. Dangerous sinks: METHOD nodes that directly call a Tree-sitter pre-flagged
//     sink (SQL, command, deserialization, etc.).
//
// Parameters:
//   - ctx: cancellation context.
//
// Returns:
//   - []Surface: selected surfaces ordered by descending heuristic priority.
//   - error: non-nil if the CPG query fails.
func (t *Targeter) SelectSurfaces(ctx context.Context) ([]Surface, error) {
	// implemented in G3.M3.1
	return nil, nil
}

// IsExternalInputNode reports whether the given CPG node receives external data.
// Used internally during surface selection to classify method parameters.
//
// Parameters:
//   - node: the CPG node to classify.
func (t *Targeter) IsExternalInputNode(ctx context.Context, node cpg.Node) (bool, error) {
	// implemented in G3.M3.1
	return false, nil
}

// IsAuthBoundaryNode reports whether the given CPG method node is an
// authorization decision point based on identifier name heuristics and
// the absence of a confirmed framework-level annotation.
//
// Parameters:
//   - node: the CPG node to classify.
func (t *Targeter) IsAuthBoundaryNode(ctx context.Context, node cpg.Node) (bool, error) {
	// implemented in G3.M3.1
	return false, nil
}
