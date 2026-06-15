// Package targeting implements Path B Tier 1 Heuristic Targeting.
// It queries the Joern CPG for language-agnostic surface selection,
// targeting external-input nodes and auth-boundary nodes. Typically ~95%
// of files are eliminated at this stage (design target; pending CVEFixes benchmark).
package targeting

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// Surface is a code location selected by Heuristic Targeting for deeper analysis.
type Surface struct {
	ID            string
	File          string
	FunctionName  string
	NodeType      cpg.NodeType
	CallGraphDepth int
	IsIDORCandidate bool
}

// Targeter selects analysis surfaces from the CPG.
type Targeter struct {
	graph cpg.Graph
}

// New returns a Targeter reading from graph.
func New(graph cpg.Graph) *Targeter {
	return &Targeter{graph: graph}
}

// SelectSurfaces returns the ranked list of surfaces for deeper analysis.
// AI agent config file nodes are handled by Path A and are excluded here.
func (t *Targeter) SelectSurfaces(ctx context.Context) ([]Surface, error) {
	// implemented in G3.M3.1
	return nil, nil
}
