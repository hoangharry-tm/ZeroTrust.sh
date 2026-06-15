// Package enrichment implements the Call Graph + CVE Enrichment + Resource ID
// Dataflow node (Path B Tier 1). It enriches each selected surface with CVE data
// from Trivy and flags IDOR candidates via zero-trust resource ID tracking.
package enrichment

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// CVEMatch holds a single CVE finding from Trivy for a dependency.
type CVEMatch struct {
	CVE      string
	CVSS     float64
	Package  string
	Version  string
}

// EnrichedSurface adds CVE and IDOR metadata to a targeting.Surface.
type EnrichedSurface struct {
	targeting.Surface
	CVEMatches      []CVEMatch
	CallerIDs       []string
	CalleeIDs       []string
}

// Enricher adds CVE and IDOR data to a surface list.
type Enricher struct {
	graph      cpg.Graph
	trivyPath  string
	offlineMode bool
}

// New returns an Enricher. Set offlineMode=true for air-gapped environments.
func New(graph cpg.Graph, trivyPath string, offlineMode bool) *Enricher {
	return &Enricher{graph: graph, trivyPath: trivyPath, offlineMode: offlineMode}
}

// Enrich augments surfaces with CVE matches and call graph edges.
// Surfaces with an exact CVE match are auto-flagged; all IDOR candidates
// are marked for mandatory LLM escalation regardless of classifier verdict.
func (e *Enricher) Enrich(ctx context.Context, surfaces []targeting.Surface, projectRoot string) ([]EnrichedSurface, error) {
	// implemented in G3.M3.1
	return nil, nil
}
