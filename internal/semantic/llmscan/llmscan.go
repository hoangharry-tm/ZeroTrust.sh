// Package llmscan implements the LLM Semantic Scan (Path B Tier 3).
// It receives ranked semantic summaries — never raw code — and runs a bounded
// ReAct loop (max 3 steps) per surface via the Python worker.
// Uncertain verdicts emit SUPPRESSED findings with reason "uncertain".
// Path A HIGH/BLOCK surfaces are pre-filtered before this scan runs.
package llmscan

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Scanner runs the bounded ReAct LLM scan over ranked surfaces.
type Scanner struct {
	w *worker.Manager
}

// New returns a Scanner backed by the Python worker.
func New(w *worker.Manager) *Scanner {
	return &Scanner{w: w}
}

// Scan runs the 3-step ReAct loop for each surface and returns findings.
// Surfaces with verdict "uncertain" are emitted as SUPPRESSED.
// A backbone capability check at scan start downgrades to single-pass
// CoD+SCoT if the configured model fails structured JSON output.
func (s *Scanner) Scan(ctx context.Context, surfaces []budget.RankedSurface) ([]finding.Finding, error) {
	// implemented in G3.M3.4
	return nil, nil
}
