// Package classifier wraps the UniXcoder-Base-Nine vulnerability classifier
// (Path B Tier 2) via the Python worker IPC boundary.
// A-18 is a blocking dependency: BigVul F1 is not valid for target languages.
// The classifier operates in high-recall mode until CVEFixes benchmark is complete.
package classifier

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Label is the 3-band classification output.
type Label string

const (
	LabelVulnerable Label = "vulnerable"
	LabelSafe       Label = "safe"
	LabelUncertain  Label = "uncertain"
)

// Result is the classifier output for one surface.
type Result struct {
	SurfaceID  string
	Label      Label
	Confidence float64
}

// Gate applies the UniXcoder classifier to a batch of surfaces.
type Gate struct {
	w *worker.Manager
}

// New returns a Gate backed by the Python worker.
func New(w *worker.Manager) *Gate {
	return &Gate{w: w}
}

// Classify classifies each surface. IDOR candidates always escalate regardless
// of verdict. Unsupported languages (Rust, Kotlin, Swift, C#) are routed directly
// to the LLM tier.
func (g *Gate) Classify(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]Result, error) {
	// implemented in G3.M3.2
	return nil, nil
}
