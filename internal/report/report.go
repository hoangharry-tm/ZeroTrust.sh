// Package report generates the self-contained HTML vulnerability dashboard and
// patch suggestions from the scored finding set.
package report

import (
	"io"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// Generator produces the HTML report and patch suggestions.
type Generator struct {
	outputPath string
}

// New returns a Generator that writes its output to outputPath.
func New(outputPath string) *Generator {
	return &Generator{outputPath: outputPath}
}

// Render writes the self-contained HTML report to w.
// All user-derived strings (justification, matched_code, file_path) are
// passed through html/template contextual escaping; no template.HTML() casts.
func (g *Generator) Render(w io.Writer, findings []finding.Finding) error {
	// implemented in G4.M4.2
	return nil
}
