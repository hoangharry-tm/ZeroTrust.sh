// Package classifier wraps the UniXcoder-Base-Nine vulnerability classifier
// (Path B Tier 2) via the Python worker IPC boundary.
//
// UniXcoder-Base-Nine (~125M parameters, CPU-only) is a code understanding model
// fine-tuned on BigVul. It gates surfaces before the expensive LLM reasoning tier,
// targeting ~75–85% elimination of surfaces that reach this stage.
//
// A-18 blocking dependency: BigVul F1 is measured on C/C++ data and is not a
// valid claim for Python / Java / JS / Go. CVEFixes fine-tuning and per-language
// benchmark validation are required before publishing accuracy figures. Until then
// the classifier operates in high-recall mode (low classification threshold).
//
// Language support:
//   - Supported (classifier runs): Python, Java, JavaScript/TypeScript, Go, Ruby, PHP.
//   - Unsupported (routed directly to LLM): Rust, Kotlin, Swift, C#.
//
// IDOR escalation: surfaces marked IsIDORCandidate always escalate to the LLM
// tier regardless of the classifier verdict.
package classifier

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Label is the 3-band classification output.
type Label string

const (
	// LabelVulnerable means the classifier predicts the surface is vulnerable.
	LabelVulnerable Label = "vulnerable"
	// LabelSafe means the classifier predicts the surface is not vulnerable.
	// High-confidence safe verdicts skip LLM entirely and are emitted as LOW or suppressed.
	LabelSafe Label = "safe"
	// LabelUncertain means the classifier confidence is below the escalation threshold.
	// Uncertain surfaces are forwarded to the Call Chain Assembler + LLM tier.
	LabelUncertain Label = "uncertain"
)

// SupportedLanguage is the set of languages the UniXcoder classifier handles.
// Languages not in this set are always routed directly to the LLM tier.
type SupportedLanguage string

// SupportedLanguage constants for languages handled by the UniXcoder classifier.
const (
	LangPython     SupportedLanguage = "python"
	LangJava       SupportedLanguage = "java"
	LangJavaScript SupportedLanguage = "javascript"
	LangTypeScript SupportedLanguage = "typescript"
	LangGo         SupportedLanguage = "go"
	LangRuby       SupportedLanguage = "ruby"
	LangPHP        SupportedLanguage = "php"
)

// Result is the classifier output for one surface.
type Result struct {
	// SurfaceID matches the input enrichment.EnrichedSurface.ID.
	SurfaceID string
	// Label is the 3-band classification.
	Label Label
	// Confidence is the model's softmax probability for the winning label (0.0–1.0).
	Confidence float64
	// Escalate is true when the surface must proceed to the LLM tier regardless
	// of Label (IDOR candidate, unsupported language, or uncertain verdict).
	Escalate bool
	// EscalateReason describes why Escalate is true ("idor_candidate",
	// "unsupported_language", "uncertain").
	EscalateReason string
}

// Gate applies the UniXcoder classifier to a batch of surfaces.
type Gate struct {
	// w is the Python worker that runs the UniXcoder classify handler.
	w *worker.Manager
	// escalationThreshold is the minimum confidence required to avoid escalation.
	// Below this value a safe/vulnerable verdict is treated as uncertain.
	escalationThreshold float64
}

// New returns a Gate backed by the Python worker with a default escalation threshold of 0.80.
//
// Parameters:
//   - w: the shared Python worker manager.
func New(w *worker.Manager) *Gate {
	return &Gate{w: w, escalationThreshold: 0.80}
}

// NewWithThreshold returns a Gate with a custom escalation confidence threshold.
//
// Parameters:
//   - w: the shared Python worker manager.
//   - threshold: confidence below which verdicts are treated as uncertain (0.0–1.0).
func NewWithThreshold(w *worker.Manager, threshold float64) *Gate {
	return &Gate{w: w, escalationThreshold: threshold}
}

// Classify classifies each surface and returns one Result per input surface.
//
// Routing rules applied in order:
//  1. If surface.IsIDORCandidate → Escalate=true, EscalateReason="idor_candidate".
//  2. If surface language is unsupported → Escalate=true, EscalateReason="unsupported_language".
//  3. Run UniXcoder; if confidence < escalationThreshold → Label=LabelUncertain, Escalate=true.
//  4. If Label=LabelSafe and confidence ≥ threshold → Escalate=false (surface exits Path B).
//
// Parameters:
//   - ctx: cancellation context.
//   - surfaces: the enriched surfaces from the enrichment stage.
//
// Returns:
//   - []Result: one result per input surface, in the same order.
//   - error: non-nil only for worker communication failures.
func (g *Gate) Classify(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]Result, error) {
	// implemented in G3.M3.2
	return nil, nil
}

// IsSupported reports whether the classifier supports the given language.
// Unsupported languages are routed directly to the LLM tier.
//
// Parameters:
//   - lang: the source language string (e.g. "go", "python", "rust").
func IsSupported(lang string) bool {
	// implemented in G3.M3.2
	return false
}
