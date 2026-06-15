// Package verifier implements the LLM Verifier for Path A.
// It receives normalised findings from OpenGrep + ast-grep and Joern taint analysis,
// applies CoD + SCoT reasoning with XGrammar-2-enforced JSON output, and classifies
// each finding as confirmed, false_positive, or uncertain.
// High-confidence rules bypass the verifier and go directly to Dedup.
package verifier

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Verdict is the LLM Verifier classification for a single finding.
type Verdict string

const (
	VerdictConfirmed     Verdict = "confirmed"
	VerdictFalsePositive Verdict = "false_positive"
	VerdictUncertain     Verdict = "uncertain"
)

// Result carries the verifier output for one finding.
type Result struct {
	FindingID     string
	Verdict       Verdict
	Confidence    float64
	Justification string
}

// Verifier applies LLM reasoning to filter false positives from pattern findings.
type Verifier struct {
	w *worker.Manager
}

// New returns a Verifier backed by the Python worker.
func New(w *worker.Manager) *Verifier {
	return &Verifier{w: w}
}

// Verify classifies findings, returning one Result per input finding.
// Uncertain results trigger adaptive self-consistency re-sampling (×2, majority-vote).
func (v *Verifier) Verify(ctx context.Context, findings []finding.Finding) ([]Result, error) {
	// implemented in G2.M2.5
	return nil, nil
}
