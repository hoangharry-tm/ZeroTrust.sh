// Package verifier implements the LLM Verifier for Path A.
//
// The Verifier receives normalised findings from OpenGrep + ast-grep and Joern
// taint analysis and uses CoD (Chain of Draft) + SCoT (Structured Chain of
// Thought) reasoning with XGrammar-2-enforced JSON output to classify each
// finding as confirmed, false_positive, or uncertain.
//
// High-confidence rules (tagged confidence: high in the rule YAML) bypass this
// verifier entirely and are sent directly to the dedup layer.
//
// Adaptive self-consistency (ASC): uncertain verdicts trigger two additional
// independent samples from the model; the majority verdict wins. If all three
// samples are uncertain the finding is emitted as SUPPRESSED with
// reason "uncertain".
package verifier

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Verdict is the LLM Verifier classification for a single finding.
type Verdict string

const (
	// VerdictConfirmed means the LLM determined this is a real vulnerability.
	VerdictConfirmed Verdict = "confirmed"
	// VerdictFalsePositive means the LLM determined this is a false positive.
	VerdictFalsePositive Verdict = "false_positive"
	// VerdictUncertain means the LLM could not reach a confident conclusion.
	// Adaptive self-consistency re-sampling is triggered for uncertain verdicts.
	VerdictUncertain Verdict = "uncertain"
)

// Result carries the verifier output for one finding.
type Result struct {
	// FindingID links this result to the input finding (finding.Finding.ID).
	FindingID string
	// Verdict is the LLM's classification.
	Verdict Verdict
	// Confidence is the LLM's self-reported confidence score (0.0–1.0).
	Confidence float64
	// Justification is the LLM's CoD reasoning summary (1–2 sentences).
	Justification string
	// ASCRounds is the number of self-consistency re-sampling rounds performed.
	// 0 means the initial verdict was not uncertain; 1 or 2 means ASC was triggered.
	ASCRounds int
}

// ASCConfig controls adaptive self-consistency re-sampling behaviour.
type ASCConfig struct {
	// MaxRounds is the maximum number of additional samples for uncertain verdicts.
	// Default 2 (producing 3 total samples; majority-vote selects the winner).
	MaxRounds int
	// ConfidenceThreshold is the minimum confidence required to avoid re-sampling.
	// Verdicts with confidence below this value trigger ASC even if not uncertain.
	ConfidenceThreshold float64
}

// Verifier applies LLM reasoning to filter false positives from pattern findings.
type Verifier struct {
	// w is the Python worker that runs the LLM Verifier handler.
	w *worker.Manager
	// asc controls adaptive self-consistency re-sampling.
	asc ASCConfig
}

// New returns a Verifier backed by the Python worker with default ASC settings.
//
// Parameters:
//   - w: the shared Python worker manager.
func New(w *worker.Manager) *Verifier {
	return &Verifier{
		w: w,
		asc: ASCConfig{
			MaxRounds:           2,
			ConfidenceThreshold: 0.70,
		},
	}
}

// NewWithASC returns a Verifier with custom adaptive self-consistency settings.
//
// Parameters:
//   - w: the shared Python worker manager.
//   - asc: self-consistency configuration.
func NewWithASC(w *worker.Manager, asc ASCConfig) *Verifier {
	return &Verifier{w: w, asc: asc}
}

// Verify classifies each finding in the input slice using CoD + SCoT reasoning.
// Returns one Result per input finding in the same order.
//
// Uncertain results trigger ASC re-sampling (up to ASCConfig.MaxRounds additional
// samples). If all samples are uncertain the result carries VerdictUncertain and
// the caller is responsible for emitting a SUPPRESSED finding.
//
// Parameters:
//   - ctx: cancellation context; honours deadline for each LLM call.
//   - findings: the normalised finding set from OpenGrep + ast-grep + Joern taint.
//
// Returns:
//   - []Result: one result per input finding, in the same order.
//   - error: non-nil only for unrecoverable worker communication failures.
func (v *Verifier) Verify(ctx context.Context, findings []finding.Finding) ([]Result, error) {
	// implemented in G2.M2.5
	return nil, nil
}

// ApplyResults merges verifier results back onto the input findings, updating
// Confidence, SeverityLabel, and SuppressReason where appropriate.
//
// Findings classified as false_positive are converted to SUPPRESSED with
// SuppressReasonFrameworkSafe (conservative label for false positives).
// Confirmed findings have their Confidence updated from the verifier score.
//
// Parameters:
//   - findings: the original input finding slice (modified in-place).
//   - results: the verifier result slice returned by Verify (same order/length).
//
// Returns:
//   - []finding.Finding: the updated finding slice.
func ApplyResults(findings []finding.Finding, results []Result) []finding.Finding {
	// implemented in G2.M2.5
	return findings
}
