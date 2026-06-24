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

// Package verifier implements the LLM Verifier for Path A.
//
// The Verifier receives normalised findings from OpenGrep + ast-grep and Joern
// taint analysis and uses CoD (Chain of Draft) + SCoT (Structured Chain of
// Thought) reasoning with XGrammar-2-enforced JSON output to classify each
// finding as confirmed, false_positive, or uncertain.
//
// # High-confidence bypass
//
// Findings whose Confidence is at or above HighConfidenceThreshold (0.90) are
// deterministic rule matches — they skip the LLM entirely and go straight to
// the dedup layer. The caller is responsible for the partition; this package
// provides the threshold constant and the Verify function for the remainder.
//
// # Adaptive Self-Consistency (ASC)
//
// ASC runs entirely in the Python worker: uncertain verdicts trigger up to two
// additional independent resamples at escalating temperatures, and a majority
// vote selects the final verdict. The Go side receives the resolved verdict and
// an ASCRounds field recording how many extra rounds were run.
//
// # Concurrency model
//
// Verify fans out one worker.Call per finding using an errgroup. Worker.Call is
// safe for concurrent use; the Python worker processes requests sequentially
// over its NDJSON stdin loop, so goroutines queue naturally. Individual LLM
// failures are non-fatal: the affected finding receives a fallback uncertain
// result at a penalty-adjusted confidence, and the batch continues.
package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// HighConfidenceThreshold is the minimum confidence at which a finding
// bypasses the LLM Verifier and goes directly to the dedup layer.
// Findings at or above this score come from deterministic rules that have
// near-zero false-positive rates; LLM verification adds cost without benefit.
const HighConfidenceThreshold = 0.90

// Verdict is the LLM Verifier classification for a single finding.
type Verdict string

const (
	// VerdictConfirmed means the LLM determined this is a real vulnerability.
	VerdictConfirmed Verdict = "confirmed"
	// VerdictFalsePositive means the LLM determined this is a false positive.
	VerdictFalsePositive Verdict = "false_positive"
	// VerdictUncertain means the LLM could not reach a confident conclusion.
	// After ASC, if all samples remain uncertain, the finding is suppressed.
	VerdictUncertain Verdict = "uncertain"
)

// Result carries the verifier output for one finding.
type Result struct {
	// FindingID links this result to the input finding (finding.Finding.ID).
	FindingID string
	// Verdict is the LLM's classification after optional ASC.
	Verdict Verdict
	// Confidence is the LLM's self-reported confidence score (0.0–1.0).
	Confidence float64
	// Justification is the LLM's CoD reasoning summary (≤200 chars).
	Justification string
	// ASCRounds is the number of extra self-consistency rounds executed.
	// 0 means the initial verdict was accepted directly.
	ASCRounds int
}

// ASCConfig controls Adaptive Self-Consistency resampling.
type ASCConfig struct {
	// MaxRounds is the maximum number of additional samples for uncertain verdicts.
	// Default 2: produces up to 3 total samples; majority vote selects the winner.
	MaxRounds int
	// ConfidenceThreshold is the minimum confidence that avoids resampling.
	// Verdicts with confidence below this value trigger ASC even if not uncertain.
	ConfidenceThreshold float64
}

// Verifier applies LLM reasoning to filter false positives from pattern findings.
type Verifier struct {
	w      *worker.Manager
	asc    ASCConfig
	logger *slog.Logger
}

// New returns a Verifier backed by w with default ASC settings.
// If logger is nil, slog.Default() is used.
func New(w *worker.Manager, logger *slog.Logger) *Verifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Verifier{
		w:      w,
		asc:    ASCConfig{MaxRounds: 2, ConfidenceThreshold: 0.70},
		logger: logger,
	}
}

// NewWithASC returns a Verifier with custom ASC configuration.
// If logger is nil, slog.Default() is used.
func NewWithASC(w *worker.Manager, asc ASCConfig, logger *slog.Logger) *Verifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Verifier{w: w, asc: asc, logger: logger}
}

// Verify classifies each finding using CoD + SCoT reasoning via the Python
// worker. Returns one Result per input finding in the same order.
//
// Individual LLM failures are non-fatal: the affected finding receives a
// fallback uncertain result at 80% of its original confidence, allowing the
// batch to complete even when the model is slow or temporarily unavailable.
// The only hard error is a total worker failure (ErrWorkerDead).
//
// Findings are dispatched concurrently; the caller must ensure ctx carries an
// appropriate deadline — a per-scan timeout is strongly recommended.
func (v *Verifier) Verify(ctx context.Context, findings []finding.Finding) ([]Result, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	results := make([]Result, len(findings))

	g, gctx := errgroup.WithContext(ctx)
	for i, f := range findings {
		g.Go(func() error {
			payload := worker.VerifyPayload{
				FindingID:              f.ID,
				RuleID:                 f.RuleID,
				CWE:                    f.CWE,
				MatchedCode:            f.MatchedCode,
				Justification:          f.Justification,
				FilePath:               f.Path,
				ASCMaxRounds:           v.asc.MaxRounds,
				ASCConfidenceThreshold: v.asc.ConfidenceThreshold,
			}

			resp, err := v.w.Call(gctx, worker.MsgLLMVerify, payload)
			if err != nil {
				if err == worker.ErrWorkerDead {
					// Hard failure: the entire worker is gone. Surface immediately
					// so the batch fails rather than producing silent garbage results.
					return fmt.Errorf("verifier: worker dead: %w", err)
				}
				// Transient failure (context cancelled, IPC error): degrade gracefully.
				results[i] = fallbackResult(f)
				return nil
			}
			if resp.Status == worker.ResponseError {
				// Application-level error from the Python handler: degrade gracefully.
				v.logger.Warn("verifier: handler error, degrading to fallback result",
					"component", "verifier",
					"finding_id", f.ID,
					"worker_error", resp.Error,
				)
				results[i] = fallbackResult(f)
				return nil
			}

			var vr worker.VerifyResult
			if err := json.Unmarshal(resp.Result, &vr); err != nil {
				// Malformed response: degrade gracefully rather than abort.
				v.logger.Warn("verifier: malformed worker response, degrading to fallback result",
					"component", "verifier",
					"finding_id", f.ID,
					"err", err,
				)
				results[i] = fallbackResult(f)
				return nil
			}

			results[i] = Result{
				FindingID:     f.ID,
				Verdict:       Verdict(vr.Verdict),
				Confidence:    vr.Confidence,
				Justification: vr.Justification,
				ASCRounds:     vr.ASCRounds,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

// ApplyResults merges verifier Results back onto the input findings slice,
// updating Confidence, SeverityLabel, SuppressReason, and Justification.
//
// Mapping:
//   - confirmed     → confidence updated; SeverityLabel re-derived.
//   - false_positive → SeveritySuppressed + SuppressReasonFrameworkSafe.
//   - uncertain      → SeveritySuppressed + SuppressReasonUncertain.
//
// The returned slice has the same length and order as findings. If the lengths
// diverge (caller bug), findings is returned unchanged.
func ApplyResults(findings []finding.Finding, results []Result) []finding.Finding {
	if len(findings) != len(results) {
		return findings
	}
	out := make([]finding.Finding, len(findings))
	for i, f := range findings {
		r := results[i]
		if r.Justification != "" {
			f.Justification = r.Justification
		}
		switch r.Verdict {
		case VerdictConfirmed:
			f.Confidence = r.Confidence
			f.SeverityLabel = finding.SeverityFromConfidence(r.Confidence)
		case VerdictFalsePositive:
			f.Confidence = r.Confidence
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonFrameworkSafe
		case VerdictUncertain:
			f.Confidence = r.Confidence
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonUncertain
		default:
			// Unknown verdict (e.g. fallback zero-value): leave finding unchanged.
		}
		out[i] = f
	}
	return out
}

// fallbackResult returns a graceful-degradation Result for a finding when the
// LLM call fails. Confidence is penalised by 20% to signal reduced certainty.
func fallbackResult(f finding.Finding) Result {
	return Result{
		FindingID:  f.ID,
		Verdict:    VerdictUncertain,
		Confidence: f.Confidence * 0.80,
	}
}
