// Copyright 2026 hoangharry-tm
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

// Package llmscan implements the LLM Semantic Scan (Path B Tier 3).
//
// The Scanner receives ranked semantic summaries — never raw source code — and
// runs a bounded ReAct loop (max 3 steps) per surface via the Python worker.
// Path A HIGH/BLOCK findings are not passed to this stage; it operates only on
// surfaces that reached Tier 3 through the Path B cost funnel.
//
// ReAct loop (VULSOLVER pattern, max 3 steps):
//   - Step 1 (Reconnaissance): identify taint flows, auth patterns, IDOR signals.
//   - Step 2 (Exploitation): model whether identified signals constitute an exploitable flaw.
//   - Step 3 (Verification): apply progressive constraints to reduce false positives.
//     Semantic exit conditions allow early termination when confidence is high.
//
// Backbone capability check: before the first surface is processed, a structured JSON
// probe is sent. If the model fails to return valid JSON within two attempts, the scan
// downgrades to single-pass CoD+SCoT for all surfaces in this run.
//
// Uncertain verdicts are emitted as SUPPRESSED findings with SuppressReasonUncertain.
// They are never silently dropped.
//
// Approach 3 replaces the single LLM with a 3-agent ensemble:
// Reconnaissance Agent → Exploitation Agent → Verification Agent (LangGraph).
//
// Scan Security Context Store: after each surface is processed, the Scanner writes
// inferences to the SCS store. The store is queried for accumulated context before
// analysing each subsequent surface, enabling cross-surface vulnerability detection
// (RepoAudit ICML 2025 memoization pattern).
package llmscan

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/scs"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// ScanMode controls whether the ReAct loop or single-pass fallback is used.
type ScanMode string

const (
	// ScanModeReAct uses the full 3-step bounded ReAct loop (default).
	ScanModeReAct ScanMode = "react"
	// ScanModeSinglePass uses single-pass CoD+SCoT (backbone capability check failed).
	ScanModeSinglePass ScanMode = "single_pass"
)

// ReActStep is one reasoning step in the bounded ReAct loop.
type ReActStep struct {
	// StepNum is 1, 2, or 3.
	StepNum int
	// Thought is the model's reasoning for this step.
	Thought string
	// Action describes what the model is checking in this step.
	Action string
	// Observation is the model's conclusion from the action.
	Observation string
}

// ScanResult is the per-surface output of the LLM Semantic Scan.
type ScanResult struct {
	// SurfaceID matches the input budget.RankedSurface.SurfaceID.
	SurfaceID string
	// Verdict is the final classification: "vulnerable" | "safe" | "uncertain".
	Verdict string
	// Confidence is the model's self-reported confidence score (0.0–1.0).
	Confidence float64
	// Justification is the final 1–3 sentence explanation.
	Justification string
	// CWE is the CWE identifier identified by the LLM (may refine the classifier's CWE).
	CWE string
	// Steps are the ReAct reasoning steps taken (empty in single-pass mode).
	Steps []ReActStep
	// Mode indicates whether ReAct or single-pass was used.
	Mode ScanMode
	// EarlyExit is true when a semantic exit condition allowed termination before step 3.
	EarlyExit bool
}

// Scanner runs the bounded ReAct LLM scan over ranked surfaces.
type Scanner struct {
	// w is the Python worker that runs the LLM scan handler.
	w *worker.Manager
	// store is the per-scan Scan Security Context Store for cross-surface inference.
	store *scs.Store
}

// New returns a Scanner backed by the Python worker.
// store is the per-scan SCS store; pass scs.New() from the pipeline orchestrator.
//
// Parameters:
//   - w: the shared Python worker manager.
func New(w *worker.Manager) *Scanner {
	return &Scanner{w: w}
}

// WithStore attaches a Scan Security Context Store to the Scanner.
// Call this before Scan when cross-surface vulnerability detection is needed.
// If not called, the Scanner operates without accumulated context.
//
// Parameters:
//   - store: the per-scan SCS store created by the pipeline orchestrator.
func (s *Scanner) WithStore(store *scs.Store) *Scanner {
	s.store = store
	return s
}

// Scan runs the bounded ReAct loop (or single-pass fallback) for each surface
// and returns normalised findings.
//
// Processing order:
//  1. Backbone capability check (one per Scan call, not per surface).
//  2. For each surface (callee-first order from budget.Rank):
//     a. Query SCS store for accumulated context from prior surfaces.
//     b. Run the ReAct loop (or single-pass) via the Python worker.
//     c. Write inferences to the SCS store.
//     d. Normalise the ScanResult into a finding.Finding.
//
// Uncertain surfaces are emitted as SUPPRESSED with SuppressReasonUncertain.
//
// Parameters:
//   - ctx: cancellation context; honours deadline across all surface scans.
//   - surfaces: the ranked surface list from the Token Budget Controller.
//
// Returns:
//   - []finding.Finding: one finding per surface (uncertain → SUPPRESSED).
//   - error: non-nil only for unrecoverable worker communication failures.
func (s *Scanner) Scan(ctx context.Context, surfaces []budget.RankedSurface) ([]finding.Finding, error) {
	// implemented in G3.M3.4
	return nil, nil
}

// BackboneCheck probes the Python worker to verify the configured model can produce
// valid structured JSON output. Returns the ScanMode to use for the full scan.
//
// Parameters:
//   - ctx: cancellation context.
//
// Returns:
//   - ScanMode: ScanModeReAct if the model passes, ScanModeSinglePass if it fails.
//   - error: non-nil only for worker communication failures (not JSON parse failures).
func (s *Scanner) BackboneCheck(ctx context.Context) (ScanMode, error) {
	// implemented in G3.M3.4
	return ScanModeSinglePass, nil
}

// scanSurface runs the ReAct loop or single-pass scan for a single surface.
// Returns the ScanResult and writes inferences to the SCS store if attached.
//
// Parameters:
//   - ctx: cancellation context.
//   - surface: the ranked surface to scan.
//   - mode: whether to use ReAct or single-pass.
//   - priorContext: accumulated inferences from the SCS store (may be nil).
func (s *Scanner) scanSurface(ctx context.Context, surface budget.RankedSurface, mode ScanMode, priorContext *scs.Result) (ScanResult, error) {
	// implemented in G3.M3.4
	return ScanResult{}, nil
}

// toFinding normalises a ScanResult into a finding.Finding.
// Uncertain verdicts produce SUPPRESSED findings; confident verdicts derive
// SeverityLabel and Confidence from the scan result's scores.
//
// Parameters:
//   - result: the ScanResult from scanSurface.
//   - surface: the ranked surface that was scanned (for file, line, CWE).
func toFinding(result ScanResult, surface budget.RankedSurface) finding.Finding {
	// implemented in G3.M3.4
	return finding.Finding{}
}
