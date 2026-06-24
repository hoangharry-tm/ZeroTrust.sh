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

// Package llmscan implements the LLM Semantic Scan (Path B Tier 3).
//
// The Scanner receives ranked semantic summaries — never raw source code — and
// runs a bounded ReAct loop (max 3 steps) per surface via the Python worker.
// Path A HIGH/BLOCK findings are not passed to this stage; it operates only on
// surfaces that reached Tier 3 through the Path B cost funnel.
//
// ReAct loop (VULSOLVER pattern, max 3 steps):
//   - Step 1 (T3): "Does tainted data flow from caller into this surface?"
//   - Step 2 (T4): "Does this surface propagate taint to any callee?"
//   - Step 3 (T5): trigger constraint at sink; XGrammar-2 output schema enforced.
//
// Backbone capability check: before the first surface is processed, a structured
// JSON probe is sent. If the model fails to return valid JSON, the scan downgrades
// to single-pass CoD+SCoT for all surfaces in this run.
//
// Uncertain verdicts are emitted as SUPPRESSED with SuppressReasonUncertain.
// Safe verdicts are emitted as SUPPRESSED with SuppressReasonSafe.
// Neither is silently dropped.
//
// Approach 3 replaces the single LLM with a 3-agent ensemble:
// Reconnaissance Agent → Exploitation Agent → Verification Agent (LangGraph).
package llmscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
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

// caller is the single method of worker.Manager used by the Scanner.
// Defined here (consumer package) per go-dev interface placement guidance.
type caller interface {
	Call(ctx context.Context, msgType worker.MessageType, payload any) (*worker.Response, error)
}

// Scanner runs the bounded ReAct LLM scan over ranked surfaces.
type Scanner struct {
	w     caller
	store *scs.Store
}

// New returns a Scanner backed by the Python worker.
func New(w *worker.Manager) *Scanner {
	return &Scanner{w: w}
}

// WithStore attaches a Scan Security Context Store to the Scanner.
// Call this before Scan when cross-surface vulnerability detection is needed.
func (s *Scanner) WithStore(store *scs.Store) *Scanner {
	s.store = store
	return s
}

// scanStepRequest is the per-step IPC payload sent to the Python llm_scan handler.
type scanStepRequest struct {
	SurfaceID    string                    `json:"surface_id"`
	Step         int                       `json:"step"`
	Mode         ScanMode                  `json:"mode"`
	TaintFlow    assembler.TaintFlowSchema `json:"taint_flow"`
	AuthGuard    assembler.AuthGuardSchema `json:"auth_guard"`
	LogicFlaw    assembler.LogicFlawSchema `json:"logic_flaw"`
	PriorSteps   []ReActStep               `json:"prior_steps,omitempty"`
	PriorContext []scs.Inference           `json:"prior_context,omitempty"`
}

// scanStepResponse is the per-step IPC response from the Python llm_scan handler.
type scanStepResponse struct {
	Thought     string `json:"thought"`
	Action      string `json:"action"`
	Observation string `json:"observation"`
	// Verdict is set on the final step or when EarlyExit is true.
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	CWE        string  `json:"cwe"`
	EarlyExit  bool    `json:"early_exit"`
}

// BackboneCheck probes the Python worker to verify the model can produce valid
// structured JSON output. Returns ScanModeReAct on success, ScanModeSinglePass
// on failure. Worker communication errors degrade gracefully to single-pass.
func (s *Scanner) BackboneCheck(ctx context.Context) (ScanMode, error) {
	resp, err := s.w.Call(ctx, worker.MsgLLMScan, map[string]string{"type": "backbone_probe"})
	if err != nil {
		return ScanModeSinglePass, nil // degrade gracefully
	}
	if resp.Status == worker.ResponseError || !json.Valid(resp.Result) {
		return ScanModeSinglePass, nil
	}
	return ScanModeReAct, nil
}

// Scan runs the backbone check once then processes each surface in order.
// For each surface it queries the SCS store, runs the ReAct loop or single-pass
// scan, writes inferences back to the store, and normalises the result to a Finding.
//
// Every surface produces exactly one finding: uncertain → SUPPRESSED(uncertain),
// safe → SUPPRESSED(safe), vulnerable → severity derived from confidence.
func (s *Scanner) Scan(ctx context.Context, surfaces []budget.RankedSurface) ([]finding.Finding, error) {
	mode, err := s.BackboneCheck(ctx)
	if err != nil {
		return nil, fmt.Errorf("backbone check: %w", err)
	}

	findings := make([]finding.Finding, 0, len(surfaces))
	for _, surf := range surfaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var prior *scs.Result
		if s.store != nil {
			prior, err = s.store.Get(ctx, scs.Query{SurfaceID: surf.SurfaceID})
			if err != nil {
				return nil, fmt.Errorf("scs get %s: %w", surf.SurfaceID, err)
			}
		}

		result, err := s.scanSurface(ctx, surf, mode, prior)
		if err != nil {
			return nil, fmt.Errorf("scan surface %s: %w", surf.SurfaceID, err)
		}

		if s.store != nil {
			s.store.Put(ctx, scs.Inference{
				SurfaceID:  surf.SurfaceID,
				Kind:       verdictToKind(result.Verdict),
				Narrative:  result.Justification,
				Confidence: result.Confidence,
			})
		}

		findings = append(findings, toFinding(result, surf))
	}
	return findings, nil
}

// scanSurface routes to reactLoop or singlePass based on mode.
func (s *Scanner) scanSurface(ctx context.Context, surface budget.RankedSurface, mode ScanMode, prior *scs.Result) (ScanResult, error) {
	if mode == ScanModeSinglePass {
		return s.singlePass(ctx, surface, prior)
	}
	return s.reactLoop(ctx, surface, prior)
}

// reactLoop runs the bounded 3-step ReAct loop.
//
// Step 1 (T3): transfer constraint — does tainted data flow from caller into this surface?
// Step 2 (T4): callee taint — does this surface propagate taint to any callee?
// Step 3 (T5, stub): trigger constraint at sink — implemented in ML3.4 T5.
func (s *Scanner) reactLoop(ctx context.Context, surface budget.RankedSurface, prior *scs.Result) (ScanResult, error) {
	var priorInfs []scs.Inference
	if prior != nil {
		priorInfs = prior.Inferences
	}
	steps := make([]ReActStep, 0, 3)

	// Step 1 (T3): transfer constraint.
	resp1, err := s.callStep(ctx, surface, 1, steps, priorInfs)
	if err != nil {
		return ScanResult{}, fmt.Errorf("step 1: %w", err)
	}
	steps = append(steps, ReActStep{StepNum: 1, Thought: resp1.Thought, Action: resp1.Action, Observation: resp1.Observation})
	if resp1.EarlyExit {
		return buildResult(surface.SurfaceID, resp1, steps, true), nil
	}

	// Step 2 (T4): callee taint propagation.
	resp2, err := s.callStep(ctx, surface, 2, steps, priorInfs)
	if err != nil {
		return ScanResult{}, fmt.Errorf("step 2: %w", err)
	}
	steps = append(steps, ReActStep{StepNum: 2, Thought: resp2.Thought, Action: resp2.Action, Observation: resp2.Observation})
	if resp2.EarlyExit {
		return buildResult(surface.SurfaceID, resp2, steps, true), nil
	}

	// Step 3 (T5): trigger constraint — stub until ML3.4 T5.
	resp3, err := s.callStep(ctx, surface, 3, steps, priorInfs)
	if err != nil {
		return ScanResult{}, fmt.Errorf("step 3: %w", err)
	}
	steps = append(steps, ReActStep{StepNum: 3, Thought: resp3.Thought, Action: resp3.Action, Observation: resp3.Observation})
	return buildResult(surface.SurfaceID, resp3, steps, false), nil
}

// singlePass sends the full surface in a single prompt (CoD+SCoT fallback).
func (s *Scanner) singlePass(ctx context.Context, surface budget.RankedSurface, prior *scs.Result) (ScanResult, error) {
	var priorInfs []scs.Inference
	if prior != nil {
		priorInfs = prior.Inferences
	}
	req := scanStepRequest{
		SurfaceID:    surface.SurfaceID,
		Step:         1,
		Mode:         ScanModeSinglePass,
		TaintFlow:    surface.TaintFlow,
		AuthGuard:    surface.AuthGuard,
		LogicFlaw:    surface.LogicFlaw,
		PriorContext: priorInfs,
	}
	resp, err := s.w.Call(ctx, worker.MsgLLMScan, req)
	if err != nil {
		return ScanResult{}, fmt.Errorf("worker call: %w", err)
	}
	if resp.Status == worker.ResponseError {
		return ScanResult{}, fmt.Errorf("worker error: %s", resp.Error)
	}
	var sr scanStepResponse
	if err := json.Unmarshal(resp.Result, &sr); err != nil {
		return ScanResult{}, fmt.Errorf("unmarshal: %w", err)
	}
	return ScanResult{
		SurfaceID:     surface.SurfaceID,
		Verdict:       sr.Verdict,
		Confidence:    sr.Confidence,
		Justification: sr.Observation,
		CWE:           sr.CWE,
		Mode:          ScanModeSinglePass,
	}, nil
}

// callStep sends one ReAct step to the Python worker and returns the response.
func (s *Scanner) callStep(ctx context.Context, surface budget.RankedSurface, stepNum int, priorSteps []ReActStep, priorContext []scs.Inference) (scanStepResponse, error) {
	req := scanStepRequest{
		SurfaceID:    surface.SurfaceID,
		Step:         stepNum,
		Mode:         ScanModeReAct,
		TaintFlow:    surface.TaintFlow,
		AuthGuard:    surface.AuthGuard,
		LogicFlaw:    surface.LogicFlaw,
		PriorSteps:   priorSteps,
		PriorContext: priorContext,
	}
	resp, err := s.w.Call(ctx, worker.MsgLLMScan, req)
	if err != nil {
		return scanStepResponse{}, fmt.Errorf("worker call: %w", err)
	}
	if resp.Status == worker.ResponseError {
		return scanStepResponse{}, fmt.Errorf("worker error: %s", resp.Error)
	}
	var sr scanStepResponse
	if err := json.Unmarshal(resp.Result, &sr); err != nil {
		return scanStepResponse{}, fmt.Errorf("unmarshal step %d: %w", stepNum, err)
	}
	return sr, nil
}

// toFinding normalises a ScanResult to a finding.Finding.
// Uncertain and safe verdicts produce SUPPRESSED findings — never silent drops.
func toFinding(result ScanResult, surface budget.RankedSurface) finding.Finding {
	severity := finding.SeverityFromConfidence(result.Confidence)
	var suppressReason finding.SuppressReason

	switch result.Verdict {
	case "uncertain", "":
		severity = finding.SeveritySuppressed
		suppressReason = finding.SuppressReasonUncertain
	case "safe":
		severity = finding.SeveritySuppressed
		suppressReason = finding.SuppressReasonSafe
	}

	return finding.Finding{
		ID:             finding.ComputeID(result.CWE, surface.SurfaceID, surface.FunctionID),
		Path:           surface.SurfaceID, // ponytail: file path not threaded to this stage; SurfaceID used as proxy
		CWE:            result.CWE,
		SeverityLabel:  severity,
		Confidence:     result.Confidence,
		SuppressReason: suppressReason,
		Justification:  result.Justification,
		SourcePath:     finding.SourceSemantic,
		PoeContext:     buildPoeContext(result, surface),
	}
}

// buildPoeContext constructs a PoeContext from the LLM scan result and surface
// taint schema. Returns nil when no taint data is available.
func buildPoeContext(result ScanResult, surface budget.RankedSurface) *finding.PoeContext {
	tf := surface.TaintFlow
	if len(tf.UntrustedSources) == 0 && tf.SinkType == "" {
		return nil
	}

	var conditions []string
	if surface.AuthGuard.CheckPresent {
		conditions = append(conditions, "bypass "+string(surface.AuthGuard.CheckLocation)+" auth check")
	}
	if surface.LogicFlaw.ResourceIDSource != "" && string(surface.LogicFlaw.CheckLocation) == "unknown" {
		conditions = append(conditions, "supply arbitrary resource ID via "+surface.LogicFlaw.ResourceIDSource)
	}

	return &finding.PoeContext{
		SourceNode:         strings.Join(tf.UntrustedSources, ", "),
		SinkNode:           tf.SinkType,
		TaintPathSummary:   result.Justification,
		RequiredConditions: strings.Join(conditions, "; "),
	}
}

// buildResult constructs a ScanResult from the final step response.
func buildResult(surfaceID string, resp scanStepResponse, steps []ReActStep, earlyExit bool) ScanResult {
	return ScanResult{
		SurfaceID:     surfaceID,
		Verdict:       resp.Verdict,
		Confidence:    resp.Confidence,
		Justification: resp.Observation,
		CWE:           resp.CWE,
		Steps:         steps,
		Mode:          ScanModeReAct,
		EarlyExit:     earlyExit,
	}
}

// verdictToKind maps an LLM verdict string to an SCS InferenceKind.
func verdictToKind(verdict string) scs.InferenceKind {
	switch verdict {
	case "vulnerable":
		return scs.InferenceTaintSink
	case "safe":
		return scs.InferenceSafe
	default:
		return scs.InferenceSafe // uncertain → record as safe for SCS accumulation
	}
}
