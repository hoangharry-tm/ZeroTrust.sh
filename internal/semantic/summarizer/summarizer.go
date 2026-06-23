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

// Package summarizer implements the Semantic Function Summarizer (Path B Tier 2).
//
// The Summarizer converts call chain context into XGrammar-2-constrained JSON
// summaries via a small local LLM (Phi-3-mini or Qwen2.5-3B running in the
// Python worker). The main reasoning LLM (LLM Semantic Scan) never sees raw
// source code — only these structured summaries.
//
// Single-pass union schema (TagDispatch):
// One JSON object per function covers all three vulnerability classes simultaneously:
//
//	{
//	  "taint_flow":  { "untrusted_sources": [...], "sanitizer_nodes": [...], "sink_type": "...", "taint_propagates": true },
//	  "auth_guard":  { "check_present": false, "check_location": "unknown" },
//	  "logic_flaw":  { "resource_id_source": "...", "db_sink": "...", "check_location": "unknown" }
//	}
//
// This replaces the prior 3-pass design and reduces Summarizer cost ~3×.
// The authorization_check_location field distinguishes real auth gaps from
// framework-level controls (LLMxCPG USENIX 2025, VULSOLVER arXiv 2025).
//
// Batch inference: up to 5 call chains per Python worker request to reduce IPC overhead.
//
// Approach 3 replaces the 3B model with a 0.5–1B model fine-tuned on CVEFixes
// CPG→JSON pairs.
package summarizer

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// CheckLocation classifies where (or whether) an authorization check occurs.
// Used in both AuthGuardSummary and LogicFlawSummary to distinguish real auth
// gaps from framework-controlled access (LLMxCPG USENIX 2025).
type CheckLocation string

const (
	// CheckFrameworkAnnotation means access control is enforced by a framework
	// annotation or decorator (e.g. @PreAuthorize, @login_required, middleware chain).
	CheckFrameworkAnnotation CheckLocation = "framework_annotation"
	// CheckExplicitCode means an explicit conditional (if/guard) performs the check.
	CheckExplicitCode CheckLocation = "explicit_code"
	// CheckMiddleware means the check is in middleware/interceptor before this function.
	CheckMiddleware CheckLocation = "middleware"
	// CheckUnknown means no check was detected.
	CheckUnknown CheckLocation = "unknown"
)

// TaintFlowSummary captures untrusted data propagation through a function.
type TaintFlowSummary struct {
	// UntrustedSources lists parameter names or call sites that introduce untrusted data.
	UntrustedSources []string `json:"untrusted_sources"`
	// SanitizerNodes lists call sites that sanitize or validate the tainted data.
	SanitizerNodes []string `json:"sanitizer_nodes"`
	// SinkType is the kind of dangerous sink the tainted data flows into
	// (e.g. "sql", "command", "template"); empty if no sink is reached.
	SinkType string `json:"sink_type"`
	// TaintPropagates is true when tainted data reaches a sink without sanitization.
	TaintPropagates bool `json:"taint_propagates"`
}

// AuthGuardSummary captures the authorization check status for a function.
// CheckLocation distinguishes real auth gaps from framework-level controls,
// reducing false positives on annotated endpoints.
type AuthGuardSummary struct {
	// CheckPresent is true when an authorization check was detected.
	CheckPresent bool `json:"check_present"`
	// CheckLocation describes where the check is performed.
	CheckLocation CheckLocation `json:"check_location"`
}

// LogicFlawSummary captures resource ID and authorization data for IDOR detection.
// Populated for surfaces flagged as IDOR candidates.
type LogicFlawSummary struct {
	// ResourceIDSource is the parameter or variable name carrying the external resource ID.
	ResourceIDSource string `json:"resource_id_source"`
	// DBSink is the database or storage call the resource ID flows into.
	DBSink string `json:"db_sink"`
	// CheckLocation describes where (if anywhere) an ownership check occurs.
	CheckLocation CheckLocation `json:"check_location"`
}

// Summary is the XGrammar-2-constrained union output for one function in a call chain.
// All three vulnerability classes are populated in a single LLM inference pass.
type Summary struct {
	// FunctionID matches the assembler.FunctionContext.NodeID.
	FunctionID string
	// SurfaceID matches the assembler.CallChain.SurfaceID.
	SurfaceID string
	// TaintFlow describes untrusted data propagation.
	TaintFlow TaintFlowSummary
	// AuthGuard describes authorization check presence and location.
	AuthGuard AuthGuardSummary
	// LogicFlaw describes resource ID flow and ownership check status.
	LogicFlaw LogicFlawSummary
}

// BatchRequest is a single IPC payload sent to the Python worker's summarize handler.
// Up to 5 call chains are batched per request to amortise IPC overhead.
type BatchRequest struct {
	// Chains is the batch of call chains to summarize (1–5 items).
	Chains []assembler.CallChain `json:"chains"`
}

// Summarizer transforms call chains into semantic summaries via the Python worker.
type Summarizer struct {
	// w is the Python worker that runs the Summarizer handler (Phi-3-mini / Qwen2.5-3B).
	w *worker.Manager
	// batchSize is the maximum number of call chains per worker request (default 5).
	batchSize int
}

// New returns a Summarizer backed by the Python worker with the default batch size of 5.
//
// Parameters:
//   - w: the shared Python worker manager.
func New(w *worker.Manager) *Summarizer {
	return &Summarizer{w: w, batchSize: 5}
}

// Summarize converts call chains into semantic summaries using batch inference.
// Call chains are split into batches of batchSize before being sent to the Python worker.
//
// The worker runs a single-pass union schema prompt (TagDispatch) covering all three
// vulnerability classes in one inference call per function.
//
// Parameters:
//   - ctx: cancellation context; honours deadline across all batch requests.
//   - chains: the call chains from the Call Chain Context Assembler.
//
// Returns:
//   - []Summary: one summary per function across all input call chains.
//     Multiple summaries may correspond to the same SurfaceID (one per function in chain).
//   - error: non-nil only for worker communication failures.
func (s *Summarizer) Summarize(ctx context.Context, chains []assembler.CallChain) ([]Summary, error) {
	// implemented in G3.M3.3
	return nil, nil
}

// summarizeBatch sends one BatchRequest to the Python worker and decodes the result.
// It is called internally by Summarize after splitting chains into batchSize groups.
//
// Parameters:
//   - ctx: cancellation context.
//   - batch: up to batchSize call chains to summarize in one worker request.
func (s *Summarizer) summarizeBatch(ctx context.Context, batch []assembler.CallChain) ([]Summary, error) {
	// implemented in G3.M3.3
	return nil, nil
}
