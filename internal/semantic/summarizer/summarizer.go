// Package summarizer implements the Semantic Function Summarizer (Path B Tier 2).
// It converts call chain context into XGrammar-2-constrained JSON summaries via
// a small local LLM (Phi-3-mini/Qwen2.5-3B). The main reasoning LLM never sees
// raw code — only these structured summaries.
//
// Single-pass union schema: one JSON object per function covers all three
// vulnerability classes simultaneously (taint_flow + auth_guard + logic_flaw),
// replacing the prior 3-pass design and reducing Summarizer cost ~3×.
// Batch inference: up to 5 surfaces per prompt.
package summarizer

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Summary is the XGrammar-2-constrained output for one function in a call chain.
type Summary struct {
	FunctionID string
	TaintFlow  TaintFlowSummary
	AuthGuard  AuthGuardSummary
	LogicFlaw  LogicFlawSummary
}

// TaintFlowSummary captures untrusted data propagation through a function.
type TaintFlowSummary struct {
	UntrustedSources []string
	SanitizerNodes   []string
	SinkType         string
	TaintPropagates  bool
}

// AuthGuardSummary captures the authorization check status.
// CheckLocation distinguishes real auth gaps from framework-level controls.
type AuthGuardSummary struct {
	CheckPresent  bool
	CheckLocation string // "framework_annotation" | "explicit_code" | "middleware" | "unknown"
}

// LogicFlawSummary captures resource ID and authorization check data for IDOR detection.
type LogicFlawSummary struct {
	ResourceIDSource string
	DBSink           string
	CheckLocation    string // same enum as AuthGuardSummary.CheckLocation
}

// Summarizer transforms call chains into semantic summaries via the Python worker.
type Summarizer struct {
	w *worker.Manager
}

// New returns a Summarizer backed by the Python worker.
func New(w *worker.Manager) *Summarizer {
	return &Summarizer{w: w}
}

// Summarize converts call chains into semantic summaries (batched, up to 5 per prompt).
func (s *Summarizer) Summarize(ctx context.Context, chains []assembler.CallChain) ([]Summary, error) {
	// implemented in G3.M3.3
	return nil, nil
}
