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
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Summary is the XGrammar-2-constrained union output for one function in a call chain.
// All three vulnerability classes are populated in a single LLM inference pass.
// Schema types are defined in assembler.UnionSchema; aliases used here for readability.
type Summary struct {
	// FunctionID matches the assembler.FunctionContext.NodeID.
	FunctionID string
	// SurfaceID matches the assembler.CallChain.SurfaceID.
	SurfaceID string
	// TaintFlow describes untrusted data propagation.
	TaintFlow assembler.TaintFlowSchema
	// AuthGuard describes authorization check presence and location.
	AuthGuard assembler.AuthGuardSchema
	// LogicFlaw describes resource ID flow and ownership check status.
	LogicFlaw assembler.LogicFlawSchema
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
	return &Summarizer{w: w, batchSize: tuning.SummarizerBatchSize}
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
	slog.Debug("summarizing call chains", slog.Int("chains", len(chains)), slog.Int("batch_size", s.batchSize))
	var out []Summary
	for i := 0; i < len(chains); i += s.batchSize {
		end := min(i+s.batchSize, len(chains))
		batchNum := i / s.batchSize
		batch, err := s.summarizeBatch(ctx, chains[i:end])
		if err != nil {
			slog.Error("summarize batch failed", "err", err, slog.Int("batch", batchNum))
			return nil, fmt.Errorf("summarize batch %d: %w", batchNum, err)
		}
		slog.Debug("batch summarized", slog.Int("batch", batchNum), slog.Int("summaries", len(batch)))
		out = append(out, batch...)
	}
	slog.Info("summarization complete", slog.Int("summaries", len(out)))
	return out, nil
}

// summarizeBatch sends one BatchRequest to the Python worker and decodes the result.
func (s *Summarizer) summarizeBatch(ctx context.Context, batch []assembler.CallChain) ([]Summary, error) {
	req := BatchRequest{Chains: batch}
	for _, ch := range batch {
		slog.Debug("summarizer: chain in batch",
			slog.String("surface_id", ch.SurfaceID),
			slog.Int("depth", ch.Depth),
			slog.Int("functions", len(ch.Functions)),
		)
	}
	slog.Debug("summarizer: calling worker", slog.Int("chains", len(batch)))
	resp, err := s.w.Call(ctx, worker.MsgSummarize, req)
	if err != nil {
		return nil, fmt.Errorf("worker call: %w", err)
	}
	if resp.Status == worker.ResponseError {
		return nil, fmt.Errorf("worker error: %s", resp.Error)
	}

	var summaries []Summary
	if err := json.Unmarshal(resp.Result, &summaries); err != nil {
		return nil, fmt.Errorf("decode summaries: %w", err)
	}
	for _, sm := range summaries {
		slog.Debug("summarizer: summary result",
			slog.String("surface_id", sm.SurfaceID),
			slog.String("function_id", sm.FunctionID),
			slog.String("sink_type", sm.TaintFlow.SinkType),
			slog.Bool("auth_present", sm.AuthGuard.CheckPresent),
			slog.String("resource_id_source", sm.LogicFlaw.ResourceIDSource),
		)
	}
	slog.Debug("summarizer: worker returned", slog.Int("summaries", len(summaries)))
	return summaries, nil
}
