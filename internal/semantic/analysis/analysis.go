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

// Package analysis implements Path B Tier 3 — LLM Semantic Reasoning.
// The Scanner receives enriched surfaces that passed the contract check and
// lightweight triage stages (Tier 2). For each surface it makes one bounded
// LLM call with three evidence layers injected into the prompt: Security
// Contract Layer (SCL), Control Flow Predicate (CFP), and AI Failure Profile
// (AIP). It returns a structured JSON verdict parsed into a finding.Finding.
package analysis

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// Scanner runs the LLM semantic reasoning pass over enriched surfaces.
type Scanner struct {
	provider llm.Provider
}

// New returns a Scanner backed by the provided LLM provider.
func New(provider llm.Provider) *Scanner {
	return &Scanner{provider: provider}
}

var analysisOpts = &llm.Options{
	Temperature: 0.1,
	// ponytail: num_predict=8192 for output budget; num_ctx=16384 overrides Ollama's
	// default 4096-token context window — thinking tokens + prompt + JSON all share one
	// pool; without explicit num_ctx the model hits done_reason=length at ~3500 eval_count
	// (prompt ~600tok + thinking ~3500tok > 4096 default ctx).
	NumPredict: 8192,
	NumCtx:     16384,
	TopP:       0.95,
}

// Scan runs Tier 3 analysis on escalated surfaces concurrently.
// Returns one finding per surface that the LLM judges exploitable.
// Surfaces judged safe are silently dropped — not returned.
func (s *Scanner) Scan(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	if len(surfaces) == 0 {
		return nil, nil
	}

	type indexedFinding struct {
		index    int
		finding  finding.Finding
		hasFound bool
	}

	results := make([]indexedFinding, len(surfaces))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(1)

	for i, surface := range surfaces {
		i, surface := i, surface
		g.Go(func() error {
			f, err := s.scanOne(gctx, surface)
			if err != nil {
				slog.Warn("analysis: scanOne error", slog.String("surface_id", surface.ID), "err", err)
				return nil
			}
			if f != nil {
				results[i] = indexedFinding{index: i, finding: *f, hasFound: true}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	findings := make([]finding.Finding, 0, len(surfaces))
	for _, rf := range results {
		if rf.hasFound {
			findings = append(findings, rf.finding)
		}
	}

	return findings, nil
}

func (s *Scanner) scanOne(ctx context.Context, surface enrichment.EnrichedSurface) (*finding.Finding, error) {
	slog.Debug(
		"analysis: input",
		"function", surface.FunctionName,
		"file", surface.File,
		"kind", surface.Kind,
		"contract_cwe", surface.ContractCWE,
		"has_sink_nodes", len(surface.SinkNodes) > 0,
		"code_len", len(surface.Code),
	)

	prompt := buildPrompt(surface)

	slog.Debug(
		"analysis: prompt",
		"prompt", prompt,
	)

	genStart := time.Now()
	raw, err := s.provider.Generate(ctx, prompt, analysisOpts)
	genElapsed := time.Since(genStart)
	if err != nil {
		slog.Debug(
			"analysis: response",
			"err", err.Error(),
			"elapsed_ms", genElapsed.Milliseconds(),
		)
		return nil, err
	}

	slog.Debug(
		"analysis: response",
		"raw_resp", raw,
		"elapsed_ms", genElapsed.Milliseconds(),
	)

	verdict := parseVerdict(raw)
	slog.Debug(
		"analysis: parse_result",
		"exploitable", verdict.Exploitable,
		"cwe", verdict.CWE,
		"severity", verdict.Severity,
		"confidence", verdict.Confidence,
		"explanation", verdict.Explanation,
		"taint_mismatch", verdict.TaintMismatch,
	)

	if verdict.TaintMismatch && !verdict.Exploitable {
		slog.Info("analysis: taint_mismatch dropped",
			"surface_id", surface.ID,
			"function", surface.FunctionName,
		)
		return nil, nil
	}

	passedGate := verdict.Exploitable || verdict.Confidence >= 0.6
	slog.Debug(
		"analysis: gate",
		"passed", passedGate,
		"exploitable", verdict.Exploitable,
		"confidence", verdict.Confidence,
		"reason", map[bool]string{true: "passed gate", false: "!exploitable && confidence < 0.6"}[passedGate],
	)

	if !verdict.Exploitable && verdict.Confidence < 0.6 {
		// confidence ≥ 0.6 with !exploitable: surface into finding for human review.
		return nil, nil
	}

	f := verdictToFinding(surface, verdict)
	return &f, nil
}

