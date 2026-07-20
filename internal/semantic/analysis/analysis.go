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
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// Scanner runs the LLM semantic reasoning pass over enriched surfaces.
type Scanner struct {
	provider llm.Provider
	llmMode  string
	root     string
}

// WithRoot sets the project root directory for resolving relative sink file paths.
func (s *Scanner) WithRoot(root string) *Scanner {
	s.root = root
	return s
}

// New returns a Scanner backed by the provided LLM provider.
// llmMode must be "small", "mid" (default), or "frontier".
func New(provider llm.Provider, llmMode string) *Scanner {
	if llmMode == "" {
		llmMode = "mid"
	}
	return &Scanner{provider: provider, llmMode: llmMode}
}

// analysisOpts returns LLM options appropriate for the given analysis mode.
func analysisOpts(mode string) *llm.Options {
	switch mode {
	case "small":
		return &llm.Options{
			Temperature: 0.1,
			NumPredict:  128,
			NumCtx:      4096,
			Think:       new(false),
		}
	case "frontier":
		return &llm.Options{
			Temperature: 0.1,
			NumPredict:  1024,
			NumCtx:      8192,
		}
	default: // mid
		return &llm.Options{
			Temperature: 0.1,
			NumPredict:  512,
			NumCtx:      16384,
			Think:       new(false),
		}
	}
}

// surfaceDeadline returns the per-surface LLM timeout for the given mode.
func surfaceDeadline(mode string) time.Duration {
	switch mode {
	case "small":
		return 45 * time.Second
	case "frontier":
		return 300 * time.Second
	default: // mid
		return 120 * time.Second
	}
}

// Scan runs Tier 3 analysis on escalated surfaces concurrently.
// Returns one finding per surface. The caller (pathb) filters for
// exploitable vs. non-exploitable based on surface context (violation
// confirmation loop, taint mismatch handling).
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
	switch s.llmMode {
	case "frontier":
		g.SetLimit(1)
	default: // mid, small
		g.SetLimit(2)
	}

	for i, surface := range surfaces {
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

	// Per-surface deadline prevents a single hung Ollama call from blocking the entire batch.
	surfaceTimeout := surfaceDeadline(s.llmMode)
	sctx, cancel := context.WithTimeout(ctx, surfaceTimeout)
	defer cancel()

	opts := analysisOpts(s.llmMode)
	prompt := buildPrompt(surface, s.llmMode, s.root)

	slog.Debug(
		"analysis: prompt",
		"prompt", prompt,
		"llm_mode", s.llmMode,
		"timeout", surfaceTimeout,
	)

	genStart := time.Now()
	raw, err := s.provider.Generate(sctx, prompt, opts)
	genElapsed := time.Since(genStart)
	if err != nil {
		if sctx.Err() != nil {
			slog.Warn("analysis: surface timeout",
				"surface_id", surface.ID,
				"function", surface.FunctionName,
				"mode", s.llmMode,
				"timeout", surfaceTimeout,
			)
		} else {
			slog.Debug(
				"analysis: response",
				"err", err.Error(),
				"elapsed_ms", genElapsed.Milliseconds(),
			)
		}
		return nil, err
	}

	// Empty response retry: context overflow or output truncation.
	// Retry once with halved NumPredict and CoT forced off.
	if raw == "" {
		slog.Warn("analysis: empty response, retrying with reduced num_predict",
			"surface_id", surface.ID,
			"mode", s.llmMode,
		)
		retryOpts := *opts
		retryOpts.NumPredict = max(opts.NumPredict / 2, 64)
		retryOpts.Think = new(false)
		raw, err = s.provider.Generate(sctx, prompt, &retryOpts)
		if err != nil || raw == "" {
			slog.Warn("analysis: retry also returned empty, dropping surface",
				"surface_id", surface.ID,
			)
			return nil, nil
		}
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

	// Self-consistency check for frontier mode: second evidence-only call
	// for high-confidence exploitable findings.
	if s.llmMode == "frontier" && verdict.Exploitable && verdict.Confidence >= 0.85 {
		verdict = s.selfConsistencyCheck(sctx, surface, verdict)
	}

	f := verdictToFinding(surface, verdict)
	return &f, nil
}

// selfConsistencyCheck runs a second code-only LLM call to verify a high-confidence
// exploitable verdict. If the second call disagrees, confidence is downgraded.
func (s *Scanner) selfConsistencyCheck(ctx context.Context, surface enrichment.EnrichedSurface, v Verdict) Verdict {
	code := stripIndent(surface.Code)
	if len(code) > 800 {
		code = code[:800] + "\n...[truncated]"
	}
	probe := "Does this code contain a security vulnerability? Answer only: YES or NO\n\n```\n" + code + "\n```"
	raw, err := s.provider.Generate(ctx, probe, &llm.Options{Temperature: 0.0, NumPredict: 8})
	if err != nil {
		return v
	}
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "NO") && !strings.Contains(upper, "YES") {
		slog.Info("analysis: self_consistency downgrade",
			"surface_id", surface.ID, "original_confidence", v.Confidence)
		v.Confidence -= 0.3
		if v.Confidence < 0 {
			v.Confidence = 0
		}
		if v.Confidence < 0.6 {
			v.Exploitable = false
		}
	}
	return v
}
