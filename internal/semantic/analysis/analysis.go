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
	"runtime"

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
	NumPredict:  256,
	TopP:        0.95,
}

// Scan runs Tier 3 analysis on escalated surfaces concurrently.
// Returns one finding per surface that the LLM judges exploitable.
// Surfaces judged safe are silently dropped — not returned.
func (s *Scanner) Scan(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	if len(surfaces) == 0 {
		return nil, nil
	}

	concurrency := runtime.NumCPU()
	if concurrency > 4 {
		concurrency = 4
	}

	type indexedFinding struct {
		index    int
		finding  finding.Finding
		hasFound bool
	}

	results := make([]indexedFinding, len(surfaces))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

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
	prompt := buildPrompt(surface)

	raw, err := s.provider.Generate(ctx, prompt, analysisOpts)
	if err != nil {
		return nil, err
	}

	verdict := parseVerdict(raw)
	if !verdict.Exploitable {
		return nil, nil
	}

	f := verdictToFinding(surface, verdict)
	return &f, nil
}