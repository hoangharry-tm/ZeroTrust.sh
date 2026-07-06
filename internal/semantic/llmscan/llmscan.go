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

// Package llmscan implements Path B Tier 3 — LLM Semantic Reasoning.
//
// The Scanner receives enriched surfaces that passed the contract check and
// lightweight triage stages (Tier 2). For each surface it makes one bounded
// Ollama HTTP call with the security contract, CFG evidence, and AI failure
// profile injected into the prompt, and parses a structured JSON verdict.
//
// TODO(impl): full implementation pending internal/semantic/contracts,
// internal/semantic/triage, and internal/semantic/analysis packages.
package llmscan

import (
	"context"
	"log/slog"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/ollama"
)

// Scanner runs the LLM semantic reasoning pass over enriched surfaces.
type Scanner struct {
	llm *ollama.Client
}

// New returns a Scanner backed by the provided Ollama client.
func New(llm *ollama.Client) *Scanner {
	return &Scanner{llm: llm}
}

// Scan processes each enriched surface and returns findings.
// Each surface produces exactly one finding: safe → SUPPRESSED, vulnerable →
// severity derived from confidence, uncertain → SUPPRESSED(uncertain).
//
// TODO(impl): currently a passthrough stub; replace with full contract-check →
// triage → LLM reasoning chain once downstream packages are implemented.
func (s *Scanner) Scan(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	slog.Info("llmscan: stub — downstream analysis packages not yet implemented",
		slog.Int("surfaces", len(surfaces)))
	return nil, nil
}
