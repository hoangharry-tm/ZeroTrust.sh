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

// Package budget implements the Token Budget Controller (Path B Tier 3).
//
// The Controller ranks semantic summaries by priority and enforces a hard per-scan
// token cap. Surfaces that exceed the cap are never silently dropped — they are
// returned in the exhausted slice and the caller must emit a SUPPRESSED finding
// with SuppressReasonBudgetExhausted for each one.
//
// Priority ranking formula:
//
//	priority = w1×cvss + w2×(1 - classifier_confidence) + w3×reachability_from_entry
//
//   - cvss: highest CVSS score among CVE matches for this surface (0.0–10.0, normalised to 0–1).
//   - classifier_confidence: the CodeT5+ classifier's confidence (0.0–1.0). High uncertainty
//     increases priority because uncertain surfaces are the most valuable LLM targets.
//   - reachability_from_entry: inverse hop count from the nearest external-input node
//     (1 / CallGraphDepth). Corrects the CVE-only bias of a simpler formula.
//
// Default weights: w1=0.4, w2=0.4, w3=0.2.
// These can be tuned via budget.New; architectural defaults set in cmd/zerotrust/scan.go.
//
// Token estimation: each surface's token cost is estimated from the length of its
// Summary fields. The Token Budget Controller does not compress summaries — the
// Semantic Function Summarizer already enforces concise structured output.
// Security-critical content is never truncated.
package budget

import (
	"log/slog"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
)

// Input bundles a semantic summary with the ranking metadata that the Summarizer
// stage cannot carry: CVSS score, classifier confidence, and call-graph depth.
// Callers construct Inputs from the classifier.ClassifiedSurface and summarizer.Summary.
type Input struct {
	// Summary is the structured semantic output from the Summarizer stage.
	Summary summarizer.Summary
	// File is the source file path (relative to project root) for this surface.
	// Used by the LLM scan stage to populate finding.Path so cross-path dedup works.
	File string
	// CVSSScore is the highest CVSS v3 score among CVE matches for this surface (0.0–10.0).
	CVSSScore float64
	// ClassifierConfidence is the CodeT5+ classifier confidence for the winning label (0.0–1.0).
	ClassifierConfidence float64
	// CallGraphDepth is the hop count from the nearest external-input node (≥ 1).
	// Surfaces with depth 0 (unknown) are treated as depth 1 by the ranker.
	CallGraphDepth int
}

// RankedSurface is a summarized surface with its computed priority score.
// Passed to the LLM Semantic Scan in descending priority order.
type RankedSurface struct {
	// Summary is the semantic summary from the Summarizer stage.
	summarizer.Summary
	// File is the source file path (relative to project root) for this surface.
	// Populated from Input by the controller, consumed by the LLM scan stage.
	File string
	// Priority is the computed priority score (higher = scanned first).
	Priority float64
	// EstimatedTokens is the estimated prompt token cost for this surface.
	EstimatedTokens int
	// ClassifierConfidence is the CodeT5+ classifier confidence for the winning label (0.0–1.0).
	ClassifierConfidence float64
}

// Stats describes what the Controller decided about the full surface set.
type Stats struct {
	// Total is the number of summaries submitted to Rank.
	Total int
	// Ranked is the number of surfaces that fit within the token cap.
	Ranked int
	// Exhausted is the number of surfaces that exceeded the token cap.
	Exhausted int
	// TokensUsed is the estimated token cost of the ranked set.
	TokensUsed int
}

// Controller ranks surfaces and enforces the token cap.
type Controller struct {
	// tokenCap is the hard per-scan token budget (default 50 000).
	tokenCap int
	// w1 is the weight for cvss in the priority formula.
	w1 float64
	// w2 is the weight for (1 - classifier_confidence).
	w2 float64
	// w3 is the weight for reachability_from_entry.
	w3 float64
}

// New returns a Controller with the given token cap and ranking weights.
// tokenCap ≤ 0 defaults to 50 000.
//
// Note: The Controller no longer gates analysis — it observes, ranks, and warns
// about cost but never suppresses scanning. All surfaces reach the LLM tier
// regardless of cap. See ExhaustedToRanked.
//
// Parameters:
//   - tokenCap: per-scan token budget (warning threshold, not a hard gate).
//   - w1: weight for CVSS normalised score (0.0–1.0).
//   - w2: weight for classifier uncertainty (1 - classifier_confidence).
//   - w3: weight for reachability from entry point (1 / CallGraphDepth).
func New(tokenCap int, w1, w2, w3 float64) *Controller {
	if tokenCap <= 0 {
		tokenCap = config.C.DefaultTokenCap
	}
	return &Controller{tokenCap: tokenCap, w1: w1, w2: w2, w3: w3}
}

// Rank sorts inputs by priority (descending) and partitions them into ranked
// (fits within token cap) and exhausted (exceeds cap) slices.
//
// Callers should merge both slices when all surfaces must be scanned:
//
//	ranked, exhausted, stats := c.RankWithStats(inputs)
//	if stats.Exhausted > 0 {
//	    warn("budget: %d surfaces exceed cap — scanning all", stats.Exhausted)
//	}
//	allSurfaces := append(ranked, c.ExhaustedToRanked(exhausted)...)
func (c *Controller) Rank(inputs []Input) (ranked []RankedSurface, exhausted []Input) {
	ranked, exhausted, _ = c.rank(inputs)
	return
}

// RankWithStats is identical to Rank but also returns a Stats summary.
func (c *Controller) RankWithStats(inputs []Input) (ranked []RankedSurface, exhausted []Input, stats Stats) {
	ranked, exhausted, stats = c.rank(inputs)
	slog.Info("token budget ranked",
		slog.Int("total", stats.Total),
		slog.Int("ranked", stats.Ranked),
		slog.Int("exhausted", stats.Exhausted),
		slog.Int("tokens_used", stats.TokensUsed),
	)
	return
}

// ExhaustedToRanked converts exhausted Inputs to RankedSurfaces so they can be
// appended to the ranked slice for the LLM scan. Each output surface has
// Priority=0 (never ranked) and EstimatedTokens computed from the summary.
//
// This enables the observer-mode pattern: rank + warn about cost, then scan
// every surface regardless of budget.
func (c *Controller) ExhaustedToRanked(exhausted []Input) []RankedSurface {
	out := make([]RankedSurface, len(exhausted))
	for i, inp := range exhausted {
		out[i] = RankedSurface{
			Summary:              inp.Summary,
			File:                 inp.File,
			Priority:             0,
			EstimatedTokens:      estimateTokens(inp.Summary),
			ClassifierConfidence: inp.ClassifierConfidence,
		}
	}
	return out
}
