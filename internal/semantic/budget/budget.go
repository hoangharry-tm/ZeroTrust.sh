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
//   - classifier_confidence: the UniXcoder classifier's confidence (0.0–1.0). High uncertainty
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

import "github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"

// RankedSurface is a summarized surface with its computed priority score.
// Passed to the LLM Semantic Scan in descending priority order.
type RankedSurface struct {
	// Summary is the semantic summary from the Summarizer stage.
	summarizer.Summary
	// Priority is the computed priority score (higher = scanned first).
	Priority float64
	// EstimatedTokens is the estimated prompt token cost for this surface.
	EstimatedTokens int
	// ClassifierConfidence is the UniXcoder confidence score, carried forward
	// from the classifier stage for use in the priority formula.
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
// Parameters:
//   - tokenCap: hard per-scan token budget. Surfaces beyond the cap are exhausted.
//   - w1: weight for CVSS normalised score (0.0–1.0).
//   - w2: weight for classifier uncertainty (1 - classifier_confidence).
//   - w3: weight for reachability from entry point (1 / CallGraphDepth).
func New(tokenCap int, w1, w2, w3 float64) *Controller {
	if tokenCap <= 0 {
		tokenCap = 50_000
	}
	return &Controller{tokenCap: tokenCap, w1: w1, w2: w2, w3: w3}
}

// Rank sorts summaries by priority (descending) and partitions them into ranked
// (fits within token cap) and exhausted (exceeds cap) slices.
//
// The caller must emit a SUPPRESSED finding with SuppressReasonBudgetExhausted
// for each entry in the exhausted slice — they must never be silently dropped.
//
// Parameters:
//   - summaries: the full list of semantic summaries from the Summarizer stage.
//
// Returns:
//   - ranked: surfaces that fit within tokenCap, ordered by descending priority.
//   - exhausted: surfaces that would exceed tokenCap, in the original order.
func (c *Controller) Rank(summaries []summarizer.Summary) (ranked []RankedSurface, exhausted []summarizer.Summary) {
	// implemented in G3.M3.4
	return nil, nil
}

// RankWithStats is identical to Rank but also returns a Stats summary describing
// the partitioning decision. Use this when the scan report should include
// token budget utilisation metadata.
//
// Parameters:
//   - summaries: the full list of semantic summaries from the Summarizer stage.
//
// Returns:
//   - ranked: surfaces within the token cap.
//   - exhausted: surfaces beyond the cap.
//   - stats: partitioning statistics.
func (c *Controller) RankWithStats(summaries []summarizer.Summary) (ranked []RankedSurface, exhausted []summarizer.Summary, stats Stats) {
	// implemented in G3.M3.4
	return nil, nil, Stats{}
}

// estimateTokens returns the estimated LLM prompt token cost for one summary.
// The estimate is based on field string lengths multiplied by a tokens-per-char
// approximation (~0.3 tokens/char for English technical text).
//
// Parameters:
//   - s: the summary whose token cost is to be estimated.
func estimateTokens(s summarizer.Summary) int {
	// implemented in G3.M3.4
	return 0
}

// computePriority applies the ranking formula to a single surface.
//
// Parameters:
//   - cvss: normalised CVSS score (cvss_raw / 10.0).
//   - classifierConf: the UniXcoder classifier confidence (0.0–1.0).
//   - callGraphDepth: hop count from the nearest external-input node (≥ 1).
//   - w1, w2, w3: the Controller's ranking weights.
func computePriority(cvss, classifierConf float64, callGraphDepth int, w1, w2, w3 float64) float64 {
	// implemented in G3.M3.4
	return 0
}
