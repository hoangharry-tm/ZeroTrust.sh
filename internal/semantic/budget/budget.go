// Package budget implements the Token Budget Controller (Path B Tier 3).
// It ranks uncertain surfaces by priority and enforces a hard per-scan token cap.
// Exhausted surfaces emit SUPPRESSED findings with reason "budget_exhausted" —
// they are never silently dropped.
//
// Priority ranking formula:
//
//	priority = w1×cvss + w2×(1-classifier_confidence) + w3×reachability_from_entry
//
// reachability_from_entry is the inverse hop count from the nearest external-input node,
// correcting the CVE-only bias of a simpler cvss×uncertainty formula.
package budget

import "github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"

// RankedSurface is a summarized surface with its computed priority score.
type RankedSurface struct {
	summarizer.Summary
	Priority float64
}

// Controller ranks surfaces and enforces the token cap.
type Controller struct {
	tokenCap int
	w1, w2, w3 float64
}

// New returns a Controller with the given token cap (default 50 000) and ranking weights.
func New(tokenCap int, w1, w2, w3 float64) *Controller {
	if tokenCap <= 0 {
		tokenCap = 50_000
	}
	return &Controller{tokenCap: tokenCap, w1: w1, w2: w2, w3: w3}
}

// Rank sorts summaries by priority and returns those that fit within the token cap.
// Surfaces that exceed the cap are returned in the exhausted slice; the caller is
// responsible for emitting SUPPRESSED findings for each exhausted surface.
func (c *Controller) Rank(summaries []summarizer.Summary) (ranked []RankedSurface, exhausted []summarizer.Summary) {
	// implemented in G3.M3.4
	return nil, nil
}
