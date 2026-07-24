package analysis

import (
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestVerdictToFinding_SetsExploitableAndTaintMismatch(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-42",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	v := Verdict{
		Exploitable:   true,
		CWE:           "CWE-89",
		Severity:      "HIGH",
		Confidence:    0.85,
		Explanation:   "direct SQL concat",
		TaintMismatch: false,
	}
	f := verdictToFinding(surface, v)
	if !f.Exploitable {
		t.Error("want Exploitable=true")
	}
	if f.TaintMismatch {
		t.Error("want TaintMismatch=false")
	}
	if f.SurfaceID != "node-42" {
		t.Errorf("want SurfaceID='node-42', got %q", f.SurfaceID)
	}
}

func TestVerdictToFinding_SurfaceIDPopulated(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-42",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	v := Verdict{Exploitable: false}
	f := verdictToFinding(surface, v)
	if f.SurfaceID != "node-42" {
		t.Errorf("want SurfaceID='node-42', got %q", f.SurfaceID)
	}
}

func TestVerdictToFinding_TaintMismatchTrue(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-99",
			File: "test.go",
		},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
	}
	f := verdictToFinding(surface, v)
	if !f.TaintMismatch {
		t.Error("want TaintMismatch=true")
	}
	if f.Exploitable {
		t.Error("want Exploitable=false")
	}
}

func TestVerdictToFinding_TaintMismatchCriticalCappedToLow(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: "node-1", File: "Foo.java"},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
		Severity:      "CRITICAL",
		Confidence:    1.0,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityLow {
		t.Errorf("want SeverityLow for TaintMismatch+CRITICAL, got %v", f.SeverityLabel)
	}
	if !f.TaintMismatch {
		t.Error("want TaintMismatch=true preserved")
	}
}

func TestVerdictToFinding_LineRangeFromSurface(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{Line: 77, File: "Bar.java"},
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.8}
	f := verdictToFinding(surface, v)
	if f.LineRange.Start != 77 {
		t.Errorf("want LineRange.Start=77, got %d", f.LineRange.Start)
	}
}

func TestVerdictToFinding_CVEFromCVEMatches(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Bar.java"},
		CVEMatches: []enrichment.CVEMatch{
			{CVE: "CVE-2022-1234", CVSS: 8.5},
		},
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.8}
	f := verdictToFinding(surface, v)
	if f.CVE != "CVE-2022-1234" {
		t.Errorf("want CVE-2022-1234, got %q", f.CVE)
	}
	if f.CVSS != 8.5 {
		t.Errorf("want CVSS=8.5, got %f", f.CVSS)
	}
}

func TestVerdictToFinding_TaintMismatchSetsPinned(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Foo.java"},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
		Severity:      "CRITICAL",
		Confidence:    0.95,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityLow {
		t.Errorf("want SeverityLow, got %v", f.SeverityLabel)
	}
	if !f.SeverityPinned {
		t.Error("want SeverityPinned=true for TaintMismatch cap")
	}
}

func TestVerdictToFinding_MatchedCodeFromSurfaceCode(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Bar.java", Line: 20},
		Code:    "void bar() {\n  exec(input);\n}",
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.9}
	f := verdictToFinding(surface, v)
	if f.MatchedCode == "" {
		t.Error("want MatchedCode populated from surface.Code")
	}
	if !strings.Contains(f.MatchedCode, "exec(input)") {
		t.Errorf("want source code in MatchedCode, got %q", f.MatchedCode)
	}
}

func TestVerdictToFinding_DefaultSeverity(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-1",
			File: "x.go",
		},
	}
	v := Verdict{
		Exploitable: true,
		Severity:    "UNKNOWN",
		Confidence:  0.9,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityMedium {
		t.Errorf("want MEDIUM for unknown severity, got %v", f.SeverityLabel)
	}
}

// TestVerdictToFinding_ConfidentSafeVerdict_SeverityPinnedLow is a
// regression test for a severity-polarity inversion bug found live on a
// real litemall scan: dedup's applyBoostAndScore re-derives SeverityLabel
// from raw Confidence whenever SeverityPinned is false, with zero awareness
// of which direction that confidence points. A model 90% confident a
// surface is SAFE (exploitable=false, confidence=0.9, severity="LOW" in its
// own JSON) had that confident negative silently flipped into a persisted
// HIGH-severity finding, because only the TaintMismatch special case pinned
// severity — an ordinary confident "not exploitable" verdict didn't.
func TestVerdictToFinding_ConfidentSafeVerdict_SeverityPinnedLow(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: "node-1", File: "StorageService.java"},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: false, // NOT a taint mismatch — an ordinary confident negative
		Severity:      "LOW", // what the model itself said
		Confidence:    0.9,   // high confidence IN THE NEGATIVE, not in exploitability
		Explanation:   "Caller is gated by @PreAuthorize; no auth bypass.",
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityLow {
		t.Errorf("want SeverityLow for a confident exploitable=false verdict, got %v", f.SeverityLabel)
	}
	if !f.SeverityPinned {
		t.Error("want SeverityPinned=true so dedup's applyBoostAndScore can't re-derive severity from the raw confidence number and invert it")
	}
	if f.Confidence != 0.9 {
		t.Errorf("want Confidence preserved at 0.9 (it's meaningful for review triage), got %v", f.Confidence)
	}
}

// TestVerdictToFinding_SummaryAndExplanationAreSeparateFields is a
// regression test for a real quality bug: Summary and Justification used to
// both be set from the same word-capped Explanation string, so every
// finding's full reasoning was capped at ~25 words no matter how much real
// investigation the model did. Summary (short headline) and Explanation
// (the actual reasoning record) must now survive as genuinely distinct
// fields all the way into the finding.
func TestVerdictToFinding_SummaryAndExplanationAreSeparateFields(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: "node-1", File: "test.go"},
	}
	longExplanation := "get_callers returned Handler as the sole caller. Reading Handler's own " +
		"source, it validates the hash as a 32-character MD5 string and returns 404 before this " +
		"function is ever invoked, so the value reaching this function is already known-safe."
	v := Verdict{
		Exploitable: false,
		Severity:    "LOW",
		Confidence:  0.9,
		Summary:     "Caller validates the hash format before this function runs.",
		Explanation: longExplanation,
	}
	f := verdictToFinding(surface, v)
	if f.Justification != longExplanation {
		t.Errorf("want Justification to carry the full explanation, got %q", f.Justification)
	}
	if f.Summary != v.Summary {
		t.Errorf("want Summary to carry the short headline (not the long explanation), got %q", f.Summary)
	}
	if f.Summary == f.Justification {
		t.Error("Summary and Justification must be genuinely different fields, not the same string twice")
	}
}

// TestVerdictToFinding_MissingSummaryFallsBackToTruncatedExplanation is
// defensive coverage for a model that omits the summary field despite the
// prompt requiring it — the finding should still get a short, usable
// headline rather than an empty Summary or an unbounded one.
func TestVerdictToFinding_MissingSummaryFallsBackToTruncatedExplanation(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: "node-1", File: "test.go"},
	}
	words := make([]string, 40)
	for i := range words {
		words[i] = "word"
	}
	v := Verdict{
		Exploitable: true,
		Severity:    "HIGH",
		Confidence:  0.9,
		Summary:     "", // omitted
		Explanation: strings.Join(words, " "),
	}
	f := verdictToFinding(surface, v)
	if f.Summary == "" {
		t.Error("want a non-empty fallback Summary when the model omitted it")
	}
	if len(strings.Fields(f.Summary)) > 26 { // 25 words + "..."
		t.Errorf("want fallback Summary truncated to ~25 words, got %d words: %q", len(strings.Fields(f.Summary)), f.Summary)
	}
}
