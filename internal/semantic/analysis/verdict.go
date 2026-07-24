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

package analysis

import (
	"encoding/json"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
)

// Verdict is the structured JSON response from the LLM for one surface.
//
// Summary and Explanation are deliberately separate fields with different
// jobs — found live: they used to be the same ≤25-word string doing both
// jobs at once (a report-card title AND the full justification), which
// meant every finding's Justification was capped at 25 words no matter how
// much real investigation the model did (checking callers, reading actual
// code across several tool calls). A human reviewing a finding saw a
// generic one-liner like "no guard found in caller chain" with zero
// indication of which caller, what code, or what was actually checked —
// worse than what a general-purpose coding agent produces for the same
// question, because the pipeline was discarding the model's own work
// product, not because the model couldn't produce more. Summary keeps the
// short report-card role; Explanation is now the actual reasoning record.
type Verdict struct {
	Exploitable bool    `json:"exploitable"`
	CWE         string  `json:"cwe"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	// Summary is a short (~25 words) report-card headline.
	Summary string `json:"summary"`
	// Explanation is the fuller reasoning: which specific evidence (CWE
	// invariant, code, tool results) led to this verdict — not word-capped.
	Explanation   string `json:"explanation"`
	TaintMismatch bool   `json:"taint_mismatch"`
}

// parseVerdict extracts the JSON verdict from a raw LLM response.
// Handles leading/trailing prose by scanning for the first '{' and last '}'.
// On strict parse failure, falls back to salvageVerdict before giving up —
// see its doc comment for why. Only returns a default safe verdict
// (Exploitable: false, everything else zero) if salvage also fails.
func parseVerdict(raw string) Verdict {
	start := strings.IndexByte(raw, '{')
	end := strings.LastIndexByte(raw, '}')
	if start == -1 || end == -1 || start >= end {
		slog.Warn("analysis: no JSON object found in LLM response", "raw", raw)
		return Verdict{Exploitable: false}
	}

	candidate := raw[start : end+1]
	var v Verdict
	if err := json.Unmarshal([]byte(candidate), &v); err == nil {
		return v
	} else {
		slog.Warn("analysis: failed to parse verdict JSON, attempting field salvage", "err", err, "raw", raw)
	}

	if salvaged, ok := salvageVerdict(candidate); ok {
		slog.Info("analysis: recovered verdict via field salvage after malformed JSON",
			"exploitable", salvaged.Exploitable, "confidence", salvaged.Confidence)
		return salvaged
	}
	slog.Warn("analysis: field salvage also failed, dropping verdict", "raw", raw)
	return Verdict{Exploitable: false}
}

// salvageRe extracts one field each from a JSON object that failed to parse
// strictly — found live: a model's generation glitched mid-sentence inside
// the "explanation" string value, leaking a stray unescaped fragment that
// corrupted the object's syntax. The model's actual judgment (a
// well-reasoned, correct exploitable=false at confidence=0.95) was
// discarded entirely because json.Unmarshal has no partial-recovery mode —
// one malformed string field lost an otherwise-good verdict. Regex-scanning
// each field independently survives exactly this kind of localized
// corruption: a single field can be truncated at the first unescaped quote
// without preventing the OTHER fields (which are usually well-formed) from
// being recovered.
var (
	salvageExploitableRe   = regexp.MustCompile(`"exploitable"\s*:\s*(true|false)`)
	salvageCWERe           = regexp.MustCompile(`"cwe"\s*:\s*"([^"]*)"`)
	salvageSeverityRe      = regexp.MustCompile(`"severity"\s*:\s*"([^"]*)"`)
	salvageConfidenceRe    = regexp.MustCompile(`"confidence"\s*:\s*([0-9]*\.?[0-9]+)`)
	salvageSummaryRe       = regexp.MustCompile(`"summary"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	salvageExplanationRe   = regexp.MustCompile(`"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	salvageTaintMismatchRe = regexp.MustCompile(`"taint_mismatch"\s*:\s*(true|false)`)
)

// salvageVerdict best-effort field-extracts a Verdict from a malformed JSON
// candidate. Requires "exploitable" to be recoverable at all — that's the
// single most decision-critical field; if even that can't be found, the
// text is too corrupted to trust and the caller should fall back to the
// safe default instead. Every other field degrades gracefully to its zero
// value if not found (matching a clean json.Unmarshal's own behavior for
// fields the model omitted).
func salvageVerdict(candidate string) (Verdict, bool) {
	m := salvageExploitableRe.FindStringSubmatch(candidate)
	if m == nil {
		return Verdict{}, false
	}
	v := Verdict{Exploitable: m[1] == "true"}

	if m := salvageCWERe.FindStringSubmatch(candidate); m != nil {
		v.CWE = m[1]
	}
	if m := salvageSeverityRe.FindStringSubmatch(candidate); m != nil {
		v.Severity = m[1]
	}
	if m := salvageConfidenceRe.FindStringSubmatch(candidate); m != nil {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			v.Confidence = f
		}
	}
	if m := salvageSummaryRe.FindStringSubmatch(candidate); m != nil {
		v.Summary = unescapeJSONString(m[1])
	}
	if m := salvageExplanationRe.FindStringSubmatch(candidate); m != nil {
		v.Explanation = unescapeJSONString(m[1])
	}
	if m := salvageTaintMismatchRe.FindStringSubmatch(candidate); m != nil {
		v.TaintMismatch = m[1] == "true"
	}

	v.Explanation = "[recovered from malformed JSON, may be truncated] " + v.Explanation
	return v, true
}

// unescapeJSONString decodes JSON escape sequences (\", \\, \n, etc.) in a
// regex-captured string fragment by re-wrapping it as a JSON string literal
// and letting encoding/json do the actual unescaping. Falls back to the raw
// fragment if that somehow still doesn't parse (shouldn't happen given the
// capturing regex only matches valid escape-sequence content, but never
// worth a panic over a salvage path).
func unescapeJSONString(s string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err == nil {
		return out
	}
	return s
}

// verdictToFinding converts an exploitable Verdict + surface into a finding.Finding.
func verdictToFinding(surface enrichment.EnrichedSurface, v Verdict) finding.Finding {
	// Use DCC ground truth first, then kind-based mapping, then LLM advisory.
	cwe := surface.ContractCWE
	if cwe == "" {
		cwe = applicableCWE(surface.Kind)
	}
	if cwe == "" {
		cwe = v.CWE
	}

	severity := severityFromLabel(v.Severity)
	severityPinned := false
	if !v.Exploitable {
		// Pin for EVERY exploitable=false verdict, not just the taint-mismatch
		// case — a real severity-polarity inversion bug, found live: dedup's
		// applyBoostAndScore re-derives SeverityLabel from raw Confidence
		// whenever SeverityPinned is false, with no awareness of which
		// direction that confidence points. A model that's 90% confident a
		// surface is SAFE (exploitable=false, confidence=0.9) had that
		// "confident negative" silently flipped into "HIGH severity" —
		// observed on a real litemall scan, where justifications reading
		// "authorization likely enforced upstream" (a safe conclusion) ended
		// up persisted as active BLOCK/HIGH findings. Pinning here means
		// dedup trusts the verdict's own severity/exploitability instead of
		// re-deriving one from a number that was never meant to answer
		// "how severe" — only "how sure."
		severity = finding.SeverityLow
		severityPinned = true
	}
	confidence := v.Confidence
	if confidence <= 0 {
		confidence = 0.5
	}

	line := surface.Line

	// Use sink line when populated (inter-procedural taint path).
	startLine := line
	endLine := line
	if surface.SinkLine > 0 {
		startLine = surface.SinkLine
		endLine = surface.SinkLine
	}

	var cve string
	var cvss float64
	if len(surface.CVEMatches) > 0 {
		cve = surface.CVEMatches[0].CVE
		cvss = surface.CVEMatches[0].CVSS
	}

	codeSnippet := surface.Code
	if codeSnippet != "" {
		codeLines := strings.Split(codeSnippet, "\n")
		if len(codeLines) > 30 {
			codeLines = codeLines[:30]
		}
		codeSnippet = strings.Join(codeLines, "\n")
	}

	// summary falls back to Explanation (truncated to a short headline) when
	// the model omitted the summary field — defensive, not the expected
	// path, since the prompt requires both fields.
	summary := v.Summary
	if summary == "" {
		summary = firstNWords(v.Explanation, 25)
	}

	return finding.Finding{
		ID:             finding.ComputeID(cwe, surface.File, startLine),
		SurfaceID:      surface.ID,
		CWE:            cwe,
		SeverityLabel:  severity,
		SeverityPinned: severityPinned,
		Confidence:     confidence,
		Path:           surface.File,
		LineRange:      finding.LineRange{Start: startLine, End: endLine},
		MatchedCode:    codeSnippet,
		CVE:            cve,
		CVSS:           cvss,
		Justification:  v.Explanation,
		Summary:        summary,
		SourcePath:     finding.SourceSemantic,
		TaintMismatch:  v.TaintMismatch,
		Exploitable:    v.Exploitable,
	}
}

// firstNWords returns the first n whitespace-separated words of s, joined
// back with single spaces — used as a defensive fallback when the model
// didn't produce a separate short summary.
func firstNWords(s string, n int) string {
	words := strings.Fields(s)
	if len(words) <= n {
		return s
	}
	return strings.Join(words[:n], " ") + "..."
}

// severityFromLabel maps a verdict severity string to a finding.SeverityLabel.
func severityFromLabel(label string) finding.SeverityLabel {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return finding.SeverityBlock
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}
