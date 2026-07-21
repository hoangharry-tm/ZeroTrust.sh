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

// Package triage provides a lightweight LLM-based coarse filter for
// contract-inconclusive surfaces. Surfaces below the confidence threshold
// are dropped; those above are escalated to the full analysis stage.
package triage

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// Disposition is the triage decision for a single surface.
type Disposition int

const (
	DispositionDrop     Disposition = iota // confidence below threshold — dropped
	DispositionEscalate                    // confidence at or above threshold — forwarded to B5
)

func (d Disposition) String() string {
	switch d {
	case DispositionDrop:
		return "DROP"
	case DispositionEscalate:
		return "ESCALATE"
	default:
		return "UNKNOWN"
	}
}

// Result wraps a triage decision with the original surface and metadata.
type Result struct {
	Surface     enrichment.EnrichedSurface
	Disposition Disposition
	Confidence  float64
	Explanation string
}

// Triager runs a lightweight LLM filter on inconclusive surfaces.
type Triager struct {
	llm       llm.Provider
	threshold float64
}

// New returns a Triager that uses provider for inference and drops surfaces
// whose confidence score falls below threshold.
func New(provider llm.Provider, threshold float64) *Triager {
	return &Triager{llm: provider, threshold: threshold}
}

// Filter evaluates each surface and returns a triage result. Surfaces with
// confidence >= threshold are escalated; the rest are dropped.
//
// ponytail: This is a lightweight coarse filter — it makes one bounded LLM
// call per surface. The full reasoner (B5) is reserved for escalated surfaces.
func (t *Triager) Filter(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]Result, error) {
	if len(surfaces) == 0 {
		return nil, nil
	}

	results := make([]Result, 0, len(surfaces))

	for _, surface := range surfaces {
		slog.Debug("triage: input",
			"function", surface.FunctionName,
			"file", surface.File,
			"has_code", surface.Code != "",
			"has_sink_nodes", len(surface.SinkNodes) > 0,
			"sink_nodes", surface.SinkNodes,
			"code_len", len(surface.Code),
		)

		code := strings.TrimSpace(surface.Code)
		if len(code) < 50 {
			slog.Debug("triage: stub dropped (no method body)",
				"function", surface.FunctionName,
				"file", surface.File,
				"code_len", len(surface.Code),
			)
			results = append(results, Result{
				Surface:     surface,
				Disposition: DispositionDrop,
				Confidence:  0.0,
				Explanation: "stub: no method body",
			})
			continue
		}

		prompt := buildTriagePrompt(surface)
		opts := triageOpts()

		slog.Debug("triage: prompt",
			"prompt", prompt,
			"opts", fmt.Sprintf("%+v", opts),
		)

		score := t.threshold
		explanation := "not evaluated"

		genStart := time.Now()
		resp, err := t.llm.Generate(ctx, prompt, opts)
		genElapsed := time.Since(genStart)
		if err == nil {
			slog.Debug("triage: response",
				"raw_resp", resp,
				"elapsed_ms", genElapsed.Milliseconds(),
			)

			confidence := parseConfidence(resp)
			slog.Debug("triage: parse_result",
				"confidence", confidence,
			)
			score = confidence
			explanation = resp
		} else {
			slog.Debug("triage: response",
				"err", err.Error(),
				"elapsed_ms", genElapsed.Milliseconds(),
			)
		}

		var disp Disposition
		if score >= t.threshold {
			disp = DispositionEscalate
		} else {
			disp = DispositionDrop
		}

		slog.Debug("triage: surface scored",
			"file", surface.File,
			"function", surface.FunctionName,
			"confidence", score,
			"disposition", disp.String(),
			"has_code", surface.Code != "",
			"has_sink_nodes", len(surface.SinkNodes) > 0,
		)

		results = append(results, Result{
			Surface:     surface,
			Disposition: disp,
			Confidence:  score,
			Explanation: explanation,
		})
	}

	var escalated, dropped int
	scoreSum := 0.0
	for _, r := range results {
		if r.Disposition == DispositionEscalate {
			escalated++
		} else {
			dropped++
		}
		scoreSum += r.Confidence
	}
	avg := 0.0
	if len(results) > 0 {
		avg = scoreSum / float64(len(results))
	}
	slog.Info("triage: summary",
		"total", len(results),
		"escalated", escalated,
		"dropped", dropped,
		"avg_confidence", avg,
	)

	return results, nil
}

// applicableCWEsForKind returns the applicable CWE IDs for a given surface kind,
// matching the contracts package mapping. Duplicated inline to avoid circular import.
func applicableCWEsForKind(kind targeting.SurfaceKind) []string {
	switch kind {
	case targeting.SurfaceExternalInput:
		return []string{"CWE-22", "CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-502", "CWE-918"}
	case targeting.SurfaceAuthBoundary:
		return []string{"CWE-862", "CWE-89", "CWE-78"}
	case targeting.SurfaceIDORCandidate:
		return []string{"CWE-862", "CWE-89", "CWE-78"}
	case targeting.SurfaceDangerousSink:
		return []string{"CWE-327"}
	default:
		return nil
	}
}

// buildTriagePromptMid builds an externalized step scaffold for 7B–30B models.
// Uses continuous scale calibration with an anchored 5-point guide.
func buildTriagePrompt(surface enrichment.EnrichedSurface) string {
	code := obfuscateCode(stripIndent(surface.Code))
	if len(code) > 1500 {
		code = code[:1500] + "\n...[truncated]"
	}

	taintInfo := "No confirmed taint path."
	if len(surface.SinkNodes) > 0 {
		taintInfo = fmt.Sprintf("CONFIRMED taint path to dangerous sink: %v", surface.SinkNodes)
	}

	var sb strings.Builder
	sb.WriteString("You are a security code reviewer. Score this function for exploitability.\n\n")
	sb.WriteString("File: ")
	sb.WriteString(shortPath(surface.File))
	sb.WriteString("\nFunction: ")
	sb.WriteString(surface.FunctionName)
	sb.WriteString("\nTaint: ")
	sb.WriteString(taintInfo)
	sb.WriteString("\nApplicable CWEs: ")
	cwes := applicableCWEsForKind(surface.Kind)
	if len(cwes) == 0 {
		sb.WriteString("[]")
	} else {
		sb.WriteString(strings.Join(cwes, ", "))
	}
	sb.WriteString("\n\nCode:\n```\n")
	sb.WriteString(code)
	sb.WriteString("\n```\n\nReply with ONLY a decimal between 0.0 and 1.0 (two decimal places).\n")
	sb.WriteString("Calibration guide:\n")
	sb.WriteString("  0.00 — certainly safe: sanitizer present on every code path\n")
	sb.WriteString("  0.25 — probably safe: pattern is benign, no sink reachable\n")
	sb.WriteString("  0.50 — uncertain: some concern but evidence is insufficient\n")
	sb.WriteString("  0.75 — probably vulnerable: sink reachable, no sanitizer found\n")
	sb.WriteString("  1.00 — certainly exploitable: taint confirmed, no safe node\n")
	sb.WriteString("Do NOT output anything other than a single decimal number.")
	return sb.String()
}

// triageOpts returns the LLM options for triage calls.
func triageOpts() *llm.Options {
	return &llm.Options{Temperature: 0.1, NumPredict: 256}
}

// shortPath returns the last 2 path segments joined by "/".
func shortPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) <= 2 {
		return p
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

// stripIndent removes leading whitespace from each line to reduce prompt token waste.
func stripIndent(code string) string {
	lines := strings.Split(code, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimLeft(l, " \t")
	}
	return strings.Join(lines, "\n")
}

// obfuscateCode strips structural identity signals from code before LLM injection.
// It removes package declarations, import blocks, line/block comments, and blanks
// string literal contents — eliminating project-name leakage without knowing the
// project name. Language-agnostic: works on Java, Go, Python, JS, etc.
func obfuscateCode(code string) string {
	var out strings.Builder
	lines := strings.Split(code, "\n")
	inBlockComment := false
	inImportBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track block comment state (/* ... */)
		if inBlockComment {
			if strings.Contains(trimmed, "*/") {
				inBlockComment = false
			}
			continue
		}
		if strings.Contains(trimmed, "/*") && !strings.Contains(trimmed, "*/") {
			inBlockComment = true
			continue
		}

		// Strip package declarations (Java: "package x.y.z;", Go: "package foo")
		if strings.HasPrefix(trimmed, "package ") {
			continue
		}

		// Strip import blocks (Java multi-line: "import (", Go single: "import x")
		if strings.HasPrefix(trimmed, "import ") || trimmed == "import (" {
			inImportBlock = trimmed == "import ("
			continue
		}
		if inImportBlock {
			if trimmed == ")" {
				inImportBlock = false
			}
			continue
		}

		// Strip line comments: // and # (any language), -- only when followed by
		// a space (SQL convention). "--identifier" is a decrement op, not a comment.
		isComment := strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "-- ")
		if isComment {
			continue
		}
		if trimmed == "" {
			continue
		}

		// Blank string literal contents while preserving structure.
		// "hello world" → ""   'x' → ''
		// Keeps quotes so concatenation patterns remain visible.
		line = blankStringLiterals(line)

		out.WriteString(line)
		out.WriteByte('\n')
	}
	return strings.TrimSpace(out.String())
}

// blankStringLiterals replaces the contents of double and single-quoted string
// literals with empty strings, preserving the quote characters themselves.
func blankStringLiterals(line string) string {
	var out strings.Builder
	i := 0
	for i < len(line) {
		ch := line[i]
		// Detect start of string literal
		if ch == '"' || ch == '\'' {
			quote := ch
			out.WriteByte(quote) // opening quote
			i++
			// Skip content until closing (unescaped) quote
			for i < len(line) {
				c := line[i]
				if c == '\\' {
					i += 2 // skip escape sequence
					continue
				}
				if c == quote {
					break
				}
				i++
			}
			if i < len(line) {
				out.WriteByte(quote) // closing quote
				i++
			}
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

// parseConfidence parses a confidence score from a raw LLM response.
// Primary path: any decimal in [0.0, 1.0] (continuous scale, per the prompt's
// calibration guide). Anchored labels and SAFE/UNSAFE are accepted as fallbacks
// for models that don't follow the decimal-only instruction exactly.
// If nothing parseable: returns 0.5 (uncertain), NOT 0.0 (certainly safe).
func parseConfidence(raw string) float64 {
	// Try regex for any decimal in [0.0, 1.0] first — primary path for continuous scale.
	re := regexp.MustCompile(`\b(0\.\d+|1\.0)\b`)
	if m := re.FindString(raw); m != "" {
		v, _ := strconv.ParseFloat(m, 64)
		if v >= 0 && v <= 1 {
			return v
		}
	}
	upper := strings.ToUpper(strings.TrimSpace(raw))
	if upper == "UNSAFE" {
		return 1.0
	}
	if upper == "SAFE" {
		return 0.0
	}
	// Backward compatibility: anchored labels
	for _, label := range []string{"1.0", "0.7", "0.5", "0.3", "0.0"} {
		if strings.Contains(raw, label) {
			v, _ := strconv.ParseFloat(label, 64)
			return v
		}
	}
	// No parseable value: return 0.5 (uncertain), NOT 0.0 (certainly safe)
	return 0.5
}
