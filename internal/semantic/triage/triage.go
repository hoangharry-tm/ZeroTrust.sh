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
	_ "embed"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// Prompt text lives in prompts/triage.md.tmpl — edit that file, not this one.
//
//go:embed prompts/triage.md.tmpl
var triagePromptSrc string

var triageTmpl = template.Must(template.New("triage").Parse(triagePromptSrc))

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

// triagePromptData is the template data for prompts/triage.md.tmpl.
type triagePromptData struct {
	File         string
	FunctionName string
	TaintInfo    string
	CWEs         string
	Code         string
}

// buildTriagePrompt builds an externalized step scaffold for 7B–30B models
// from prompts/triage.md.tmpl. Uses continuous scale calibration with an
// anchored 5-point guide. Edit prompts/triage.md.tmpl to change wording;
// this function only supplies the dynamic evidence fields.
func buildTriagePrompt(surface enrichment.EnrichedSurface) string {
	const budget = 1500
	code := stripIndent(surface.Code)
	if len(code) > budget {
		// Anchor the truncation window on the sink line (when known) instead
		// of blind head-truncation — found live: a long function whose sink
		// call sits past byte 1500 would have the actual dangerous call cut
		// out of the prompt entirely, and the model would score the
		// surviving (irrelevant) head as PROBABLY_SAFE/SAFE with no way to
		// ever see the thing it's supposed to be judging. This drop is
		// silent (no finding emitted), so the failure mode is worse here
		// than the same mistake in B5. Truncate BEFORE obfuscateCode (unlike
		// B5, which truncates after minifyCode) so the line-number math
		// isn't thrown off by lines obfuscateCode removes.
		if surface.SinkFile == surface.File && surface.SinkLine > 0 && surface.SinkLine >= surface.Line {
			code = truncateAroundLine(code, surface.SinkLine-surface.Line, budget)
		} else {
			code = truncateUTF8(code, budget) + "\n...[truncated]"
		}
	}
	code = obfuscateCode(code)

	taintInfo := "No confirmed taint path."
	if len(surface.SinkNodes) > 0 {
		taintInfo = fmt.Sprintf("CONFIRMED taint path to dangerous sink: %v", surface.SinkNodes)
	}

	cwes := "[]"
	if list := applicableCWEsForKind(surface.Kind); len(list) > 0 {
		cwes = strings.Join(list, ", ")
	}

	var sb strings.Builder
	if err := triageTmpl.Execute(&sb, triagePromptData{
		File:         shortPath(surface.File),
		FunctionName: surface.FunctionName,
		TaintInfo:    taintInfo,
		CWEs:         cwes,
		Code:         code,
	}); err != nil {
		panic("triage: triage.md.tmpl execute: " + err.Error())
	}
	return sb.String()
}

// triageOpts returns the LLM options for triage calls.
//
// NumCtx was previously unset here, which meant every triage call ran at
// Ollama's server-side default context window (~2048 tokens on most model
// configs) — code+evidence exceeding that gets silently truncated by Ollama
// itself, with no error and no visibility into what was cut. That's a worse
// failure mode than our own deliberate truncation: at least our truncation
// is logged and bounded on purpose. 8192 covers triage's smaller prompt
// (single function body, no multi-section evidence bundle) with headroom.
func triageOpts() *llm.Options {
	// Think: new(false) — see analysisOpts' doc comment in
	// internal/semantic/analysis/analysis.go for why every call site
	// disables thinking-mode explicitly rather than leaving it to the
	// model's default: a thinking-capable model can burn its entire
	// NumPredict budget on invisible chain-of-thought and return empty
	// content, and triage's job (emit one decimal number) needs none of it.
	return &llm.Options{Temperature: 0.1, NumPredict: 256, NumCtx: 8192, Think: new(false)}
}

// shortPath returns the last 2 path segments joined by "/".
// truncateUTF8 returns the first n bytes of s, backing up to the nearest
// rune boundary if n would otherwise split a multi-byte UTF-8 character —
// plain code[:n] byte-slicing corrupts non-ASCII comments/strings (Chinese,
// Japanese, Vietnamese etc. are common in real codebases).
func truncateUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func shortPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) <= 2 {
		return p
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

// truncateAroundLine returns a budget-byte window of code centred on
// targetLine (0-indexed), rather than the head of the string. Mirrors
// internal/semantic/analysis's helper of the same name/purpose; kept
// package-local rather than shared since each package already keeps its own
// stripIndent copy and neither has drifted.
func truncateAroundLine(code string, targetLine, budget int) string {
	lines := strings.Split(code, "\n")
	if targetLine < 0 {
		targetLine = 0
	}
	if targetLine >= len(lines) {
		targetLine = len(lines) - 1
	}

	lo, hi := targetLine, targetLine
	size := len(lines[targetLine])
	for {
		grew := false
		if hi+1 < len(lines) && size+len(lines[hi+1])+1 <= budget {
			hi++
			size += len(lines[hi]) + 1
			grew = true
		}
		if lo-1 >= 0 && size+len(lines[lo-1])+1 <= budget {
			lo--
			size += len(lines[lo]) + 1
			grew = true
		}
		if !grew {
			break
		}
	}

	var sb strings.Builder
	if lo > 0 {
		sb.WriteString("... [truncated head]\n")
	}
	sb.WriteString(strings.Join(lines[lo:hi+1], "\n"))
	if hi < len(lines)-1 {
		sb.WriteString("\n... [truncated tail]")
	}
	return sb.String()
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

// categoryPattern maps a category word (from prompts/triage.md.tmpl) to its
// numeric confidence. This mapping lives only here, in Go — never shown to
// the model as a literal number. Checked most-specific-first (PROBABLY_SAFE
// before bare SAFE) so a substring match can't pick the wrong one.
//
// This replaced a decimal-scale prompt ("reply with a number 0.0-1.0, here
// are 5 example anchor values") after a real anchoring-bias bug: every one
// of 49 real triage calls in one litemall scan returned the literal string
// "0.25" — the second example number printed in the old prompt — verbatim,
// regardless of which of 14+ different functions was being scored. The
// model was copying a displayed digit, not reasoning about the code (the
// same failure mode as a multiple-choice test-taker who always picks "A").
// Requiring a category WORD (no digit in the prompt to copy) plus a
// mandatory one-sentence Reasoning line before the Category line is meant to
// force at least minimal deliberation instead of pattern-completion.
var categoryPattern = []struct {
	re    *regexp.Regexp
	score float64
}{
	{regexp.MustCompile(`PROBABLY[ _]SAFE`), 0.25},
	{regexp.MustCompile(`PROBABLY[ _]VULNERABLE`), 0.75},
	{regexp.MustCompile(`EXPLOITABLE`), 1.0},
	{regexp.MustCompile(`UNCERTAIN`), 0.5},
	{regexp.MustCompile(`\bSAFE\b`), 0.0},
}

// parseConfidence parses a confidence score from a raw LLM response.
// Primary path: the "Category: <WORD>" line the prompt asks for. Fallback:
// a category word anywhere in the response. Last-resort fallback: a bare
// decimal, for a model that ignores the format entirely — logged as a
// warning, since seeing this path taken means the model isn't following
// instructions, not a healthy signal.
// If nothing parseable: returns 0.5 (uncertain), NOT 0.0 (certainly safe).
func parseConfidence(raw string) float64 {
	upper := strings.ToUpper(raw)

	if idx := strings.Index(upper, "CATEGORY:"); idx != -1 {
		line := upper[idx:]
		if nl := strings.IndexByte(line, '\n'); nl != -1 {
			line = line[:nl]
		}
		for _, p := range categoryPattern {
			if p.re.MatchString(line) {
				return p.score
			}
		}
	}

	for _, p := range categoryPattern {
		if p.re.MatchString(upper) {
			return p.score
		}
	}

	re := regexp.MustCompile(`\b(0\.\d+|1\.0)\b`)
	if m := re.FindString(raw); m != "" {
		v, _ := strconv.ParseFloat(m, 64)
		if v >= 0 && v <= 1 {
			slog.Warn("triage: response used a bare decimal instead of the requested category word — model did not follow the expected format", "raw", raw)
			return v
		}
	}

	// No parseable value: return 0.5 (uncertain), NOT 0.0 (certainly safe)
	return 0.5
}
