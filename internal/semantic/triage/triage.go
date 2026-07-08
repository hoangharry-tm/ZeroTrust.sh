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
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
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

		code := stripIndent(surface.Code)
		if len(code) > 1500 {
			code = code[:1500]
		}
		taintInfo := "No confirmed taint path."
		if len(surface.SinkNodes) > 0 {
			taintInfo = fmt.Sprintf("CONFIRMED taint path to dangerous sink: %v", surface.SinkNodes)
		}
		prompt := fmt.Sprintf(
			"You are a security code reviewer. Assess whether this function contains an exploitable vulnerability.\n"+
				"File: %s\nFunction: %s\n"+
				"Taint analysis: %s\n"+
				"CWE candidates: %v\n\n"+
				"Source code:\n```\n%s\n```\n\n"+
				"Reply with ONLY a single decimal number between 0.0 and 1.0 representing your confidence "+
				"that this function is exploitable. 1.0 = certain vulnerability, 0.0 = certainly safe.",
			surface.File, surface.FunctionName, taintInfo, surface.CVEMatches, code)

		slog.Debug("triage: prompt",
			"prompt", prompt,
		)

		score := t.threshold
		explanation := "not evaluated"

		// ponytail: 2048 tokens — qwen3.5:9b consumes 873–2323 thinking tokens before
		// emitting output; 512 still exhausts mid-CoT → empty → threshold fallback.
		slog.Debug("triage: pre_send",
			"num_predict", 2048,
		)
		genStart := time.Now()
		resp, err := t.llm.Generate(ctx, prompt, &llm.Options{NumPredict: 2048, Think: boolPtr(false)})
		genElapsed := time.Since(genStart)
		if err == nil {
			slog.Debug("triage: response",
				"raw_resp", resp,
				"elapsed_ms", genElapsed.Milliseconds(),
			)

			// ponytail: simple confidence parsing — enhancement planned with
			// structured JSON output in the post-MVP LLM reasoner.
			confidence := parseConfidence(resp)
			slog.Debug("triage: parse_result",
				"confidence", confidence,
				"fell_back_to_threshold", confidence < 0,
			)
			if confidence >= 0 {
				score = confidence
			}
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

// boolPtr returns a pointer to b for use with llm.Options.Think.
func boolPtr(b bool) *bool { return &b }

// stripIndent removes leading whitespace from each line to reduce prompt token waste.
func stripIndent(code string) string {
	lines := strings.Split(code, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimLeft(l, " \t")
	}
	return strings.Join(lines, "\n")
}

// parseConfidence scans all whitespace-delimited tokens in s and returns the
// last token that parses as a float64 in [0.0, 1.0]. Returns -1 when no valid
// token is found.
func parseConfidence(s string) float64 {
	best := -1.0
	for _, token := range strings.Fields(s) {
		token = strings.TrimRight(token, ".,;:")
		var v float64
		if _, err := fmt.Sscanf(token, "%f", &v); err == nil && v >= 0 && v <= 1 {
			best = v
		}
	}
	return best
}
