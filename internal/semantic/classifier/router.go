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

package classifier

import (
	"log/slog"
	"path/filepath"

	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// ClassifiedSurface pairs an EnrichedSurface result with the classifier verdict.
type ClassifiedSurface struct {
	// Result is the classifier output for this surface.
	Result
	// File is the source file path (copied from the surface for routing decisions).
	File string
	// BypassedClassifier is true when the classifier was skipped entirely because
	// the source language is not supported (Rust, Kotlin, Swift, C#).
	BypassedClassifier bool
}

// RouteResult holds the three destination buckets returned by Route.
type RouteResult struct {
	// ToDedup receives surfaces classified as vulnerable with high confidence.
	// These bypass the Assembler and go directly to Dedup.
	ToDedup []ClassifiedSurface
	// ToAssembler receives uncertain, IDOR, and unsupported-language surfaces.
	// These proceed to the Call Chain Assembler + LLM semantic scan.
	ToAssembler []ClassifiedSurface
	// Dismissed receives surfaces classified as safe with high confidence.
	// These exit Path B without further cost.
	Dismissed []ClassifiedSurface
}

// unsupportedExts is the set of file extensions whose languages UniXcoder does
// not support. Surfaces with these extensions bypass the classifier entirely.
var unsupportedExts = map[string]struct{}{
	".rs":    {},
	".kt":    {},
	".swift": {},
	".cs":    {},
}

// isUnsupportedExt reports whether the file extension requires a classifier bypass.
func isUnsupportedExt(file string) bool {
	_, ok := unsupportedExts[filepath.Ext(file)]
	return ok
}

// RouteAndLog calls Route then logs funnel stats via logger. If the fraction of
// surfaces reaching the LLM tier (ToDedup + ToAssembler) exceeds 25%, it logs
// a warning — the pipeline is not hard-failed. If logger is nil, slog.Default()
// is used.
func RouteAndLog(surfaces []ClassifiedSurface, logger *slog.Logger) RouteResult {
	if logger == nil {
		logger = slog.Default()
	}
	r := Route(surfaces)
	total := len(surfaces)
	if total == 0 {
		return r
	}
	toDedup := len(r.ToDedup)
	toAssembler := len(r.ToAssembler)
	dismissed := len(r.Dismissed)
	logger.Info("classifier funnel",
		"component", "classifier",
		"total", total,
		"to_dedup", toDedup,
		"to_assembler", toAssembler,
		"dismissed", dismissed,
	)
	escalationRate := float64(toDedup+toAssembler) / float64(total)
	if escalationRate > tuning.EscalationCap {
		logger.Warn("classifier funnel escalation rate exceeds cap",
			"component", "classifier",
			"escalation_rate", escalationRate,
			"cap", tuning.EscalationCap,
			"to_dedup", toDedup,
			"to_assembler", toAssembler,
			"total", total,
		)
	}
	return r
}

// Route partitions classified surfaces into three destination buckets.
//
// Routing rules (evaluated in priority order):
//  1. IDOR candidate → ToAssembler with EscalateReason "idor_candidate",
//     regardless of classifier verdict or file extension.
//  2. Unsupported language extension (.rs, .kt, .swift, .cs) → ToAssembler
//     with BypassedClassifier=true, regardless of classifier verdict.
//  3. LabelVulnerable → ToDedup (classifier confident; Assembler adds no value).
//  4. LabelSafe, confidence ≥ ThresholdVulnerable → Dismissed.
//  5. LabelUncertain or low-confidence safe → ToAssembler.
func Route(surfaces []ClassifiedSurface) RouteResult {
	var r RouteResult
	for _, s := range surfaces {
		switch {
		case s.Escalate && s.EscalateReason == EscalateIDOR:
			r.ToAssembler = append(r.ToAssembler, s)
		case isUnsupportedExt(s.File):
			s.BypassedClassifier = true
			r.ToAssembler = append(r.ToAssembler, s)
		case s.Label == LabelVulnerable:
			r.ToDedup = append(r.ToDedup, s)
		case s.Label == LabelSafe && s.Confidence >= ThresholdVulnerable:
			r.Dismissed = append(r.Dismissed, s)
		default:
			r.ToAssembler = append(r.ToAssembler, s)
		}
	}
	return r
}
