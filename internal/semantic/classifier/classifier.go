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

// Package classifier wraps the UniXcoder-Base-Nine vulnerability classifier
// (Path B Tier 2) via the Python worker IPC boundary.
//
// UniXcoder-Base-Nine (~125M parameters, CPU-only) is a code understanding model
// fine-tuned on BigVul. It gates surfaces before the expensive LLM reasoning tier,
// targeting ~75–85% elimination of surfaces that reach this stage.
//
// # A-18 blocking dependency
//
// BigVul F1 (94.73%) is measured on C/C++ only and is NOT a valid claim for
// Python / Java / JS / Go. CVEFixes fine-tuning and per-language benchmark
// validation are required before publishing accuracy figures. Until then the
// classifier operates in high-recall mode: the escalation threshold is set
// conservatively (default 0.80) so uncertain verdicts escalate to the LLM rather
// than being silently dismissed.
//
// # Language support
//
// Supported (classifier runs): Python, Java, JavaScript, TypeScript, Go, Ruby, PHP.
// Unsupported (routed directly to LLM): Rust, Kotlin, Swift, C#.
//
// # IDOR escalation
//
// Surfaces marked IsIDORCandidate always escalate to the LLM tier regardless of
// the classifier verdict. The classifier result is still recorded for observability.
//
// # Routing summary
//
//	IDOR candidate          → Escalate=true,  EscalateReason="idor_candidate"
//	Unsupported language    → Escalate=true,  EscalateReason="unsupported_language"
//	Classifier: uncertain   → Escalate=true,  EscalateReason="uncertain"
//	Classifier: safe        → Escalate=false  (surface exits Path B)
//	Classifier: vulnerable  → Escalate=true,  EscalateReason="vulnerable" (→ LLM scan)
package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// Label is the 3-band classification output from UniXcoder.
type Label string

const (
	// LabelVulnerable means the classifier predicts the surface is vulnerable.
	// These surfaces are forwarded to the Call Chain Assembler + LLM tier.
	LabelVulnerable Label = "vulnerable"
	// LabelSafe means the classifier predicts the surface is benign.
	// High-confidence safe verdicts exit Path B without LLM cost.
	LabelSafe Label = "safe"
	// LabelUncertain means confidence is below the escalation threshold.
	// Uncertain surfaces are forwarded to the LLM tier (high-recall guarantee).
	LabelUncertain Label = "uncertain"
)

// EscalateReason describes why a surface must proceed past the classifier gate.
type EscalateReason string

const (
	// EscalateIDOR means the surface is an IDOR candidate; always escalates.
	EscalateIDOR EscalateReason = "idor_candidate"
	// EscalateUnsupportedLang means the source language has no classifier support.
	EscalateUnsupportedLang EscalateReason = "unsupported_language"
	// EscalateUncertain means the classifier confidence fell below the threshold.
	EscalateUncertain EscalateReason = "uncertain"
	// EscalateVulnerable means the classifier predicted the surface is vulnerable.
	EscalateVulnerable EscalateReason = "vulnerable"
)

// ThresholdVulnerable is the minimum confidence at which a classifier verdict
// of "vulnerable" is accepted without down-grading to "uncertain".
// A-18: conservative until CVEFixes multi-language benchmark is complete.
const ThresholdVulnerable = tuning.ClassifierVulnerableThreshold

// ThresholdSafe is the minimum confidence required for a "safe" verdict to
// dismiss a surface without LLM escalation. Below this the verdict is treated
// as "uncertain" and escalates to the LLM tier (high-recall guarantee).
// A-18: conservative until CVEFixes multi-language benchmark is complete.
const ThresholdSafe = tuning.ClassifierSafeThreshold

// supportedLanguages is the set of language identifiers that UniXcoder handles.
// Keys are normalised lowercase strings (e.g. "js" is not in the set; callers
// should normalise before calling IsSupported).
var supportedLanguages = map[string]struct{}{
	"python":     {},
	"java":       {},
	"javascript": {},
	"typescript": {},
	"go":         {},
	"ruby":       {},
	"php":        {},
}

// IsSupported reports whether lang is handled by the UniXcoder classifier.
// Unsupported languages bypass the classifier and route directly to the LLM tier.
// lang is normalised to lowercase before the lookup.
func IsSupported(lang string) bool {
	_, ok := supportedLanguages[strings.ToLower(lang)]
	return ok
}

// Result is the classifier output for one surface.
type Result struct {
	// SurfaceID matches the input enrichment.EnrichedSurface.ID.
	SurfaceID string
	// Label is the 3-band classification from UniXcoder.
	Label Label
	// Confidence is the model's probability for the winning label (0.0–1.0).
	Confidence float64
	// Escalate is true when the surface must proceed to the LLM tier.
	Escalate bool
	// EscalateReason describes why the surface escalated (empty when Escalate=false).
	EscalateReason EscalateReason
}

// Gate applies the UniXcoder classifier to a batch of enriched surfaces.
type Gate struct {
	w                   *worker.Manager
	escalationThreshold float64
	logger              *slog.Logger
}

// New returns a Gate with the default escalation threshold of 0.80.
// In high-recall mode, only surfaces classified with confidence ≥ 0.80 as safe
// exit Path B; everything else escalates to the LLM tier.
// If logger is nil, slog.Default() is used.
func New(w *worker.Manager, logger *slog.Logger) *Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gate{w: w, escalationThreshold: ThresholdVulnerable, logger: logger}
}

// NewWithThreshold returns a Gate with a custom escalation threshold.
// If logger is nil, slog.Default() is used.
func NewWithThreshold(w *worker.Manager, threshold float64, logger *slog.Logger) *Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gate{w: w, escalationThreshold: threshold, logger: logger}
}

// classifyBatch sends one classify request to the Python worker for a slice of
// surfaces and returns raw worker.ClassifyResult. Surfaces must be non-empty.
func (g *Gate) classifyBatch(ctx context.Context, surfaces []enrichment.EnrichedSurface) (worker.ClassifyResult, error) {
	if g.w == nil {
		return worker.ClassifyResult{}, worker.ErrWorkerDead
	}
	payload := worker.ClassifyPayload{
		Surfaces: make([]worker.ClassifySurface, len(surfaces)),
	}
	for i, s := range surfaces {
		payload.Surfaces[i] = worker.ClassifySurface{
			SurfaceID: s.ID,
			Code:      s.Code,
			Language:  s.Language,
		}
	}

	resp, err := g.w.Call(ctx, worker.MsgClassify, payload)
	if err != nil {
		return worker.ClassifyResult{}, fmt.Errorf("classifier: worker call: %w", err)
	}
	if resp.Status == worker.ResponseError {
		return worker.ClassifyResult{}, fmt.Errorf("classifier: worker error: %s", resp.Error)
	}

	var cr worker.ClassifyResult
	if err := json.Unmarshal(resp.Result, &cr); err != nil {
		return worker.ClassifyResult{}, fmt.Errorf("classifier: unmarshal response: %w", err)
	}
	return cr, nil
}

// Classify classifies each surface and returns one Result per input surface in order.
//
// Routing rules applied before classifier invocation:
//  1. IDOR candidates → Escalate immediately (classifier still runs for observability).
//  2. Unsupported languages → Escalate immediately (no classifier call).
//
// After classifier verdict:
//  3. confidence < escalationThreshold → LabelUncertain, Escalate=true.
//  4. LabelVulnerable → Escalate=true (LLM scan confirms or refutes).
//  5. LabelSafe, confidence ≥ threshold → Escalate=false (surface exits Path B).
//
// Supported and unsupported language surfaces are dispatched concurrently:
// supported surfaces go to the Python worker in one batch; unsupported surfaces
// receive their result immediately without an IPC round-trip.
func (g *Gate) Classify(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]Result, error) {
	if len(surfaces) == 0 {
		return nil, nil
	}

	results := make([]Result, len(surfaces))

	// Partition surfaces into those the classifier handles and those it bypasses.
	// Track index mappings so results slot back in order.
	type indexedSurface struct {
		originalIdx int
		surface     enrichment.EnrichedSurface
	}
	var supported, unsupported []indexedSurface

	for i, s := range surfaces {
		if IsSupported(s.Language) {
			supported = append(supported, indexedSurface{i, s})
		} else {
			unsupported = append(unsupported, indexedSurface{i, s})
		}
	}

	// Fill unsupported results immediately — no IPC needed.
	for _, is := range unsupported {
		results[is.originalIdx] = Result{
			SurfaceID:      is.surface.ID,
			Label:          LabelUncertain,
			Confidence:     0,
			Escalate:       true,
			EscalateReason: EscalateUnsupportedLang,
		}
	}

	if len(supported) == 0 {
		return results, nil
	}

	// Run the classifier on all supported surfaces in one batch.
	supportedSurfaces := make([]enrichment.EnrichedSurface, len(supported))
	for i, is := range supported {
		supportedSurfaces[i] = is.surface
	}

	// classifyBatch is a single IPC call — we still use errgroup for consistent
	// error propagation and context cancellation.
	g2, gctx := errgroup.WithContext(ctx)
	var cr worker.ClassifyResult
	g2.Go(func() error {
		var err error
		cr, err = g.classifyBatch(gctx, supportedSurfaces)
		return err
	})
	if err := g2.Wait(); err != nil {
		// Non-fatal fallback: escalate all supported surfaces rather than aborting.
		// A classifier failure should not kill the entire Path B pipeline.
		g.logger.Warn("classifier: batch call failed, escalating all supported surfaces to LLM",
			"component", "classifier",
			"surfaces", len(supported),
			"err", err,
		)
		for _, is := range supported {
			results[is.originalIdx] = Result{
				SurfaceID:      is.surface.ID,
				Label:          LabelUncertain,
				Confidence:     0,
				Escalate:       true,
				EscalateReason: EscalateUncertain,
			}
		}
		return results, nil
	}

	// Index classifier results by SurfaceID for O(1) lookup.
	crByID := make(map[string]worker.ClassifySurfaceResult, len(cr.Results))
	for _, r := range cr.Results {
		crByID[r.SurfaceID] = r
	}

	for _, is := range supported {
		s := is.surface
		wr, ok := crByID[s.ID]
		if !ok {
			// Surface missing from response: treat as uncertain.
			results[is.originalIdx] = Result{
				SurfaceID: s.ID, Label: LabelUncertain, Escalate: true, EscalateReason: EscalateUncertain,
			}
			continue
		}

		label := Label(wr.Label)
		conf := wr.Confidence

		// Apply threshold: low-confidence verdicts become uncertain.
		if conf < g.escalationThreshold && label != LabelVulnerable {
			label = LabelUncertain
		}

		var escalate bool
		var reason EscalateReason
		switch {
		case s.IsIDORCandidate:
			escalate = true
			reason = EscalateIDOR
		case label == LabelVulnerable:
			escalate = true
			reason = EscalateVulnerable
		case label == LabelUncertain:
			escalate = true
			reason = EscalateUncertain
		default:
			// LabelSafe with confidence ≥ threshold: surface exits Path B.
		}

		results[is.originalIdx] = Result{
			SurfaceID:      s.ID,
			Label:          label,
			Confidence:     conf,
			Escalate:       escalate,
			EscalateReason: reason,
		}
	}

	return results, nil
}
