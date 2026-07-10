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

package pipeline

// Path B — Semantic Analysis Funnel
//
// Execution order:
//
//  B1: Surface Selection (targeting) — import-boundary BFS, IDOR detection.
//  B2: CVE Enrichment  — Trivy CVE correlation per surface.
//  B3: Contract Check  — deterministic CWE→invariant check; safe → drop,
//                        violated → PoE queue, inconclusive → B4.
//  B4: LLM Triage      — lightweight local model coarse filter; low → drop,
//                        high → B5.
//  B5: LLM Reasoner    — one bounded Ollama call per surface, structured JSON
//                        verdict; SCL + CFP + AI failure profile injected.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/triage"
)

// b5ElevationThreshold is the minimum B5 confidence to elevate a B3 violation
// from MEDIUM to HIGH. Exported for testing.
const b5ElevationThreshold = 0.7

// b5SuppressionThreshold is the minimum B5 confidence required to suppress
// a B3 violation. Below this, the model is too uncertain to trust a suppression.
const b5SuppressionThreshold = 0.75

// violationToFinding converts a B3 violation result into a direct finding
// at SeverityMedium with a DCC confirmation note. Exported for testing.
func violationToFinding(r contracts.Result) finding.Finding {
	justification := r.Evidence
	if !strings.Contains(justification, "DCC") {
		justification += " — DCC structural match, pending LLM confirmation"
	}
	return finding.Finding{
		ID:            newRunID(),
		SurfaceID:     r.Surface.ID,
		CWE:           r.CWE,
		SeverityLabel: finding.SeverityMedium,
		Path:          r.Surface.File,
		Justification: justification,
		SourcePath:    finding.SourceSemantic,
	}
}

// taintGateClassify classifies an escalated surface into confirmed (strong taint),
// weak (contract-flagged only), or dropped (no evidence). Exported for testing.
func taintGateClassify(es enrichment.EnrichedSurface) (enrichment.EnrichedSurface, string) {
	if len(es.SinkNodes) > 0 {
		es.TaintConfidence = "confirmed"
		return es, "confirmed"
	}
	if es.ContractCWE != "" {
		es.TaintConfidence = "weak"
		return es, "weak"
	}
	return es, "dropped"
}

// processB5Findings applies the B5 confirmation loop. For each B5 finding,
// checks if it corresponds to a B3 violation and either suppresses (taint
// mismatch), elevates (exploitable with high confidence), or passes through
// unchanged. Exported for testing.
func processB5Findings(
	analysisFindings []finding.Finding,
	violationBySurfaceID map[string]finding.Finding,
) []finding.Finding {
	out := make([]finding.Finding, 0, len(analysisFindings))
	for _, f := range analysisFindings {
		orig, isViolation := violationBySurfaceID[f.SurfaceID]
		if !isViolation {
			out = append(out, f)
			continue
		}
		// Guard: if B5 identified a different CWE than B3 filed (Joern mislabeling),
		// the taint_mismatch is a contract mismatch, not a false positive — don't suppress.
		cweMismatch := f.CWE != "" && orig.CWE != "" && f.CWE != orig.CWE
		if f.TaintMismatch && !f.Exploitable && f.Confidence >= b5SuppressionThreshold && !cweMismatch {
			// B5 says false positive with high confidence — suppress the original B3 finding.
			suppressed := orig
			suppressed.SeverityLabel = finding.SeveritySuppressed
			suppressed.SuppressReason = finding.SuppressReasonFalsePositive
			suppressed.Justification += " — B5 LLM: taint mismatch, not exploitable"
			out = append(out, suppressed)
			slog.Info("analysis: violation suppressed by B5",
				"surface_id", f.SurfaceID,
				"function", orig.Path,
			)
		} else if f.Exploitable && f.Confidence >= b5ElevationThreshold {
			// B5 confirms — elevate from MEDIUM to HIGH.
			elevated := orig
			elevated.SeverityLabel = finding.SeverityHigh
			elevated.Justification += fmt.Sprintf(
				" — B5 LLM confirmed (conf=%.2f): %s", f.Confidence, f.Justification)
			out = append(out, elevated)
			slog.Info("analysis: violation elevated by B5",
				"surface_id", f.SurfaceID,
				"confidence", f.Confidence,
			)
		}
		// else: B5 inconclusive — B3 MEDIUM finding already emitted, no change.
	}
	return out
}

func (p *Pipeline) runPathB(ctx context.Context, _ *ingestion.Result, ch chan<- finding.Finding) error {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "path b"})

	// B1: Surface Selection.
	surfaces, err := p.target.SelectSurfaces(ctx)
	if err != nil {
		p.logger.Warn("path b targeting failed — CPG unavailable", "err", err)
		output.Emit(p.events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "path b",
			Summary: &output.StageSummary{Stage: "path b", Detail: "skipped: CPG unavailable"},
		})
		return nil
	}
	if len(surfaces) == 0 {
		output.Emit(p.events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "path b",
			Summary: &output.StageSummary{Stage: "path b", Detail: "no surfaces selected"},
		})
		return nil
	}

	slog.Debug("path b: B2 input",
		"surfaces", len(surfaces),
	)

	// B2: CVE Enrichment.
	enriched, err := p.enrich.Enrich(ctx, surfaces, p.cfg.Target)
	if err != nil {
		return fmt.Errorf("path b enrichment: %w", err)
	}

	var withSinks int
	for _, es := range enriched {
		if len(es.SinkNodes) > 0 {
			withSinks++
		}
	}
	p.logger.Info("path b: enrichment complete",
		"surfaces", len(enriched),
		"with_sink_nodes", withSinks,
	)

	// Crypto: deterministic weak-crypto check — runs in parallel with B3, findings emitted directly.
	cryptoFindings, err := p.cryptoChecker.CheckAll(ctx, enriched)
	if err != nil {
		p.logger.WarnContext(ctx, "crypto check error", "err", err)
	} else {
		for _, f := range cryptoFindings {
			ch <- f
		}
	}

	// B3: Contract Check — deterministic CWE→invariant check.
	b3names := make([]string, 0, 5)
	for i, es := range enriched {
		if i >= 5 {
			break
		}
		b3names = append(b3names, es.FunctionName)
	}
	slog.Debug("path b: B3 input",
		"surfaces", len(enriched),
		"first_5", b3names,
	)
	results := p.checker.CheckAll(ctx, enriched)

	var violations, inconclusives []contracts.Result
	for _, r := range results {
		switch r.Verdict {
		case contracts.VerdictViolation:
			violations = append(violations, r)
		case contracts.VerdictInconclusive:
			inconclusives = append(inconclusives, r)
		}
	}
	safeDropped := len(results) - len(violations) - len(inconclusives)

	output.Emit(p.events, output.Event{
		Kind: output.EventLog,
		Log:  fmt.Sprintf("path b: contracts — %d safe dropped, %d violations, %d inconclusive", safeDropped, len(violations), len(inconclusives)),
	})

	// Violations go directly to findings at Medium severity (DCC structural
	// match only — no LLM confirmation yet). Index by SurfaceID so B5 results
	// can suppress or elevate the original finding.
	violationBySurfaceID := make(map[string]finding.Finding, len(violations))
	for _, r := range violations {
		f := violationToFinding(r)
		ch <- f
		violationBySurfaceID[r.Surface.ID] = f
	}
	p.logger.Info("path b: contracts violations", "count", len(violations))

	// B4: LLM Triage — lightweight coarse filter on inconclusive results.
	inconclusiveSurfaces := make([]enrichment.EnrichedSurface, 0, len(inconclusives))
	for _, r := range inconclusives {
		es := r.Surface
		es.ContractCWE = r.CWE
		slog.Debug("path b: B3→B4 handoff",
			"function", es.FunctionName,
			"contract_cwe", es.ContractCWE,
			"sink_nodes", es.SinkNodes,
		)
		inconclusiveSurfaces = append(inconclusiveSurfaces, es)
	}

	b4names := make([]string, 0, len(inconclusiveSurfaces))
	for _, es := range inconclusiveSurfaces {
		b4names = append(b4names, es.FunctionName)
	}
	slog.Debug("path b: B4 input",
		"surfaces", len(inconclusiveSurfaces),
		"functions", b4names,
	)
	triageResults, err := p.triager.Filter(ctx, inconclusiveSurfaces)
	if err != nil {
		p.logger.Warn("path b triage error", "err", err)
		triageResults = nil
	}

	var escalated []enrichment.EnrichedSurface
	droppedCount := 0
	for _, tr := range triageResults {
		switch tr.Disposition {
		case triage.DispositionEscalate:
			slog.Debug("path b: B4→B5 handoff",
				"function", tr.Surface.FunctionName,
				"confidence", tr.Confidence,
				"sink_nodes", tr.Surface.SinkNodes,
			)
			escalated = append(escalated, tr.Surface)
		case triage.DispositionDrop:
			droppedCount++
		}
	}

	output.Emit(p.events, output.Event{
		Kind: output.EventLog,
		Log:  fmt.Sprintf("path b: triage — %d dropped, %d escalated", droppedCount, len(escalated)),
	})
	p.logger.Info("path b: triage complete", "dropped", droppedCount, "escalated", len(escalated))

	// Gate: tiered taint gate — surfaces with confirmed taint go to B5 as
	// strong evidence; contract-flagged surfaces with no taint path go as weak.
	taintConfirmed := make([]enrichment.EnrichedSurface, 0, len(escalated))
	taintWeak := make([]enrichment.EnrichedSurface, 0, len(escalated))

	for _, es := range escalated {
		classified, bucket := taintGateClassify(es)
		switch bucket {
		case "confirmed":
			taintConfirmed = append(taintConfirmed, classified)
			slog.Debug("path b: taint gate passed (strong)", "function", es.FunctionName)
		case "weak":
			taintWeak = append(taintWeak, classified)
			slog.Debug("path b: taint gate passed (weak)", "function", es.FunctionName, "contract_cwe", es.ContractCWE)
		default:
			slog.Debug("path b: taint gate dropped", "function", es.FunctionName, "file", es.File)
		}
	}

	// Route B3 violations through B5 for LLM confirmation (may elevate to HIGH).
	for _, r := range violations {
		es := r.Surface
		es.ContractCWE = r.CWE
		es.TaintConfidence = "confirmed"
		taintConfirmed = append(taintConfirmed, es)
		slog.Debug("path b: routing violation to B5", "function", es.FunctionName, "contract_cwe", es.ContractCWE, "cwe", r.CWE)
	}

	allB5 := append(taintConfirmed, taintWeak...)
	p.logger.Info("path b: taint gate",
		"escalated", len(escalated),
		"taint_confirmed", len(taintConfirmed),
		"taint_weak", len(taintWeak),
		"b5_total", len(allB5),
	)

	b5names := make([]string, 0, len(allB5))
	for _, es := range allB5 {
		b5names = append(b5names, es.FunctionName)
	}
	slog.Debug("path b: B5 input",
		"surfaces", len(allB5),
		"functions", b5names,
	)

	// B5: LLM Reasoner — full analysis on escalated surfaces.
	concurrency := 2
	if p.cfg.LLMMode == "frontier" {
		concurrency = 1
	}
	slog.Info("path b: B5 start",
		"surfaces", len(allB5),
		"llm_mode", p.cfg.LLMMode,
		"concurrency", concurrency,
	)
	analysisFindings, err := p.scan.Scan(ctx, allB5)
	if err != nil {
		p.logger.Warn("path b analysis error", "err", err)
	}
	for _, f := range processB5Findings(analysisFindings, violationBySurfaceID) {
		ch <- f
	}

	output.Emit(p.events, output.Event{
		Kind: output.EventLog,
		Log:  fmt.Sprintf("path b: analysis — %d findings from analysis", len(analysisFindings)),
	})

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path b",
		Summary: &output.StageSummary{
			Stage:    "path b",
			Detail:   fmt.Sprintf("%d findings from %d surfaces (B3: %d violations, B5: %d findings)", len(violations)+len(analysisFindings), len(enriched), len(violations), len(analysisFindings)),
			Findings: len(violations) + len(analysisFindings),
		},
	})
	return nil
}

