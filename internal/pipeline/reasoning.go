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

// Reasoning — Semantic Analysis Funnel
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

// sinkContextLines extracts a ±context line window from a function body centred on
// the first line containing any sinkNode label. Returns the extracted snippet,
// the absolute line number of the window's first line, and the absolute line
// number of the sink.
func sinkContextLines(funcBody string, funcStartLine int, sinkNodes []string, context int) (string, int, int) {
	if funcBody == "" || len(sinkNodes) == 0 || funcStartLine <= 0 {
		return "", funcStartLine, funcStartLine
	}
	lines := strings.Split(funcBody, "\n")
	sinkIdx := -1
	for i, l := range lines {
		for _, sn := range sinkNodes {
			if sn == "" {
				continue
			}
			name := sn
			if dot := strings.LastIndexByte(sn, '.'); dot >= 0 {
				name = sn[dot+1:]
			}
			if name != "" && strings.Contains(l, name) {
				sinkIdx = i
				break
			}
		}
		if sinkIdx >= 0 {
			break
		}
	}
	if sinkIdx < 0 {
		end := len(lines)
		if end > 20 {
			end = 20
		}
		return strings.Join(lines[:end], "\n"), funcStartLine, funcStartLine
	}
	start := sinkIdx - context
	if start < 0 {
		start = 0
	}
	end := sinkIdx + context + 1
	if end > len(lines) {
		end = len(lines)
	}
	snippet := strings.Join(lines[start:end], "\n")
	absoluteStart := funcStartLine + start
	sinkAbsLine := funcStartLine + sinkIdx
	return snippet, absoluteStart, sinkAbsLine
}

// violationToFinding converts a B3 violation result into a direct finding
// at SeverityMedium with a DCC confirmation note. Exported for testing.
func violationToFinding(r contracts.Result) finding.Finding {
	justification := r.Evidence
	if !strings.Contains(justification, "DCC") {
		justification += " — DCC structural match, awaiting B5 review"
	}
	if r.Surface.FunctionName != "" {
		justification += fmt.Sprintf(" [function: %s", r.Surface.FunctionName)
		if r.Surface.Line > 0 {
			justification += fmt.Sprintf(" @ line %d", r.Surface.Line)
		}
		justification += "]"
	}

	matchedCode, lineStart, sinkLine := sinkContextLines(r.Surface.Code, r.Surface.Line, r.Surface.SinkNodes, 5)
	if matchedCode == "" {
		matchedCode = strings.Join(r.Surface.SinkNodes, ", ")
		lineStart = r.Surface.Line
		sinkLine = r.Surface.Line
	}

	var cve string
	var cvss float64
	if len(r.Surface.CVEMatches) > 0 {
		cve = r.Surface.CVEMatches[0].CVE
		cvss = r.Surface.CVEMatches[0].CVSS
	}

	return finding.Finding{
		ID:            finding.ComputeID(r.CWE, r.Surface.File, lineStart),
		SurfaceID:     r.Surface.ID,
		CWE:           r.CWE,
		SeverityLabel: finding.SeverityMedium,
		Confidence:    0.65,
		Path:          r.Surface.File,
		LineRange:     finding.LineRange{Start: lineStart, End: sinkLine},
		RuleID:        "dcc-" + r.CWE,
		MatchedCode:   matchedCode,
		CVE:           cve,
		CVSS:          cvss,
		DCCEvidence:   r.Evidence,
		Justification: justification,
		Summary:       r.Evidence,
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
// unchanged. Returns the processed findings plus a set of SurfaceIDs that
// were handled (elevated or suppressed) so the caller can patch no-change
// violations. Exported for testing.
func processB5Findings(
	analysisFindings []finding.Finding,
	violationBySurfaceID map[string]finding.Finding,
) ([]finding.Finding, map[string]bool) {
	out := make([]finding.Finding, 0, len(analysisFindings))
	handled := make(map[string]bool, len(analysisFindings))
	for _, f := range analysisFindings {
		orig, isViolation := violationBySurfaceID[f.SurfaceID]
		if !isViolation {
			out = append(out, f)
			continue
		}
		// Guard: if B5 identified a different CWE than B3 filed (Joern mislabeling),
		// the taint_mismatch is a contract mismatch, not a false positive — don't suppress.
		cweMismatch := f.CWE != "" && orig.CWE != "" && f.CWE != orig.CWE
		if !f.Exploitable && f.Confidence >= b5SuppressionThreshold && !cweMismatch {
			// B5 says not exploitable with high confidence — suppress the original B3
			// finding. Covers two distinct cases, both legitimate reasons to override a
			// DCC structural-match placeholder: the sink evidence was wrong
			// (taint_mismatch=true) vs. the evidence was right but B5 read the real
			// code/control-flow and found no exploitable path (taint_mismatch=false).
			// Requiring taint_mismatch==true here previously meant a confident,
			// evidence-grounded "not exploitable" from B5 had no way to suppress —
			// the DCC MEDIUM finding persisted unchanged regardless of what B5 concluded.
			suppressed := orig
			suppressed.SeverityLabel = finding.SeveritySuppressed
			suppressed.SeverityPinned = true
			var reason, note string
			if f.TaintMismatch {
				reason, note = string(finding.SuppressReasonFalsePositive), "B5: taint mismatch, suppressed"
			} else {
				reason, note = string(finding.SuppressReasonSafe), fmt.Sprintf("B5: not exploitable (conf=%.2f), suppressed: %s", f.Confidence, f.Justification)
			}
			suppressed.SuppressReason = finding.SuppressReason(reason)
			suppressed.Justification = strings.Replace(
				orig.Justification,
				" — DCC structural match, awaiting B5 review",
				" — DCC structural match",
				1,
			) + " — " + note
			suppressed.Summary = "B5 found no exploitable path — suppressed"
			handled[f.SurfaceID] = true
			out = append(out, suppressed)
			slog.Info("analysis: violation suppressed by B5",
				"surface_id", f.SurfaceID,
				"function", orig.Path,
				"reason", reason,
			)
		} else if f.Exploitable && f.Confidence >= b5ElevationThreshold {
			// B5 confirms — elevate using B5 confidence for severity, pin it.
			elevated := orig
			elevated.SeverityLabel = finding.SeverityFromConfidence(f.Confidence)
			elevated.Confidence = f.Confidence
			elevated.Exploitable = f.Exploitable
			elevated.TaintMismatch = f.TaintMismatch
			elevated.SeverityPinned = true
			elevated.Justification = strings.Replace(
				orig.Justification,
				" — DCC structural match, awaiting B5 review",
				" — DCC structural match",
				1,
			) + fmt.Sprintf(" — B5 confirmed (conf=%.2f): %s", f.Confidence, f.Justification)
			// f.Summary (not f.Justification) — Justification is now B5's
			// fuller reasoning, not a short headline; using it here would
			// have made the elevated finding's report-card title an
			// unbounded paragraph instead of a scannable one-liner.
			elevated.Summary = f.Summary
			handled[f.SurfaceID] = true
			out = append(out, elevated)
			slog.Info("analysis: violation elevated by B5",
				"surface_id", f.SurfaceID,
				"confidence", f.Confidence,
			)
		}
		// else: B5 inconclusive — handled by runReasoning no-change patch.
	}
	return out, handled
}

func (p *Pipeline) runReasoning(ctx context.Context, _ *ingestion.Result, ch chan<- finding.Finding) error {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "reasoning"})

	// B1: Surface Selection.
	surfaces, err := p.target.SelectSurfaces(ctx)
	if err != nil {
		p.logger.Warn("reasoning targeting failed — CPG unavailable", "err", err)
		output.Emit(p.events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "reasoning",
			Summary: &output.StageSummary{Stage: "reasoning", Detail: "skipped: CPG unavailable"},
		})
		return nil
	}
	if len(surfaces) == 0 {
		output.Emit(p.events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "reasoning",
			Summary: &output.StageSummary{Stage: "reasoning", Detail: "no surfaces selected"},
		})
		return nil
	}

	slog.Debug("reasoning: B2 input",
		"surfaces", len(surfaces),
	)

	// B2: CVE Enrichment.
	enriched, err := p.enrich.Enrich(ctx, surfaces, p.cfg.Target)
	if err != nil {
		return fmt.Errorf("reasoning enrichment: %w", err)
	}

	var withSinks int
	for _, es := range enriched {
		if len(es.SinkNodes) > 0 {
			withSinks++
		}
	}
	p.logger.Info("reasoning: enrichment complete",
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
	slog.Debug("reasoning: B3 input",
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

	p.logger.Info("reasoning: contracts complete",
		"safe_dropped", safeDropped, "violations", len(violations), "inconclusive", len(inconclusives))

	// Violations go directly to findings at Medium severity (DCC structural
	// match only — no LLM confirmation yet). Index by SurfaceID so B5 results
	// can suppress or elevate the original finding.
	violationBySurfaceID := make(map[string]finding.Finding, len(violations))
	for _, r := range violations {
		f := violationToFinding(r)
		violationBySurfaceID[r.Surface.ID] = f
	}
	p.logger.Info("reasoning: contracts violations", "count", len(violations))

	// B4: LLM Triage — lightweight coarse filter on inconclusive results.
	inconclusiveSurfaces := make([]enrichment.EnrichedSurface, 0, len(inconclusives))
	for _, r := range inconclusives {
		es := r.Surface
		es.ContractCWE = r.CWE
		slog.Debug("reasoning: B3→B4 handoff",
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
	slog.Debug("reasoning: B4 input",
		"surfaces", len(inconclusiveSurfaces),
		"functions", b4names,
	)
	triageResults, err := p.triager.Filter(ctx, inconclusiveSurfaces)
	if err != nil {
		p.logger.Warn("reasoning triage error", "err", err)
		triageResults = nil
	}

	var escalated []enrichment.EnrichedSurface
	droppedCount := 0
	for _, tr := range triageResults {
		switch tr.Disposition {
		case triage.DispositionEscalate:
			slog.Debug("reasoning: B4→B5 handoff",
				"function", tr.Surface.FunctionName,
				"confidence", tr.Confidence,
				"sink_nodes", tr.Surface.SinkNodes,
			)
			escalated = append(escalated, tr.Surface)
		case triage.DispositionDrop:
			droppedCount++
		}
	}

	p.logger.Info("reasoning: triage complete", "dropped", droppedCount, "escalated", len(escalated))

	// Gate: tiered taint gate — surfaces with confirmed taint go to B5 as
	// strong evidence; contract-flagged surfaces with no taint path go as weak.
	taintConfirmed := make([]enrichment.EnrichedSurface, 0, len(escalated))
	taintWeak := make([]enrichment.EnrichedSurface, 0, len(escalated))

	for _, es := range escalated {
		classified, bucket := taintGateClassify(es)
		switch bucket {
		case "confirmed":
			taintConfirmed = append(taintConfirmed, classified)
			slog.Debug("reasoning: taint gate passed (strong)", "function", es.FunctionName)
		case "weak":
			taintWeak = append(taintWeak, classified)
			slog.Debug("reasoning: taint gate passed (weak)", "function", es.FunctionName, "contract_cwe", es.ContractCWE)
		default:
			slog.Debug("reasoning: taint gate dropped", "function", es.FunctionName, "file", es.File)
		}
	}

	// Route B3 violations through B5 for LLM confirmation (may elevate to HIGH).
	for _, r := range violations {
		es := r.Surface
		es.ContractCWE = r.CWE
		es.TaintConfidence = "confirmed"
		taintConfirmed = append(taintConfirmed, es)
		slog.Debug("reasoning: routing violation to B5", "function", es.FunctionName, "contract_cwe", es.ContractCWE, "cwe", r.CWE)
	}

	allB5 := append(taintConfirmed, taintWeak...)
	// Deduplicate by SurfaceID — two B3 CWE rules can produce two violations for
	// the same surface; send it to B5 only once.
	b5Seen := make(map[string]struct{}, len(allB5))
	deduped := allB5[:0]
	for _, es := range allB5 {
		if _, dup := b5Seen[es.ID]; !dup {
			b5Seen[es.ID] = struct{}{}
			deduped = append(deduped, es)
		}
	}
	allB5 = deduped
	p.logger.Info("reasoning: taint gate",
		"escalated", len(escalated),
		"taint_confirmed", len(taintConfirmed),
		"taint_weak", len(taintWeak),
		"b5_total", len(allB5),
	)

	b5names := make([]string, 0, len(allB5))
	for _, es := range allB5 {
		b5names = append(b5names, es.FunctionName)
	}
	slog.Debug("reasoning: B5 input",
		"surfaces", len(allB5),
		"functions", b5names,
	)

	// B5: LLM Reasoner — full analysis on escalated surfaces.
	slog.Info("reasoning: B5 start", "surfaces", len(allB5))
	analysisFindings, err := p.scan.Scan(ctx, allB5)
	if err != nil {
		p.logger.Warn("reasoning analysis error", "err", err)
	}
	b5Results, handled := processB5Findings(analysisFindings, violationBySurfaceID)
	for _, f := range b5Results {
		ch <- f
	}

	// No-change path: violations that B5 did not elevate or suppress.
	// Update Justification to reflect B5 ran and emit the patched finding
	// so dedup picks up the updated version over the original B3 emission.
	for sid, v := range violationBySurfaceID {
		if handled[sid] {
			continue
		}
		v.Justification = strings.Replace(
			v.Justification,
			" — DCC structural match, awaiting B5 review",
			" — DCC structural match, B5 reviewed (no change)",
			1,
		)
		v.Summary = "DCC contract matched; B5 found insufficient evidence for elevation"
		ch <- v
	}

	p.logger.Info("reasoning: analysis complete", "findings", len(analysisFindings))

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "reasoning",
		Summary: &output.StageSummary{
			Stage: "reasoning",
			Detail: fmt.Sprintf("%d findings from %d surfaces (B3: %d violations, B5: %d findings)",
				len(violations)+len(analysisFindings),
				len(enriched),
				len(violations),
				len(analysisFindings)),
			Findings: len(violations) + len(analysisFindings),
		},
	})
	return nil
}
