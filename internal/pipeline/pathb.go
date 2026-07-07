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

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/triage"
)

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

	// Violations go directly to findings (skip triage + analysis).
	for _, r := range violations {
		ch <- finding.Finding{
			ID:            newRunID(),
			CWE:           r.CWE,
			SeverityLabel: finding.SeverityHigh,
			Path:          r.Surface.File,
			Justification: r.Evidence,
			SourcePath:    finding.SourceSemantic,
		}
	}
	p.logger.Info("path b: contracts violations", "count", len(violations))

	// B4: LLM Triage — lightweight coarse filter on inconclusive results.
	inconclusiveSurfaces := make([]enrichment.EnrichedSurface, 0, len(inconclusives))
	for _, r := range inconclusives {
		inconclusiveSurfaces = append(inconclusiveSurfaces, r.Surface)
	}

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

	// B5: LLM Reasoner — full analysis on escalated surfaces.
	analysisFindings, err := p.scan.Scan(ctx, escalated)
	if err != nil {
		p.logger.Warn("path b analysis error", "err", err)
	}
	for _, f := range analysisFindings {
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

