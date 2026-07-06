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
//
// TODO(impl): B3–B5 are stubs pending implementation of
// internal/semantic/contracts, internal/semantic/triage, and
// internal/semantic/analysis.

import (
	"context"
	"fmt"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

func (p *Pipeline) runPathB(ctx context.Context, _ *ingestion.Result, ch finding.Channel) error {
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

	// B3–B5: Contract Check → LLM Triage → LLM Reasoner.
	// Delegated to llmscan.Scanner which will be refactored to implement
	// the three-stage funnel once contracts/triage/analysis packages exist.
	findings, err := p.scan.Scan(ctx, enriched)
	if err != nil {
		return fmt.Errorf("path b scan: %w", err)
	}
	for _, f := range findings {
		ch <- f
	}

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path b",
		Summary: &output.StageSummary{
			Stage:    "path b",
			Detail:   fmt.Sprintf("%d findings from %d surfaces", len(findings), len(enriched)),
			Findings: len(findings),
		},
	})
	return nil
}

