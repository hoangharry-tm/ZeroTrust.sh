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

//go:build integration

// T9: Cross-surface detection — vulnerability is only visible when two surfaces
// are scanned in sequence. Surface 1 stores an IDOR inference; surface 2 receives
// that inference as prior context and emits HIGH rather than uncertain.
//
// Scenario (Spring Boot IDOR):
//   - Surface 1: getDocument(documentId) — no auth check; IDOR candidate.
//     Step 3 verdict: uncertain (0.35) because auth check could be in a filter.
//   - Surface 2: documentRepository.findById(documentId) — DB sink.
//     The SCS inference from surface 1 is injected as prior context, pushing
//     the model past the HIGH threshold. Step 3 verdict: vulnerable (0.78).
//
// Without SCSS, surface 2 would be uncertain (the stub's non-SCSS branch returns
// uncertain). With SCSS the prior context is visible to the mock, which returns
// a confident vulnerable verdict.
package llmscan

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/scs"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// contextAwareCaller returns different step-3 verdicts depending on whether the
// request includes prior SCS inferences. It simulates a model that can reason
// across surfaces only when cross-surface context is present.
type contextAwareCaller struct {
	probeReturned bool
}

func (c *contextAwareCaller) Call(_ context.Context, _ worker.MessageType, payload any) (*worker.Response, error) {
	if !c.probeReturned {
		c.probeReturned = true
		b, _ := json.Marshal(map[string]string{"status": "ok"})
		return &worker.Response{Status: worker.ResponseOK, Result: b}, nil
	}

	// Decode the request to inspect PriorContext.
	raw, _ := json.Marshal(payload)
	var req scanStepRequest
	_ = json.Unmarshal(raw, &req)

	hasPrior := len(req.PriorContext) > 0

	var verdict string
	var conf float64
	switch {
	case req.Step == 3 && hasPrior:
		// Any prior cross-surface inference → model can reason about the chain → vulnerable.
		verdict, conf = "vulnerable", 0.78
	case req.Step == 3:
		// No prior context → uncertain (filter might guard this).
		verdict, conf = "uncertain", 0.35
	default:
		// Steps 1 and 2 always continue.
		verdict, conf = "", 0.0
	}

	b, _ := json.Marshal(scanStepResponse{
		Thought: "reasoning", Action: "check", Observation: "checked",
		Verdict: verdict, Confidence: conf, CWE: "CWE-639",
	})
	return &worker.Response{Status: worker.ResponseOK, Result: b}, nil
}

func TestScan_CrossSurface_SCSBoostsSecondSurface(t *testing.T) {
	store := scs.New()
	// Register CPG neighbours so surface 2 can pull surface 1's inferences.
	store.RegisterNeighbours("documentRepository.findById", []string{"getDocument"})

	surfaces := []budget.RankedSurface{
		{
			Summary:              summarizer.Summary{SurfaceID: "getDocument", FunctionID: "DocumentController.getDocument"},
			Priority:             0.8,
			EstimatedTokens:      120,
			ClassifierConfidence: 0.5,
		},
		{
			Summary:              summarizer.Summary{SurfaceID: "documentRepository.findById", FunctionID: "DocumentRepository.findById"},
			Priority:             0.6,
			EstimatedTokens:      100,
			ClassifierConfidence: 0.5,
		},
	}

	sc := &Scanner{w: &contextAwareCaller{}, store: store}
	findings, err := sc.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	f1 := findings[0] // getDocument — no prior context → uncertain
	if f1.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("surface 1 without prior context: want SUPPRESSED(uncertain), got %q", f1.SeverityLabel)
	}

	f2 := findings[1] // documentRepository.findById — SCSS context → vulnerable
	if f2.SeverityLabel != finding.SeverityHigh {
		t.Errorf("surface 2 with SCSS prior context (conf=0.78): want HIGH, got %q", f2.SeverityLabel)
	}
}

func TestScan_CrossSurface_WithoutSCSS_BothUncertain(t *testing.T) {
	surfaces := []budget.RankedSurface{
		{
			Summary:              summarizer.Summary{SurfaceID: "getDocument", FunctionID: "DocumentController.getDocument"},
			Priority:             0.8,
			EstimatedTokens:      120,
			ClassifierConfidence: 0.5,
		},
		{
			Summary:              summarizer.Summary{SurfaceID: "documentRepository.findById", FunctionID: "DocumentRepository.findById"},
			Priority:             0.6,
			EstimatedTokens:      100,
			ClassifierConfidence: 0.5,
		},
	}

	// No store attached → no cross-surface context.
	sc := &Scanner{w: &contextAwareCaller{}}
	findings, err := sc.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.SeverityLabel != finding.SeveritySuppressed {
			t.Errorf("without SCSS: want SUPPRESSED(uncertain) for %q, got %q", f.Path, f.SeverityLabel)
		}
	}
}
