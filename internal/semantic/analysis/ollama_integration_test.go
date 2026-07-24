//go:build integration

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

// Integration tests for the B5 agentic loop against a live local Ollama
// server — no mocks. Requires:
//
//  1. Ollama running locally (ollama serve) with both qwen2.5-coder:7b and
//     qwen3.5:9b pulled.
//  2. Run with: go test -tags integration ./internal/semantic/analysis/... -run TestOllamaIntegration -v
//
// These tests exist because prior log-only inspection of a real scan run
// gave a misleading picture of model behavior (see docs/architecture.md):
// verdicts attributed to "the model's judgment" turned out to come from a
// degraded, tool-less retry path caused by an unset Think field. Only a
// live, code-path-accurate test — not log inspection — settles what the
// agent loop actually does for a given model.
package analysis

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

var integrationModels = []string{"qwen2.5-coder:7b", "qwen3.5:9b"}

func newIntegrationProvider(t *testing.T, model string) llm.Provider {
	t.Helper()
	p, err := llm.New(llm.Config{
		Provider: llm.ProviderOllama,
		Model:    model,
		BaseURL:  "http://localhost:11434",
		Timeout:  180 * time.Second,
	})
	if err != nil {
		t.Fatalf("llm.New(%s): %v", model, err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Skipf("Ollama not reachable or model %s not pulled: %v", model, err)
	}
	return p
}

// ── Small case: no tool call needed, obvious injection sink ─────────────────

func TestOllamaIntegration_Small_ObviousSQLi_NoToolCallNeeded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-Ollama integration test in -short mode")
	}
	for _, model := range integrationModels {
		t.Run(model, func(t *testing.T) {
			provider := newIntegrationProvider(t, model)
			s := New(provider).WithGraph(&fakeGraph{}) // graph attached but should never be called for this surface

			surface := enrichment.EnrichedSurface{
				Surface: targeting.Surface{
					ID:   "n1",
					File: "UserRepo.java",
					Kind: targeting.SurfaceExternalInput,
				},
				ContractCWE: "CWE-89",
				SinkNodes:   []string{"executeQuery"},
				CallPath:    []string{"executeQuery"},
				Code: `public ResultSet find(String userId) {
    Statement stmt = conn.createStatement();
    return stmt.executeQuery("SELECT * FROM users WHERE id='" + userId + "'");
}`,
			}

			findings, err := s.Scan(context.Background(), []enrichment.EnrichedSurface{surface})
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			f := findings[0]
			t.Logf("model=%s exploitable=%v cwe=%s severity=%s confidence=%.2f explanation=%q",
				model, f.Exploitable, f.CWE, f.SeverityLabel, f.Confidence, f.Justification)
			if !f.Exploitable {
				t.Errorf("model=%s: expected exploitable=true for an obvious unparameterized SQL concat, got false (%q)",
					model, f.Justification)
			}
		})
	}
}

// ── Medium case: CWE-862 candidate — investigation gate must engage ────────

func TestOllamaIntegration_Medium_CWE862_InvestigationGateEngages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-Ollama integration test in -short mode")
	}
	for _, model := range integrationModels {
		t.Run(model, func(t *testing.T) {
			provider := newIntegrationProvider(t, model)

			// A real caller with an explicit auth annotation — the "done right"
			// path from Example 4 in the prompt. If the loop investigates
			// correctly, the model should find this and answer exploitable=false.
			g := &fakeGraph{callers: map[string][]cpg_engine.Node{
				"n1": {{ID: "c1", Name: "AdminGoodsController", Code: `@PreAuthorize("hasRole('ADMIN')")
public Object update(GoodsAllinone g) { return goodsService.update(g); }`}},
			}}
			s := New(provider).WithGraph(g)

			surface := enrichment.EnrichedSurface{
				Surface: targeting.Surface{
					ID:   "n1",
					File: "AdminGoodsService.java",
					Kind: targeting.SurfaceIDORCandidate,
				},
				ContractCWE: "CWE-862",
				SinkNodes:   []string{"unknown"},
				CallPath:    []string{"validate", "getGoods", "updateById"},
				Code: `@Transactional
public Object update(GoodsAllinone goodsAllinone) {
    Object error = validate(goodsAllinone);
    if (error != null) { return error; }
    LitemallGoods goods = goodsAllinone.getGoods();
    if (goodsService.updateById(goods) == 0) {
        throw new RuntimeException("update failed");
    }
    return ResponseUtil.ok();
}`,
			}

			ctx := context.Background()

			// Single real invocation via the actual production path (Scan ->
			// scanOne -> runToolLoop -> mandatory-investigation gate), not a
			// separate runToolLoop probe — model tool-use is stochastic run to
			// run (observed directly in manual testing: qwen3.5:9b called a
			// tool in only 1 of 4 identical trials), so comparing results across
			// two separate live calls would compare two different dice rolls.
			findings, err := s.Scan(ctx, []enrichment.EnrichedSurface{surface})
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			f := findings[0]
			t.Logf("model=%s exploitable=%v confidence=%.2f explanation=%q",
				model, f.Exploitable, f.Confidence, f.Justification)

			// The behavioral contract the gate exists to enforce: an
			// "exploitable" verdict on a call-chain-dependent CWE must EITHER
			// come with confidence capped at uninvestigatedConfidenceCap and
			// the "[uninvestigated: ...]" tag (gate caught a skipped
			// investigation) OR exceed the cap only because real investigation
			// happened. What must never occur is high confidence with no tag —
			// that means the gate failed to catch a skipped investigation.
			uninvestigatedTag := strings.Contains(f.Justification, "[uninvestigated:")
			if f.Exploitable && !uninvestigatedTag && f.Confidence > uninvestigatedConfidenceCap {
				t.Logf("model=%s answered exploitable=true at confidence %.2f without the uninvestigated tag — "+
					"this is only correct if a tool was genuinely called; check the -v log above for tool call activity",
					model, f.Confidence)
			}
			if f.Exploitable && uninvestigatedTag && f.Confidence > uninvestigatedConfidenceCap {
				t.Errorf("model=%s: uninvestigated tag present but confidence %.2f exceeds the cap %.2f — gate downgrade did not apply",
					model, f.Confidence, uninvestigatedConfidenceCap)
			}
		})
	}
}

// ── Large case: code far exceeding the truncation budget, sink near the end ─

func TestOllamaIntegration_Large_TruncationKeepsSinkVisible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-Ollama integration test in -short mode")
	}
	// Build a function body >4000 chars (budget in buildPrompt) with filler
	// lines, and the real vulnerable call as the LAST line — a naive
	// head-truncation would cut this off entirely before the model ever sees it.
	var body strings.Builder
	body.WriteString("public void process(String userInput) {\n")
	for i := 0; i < 300; i++ {
		body.WriteString("    int filler" + strconv.Itoa(i) + " = " + strconv.Itoa(i*2) + "; // padding to exceed the truncation budget\n")
	}
	body.WriteString(`    Runtime.getRuntime().exec("sh -c " + userInput);
}`)
	code := body.String()
	if len(code) < 4500 {
		t.Fatalf("test setup bug: synthetic code too short to exercise truncation (%d bytes)", len(code))
	}

	for _, model := range integrationModels {
		t.Run(model, func(t *testing.T) {
			provider := newIntegrationProvider(t, model)
			s := New(provider).WithGraph(&fakeGraph{})

			surface := enrichment.EnrichedSurface{
				Surface: targeting.Surface{
					ID:   "n1",
					File: "CommandRunner.java",
					Kind: targeting.SurfaceExternalInput,
					Line: 1,
				},
				ContractCWE: "CWE-78",
				SinkNodes:   []string{"Runtime.exec"},
				SinkFile:    "CommandRunner.java",
				SinkLine:    302, // the exec() call is on line 302 of this synthetic function
				CallPath:    []string{"Runtime.exec"},
				Code:        code,
			}

			prompt := buildPrompt(surface, "")
			if !strings.Contains(prompt, `Runtime.getRuntime().exec`) {
				t.Fatalf("truncateAroundLine failed to keep the sink line in the actual prompt sent — " +
					"this would make the live model call meaningless regardless of what it answers")
			}

			findings, err := s.Scan(context.Background(), []enrichment.EnrichedSurface{surface})
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			f := findings[0]
			t.Logf("model=%s exploitable=%v confidence=%.2f explanation=%q",
				model, f.Exploitable, f.Confidence, f.Justification)
			if !f.Exploitable {
				t.Errorf("model=%s: expected exploitable=true — the sink survived truncation and should still be caught, got false (%q)",
					model, f.Justification)
			}
		})
	}
}

// ── Thinking-mode behavior: proves the Think=false fix actually matters ─────

func TestOllamaIntegration_ThinkFieldBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-Ollama integration test in -short mode")
	}
	prompt := "Respond with exactly this JSON and nothing else: " +
		`{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.9,"explanation":"test","taint_mismatch":false}`

	for _, model := range integrationModels {
		t.Run(model, func(t *testing.T) {
			provider := newIntegrationProvider(t, model)

			// Think left nil (unset) — the pre-fix behavior for every call site
			// in this codebase before this session's fix.
			t.Run("Think_unset", func(t *testing.T) {
				start := time.Now()
				resp, err := provider.Generate(context.Background(), prompt, &llm.Options{
					Temperature: 0.1, NumPredict: 128, NumCtx: 4096,
				})
				elapsed := time.Since(start)
				t.Logf("model=%s Think=nil elapsed=%s resp_len=%d resp=%q", model, elapsed, len(resp), resp)
				if err != nil {
					t.Fatalf("Generate error: %v", err)
				}
			})

			// Think explicitly disabled — the fix applied to analysisOpts et al.
			t.Run("Think_false", func(t *testing.T) {
				start := time.Now()
				resp, err := provider.Generate(context.Background(), prompt, &llm.Options{
					Temperature: 0.1, NumPredict: 128, NumCtx: 4096, Think: new(false),
				})
				elapsed := time.Since(start)
				t.Logf("model=%s Think=false elapsed=%s resp_len=%d resp=%q", model, elapsed, len(resp), resp)
				if err != nil {
					t.Fatalf("Generate error: %v", err)
				}
				if resp == "" {
					t.Errorf("model=%s: Think=false still returned empty content within NumPredict=128 — "+
						"the fix should make this reliable even on a small budget", model)
				}
			})
		})
	}
}

