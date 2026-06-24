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

package budget

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
)

// helpers

func makeInput(cvss, conf float64, depth int) Input {
	return Input{
		Summary:              summarizer.Summary{SurfaceID: "s", FunctionID: "f"},
		CVSSScore:            cvss,
		ClassifierConfidence: conf,
		CallGraphDepth:       depth,
	}
}

func makeInputWithSummary(id string, cvss, conf float64, depth int, sinkType string) Input {
	return Input{
		Summary: summarizer.Summary{
			SurfaceID:  id,
			FunctionID: id + "_fn",
			TaintFlow:  assembler.TaintFlowSchema{SinkType: sinkType, UntrustedSources: []string{"param1"}},
		},
		CVSSScore:            cvss,
		ClassifierConfidence: conf,
		CallGraphDepth:       depth,
	}
}

// T1: computePriority formula

func TestComputePriority(t *testing.T) {
	cases := []struct {
		name      string
		cvss      float64
		conf      float64
		depth     int
		w1, w2, w3 float64
		wantMin   float64
		wantMax   float64
	}{
		{
			name: "max all inputs",
			cvss: 10.0, conf: 0.0, depth: 1,
			w1: 0.4, w2: 0.4, w3: 0.2,
			wantMin: 0.99, wantMax: 1.01, // 0.4*1 + 0.4*1 + 0.2*1 = 1.0
		},
		{
			name: "zero CVSS low conf shallow",
			cvss: 0.0, conf: 0.0, depth: 1,
			w1: 0.4, w2: 0.4, w3: 0.2,
			wantMin: 0.59, wantMax: 0.61, // 0 + 0.4 + 0.2 = 0.6
		},
		{
			name: "high conf deep surface = low priority",
			cvss: 0.0, conf: 1.0, depth: 10,
			w1: 0.4, w2: 0.4, w3: 0.2,
			wantMin: 0.01, wantMax: 0.03, // 0 + 0 + 0.2*(1/10) = 0.02
		},
		{
			name: "depth 0 treated as 1",
			cvss: 0.0, conf: 0.0, depth: 0,
			w1: 0.0, w2: 0.0, w3: 1.0,
			wantMin: 0.99, wantMax: 1.01, // 1*(1/1)=1.0
		},
		{
			name: "depth negative treated as 1",
			cvss: 0.0, conf: 0.0, depth: -5,
			w1: 0.0, w2: 0.0, w3: 1.0,
			wantMin: 0.99, wantMax: 1.01,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computePriority(tc.cvss, tc.conf, tc.depth, tc.w1, tc.w2, tc.w3)
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("computePriority(cvss=%.1f, conf=%.1f, depth=%d) = %.4f, want [%.2f, %.2f]",
					tc.cvss, tc.conf, tc.depth, got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestComputePriority_HighCVSSBeatsHighConf(t *testing.T) {
	// A high-CVSS uncertain surface must rank above a low-CVSS certain surface.
	highCVSS := computePriority(9.0, 0.50, 2, 0.4, 0.4, 0.2)
	highConf := computePriority(2.0, 0.95, 2, 0.4, 0.4, 0.2)
	if highCVSS <= highConf {
		t.Errorf("high-CVSS priority %.4f should exceed high-conf priority %.4f", highCVSS, highConf)
	}
}

// T1: estimateTokens

func TestEstimateTokens_NonZero(t *testing.T) {
	s := summarizer.Summary{
		SurfaceID:  "getDocument",
		FunctionID: "ctrl.getDocument",
		TaintFlow: assembler.TaintFlowSchema{
			SinkType:         "sql",
			UntrustedSources: []string{"documentId", "userId"},
			SanitizerNodes:   []string{},
		},
	}
	tokens := estimateTokens(s)
	if tokens <= 0 {
		t.Errorf("estimateTokens: want > 0, got %d", tokens)
	}
}

func TestEstimateTokens_EmptySummaryStillHasOverhead(t *testing.T) {
	tokens := estimateTokens(summarizer.Summary{})
	if tokens < 50 {
		t.Errorf("empty summary should still have ≥50 token overhead, got %d", tokens)
	}
}

// T2: Rank sort order

func TestRank_SortOrder(t *testing.T) {
	// Three surfaces: low, high, medium priority (by CVSS + uncertainty).
	inputs := []Input{
		makeInputWithSummary("low", 1.0, 0.95, 3, ""),    // low: low cvss, high conf, deep
		makeInputWithSummary("high", 9.5, 0.10, 1, "sql"), // high: high cvss, low conf, shallow
		makeInputWithSummary("med", 5.0, 0.50, 2, "cmd"),  // medium
	}
	c := New(500_000, 0.4, 0.4, 0.2)
	ranked, exhausted := c.Rank(inputs)

	if len(exhausted) != 0 {
		t.Fatalf("want 0 exhausted with large cap, got %d", len(exhausted))
	}
	if len(ranked) != 3 {
		t.Fatalf("want 3 ranked, got %d", len(ranked))
	}
	// ranked[0] must have the highest priority
	if ranked[0].SurfaceID != "high" {
		t.Errorf("ranked[0]: want 'high', got %q", ranked[0].SurfaceID)
	}
	if ranked[2].SurfaceID != "low" {
		t.Errorf("ranked[2]: want 'low', got %q", ranked[2].SurfaceID)
	}
	// Descending priority
	for i := 1; i < len(ranked); i++ {
		if ranked[i].Priority > ranked[i-1].Priority {
			t.Errorf("ranked[%d].Priority %.4f > ranked[%d].Priority %.4f — not descending",
				i, ranked[i].Priority, i-1, ranked[i-1].Priority)
		}
	}
}

// T2: Budget cap enforcement

func TestRank_CapExhaustsHighestCostFirst(t *testing.T) {
	// cap = 100 tokens; each surface costs >50 so only the highest-priority one fits.
	inputs := []Input{
		makeInputWithSummary("a", 9.0, 0.1, 1, "sql"),
		makeInputWithSummary("b", 7.0, 0.2, 1, "sql"),
		makeInputWithSummary("c", 5.0, 0.3, 1, "sql"),
	}
	// estimateTokens for a minimal summary is the 50-token base + small char overhead.
	// Set tokenCap to allow exactly one surface.
	tokens := estimateTokens(inputs[0].Summary)
	c := New(tokens+1, 0.4, 0.4, 0.2) // cap: one surface fits, two exhausted

	ranked, exhausted := c.Rank(inputs)

	if len(ranked) != 1 {
		t.Fatalf("want 1 ranked, got %d (tokenCap=%d, tokens=%d)", len(ranked), tokens+1, tokens)
	}
	if len(exhausted) != 2 {
		t.Fatalf("want 2 exhausted, got %d", len(exhausted))
	}
	// The ranked surface must be the highest-priority one ("a")
	if ranked[0].SurfaceID != "a" {
		t.Errorf("ranked[0]: want 'a' (highest priority), got %q", ranked[0].SurfaceID)
	}
}

func TestRank_ZeroCap_AllExhausted(t *testing.T) {
	inputs := []Input{makeInput(5.0, 0.5, 2), makeInput(7.0, 0.3, 1)}
	c := New(0, 0.4, 0.4, 0.2) // defaults to 50_000
	// tokenCap defaults to 50_000 when ≤0; to test zero-cap use a small explicit value
	c.tokenCap = 1 // force: no surface fits (min tokens is 50+overhead)
	ranked, exhausted := c.Rank(inputs)
	if len(ranked) != 0 {
		t.Errorf("want 0 ranked with tokenCap=1, got %d", len(ranked))
	}
	if len(exhausted) != len(inputs) {
		t.Errorf("want %d exhausted, got %d", len(inputs), len(exhausted))
	}
}

// T2: RankWithStats totals

func TestRankWithStats_TotalsConsistent(t *testing.T) {
	inputs := []Input{
		makeInputWithSummary("x", 8.0, 0.1, 1, "sql"),
		makeInputWithSummary("y", 3.0, 0.8, 3, ""),
		makeInputWithSummary("z", 6.0, 0.4, 2, "cmd"),
	}
	c := New(500_000, 0.4, 0.4, 0.2)
	ranked, exhausted, stats := c.RankWithStats(inputs)

	if stats.Total != len(inputs) {
		t.Errorf("stats.Total: want %d, got %d", len(inputs), stats.Total)
	}
	if stats.Ranked != len(ranked) {
		t.Errorf("stats.Ranked: want %d, got %d", len(ranked), stats.Ranked)
	}
	if stats.Exhausted != len(exhausted) {
		t.Errorf("stats.Exhausted: want %d, got %d", len(exhausted), stats.Exhausted)
	}
	if stats.Ranked+stats.Exhausted != stats.Total {
		t.Errorf("Ranked(%d)+Exhausted(%d) != Total(%d)", stats.Ranked, stats.Exhausted, stats.Total)
	}
	if stats.TokensUsed <= 0 && len(ranked) > 0 {
		t.Error("stats.TokensUsed should be > 0 when ranked is non-empty")
	}
}

func TestRank_Empty(t *testing.T) {
	c := New(50_000, 0.4, 0.4, 0.2)
	ranked, exhausted := c.Rank(nil)
	if ranked != nil || exhausted != nil {
		t.Errorf("empty input should return nil slices, got ranked=%v exhausted=%v", ranked, exhausted)
	}
}
