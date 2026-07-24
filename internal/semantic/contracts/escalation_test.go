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

package contracts

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// fakeGraph is a minimal cpg_engine.Graph stub exercising only GetCallers,
// the one method callerContext uses. Mirrors the pattern already used in
// internal/semantic/analysis/tools_test.go.
type fakeGraph struct {
	callers map[string][]cpg_engine.Node
}

func (g *fakeGraph) QueryNodes(cpg_engine.NodeType) ([]cpg_engine.Node, error) { panic("unused") }
func (g *fakeGraph) QueryNodesByFile(string, cpg_engine.NodeType) ([]cpg_engine.Node, error) {
	panic("unused")
}
func (g *fakeGraph) QueryEdges(string, string) ([]cpg_engine.Edge, error) { panic("unused") }
func (g *fakeGraph) GetCallGraph() (cpg_engine.CallGraph, error)          { panic("unused") }
func (g *fakeGraph) GetCallers(id string) ([]cpg_engine.Node, error)      { return g.callers[id], nil }
func (g *fakeGraph) GetCallees(string) ([]cpg_engine.Node, error)         { panic("unused") }
func (g *fakeGraph) GetNeighboursAtDepth(string, int) ([]cpg_engine.Node, error) {
	panic("unused")
}
func (g *fakeGraph) TaintPaths([]cpg_engine.TaintSource, []cpg_engine.TaintSink) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) ProjectWideTaintPaths([]string, string) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) PreFlaggedSinks() ([]cpg_engine.TaintSink, error) { panic("unused") }

// mockProvider returns a canned response for every Generate call, mirroring
// the pattern already used in internal/semantic/triage/triage_test.go.
type mockProvider struct {
	response string
	err      error
}

func (m *mockProvider) Generate(_ context.Context, _ string, _ *llm.Options) (string, error) {
	return m.response, m.err
}
func (m *mockProvider) Chat(_ context.Context, _ []llm.Message, _ *llm.Options) (llm.Message, error) {
	return llm.Message{}, nil
}
func (m *mockProvider) Ping(_ context.Context) error { return nil }
func (m *mockProvider) ModelName() string            { return "mock" }

// sequencedProvider returns a different canned response on each successive
// Generate call, for testing the majority-vote logic in escalate() with
// genuinely mixed answers across the escalationSamples samples.
type sequencedProvider struct {
	responses []string
	calls     int
}

func (m *sequencedProvider) Generate(_ context.Context, _ string, _ *llm.Options) (string, error) {
	i := m.calls
	m.calls++
	if i >= len(m.responses) {
		return m.responses[len(m.responses)-1], nil
	}
	return m.responses[i], nil
}
func (m *sequencedProvider) Chat(_ context.Context, _ []llm.Message, _ *llm.Options) (llm.Message, error) {
	return llm.Message{}, nil
}
func (m *sequencedProvider) Ping(_ context.Context) error { return nil }
func (m *sequencedProvider) ModelName() string            { return "mock-sequenced" }

// capturingProvider returns a fixed response but records the last prompt it
// was asked, for asserting on prompt content (e.g. caller-context inclusion).
type capturingProvider struct {
	response   string
	lastPrompt string
}

func (m *capturingProvider) Generate(_ context.Context, prompt string, _ *llm.Options) (string, error) {
	m.lastPrompt = prompt
	return m.response, nil
}
func (m *capturingProvider) Chat(_ context.Context, _ []llm.Message, _ *llm.Options) (llm.Message, error) {
	return llm.Message{}, nil
}
func (m *capturingProvider) Ping(_ context.Context) error { return nil }
func (m *capturingProvider) ModelName() string            { return "mock-capturing" }

// surfaceWithSanitized extends surfaceWith with a Sanitized flag and Code —
// the two fields the new structural-signal / escalation logic depends on.
func surfaceWithSanitized(kind targeting.SurfaceKind, sinkNodes, callPath []string, sanitized bool, code string) enrichment.EnrichedSurface {
	s := surfaceWith(kind, sinkNodes, callPath)
	s.Sanitized = sanitized
	s.Code = code
	return s
}

func TestCheck_SanitizedTakesPriorityOverMissingKeyword(t *testing.T) {
	// No keyword in CallPath/Code would match any CWE-89 SafeNodes entry —
	// under the old logic this would be a VIOLATION. With Sanitized=true
	// (the CPG's own taint-taxonomy signal), it must be SAFE instead.
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, true, "")

	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictSafe {
		t.Fatalf("expected VerdictSafe when Sanitized=true, got %s (evidence=%q)", result.Verdict, result.Evidence)
	}
}

func TestCheck_NotSanitizedNoKeyword_NilLLM_DefaultsToViolation(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false, "func f() {}")

	c := New() // no LLM configured
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation with nil llm, got %s", result.Verdict)
	}
}

func TestCheck_Escalation_YESConfirmsSafe(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return escapeSQL(s) }")

	c := NewWithEscalation(&mockProvider{response: "The function calls escapeSQL before use. YES"})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictSafe {
		t.Fatalf("expected VerdictSafe on YES answer, got %s (evidence=%q)", result.Verdict, result.Evidence)
	}
}

func TestCheck_Escalation_NOStaysViolation(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return s }")

	c := NewWithEscalation(&mockProvider{response: "NO — the function returns the input unchanged."})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation on NO answer, got %s", result.Verdict)
	}
}

func TestCheck_Escalation_LLMErrorDefaultsToViolation(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return s }")

	c := NewWithEscalation(&mockProvider{err: context.DeadlineExceeded})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation when the escalation call errors, got %s", result.Verdict)
	}
}

func TestCheck_Escalation_AmbiguousAnswerDefaultsToViolation(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return s }")

	c := NewWithEscalation(&mockProvider{response: "I'm not sure, it depends on the caller."})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation on an ambiguous non-YES answer, got %s", result.Verdict)
	}
}

// TestCheck_KeywordMatchedSafeNode_StillEscalatesWhenLLMConfigured is a
// regression test for a real gap found live: a keyword-matched SafeNode
// (e.g. "filepath.Clean" found in the code) used to be trusted as
// VerdictSafe immediately, with no LLM involved at all, even when an LLM
// was configured and available to double-check. Found on a real Grafana
// scan: getPluginAssets (CVE-2021-43798) calls filepath.Clean on the
// tainted value — a real CWE-22 SafeNodes entry — so contracts declared it
// safe outright, never giving the LLM a chance to apply CWE-22's own AI
// Failure Profile warning ("normalization appears to happen but uses a
// non-canonical form... verify canonicalization order"). A keyword match
// only proves a sanitizer-shaped call is present in the text, not that
// it's sufficient in this position — this locks in that a keyword match no
// longer short-circuits when an LLM is available; escalate() must run and
// its answer decides the verdict.
func TestCheck_KeywordMatchedSafeNode_StillEscalatesWhenLLMConfigured(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceIDORCandidate,
		[]string{"os.Open"}, []string{"getPluginAssets"}, false,
		`requestedFile := filepath.Clean(userInput)
f, err := os.Open(requestedFile)`)

	t.Run("LLM says NO (Clean insufficient here) -> Violation, not blindly Safe", func(t *testing.T) {
		c := NewWithEscalation(&mockProvider{response: "NO — Clean does not stop absolute paths or drive-letter traversal on this OS."})
		result := c.Check(context.Background(), surface)
		if result.Verdict != VerdictViolation {
			t.Fatalf("expected VerdictViolation — the keyword match must not have won outright; got %s (evidence=%q)",
				result.Verdict, result.Evidence)
		}
	})

	t.Run("LLM says YES -> Safe, and evidence reflects the LLM's own confirmation, not the bare keyword", func(t *testing.T) {
		c := NewWithEscalation(&mockProvider{response: "filepath.Clean fully normalizes the path before use here. YES"})
		result := c.Check(context.Background(), surface)
		if result.Verdict != VerdictSafe {
			t.Fatalf("expected VerdictSafe on YES answer, got %s", result.Verdict)
		}
		if !strings.Contains(result.Evidence, "scoped LLM check confirmed") {
			t.Errorf("evidence should come from the LLM escalation, not the bare keyword match; got %q", result.Evidence)
		}
	})
}

// TestCheck_KeywordMatchedSafeNode_NoLLMConfigured_StillTrustsKeyword confirms
// the fallback path is unchanged: without an LLM configured at all, a
// keyword match still wins immediately (same as before this fix) — there's
// no one to escalate to, so falling back to the keyword-only signal is
// strictly better than defaulting to VerdictViolation on every match.
func TestCheck_KeywordMatchedSafeNode_NoLLMConfigured_StillTrustsKeyword(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceIDORCandidate,
		[]string{"os.Open"}, []string{"getPluginAssets"}, false,
		`requestedFile := filepath.Clean(userInput)
f, err := os.Open(requestedFile)`)

	c := New() // no LLM configured
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictSafe {
		t.Fatalf("expected VerdictSafe (keyword-only fallback) with nil llm, got %s", result.Verdict)
	}
}

func TestCheck_Escalation_SkippedWhenNoCode(t *testing.T) {
	// No code to scope the question against — escalate must not fire a
	// blind LLM call, so a provider that always errors must never be hit.
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false, "")

	c := NewWithEscalation(&mockProvider{err: context.DeadlineExceeded})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation when there's no code to escalate with, got %s", result.Verdict)
	}
}

// TestCheck_Escalation_MajorityVoteWins is a regression test for genuine
// self-consistency (Wang et al. 2022): escalate() now samples the prompt
// escalationSamples times and majority-votes rather than trusting a single
// sample. 2 YES + 1 NO should win as Safe.
func TestCheck_Escalation_MajorityVoteWins(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return escapeSQL(s) }")

	c := NewWithEscalation(&sequencedProvider{responses: []string{
		"Calls escapeSQL before use. YES",
		"Calls escapeSQL before use. YES",
		"Not entirely sure escapeSQL covers every case here. NO",
	}})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictSafe {
		t.Fatalf("expected VerdictSafe on a 2-1 YES majority, got %s (evidence=%q)", result.Verdict, result.Evidence)
	}
	if !strings.Contains(result.Evidence, "2/3 votes") {
		t.Errorf("evidence should report the vote tally, got %q", result.Evidence)
	}
}

// TestCheck_Escalation_TiedOrMinorityVoteStaysViolation confirms a 1-2 (or
// tied) vote does NOT win as Safe — the asymmetric-trust posture means a
// split decision defaults to Violation, not Safe.
func TestCheck_Escalation_TiedOrMinorityVoteStaysViolation(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return s }")

	c := NewWithEscalation(&sequencedProvider{responses: []string{
		"Nothing neutralizes the value here. NO",
		"Nothing neutralizes the value here. NO",
		"Looks fine to me. YES",
	}})
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation on a 1-2 minority YES vote, got %s", result.Verdict)
	}
}

// TestCheck_Escalation_IncludesCallerContextWhenGraphAttached is a
// regression test for the same structural blind spot already fixed in B5:
// escalate() previously could only ever see the SafeNode-matched function's
// own text, never its caller — so a guard living one hop up (a common
// pattern: a thin wrapper with no guard, called only by a caller that
// validates first) was invisible to it. With WithGraph attached, the
// prompt sent to the LLM must include the caller's source.
func TestCheck_Escalation_IncludesCallerContextWhenGraphAttached(t *testing.T) {
	surface := surfaceWithSanitized(targeting.SurfaceExternalInput,
		[]string{"db.Query"}, []string{"customSanitizerWrapper"}, false,
		"func customSanitizerWrapper(s string) string { return s }")
	surface.ID = "test-surface"

	tmpDir := t.TempDir()
	callerFile := tmpDir + "/caller.go"
	callerSrc := "package main\n\nfunc callerFn() {\n\tif !isAdmin() {\n\t\treturn\n\t}\n\tcustomSanitizerWrapper(x)\n}\n"
	if err := os.WriteFile(callerFile, []byte(callerSrc), 0o644); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"test-surface": {{ID: "c1", Name: "callerFn", File: "caller.go", Line: 3}},
	}}
	cp := &capturingProvider{response: "The caller checks isAdmin before invoking this function. YES"}
	c := NewWithEscalation(cp).WithRoot(tmpDir).WithGraph(g)

	c.Check(context.Background(), surface)
	if !strings.Contains(cp.lastPrompt, "CALLER CONTEXT") {
		t.Errorf("prompt should include a CALLER CONTEXT section when a graph is attached, got:\n%s", cp.lastPrompt)
	}
	if !strings.Contains(cp.lastPrompt, "callerFn") || !strings.Contains(cp.lastPrompt, "isAdmin") {
		t.Errorf("prompt should include the caller's actual source (name + isAdmin check), got:\n%s", cp.lastPrompt)
	}
}
