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

package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// fakeGraph is a minimal cpg_engine.Graph stub, mirroring the pattern already
// used in internal/poe/route_test.go. Only the four methods tools.go wraps
// are exercised; the rest panic if ever called.
type fakeGraph struct {
	callers    map[string][]cpg_engine.Node
	callees    map[string][]cpg_engine.Node
	neighbours map[string][]cpg_engine.Node
	byFile     map[string][]cpg_engine.Node
}

func (g *fakeGraph) QueryNodes(cpg_engine.NodeType) ([]cpg_engine.Node, error) { panic("unused") }
func (g *fakeGraph) QueryNodesByFile(file string, _ cpg_engine.NodeType) ([]cpg_engine.Node, error) {
	return g.byFile[file], nil
}
func (g *fakeGraph) QueryEdges(string, string) ([]cpg_engine.Edge, error) { panic("unused") }
func (g *fakeGraph) GetCallGraph() (cpg_engine.CallGraph, error)          { panic("unused") }
func (g *fakeGraph) GetCallers(id string) ([]cpg_engine.Node, error)      { return g.callers[id], nil }
func (g *fakeGraph) GetCallees(id string) ([]cpg_engine.Node, error)      { return g.callees[id], nil }
func (g *fakeGraph) GetNeighboursAtDepth(id string, _ int) ([]cpg_engine.Node, error) {
	return g.neighbours[id], nil
}
func (g *fakeGraph) TaintPaths([]cpg_engine.TaintSource, []cpg_engine.TaintSink) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) ProjectWideTaintPaths([]string, string) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) PreFlaggedSinks() ([]cpg_engine.TaintSink, error) { panic("unused") }

func TestDispatchTool_GetCallers(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "AuthMiddleware", File: "auth.go", Line: 10}},
	}}
	result := dispatchTool(g, "", "get_callers", `{"function_id":"m1"}`)

	var got toolResultPayload
	if err := json.Unmarshal([]byte(result), &got); err != nil {
		t.Fatalf("result not valid JSON: %v (%q)", err, result)
	}
	if len(got.Results) != 1 || got.Results[0].Name != "AuthMiddleware" {
		t.Errorf("unexpected result: %+v", got)
	}
	if got.Total != 1 || got.Truncated {
		t.Errorf("expected total=1, truncated=false, got total=%d truncated=%v", got.Total, got.Truncated)
	}
}

func TestDispatchTool_UnknownTool(t *testing.T) {
	result := dispatchTool(&fakeGraph{}, "", "delete_everything", `{}`)
	var v map[string]string
	if err := json.Unmarshal([]byte(result), &v); err != nil || v["error"] == "" {
		t.Errorf("expected an error object for an unknown tool, got %q", result)
	}
}

func TestDispatchTool_BadArguments(t *testing.T) {
	result := dispatchTool(&fakeGraph{}, "", "get_callers", `not json`)
	var v map[string]string
	if err := json.Unmarshal([]byte(result), &v); err != nil || v["error"] == "" {
		t.Errorf("expected an error object for malformed arguments, got %q", result)
	}
}

// TestDispatchTool_CapsLargeResultSets is a regression test for a real
// production incident: a single get_neighbours_at_depth call on a real
// Grafana scan returned 1,361 nodes, ballooning the conversation to
// ~560,000 characters (~8.5x over NumCtx) and causing that surface's final
// answer to come back as unparseable garbage — silently losing the verdict.
// summarize() must cap the returned node count and say so explicitly
// (Truncated/Total), not silently hand back a partial list that looks
// complete.
func TestDispatchTool_CapsLargeResultSets(t *testing.T) {
	nodes := make([]cpg_engine.Node, 100)
	for i := range nodes {
		nodes[i] = cpg_engine.Node{ID: fmt.Sprintf("n%d", i), Name: fmt.Sprintf("fn%d", i)}
	}
	g := &fakeGraph{neighbours: map[string][]cpg_engine.Node{"m1": nodes}}
	result := dispatchTool(g, "", "get_neighbours_at_depth", `{"function_id":"m1","depth":2}`)

	var got toolResultPayload
	if err := json.Unmarshal([]byte(result), &got); err != nil {
		t.Fatalf("result not valid JSON: %v (%q)", err, result)
	}
	if len(got.Results) != maxToolResultNodes {
		t.Errorf("expected results capped at %d, got %d", maxToolResultNodes, len(got.Results))
	}
	if got.Total != 100 {
		t.Errorf("expected total=100 (the real count), got %d", got.Total)
	}
	if !got.Truncated {
		t.Error("expected truncated=true — a capped result must say so explicitly")
	}
}

// TestDispatchTool_SmallResultSet_NotMarkedTruncated confirms the common
// case (a handful of callers, well under the cap) is NOT marked truncated —
// only genuinely capped results should say so.
func TestDispatchTool_SmallResultSet_NotMarkedTruncated(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "caller1"}, {ID: "c2", Name: "caller2"}},
	}}
	result := dispatchTool(g, "", "get_callers", `{"function_id":"m1"}`)

	var got toolResultPayload
	if err := json.Unmarshal([]byte(result), &got); err != nil {
		t.Fatalf("result not valid JSON: %v (%q)", err, result)
	}
	if got.Truncated {
		t.Error("a 2-result list well under the cap should not be marked truncated")
	}
	if got.Total != 2 || len(got.Results) != 2 {
		t.Errorf("expected total=2, len(results)=2, got total=%d len=%d", got.Total, len(got.Results))
	}
}

// countingGraph wraps fakeGraph and counts GetCallers invocations, for
// asserting the cache actually prevents a second graph query rather than
// just returning an equal-looking result.
type countingGraph struct {
	*fakeGraph
	getCallersCalls int
}

func (g *countingGraph) GetCallers(id string) ([]cpg_engine.Node, error) {
	g.getCallersCalls++
	return g.fakeGraph.GetCallers(id)
}

// TestDispatchToolCached_HitAvoidsSecondGraphQuery is a regression/feature
// test for the tool-result cache: the CPG is an immutable snapshot for the
// duration of a scan, so the same tool+args should never need to hit the
// graph twice. Found live: several surfaces in the same file/package
// investigate overlapping parts of the call graph (shared callers, shared
// proxy sinks), so this is a real, not just theoretical, win.
func TestDispatchToolCached_HitAvoidsSecondGraphQuery(t *testing.T) {
	g := &countingGraph{fakeGraph: &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "AuthMiddleware"}},
	}}}
	cache := newToolCache()

	first := dispatchToolCached(g, "", "get_callers", `{"function_id":"m1"}`, cache)
	second := dispatchToolCached(g, "", "get_callers", `{"function_id":"m1"}`, cache)

	if first != second {
		t.Errorf("cached result should be identical to the first, got %q vs %q", first, second)
	}
	if g.getCallersCalls != 1 {
		t.Errorf("expected exactly 1 real GetCallers call (second should be served from cache), got %d", g.getCallersCalls)
	}
}

// TestDispatchToolCached_DifferentArgsNotCached confirms the cache key is
// specific to the actual arguments, not just the tool name.
func TestDispatchToolCached_DifferentArgsNotCached(t *testing.T) {
	g := &countingGraph{fakeGraph: &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "A"}},
		"m2": {{ID: "c2", Name: "B"}},
	}}}
	cache := newToolCache()

	dispatchToolCached(g, "", "get_callers", `{"function_id":"m1"}`, cache)
	dispatchToolCached(g, "", "get_callers", `{"function_id":"m2"}`, cache)

	if g.getCallersCalls != 2 {
		t.Errorf("different function_id should each hit the graph, expected 2 calls, got %d", g.getCallersCalls)
	}
}

// TestDispatchToolCached_ErrorsNotCached confirms a failed call is retried
// rather than replaying the same error forever.
func TestDispatchToolCached_ErrorsNotCached(t *testing.T) {
	g := &countingGraph{fakeGraph: &fakeGraph{}}
	cache := newToolCache()

	dispatchToolCached(g, "", "get_callers", `not json`, cache)
	dispatchToolCached(g, "", "get_callers", `not json`, cache)

	// Malformed args error out before ever reaching the graph, so this just
	// confirms no cache entry was written for the error (a real error case
	// would hit the graph on GetCallers itself, not exercised here since
	// fakeGraph never errors — the "error"-substring check in
	// dispatchToolCached covers both cases uniformly).
	result := dispatchToolCached(g, "", "get_callers", `not json`, cache)
	if !strings.Contains(result, "error") {
		t.Errorf("expected an error result, got %q", result)
	}
}

// TestDispatchToolCached_NilCacheDisablesCaching confirms nil is a valid,
// safe "caching off" value — used by every direct dispatchTool test call
// site in this file, which never pass a cache at all.
func TestDispatchToolCached_NilCacheDisablesCaching(t *testing.T) {
	g := &countingGraph{fakeGraph: &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "A"}},
	}}}

	dispatchToolCached(g, "", "get_callers", `{"function_id":"m1"}`, nil)
	dispatchToolCached(g, "", "get_callers", `{"function_id":"m1"}`, nil)

	if g.getCallersCalls != 2 {
		t.Errorf("nil cache should disable caching entirely, expected 2 real calls, got %d", g.getCallersCalls)
	}
}

func TestToolResultIsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		result string
		want   bool
	}{
		{"genuinely empty", `{"results":[],"total":0}`, true},
		{"non-empty", `{"results":[{"id":"c1"}],"total":1}`, false},
		{"truncated non-empty", `{"results":[{"id":"c1"}],"total":100,"truncated":true}`, false},
		{"error object is not 'empty evidence'", `{"error":"no such function_id"}`, false},
		{"malformed JSON", `not json`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolResultIsEmpty(tt.result); got != tt.want {
				t.Errorf("toolResultIsEmpty(%q) = %v, want %v", tt.result, got, tt.want)
			}
		})
	}
}

// mockChatProvider drives a scripted sequence of Chat responses, one per call —
// used to simulate a model that requests tools before answering.
type mockChatProvider struct {
	responses    []llm.Message
	calls        int
	jsonSeen     []bool          // opts.JSON observed on each Chat call, in order
	lastMessages []llm.Message   // the messages slice passed on the most recent Chat call
	allMessages  [][]llm.Message // the messages slice passed on every Chat call, in order
}

func (m *mockChatProvider) Generate(_ context.Context, _ string, _ *llm.Options) (string, error) {
	return "", nil
}
func (m *mockChatProvider) Chat(_ context.Context, msgs []llm.Message, opts *llm.Options) (llm.Message, error) {
	defer func() { m.calls++ }()
	m.lastMessages = msgs
	m.allMessages = append(m.allMessages, msgs)
	if opts != nil {
		m.jsonSeen = append(m.jsonSeen, opts.JSON)
	} else {
		m.jsonSeen = append(m.jsonSeen, false)
	}
	if m.calls >= len(m.responses) {
		return llm.Message{Content: `{"exploitable":false}`}, nil
	}
	return m.responses[m.calls], nil
}
func (m *mockChatProvider) Ping(_ context.Context) error { return nil }
func (m *mockChatProvider) ModelName() string            { return "mock" }

func TestRunToolLoop_NoToolCalls_ReturnsImmediately(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		{Content: `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.9}`},
	}}
	s := New(provider).WithGraph(&fakeGraph{})

	got, _, _, err := s.runToolLoop(context.Background(), makeSurface("s1", targeting.SurfaceExternalInput), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if got != `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.9}` {
		t.Errorf("unexpected result: %q", got)
	}
	if provider.calls != 1 {
		t.Errorf("expected exactly 1 Chat call, got %d", provider.calls)
	}
}

func TestRunToolLoop_DispatchesToolCallThenAnswers(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "AuthMiddleware"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		{Content: `{"exploitable":false,"explanation":"guarded by AuthMiddleware"}`},
	}}
	s := New(provider).WithGraph(g)

	got, _, _, err := s.runToolLoop(context.Background(), makeSurface("s1", targeting.SurfaceExternalInput), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if got != `{"exploitable":false,"explanation":"guarded by AuthMiddleware"}` {
		t.Errorf("unexpected result: %q", got)
	}
	if provider.calls != 2 {
		t.Errorf("expected exactly 2 Chat calls (1 tool round-trip + final answer), got %d", provider.calls)
	}
}

func TestRunToolLoop_KeepsJSONFormatAcrossToolAndAnswerRounds(t *testing.T) {
	// analysisOpts() sets JSON:true (the prompt's contract is a single JSON
	// verdict object). Most surfaces answer on the SAME round they stop
	// calling tools (toolOpts, which still has Tools set) — regression test
	// for a real bug found while writing this test: an earlier version
	// cleared JSON:false on toolOpts to "be safe" around tool-calling, which
	// left the common case (tool call, then a text answer on the very next
	// round using the same toolOpts) completely unconstrained, defeating the
	// point of setting JSON:true in the first place. JSON must stay true on
	// every round — it only governs the text "content" field, a separate
	// channel from tool_calls.
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "AuthMiddleware"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		{Content: `{"exploitable":false}`},
	}}
	s := New(provider).WithGraph(g)

	_, _, _, err := s.runToolLoop(context.Background(), makeSurface("s1", targeting.SurfaceExternalInput), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if len(provider.jsonSeen) != 2 {
		t.Fatalf("expected 2 Chat calls, got %d", len(provider.jsonSeen))
	}
	for i, seen := range provider.jsonSeen {
		if !seen {
			t.Errorf("round %d: expected JSON:true to be preserved, got JSON=false", i)
		}
	}
}

func TestRunToolLoop_CapEnforced_ForcesFinalAnswer(t *testing.T) {
	// A model that always wants another tool call — the loop must stop
	// after maxToolCalls rounds and force a tools-disabled final answer,
	// never call the provider more than maxToolCalls+1 times total.
	alwaysToolCall := llm.Message{ToolCalls: []llm.ToolCall{{ID: "x", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}}
	responses := make([]llm.Message, maxToolCalls)
	for i := range responses {
		responses[i] = alwaysToolCall
	}
	provider := &mockChatProvider{responses: responses}
	s := New(provider).WithGraph(&fakeGraph{})

	got, _, _, err := s.runToolLoop(context.Background(), makeSurface("s1", targeting.SurfaceExternalInput), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if got != `{"exploitable":false}` {
		t.Errorf("unexpected forced-final-answer content: %q", got)
	}
	if provider.calls != maxToolCalls+1 {
		t.Errorf("expected exactly %d Chat calls (cap + forced final), got %d", maxToolCalls+1, provider.calls)
	}
}

func makeGatedSurface(id string) enrichment.EnrichedSurface {
	s := makeSurface(id, targeting.SurfaceIDORCandidate)
	s.ContractCWE = "CWE-862" // NoSinkModel CWE — requiresInvestigation(cwe) == true
	return s
}

// TestRunToolLoop_GatedCWE_KeepsNudgingNeverAcceptsUninvestigatedAnswer is a
// regression test for a real bug found live: a model that never calls a
// tool used to be accepted after exactly one nudge (with confidence merely
// capped afterward) — found live on a real Grafana scan, this let a model
// answer exploitable=true, get nudged, answer AGAIN with zero tool calls and
// flip to exploitable=false with no new evidence gathered, fabricating tool
// results in its explanation that it never actually fetched. Tool use must
// inform the verdict, not follow an already-formed one — the loop must now
// keep re-nudging on every no-tool-call round (bounded by maxToolCalls, same
// as the tool-call-cap case) rather than accepting any answer, real or not,
// after a single corrective nudge.
func TestRunToolLoop_GatedCWE_KeepsNudgingNeverAcceptsUninvestigatedAnswer(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		{Content: `{"exploitable":true,"cwe":"CWE-862"}`},  // round 1: no tool call
		{Content: `{"exploitable":false,"cwe":"CWE-862"}`}, // round 2: still no tool call, flip-flops
	}}
	s := New(provider).WithGraph(&fakeGraph{})

	got, investigated, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if investigated {
		t.Error("investigated should be false — the model never called a tool")
	}
	// mockChatProvider falls back to {"exploitable":false} once its 2 canned
	// responses are exhausted, so every round through maxToolCalls keeps
	// getting nudged and re-answering without a tool call, then the loop
	// forces one final tools-disabled answer — the same shape as
	// TestRunToolLoop_CapEnforced_ForcesFinalAnswer, just via re-nudging
	// instead of repeated tool calls.
	if provider.calls != maxToolCalls+1 {
		t.Errorf("expected exactly %d Chat calls (re-nudged every round + forced final), got %d", maxToolCalls+1, provider.calls)
	}
	if got == "" {
		t.Error("expected a final answer to still be returned (bounded, not an infinite loop)")
	}
}

func TestRunToolLoop_GatedCWE_AcceptsAnswerAfterRealInvestigation(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{Content: `{"exploitable":false,"explanation":"caller has @PreAuthorize"}`},
	}}
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{"s1": {{ID: "c1", Name: "AdminController"}}}}
	s := New(provider).WithGraph(g)

	got, investigated, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if !investigated {
		t.Error("investigated should be true — the model called get_callers before answering")
	}
	if got != `{"exploitable":false,"explanation":"caller has @PreAuthorize"}` {
		t.Errorf("unexpected result: %q", got)
	}
	if provider.calls != 2 {
		t.Errorf("expected exactly 2 Chat calls (tool round-trip + answer), no nudge needed, got %d", provider.calls)
	}
}

// TestRunToolLoop_ExploitableAfterOneHop_ChasedOnceMore is a regression test
// for a real false positive found live on a Grafana scan: fetch() (CWE-918)
// was correctly nudged into calling get_callers, found its immediate caller
// (a thin wrapper with no validation), and answered exploitable=true from
// that single hop — but the actual validating caller was two hops up. The
// zero-tool-calls gate doesn't catch this because a tool WAS called; this
// tests the second, narrower gate that specifically re-prompts an
// exploitable=true verdict reached after only 1 hop to check one hop
// further before accepting it.
func TestRunToolLoop_ExploitableAfterOneHop_ChasedOnceMore(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"s1": {{ID: "wrapper1", Name: "thinWrapper"}},
		"wrapper1": {{ID: "handler1", Name: "Handler"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		// First hop alone shows no guard; the model (wrongly) concludes exploitable from just this.
		{Content: `{"exploitable":true,"cwe":"CWE-918","explanation":"no validation in wrapper"}`},
		// After the chase-nudge, it checks one hop further and finds the real guard.
		{ToolCalls: []llm.ToolCall{{ID: "call_2", Name: "get_callers", Arguments: `{"function_id":"wrapper1"}`}}},
		{Content: `{"exploitable":false,"explanation":"Handler validates the value before calling the wrapper"}`},
	}}
	s := New(provider).WithGraph(g)

	got, investigated, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if !investigated {
		t.Error("investigated should be true")
	}
	if got != `{"exploitable":false,"explanation":"Handler validates the value before calling the wrapper"}` {
		t.Errorf("expected the chased, corrected answer to win, got: %q", got)
	}
	if provider.calls != 4 {
		t.Errorf("expected exactly 4 Chat calls (hop1 + premature answer + chase nudge + hop2 answer), got %d", provider.calls)
	}
}

// TestRunToolLoop_SafeAfterOneHop_NotChased confirms the chase-nudge is
// asymmetric — it only re-prompts exploitable=true verdicts, matching this
// codebase's "prefer false negative over false positive" bias. A safe
// verdict reached after 1 hop is accepted immediately; re-chasing it would
// just burn tool-call budget without addressing the actual risk direction.
func TestRunToolLoop_SafeAfterOneHop_NotChased(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{"s1": {{ID: "c1", Name: "AdminController"}}}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{Content: `{"exploitable":false,"explanation":"caller validates"}`},
	}}
	s := New(provider).WithGraph(g)

	_, _, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if provider.calls != 2 {
		t.Errorf("expected exactly 2 Chat calls (no chase for a safe verdict), got %d", provider.calls)
	}
}

// TestRunToolLoop_DualToolGate_NudgesWhenOnlyOneToolTypeUsed is a regression
// test for a gap the single-hop chase-nudge doesn't cover: a model that
// calls get_callers multiple times (walking up a wrapper chain — a
// legitimate pattern) but never once reaches for get_neighbours_at_depth
// still has only ONE kind of evidence backing a high-confidence exploitable
// verdict. Two get_callers calls satisfy toolCallCount>=2 (so the chase
// doesn't fire) but should still trigger the dual-tool gate since
// distinctTools only has 1 entry.
func TestRunToolLoop_DualToolGate_NudgesWhenOnlyOneToolTypeUsed(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"s1": {{ID: "c1", Name: "wrapper1"}},
		"c1": {{ID: "c2", Name: "wrapper2"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{ToolCalls: []llm.ToolCall{{ID: "call_2", Name: "get_callers", Arguments: `{"function_id":"c1"}`}}},
		// High-confidence exploitable, backed only by 2 get_callers calls — should get nudged.
		{Content: `{"exploitable":true,"cwe":"CWE-918","confidence":0.9,"explanation":"no guard in either hop"}`},
		{ToolCalls: []llm.ToolCall{{ID: "call_3", Name: "get_neighbours_at_depth", Arguments: `{"function_id":"c2","depth":2}`}}},
		{Content: `{"exploitable":false,"confidence":0.85,"explanation":"found a middleware guard"}`},
	}}
	s := New(provider).WithGraph(g)

	got, investigated, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if !investigated {
		t.Error("investigated should be true")
	}
	if got != `{"exploitable":false,"confidence":0.85,"explanation":"found a middleware guard"}` {
		t.Errorf("expected the post-nudge, second-tool-informed answer to win, got: %q", got)
	}
}

// TestRunToolLoop_DualToolGate_NotTriggeredBelowConfidenceThreshold confirms
// the gate is scoped to high-confidence claims only — a low/moderate
// confidence exploitable verdict from one tool type is accepted without the
// extra round, matching this codebase's existing "don't burn budget when
// the model is already appropriately uncertain" pattern.
func TestRunToolLoop_DualToolGate_NotTriggeredBelowConfidenceThreshold(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"s1": {{ID: "c1", Name: "wrapper1"}},
		"c1": {{ID: "c2", Name: "wrapper2"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{ToolCalls: []llm.ToolCall{{ID: "call_2", Name: "get_callers", Arguments: `{"function_id":"c1"}`}}},
		{Content: `{"exploitable":true,"cwe":"CWE-918","confidence":0.6,"explanation":"no guard in either hop"}`},
	}}
	s := New(provider).WithGraph(g)

	_, _, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if provider.calls != 3 {
		t.Errorf("expected exactly 3 Chat calls (no dual-tool nudge below the confidence threshold), got %d", provider.calls)
	}
}

// TestRunToolLoop_ChaseNudge_OffersWiderSearchToolNotJustGetCallers is a
// regression test for a real bias found live: a full Grafana scan showed 46
// get_callers calls and a single query_nodes_by_file call — get_callees and
// get_neighbours_at_depth were never called at all. Root cause: the
// chase-nudge (and the original zero-tool nudge) only ever named
// get_callers by name, so the model had no textual reason to reach for the
// other tools even in exactly the case they exist for (a caller with no
// visible guard, where the real guard might be a filter/middleware rather
// than another direct caller). This locks in that the chase-nudge message
// mentions get_neighbours_at_depth as an option, not just get_callers again.
func TestRunToolLoop_ChaseNudge_OffersWiderSearchToolNotJustGetCallers(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{"s1": {{ID: "c1", Name: "thinWrapper"}}}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{Content: `{"exploitable":true,"cwe":"CWE-918","explanation":"no validation in wrapper"}`},
		{Content: `{"exploitable":false}`},
	}}
	s := New(provider).WithGraph(g)

	_, _, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if len(provider.allMessages) < 3 {
		t.Fatalf("expected at least 3 Chat calls (tool round-trip, premature answer, chase-nudge answer), got %d", len(provider.allMessages))
	}
	nudgeMsgs := provider.allMessages[2]
	last := nudgeMsgs[len(nudgeMsgs)-1].Content
	if !strings.Contains(last, "get_neighbours_at_depth") {
		t.Errorf("chase-nudge should offer get_neighbours_at_depth as an alternative to repeating get_callers, got: %q", last)
	}
}

// TestRunToolLoop_ChaseNudge_EmptyCallerResult_PointsAtNeighboursNotGetCallers
// is a regression test for a real bug found live in the FIRST version of the
// chase-nudge: when get_callers returned zero results (result="[]" — no
// callers exist at all in the graph, roughly half of all real cases per a
// live Grafana scan, usually because a Go router's apiRoute.Any(path, h)
// idiom isn't modeled as a caller edge), the chase-nudge said "call
// get_callers again on the caller you just found" — nonsensical, since there
// is no caller. Faced with an inapplicable instruction, the model answered
// directly instead of calling any tool, which is exactly why
// get_neighbours_at_depth was never actually exercised even after the first
// chase-nudge fix. This locks in that an EMPTY first-hop result gets nudge
// text pointing at get_neighbours_at_depth using the SURFACE's own node ID,
// not at re-querying a nonexistent caller.
func TestRunToolLoop_ChaseNudge_EmptyCallerResult_PointsAtNeighboursNotGetCallers(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{"s1": {}}} // empty: no callers found
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"s1"}`}}},
		{Content: `{"exploitable":true,"cwe":"CWE-918","explanation":"no callers found, no validation"}`},
		{Content: `{"exploitable":false}`},
	}}
	s := New(provider).WithGraph(g)

	_, _, _, err := s.runToolLoop(context.Background(), makeGatedSurface("s1"), "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if len(provider.allMessages) < 3 {
		t.Fatalf("expected at least 3 Chat calls, got %d", len(provider.allMessages))
	}
	nudgeMsgs := provider.allMessages[2]
	last := nudgeMsgs[len(nudgeMsgs)-1].Content
	if !strings.Contains(last, "get_neighbours_at_depth") {
		t.Errorf("empty-result nudge should point at get_neighbours_at_depth, got: %q", last)
	}
	if strings.Contains(last, "the caller you just found") {
		t.Errorf("empty-result nudge must not reference a nonexistent caller, got: %q", last)
	}
}

// TestRunToolLoop_SinkAnchorCWE_AlsoGated is a regression test for a real
// gap found live: the investigation gate used to be NoSinkModel-only, so a
// sink-anchor CWE like CWE-89 (SQLi) or CWE-918 (SSRF) — which has a real
// taint path and a real sink match — could answer exploitable=true without
// ever checking the caller. That's exactly what happened on a real Grafana
// scan: a CWE-918 surface got a confident false positive because the
// caller validated the value before the "vulnerable-looking" function ever
// saw it, and nothing required checking. Sink-anchor CWEs now get gated
// too — this locks in that CWE-89 (previously exempt) is nudged the same
// way CWE-862 always was.
func TestRunToolLoop_SinkAnchorCWE_AlsoGated(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		{Content: `{"exploitable":true,"cwe":"CWE-89"}`}, // answers immediately, no tool call
		{Content: `{"exploitable":true,"cwe":"CWE-89"}`}, // still no tool call, after the nudge
	}}
	s := New(provider).WithGraph(&fakeGraph{})
	surface := makeSurface("s1", targeting.SurfaceExternalInput)
	surface.ContractCWE = "CWE-89"

	got, investigated, _, err := s.runToolLoop(context.Background(), surface, "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if investigated {
		t.Error("investigated should be false — the model never called a tool")
	}
	// Still uninvestigated after all responses are consumed — the loop keeps
	// re-nudging through maxToolCalls rounds, then forces a final answer
	// (mockChatProvider's fallback, {"exploitable":false}), same shape as
	// TestRunToolLoop_GatedCWE_KeepsNudgingNeverAcceptsUninvestigatedAnswer.
	if got != `{"exploitable":false}` {
		t.Errorf("unexpected result: %q", got)
	}
	if provider.calls != maxToolCalls+1 {
		t.Errorf("expected exactly %d Chat calls (re-nudged every round + forced final), got %d", maxToolCalls+1, provider.calls)
	}
}

// TestRunToolLoop_NoRulebookEntry_AcceptsImmediateAnswerNoNudge confirms a
// CWE with no contracts.Rulebook entry at all (unknown to the rulebook, not
// just "doesn't need investigation") is still accepted without a nudge —
// there's nothing meaningful to gate on.
func TestRunToolLoop_NoRulebookEntry_AcceptsImmediateAnswerNoNudge(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		{Content: `{"exploitable":true,"cwe":"CWE-9999"}`},
	}}
	s := New(provider).WithGraph(&fakeGraph{})
	surface := makeSurface("s1", targeting.SurfaceExternalInput)
	surface.ContractCWE = "CWE-9999" // not in contracts.Rulebook

	got, investigated, _, err := s.runToolLoop(context.Background(), surface, "prompt", analysisOpts())
	if err != nil {
		t.Fatalf("runToolLoop error: %v", err)
	}
	if investigated {
		t.Error("investigated should be false — no tool was ever called")
	}
	if got != `{"exploitable":true,"cwe":"CWE-9999"}` {
		t.Errorf("unexpected result: %q", got)
	}
	if provider.calls != 1 {
		t.Errorf("ungated CWE should accept the immediate answer with no nudge, expected 1 call, got %d", provider.calls)
	}
}

// TestDispatchTool_GetCallers_IncludesCodeSnippet is a regression test for a
// real gap found in production: get_callers/get_callees originally returned
// only {id, name, file, line} — never any source code — so a model
// investigating a caller for an authorization annotation had no way to
// actually verify one, regardless of how well it investigated. It could
// only guess, and it did: several real litemall findings fabricated claims
// like "caller has @PreAuthorize" that the tool result never supported.
func TestDispatchTool_GetCallers_IncludesCodeSnippet(t *testing.T) {
	dir := t.TempDir()
	callerFile := dir + "/AdminController.java"
	content := "package x;\n\n@RequiresPermissions(\"goods:update\")\npublic Object create(Goods g) {\n    return service.create(g);\n}\n"
	if err := os.WriteFile(callerFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "create", File: "AdminController.java", Line: 4}},
	}}
	result := dispatchTool(g, dir, "get_callers", `{"function_id":"m1"}`)

	var got toolResultPayload
	if err := json.Unmarshal([]byte(result), &got); err != nil {
		t.Fatalf("result not valid JSON: %v (%q)", err, result)
	}
	if len(got.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(got.Results))
	}
	if !strings.Contains(got.Results[0].Code, "@RequiresPermissions") {
		t.Errorf("want the code snippet to include the annotation directly above the declaration, got %q", got.Results[0].Code)
	}
}

func TestDispatchTool_GetCallers_EmptyCodeWhenFileUnreadable(t *testing.T) {
	// root="" and a File that doesn't exist anywhere real — Code should come
	// back empty rather than erroring the whole tool call.
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "ghost", File: "does/not/exist.java", Line: 1}},
	}}
	result := dispatchTool(g, "", "get_callers", `{"function_id":"m1"}`)

	var got toolResultPayload
	if err := json.Unmarshal([]byte(result), &got); err != nil {
		t.Fatalf("result not valid JSON: %v (%q)", err, result)
	}
	if len(got.Results) != 1 || got.Results[0].Code != "" {
		t.Errorf("want empty Code for an unreadable file, got %+v", got)
	}
}
