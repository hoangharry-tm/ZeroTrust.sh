package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// mockProvider returns a canned response for every Generate call.
type mockProvider struct {
	response string
}

func (m *mockProvider) Generate(_ context.Context, _ string, _ *llm.Options) (string, error) {
	return m.response, nil
}
func (m *mockProvider) Chat(_ context.Context, _ []llm.Message, _ *llm.Options) (llm.Message, error) {
	return llm.Message{}, nil
}
func (m *mockProvider) Ping(_ context.Context) error { return nil }
func (m *mockProvider) ModelName() string            { return "mock" }

func makeSurface(code string) enrichment.EnrichedSurface {
	return enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s1",
			File:         "src/main/java/com/example/Controller.java",
			FunctionName: "handleRequest",
			Kind:         targeting.SurfaceExternalInput,
		},
		Code: code,
	}
}

func TestTriagePrompt_HasCategoricalScaleNoLiteralNumbers(t *testing.T) {
	// The prompt must NOT contain a literal numeric anchor scale — a real bug
	// found in production: every one of 49 real triage calls in a litemall
	// scan returned the literal string "0.25", the second example number in
	// the old decimal calibration guide, verbatim, regardless of the actual
	// code being scored. The model was copying a displayed digit, not
	// reasoning. Category words (parsed to numbers only in Go, never shown to
	// the model) plus a mandatory Reasoning line replaced it.
	surface := makeSurface("func() { return 1; }")
	prompt := buildTriagePrompt(surface)

	for _, category := range []string{"SAFE", "PROBABLY_SAFE", "UNCERTAIN", "PROBABLY_VULNERABLE", "EXPLOITABLE"} {
		if !strings.Contains(prompt, category) {
			t.Errorf("prompt should contain category %q", category)
		}
	}
	if !strings.Contains(prompt, "Reasoning:") {
		t.Errorf("prompt should require a Reasoning line before the Category line")
	}
	if !strings.Contains(prompt, "Category:") {
		t.Errorf("prompt should require a Category line")
	}
	for _, anchor := range []string{"0.00", "0.25", "0.50", "0.75", "1.00"} {
		if strings.Contains(prompt, anchor) {
			t.Errorf("prompt must not contain the old literal numeric anchor %q — this is the exact anchoring bug being fixed", anchor)
		}
	}
}

func TestTriagePrompt_TruncatesLongCode(t *testing.T) {
	longCode := string(make([]byte, 5000))
	surface := makeSurface(longCode)
	prompt := buildTriagePrompt(surface)
	// Ceiling = code budget (1500) + template's fixed scaffold overhead
	// (worked examples, anti-fabrication guard) with headroom — the point
	// of this test is that a 5000-byte input doesn't linearly bloat the
	// prompt, not that the fixed scaffold text itself stays under an
	// arbitrary cap.
	if len(prompt) > 4000 {
		t.Errorf("prompt should truncate code, got length %d", len(prompt))
	}
}

func TestTriagePrompt_TruncationAnchorsOnSinkLine(t *testing.T) {
	// Regression test for a real gap: truncation used to be a blind
	// byte-offset head-cut, so a long function whose sink call sat past
	// byte 1500 would never have that call shown to the model at all —
	// it would score the surviving (irrelevant) head as SAFE/PROBABLY_SAFE
	// with no way to ever see the thing it's supposed to be judging, and
	// that drop is silent (no finding emitted). Build a function with 200
	// filler lines before a uniquely-named sink call near the end, well
	// past the 1500-byte budget from the head.
	var sb strings.Builder
	sb.WriteString("func handleRequest() {\n")
	for i := 0; i < 200; i++ {
		sb.WriteString("    doSomethingUnrelated()\n")
	}
	sb.WriteString("    UNIQUE_SINK_MARKER(userInput)\n")
	sb.WriteString("}\n")

	surface := makeSurface(sb.String())
	surface.Line = 1
	surface.SinkFile = surface.File
	surface.SinkLine = 202 // the UNIQUE_SINK_MARKER line

	prompt := buildTriagePrompt(surface)
	if !strings.Contains(prompt, "UNIQUE_SINK_MARKER") {
		t.Errorf("truncated prompt should still contain the sink line even though it's past the byte budget from the head, got:\n%s", prompt)
	}
}

func TestParseConfidence_FallbackIs0_5(t *testing.T) {
	v := parseConfidence("I cannot determine")
	if v != 0.5 {
		t.Errorf("parseConfidence('I cannot determine') = %f, want 0.5", v)
	}

	v2 := parseConfidence("")
	if v2 != 0.5 {
		t.Errorf("parseConfidence('') = %f, want 0.5", v2)
	}

	v3 := parseConfidence("gibberish no numbers")
	if v3 != 0.5 {
		t.Errorf("parseConfidence('gibberish') = %f, want 0.5", v3)
	}
}

// ── Fix 2: applicable CWEs in triage prompts ───────────────────────────

func TestBuildTriagePrompt_ApplicableCWEs_ExternalInput(t *testing.T) {
	surface := makeSurface("func() { return input; }")
	prompt := buildTriagePrompt(surface)
	if !strings.Contains(prompt, "CWE-89") {
		t.Errorf("ExternalInput prompt should contain CWE-89, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "CWE-918") {
		t.Errorf("ExternalInput prompt should contain CWE-918, got:\n%s", prompt)
	}
	if strings.Contains(prompt, "[]") {
		t.Errorf("ExternalInput prompt should NOT contain '[]', got:\n%s", prompt)
	}
	if strings.Contains(prompt, "CVEMatches") {
		t.Errorf("prompt should not reference CVEMatches field, got:\n%s", prompt)
	}
}

func TestBuildTriagePrompt_ApplicableCWEs_AuthBoundary(t *testing.T) {
	surface := makeSurface("func() { return input; }")
	surface.Kind = targeting.SurfaceAuthBoundary
	prompt := buildTriagePrompt(surface)
	if !strings.Contains(prompt, "CWE-862") {
		t.Errorf("AuthBoundary prompt should contain CWE-862, got:\n%s", prompt)
	}
	if strings.Contains(prompt, "[]") {
		t.Errorf("AuthBoundary prompt should NOT contain '[]', got:\n%s", prompt)
	}
}

// ── Fix 1 regression: B4 triage still obfuscates string literals ─────────

func TestBuildTriagePrompt_StillObfuscates(t *testing.T) {
	code := `executeQuery("SELECT * FROM users WHERE id='" + id + "'")`
	surface := makeSurface(code)
	prompt := buildTriagePrompt(surface)
	if strings.Contains(prompt, "SELECT") {
		t.Errorf("B4 triage prompt should obfuscate string literals (no 'SELECT'), got:\n%s", prompt)
	}
}

// ── Stub gate: surfaces without a method body ────────────────────────────

func TestStubGateDropsNoBodySurfaces(t *testing.T) {
	mock := &mockProvider{response: "0.7"}
	triager := New(mock, 0.5)

	surfaces := []enrichment.EnrichedSurface{
		{
			Surface: targeting.Surface{
				ID:           "s1",
				FunctionName: "getPath",
				File:         "src/main/java/PathUtil.java",
				Kind:         targeting.SurfaceExternalInput,
			},
			Code: "public String getPath()",
		},
		{
			Surface: targeting.Surface{
				ID:           "s2",
				FunctionName: "findByUser",
				File:         "UserProgressRepository.java",
				Kind:         targeting.SurfaceExternalInput,
			},
			Code: "UserProgress findByUser(String user);\n}",
		},
		{
			Surface: targeting.Surface{
				ID:           "s3",
				FunctionName: "doExec",
				File:         "Executor.java",
				Kind:         targeting.SurfaceExternalInput,
			},
			Code: "public void doExec(String cmd) {\n  String result = exec(cmd);\n  log.info(\"executed: \" + result);\n  return result;\n}",
		},
	}

	results, err := triager.Filter(context.Background(), surfaces)
	if err != nil {
		t.Fatalf("Filter() returned error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, r := range results {
		switch r.Surface.FunctionName {
		case "getPath", "findByUser":
			if r.Disposition != DispositionDrop {
				t.Errorf("%s: expected DispositionDrop, got %v (confidence=%.1f)", r.Surface.FunctionName, r.Disposition, r.Confidence)
			}
			if r.Confidence != 0.0 {
				t.Errorf("%s: expected Confidence=0.0, got %.1f", r.Surface.FunctionName, r.Confidence)
			}
			if r.Explanation != "stub: no method body" {
				t.Errorf("%s: expected explanation 'stub: no method body', got %q", r.Surface.FunctionName, r.Explanation)
			}
		case "doExec":
			if r.Disposition != DispositionEscalate {
				t.Errorf("doExec: expected DispositionEscalate (passes through to LLM), got %v (confidence=%.1f)", r.Disposition, r.Confidence)
			}
			if r.Confidence != 0.7 {
				t.Errorf("doExec: expected Confidence=0.7 from mock LLM, got %.1f", r.Confidence)
			}
		}
	}
}

func TestStubGatePassesThroughLongCodeWithoutBrace(t *testing.T) {
	mock := &mockProvider{response: "0.3"}
	triager := New(mock, 0.5)

	surfaces := []enrichment.EnrichedSurface{
		{
			Surface: targeting.Surface{
				ID:           "s-nobrace",
				FunctionName: "processRequest",
				File:         "Controller.java",
				Kind:         targeting.SurfaceExternalInput,
			},
			Code: "@PreAuthorize(\"hasRole('ADMIN')\") public ResponseEntity processRequest()",
		},
	}

	results, err := triager.Filter(context.Background(), surfaces)
	if err != nil {
		t.Fatalf("Filter() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Disposition == DispositionDrop && results[0].Explanation == "stub: no method body" {
		t.Error("long code without '{' must NOT be stub-dropped — remove the !strings.Contains check")
	}
}

func TestParseConfidence_CategoryLine(t *testing.T) {
	// Primary path: the "Reasoning: ... / Category: X" format the prompt asks for.
	tests := []struct {
		input string
		want  float64
	}{
		{"Reasoning: no sanitizer anywhere.\nCategory: EXPLOITABLE", 1.0},
		{"Reasoning: sink reachable, nothing neutralizes it.\nCategory: PROBABLY_VULNERABLE", 0.75},
		{"Reasoning: not enough evidence either way.\nCategory: UNCERTAIN", 0.5},
		{"Reasoning: no sink is reachable here.\nCategory: PROBABLY_SAFE", 0.25},
		{"Reasoning: guarded on every path.\nCategory: SAFE", 0.0},
		{"reasoning: lowercase should still work\ncategory: exploitable", 1.0},
		{"Category: PROBABLY_SAFE", 0.25}, // Reasoning line missing — still parses the Category
	}
	for _, tc := range tests {
		got := parseConfidence(tc.input)
		if got != tc.want {
			t.Errorf("parseConfidence(%q) = %f, want %f", tc.input, got, tc.want)
		}
	}
}

func TestParseConfidence_BareCategoryWordFallback(t *testing.T) {
	// No "Category:" line at all — a bare category word anywhere still parses.
	tests := []struct {
		input string
		want  float64
	}{
		{"EXPLOITABLE", 1.0},
		{"SAFE", 0.0},
		{"probably safe", 0.25},   // space instead of underscore
		{"PROBABLY VULNERABLE", 0.75},
	}
	for _, tc := range tests {
		got := parseConfidence(tc.input)
		if got != tc.want {
			t.Errorf("parseConfidence(%q) = %f, want %f", tc.input, got, tc.want)
		}
	}
}

func TestParseConfidence_LegacyBareDecimalFallback(t *testing.T) {
	// A model that ignores the category format entirely and emits a bare
	// decimal is still parsed defensively (last-resort fallback), even
	// though this path logs a warning in production.
	tests := []struct {
		input string
		want  float64
	}{
		{"0.7", 0.7},
		{"1.0", 1.0},
		{" 0.7 ", 0.7},
		{"certainly vulnerable: 0.9", 0.9},
	}
	for _, tc := range tests {
		got := parseConfidence(tc.input)
		if got != tc.want {
			t.Errorf("parseConfidence(%q) = %f, want %f", tc.input, got, tc.want)
		}
	}
}
