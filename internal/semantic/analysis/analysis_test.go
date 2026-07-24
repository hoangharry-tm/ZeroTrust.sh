package analysis

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// mockProvider implements llm.Provider for testing.
type mockProvider struct {
	llm.Provider
	generateFunc func(ctx context.Context, prompt string, opts *llm.Options) (string, error)
}

func (m *mockProvider) Generate(ctx context.Context, prompt string, opts *llm.Options) (string, error) {
	return m.generateFunc(ctx, prompt, opts)
}

func (m *mockProvider) Ping(_ context.Context) error { return nil }
func (m *mockProvider) ModelName() string            { return "mock" }

func makeSurface(id string, kind targeting.SurfaceKind) enrichment.EnrichedSurface {
	return enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   id,
			File: "test.go",
			Kind: kind,
		},
	}
}

func makeSurfaceWithCallPath(id string, kind targeting.SurfaceKind, callPath []string) enrichment.EnrichedSurface {
	s := makeSurface(id, kind)
	s.CallPath = callPath
	return s
}

func TestScan_ExploitableVerdict_ReturnsFinding(t *testing.T) {
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"Direct SQL concat"}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{makeSurface("s1", targeting.SurfaceExternalInput)}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].CWE != "CWE-89" {
		t.Errorf("want CWE-89, got %s", findings[0].CWE)
	}
	if findings[0].SeverityLabel != finding.SeverityHigh {
		t.Errorf("want HIGH, got %v", findings[0].SeverityLabel)
	}
}

func TestScan_NonExploitableVerdict_ReturnsFinding(t *testing.T) {
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			return `{"exploitable":false,"cwe":"CWE-89","severity":"LOW","confidence":0.2,"explanation":"safe"}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{makeSurface("s1", targeting.SurfaceExternalInput)}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Exploitable {
		t.Error("want Exploitable=false")
	}
	if findings[0].TaintMismatch {
		t.Error("want TaintMismatch=false")
	}
}

func TestScan_MalformedJSON_ReturnsDefaultFinding(t *testing.T) {
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			return "not json", nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{makeSurface("s1", targeting.SurfaceExternalInput)}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (default safe verdict), got %d", len(findings))
	}
	if findings[0].Exploitable {
		t.Error("want Exploitable=false for malformed JSON")
	}
}

func TestScan_BatchPreservesOrder(t *testing.T) {
	// All surfaces now return findings (no gates). Exploitable at 0, 2, 4.
	p := &mockProvider{
		generateFunc: func(_ context.Context, prompt string, _ *llm.Options) (string, error) {
			if strings.Contains(prompt, "CWE-862") {
				return `{"exploitable":true,"cwe":"CWE-862","severity":"HIGH","confidence":0.85,"explanation":"auth vuln"}`, nil
			}
			return `{"exploitable":false,"cwe":"CWE-327","severity":"LOW","confidence":0.1,"explanation":"safe"}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{
		{Surface: targeting.Surface{ID: "s0", File: "a.go", Kind: targeting.SurfaceAuthBoundary}},
		{Surface: targeting.Surface{ID: "s1", File: "b.go", Kind: targeting.SurfaceDangerousSink}},
		{Surface: targeting.Surface{ID: "s2", File: "c.go", Kind: targeting.SurfaceAuthBoundary}},
		{Surface: targeting.Surface{ID: "s3", File: "d.go", Kind: targeting.SurfaceDangerousSink}},
		{Surface: targeting.Surface{ID: "s4", File: "e.go", Kind: targeting.SurfaceAuthBoundary}},
	}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 5 {
		t.Fatalf("want 5 findings (all surfaces return), got %d", len(findings))
	}
	// Input order preserved: indices 0,1,2,3,4 → a.go, b.go, c.go, d.go, e.go.
	for i, want := range []string{"a.go", "b.go", "c.go", "d.go", "e.go"} {
		if findings[i].Path != want {
			t.Errorf("finding %d: want %s, got %s", i, want, findings[i].Path)
		}
	}
}

func TestScan_PerSurfaceErrorSkipped(t *testing.T) {
	// callCount is accessed concurrently (g.SetLimit(2)) — must be atomic.
	var callCount atomic.Int32
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			if callCount.Add(1) == 1 {
				return "", assertAnError("llm error")
			}
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"ok","taint_mismatch":false}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{
		makeSurface("s1", targeting.SurfaceExternalInput),
		makeSurface("s2", targeting.SurfaceExternalInput),
	}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
}

// assertAnError returns an error value for testing.
type assertAnError string

func (e assertAnError) Error() string { return string(e) }

func TestBuildPrompt_ContainsCWE(t *testing.T) {
	surface := makeSurface("s1", targeting.SurfaceExternalInput)
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "CWE-89") {
		t.Errorf("prompt for ExternalInput surface should contain CWE-89, got:\n%s", prompt)
	}
}

func TestBuildCFP_CapsCallPathAt10(t *testing.T) {
	const numNodes = 20
	callPath := make([]string, numNodes)
	for i := range callPath {
		callPath[i] = "node"
	}
	surface := makeSurfaceWithCallPath("s1", targeting.SurfaceExternalInput, callPath)
	cfp := buildCFP(surface)
	// Count " → " separators — there should be at most 9 (for 10 nodes)
	count := strings.Count(cfp, "→")
	if count >= 10 {
		t.Errorf("buildCFP output has %d arrows, want < 10 (capped at 10 nodes). Output:\n%s", count, cfp)
	}
}

func TestBuildAIP_RespectsContractCWE(t *testing.T) {
	surface := makeSurface("s1", targeting.SurfaceAuthBoundary)
	surface.ContractCWE = "CWE-89"
	aip := buildAIP(surface)
	// CWE-89 profile mentions "SQL injection" — verify right profile is selected.
	if !strings.Contains(aip, "SQL injection") {
		t.Errorf("buildAIP with ContractCWE=CWE-89 should contain SQL injection profile, got:\n%s", aip)
	}
	// CWE-862 profile mentions "authorization" — must not appear.
	if strings.Contains(aip, "authorization") {
		t.Errorf("buildAIP should NOT use kind-based CWE-862 when ContractCWE=CWE-89, got:\n%s", aip)
	}
}

// TestBuildAIP_CWE22MentionsHttpDirSafety is a regression test for a real
// false-positive pattern found live: multiple Grafana findings flagged
// http.Dir(dir).Open(path)-routed reads as exploitable path traversal
// purely because no explicit sanitizer was visible upstream — but
// http.Dir.Open is root-anchored by construction (it prefixes the path with
// "/" before Clean, so ".." can never escape the base directory) regardless
// of upstream validation quality. The AI Failure Profile must call this out
// so B5 stops flagging this exact structurally-safe pattern.
func TestBuildAIP_CWE22MentionsHttpDirSafety(t *testing.T) {
	surface := makeSurface("s1", targeting.SurfaceExternalInput)
	surface.ContractCWE = "CWE-22"
	aip := buildAIP(surface)
	if !strings.Contains(aip, "http.Dir") {
		t.Errorf("CWE-22 AI Failure Profile should mention http.Dir's root-anchoring safety, got:\n%s", aip)
	}
}

func TestBuildAIP_KindFallbackWhenNoContractCWE(t *testing.T) {
	surface := makeSurface("s1", targeting.SurfaceAuthBoundary)
	surface.ContractCWE = ""
	aip := buildAIP(surface)
	// Auth boundary without contract CWE falls back to CWE-862.
	if !strings.Contains(aip, "authorization") {
		t.Errorf("buildAIP should fall back to CWE-862 when ContractCWE is empty, got:\n%s", aip)
	}
}

func TestParseVerdict_ProseWrappedJSON(t *testing.T) {
	raw := `Sure! Here's my analysis: {"exploitable":true,"cwe":"CWE-22","severity":"HIGH","confidence":0.9,"explanation":"path traversal","taint_mismatch":false}`
	v := parseVerdict(raw)
	if !v.Exploitable {
		t.Error("want exploitable=true")
	}
	if v.CWE != "CWE-22" {
		t.Errorf("want CWE-22, got %s", v.CWE)
	}
	if v.Confidence != 0.9 {
		t.Errorf("want confidence 0.9, got %f", v.Confidence)
	}
	if v.Explanation != "path traversal" {
		t.Errorf("want explanation 'path traversal', got %s", v.Explanation)
	}
	if v.TaintMismatch {
		t.Error("want taint_mismatch=false")
	}
}

func TestParseVerdict_TaintMismatchParsed(t *testing.T) {
	raw := `{"exploitable":false,"cwe":"CWE-89","severity":"LOW","confidence":0.3,"explanation":"no DB calls in func","taint_mismatch":true}`
	v := parseVerdict(raw)
	if v.Exploitable {
		t.Error("want exploitable=false")
	}
	if !v.TaintMismatch {
		t.Error("want taint_mismatch=true")
	}
}

// TestParseVerdict_SalvagesMalformedJSON is a regression test for a real
// production incident: a model's generation glitched mid-sentence inside
// the "explanation" string value, leaking an unescaped fragment that broke
// strict JSON parsing. The verdict itself was correct and well-reasoned
// (exploitable=false, confidence=0.95) but json.Unmarshal has no partial
// recovery, so the whole thing was discarded and replaced with a
// meaningless zero-value verdict. Exact raw text reproduced from the log.
func TestParseVerdict_SalvagesMalformedJSON(t *testing.T) {
	raw := `{"exploitable":false,"cwe":"","severity":"LOW","confidence":0.95,"summary":"Caller validates hash format before reaching sink.","explanation":"get_callers returned Handler as the sole caller of this function, whose code checks that the :hash parameter is exactly 32 hex characters via validMD5.MatchString and returns early if invalid — so by the time Encode() runs with a.taint_mismatch=false,"taint_mismatch":false}`
	v := parseVerdict(raw)
	if v.Exploitable {
		t.Error("want exploitable=false, salvaged from the malformed JSON")
	}
	if v.Confidence != 0.95 {
		t.Errorf("want confidence=0.95 salvaged, got %v", v.Confidence)
	}
	if v.Severity != "LOW" {
		t.Errorf("want severity=LOW salvaged, got %q", v.Severity)
	}
	if !strings.Contains(v.Explanation, "get_callers returned Handler") {
		t.Errorf("want the explanation text salvaged (even if truncated), got %q", v.Explanation)
	}
	if !strings.Contains(v.Explanation, "[recovered from malformed JSON") {
		t.Errorf("salvaged verdict should be tagged as recovered, got %q", v.Explanation)
	}
	if v.Summary != "Caller validates hash format before reaching sink." {
		t.Errorf("want summary salvaged intact, got %q", v.Summary)
	}
}

// TestParseVerdict_SalvageFailsWithoutExploitableField confirms salvage
// requires the single most decision-critical field to be recoverable at
// all — text too corrupted to find "exploitable" in falls back to the safe
// default rather than guessing.
func TestParseVerdict_SalvageFailsWithoutExploitableField(t *testing.T) {
	raw := `{"cwe":"CWE-22","confidence":0.9, this is not valid json at all}`
	v := parseVerdict(raw)
	if v.Exploitable {
		t.Error("want the safe default (exploitable=false) when salvage can't even find the exploitable field")
	}
	if v.Confidence != 0 {
		t.Errorf("want a fully zero-value default, not a partial salvage, got confidence=%v", v.Confidence)
	}
}

func TestSurfaceDeadline(t *testing.T) {
	if surfaceDeadline != 300*time.Second {
		t.Errorf("surfaceDeadline = %v, want 300s", surfaceDeadline)
	}
}

func TestScan_ConcurrencySmoke(t *testing.T) {
	// Scan runs serialized (SetLimit(1)). 4 surfaces must complete without deadlock.
	var callCount int
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			callCount++
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"test"}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{
		makeSurface("s1", targeting.SurfaceExternalInput),
		makeSurface("s2", targeting.SurfaceExternalInput),
		makeSurface("s3", targeting.SurfaceExternalInput),
		makeSurface("s4", targeting.SurfaceExternalInput),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := s.Scan(ctx, surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Errorf("want 4 findings, got %d", len(findings))
	}
}

func TestScanOne_EmptyResponseRetry(t *testing.T) {
	var callCount int
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, opts *llm.Options) (string, error) {
			callCount++
			if callCount == 1 {
				// First call returns empty — triggers retry
				return "", nil
			}
			// Second call returns valid verdict. Confidence kept below the
			// self-consistency threshold (0.85) so this test stays isolated
			// to the empty-response retry path.
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.80,"explanation":"test"}`, nil
		},
	}
	s := New(p)
	surface := makeSurface("s1", targeting.SurfaceExternalInput)
	finding, err := s.scanOne(context.Background(), surface)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil {
		t.Fatal("want non-nil finding after retry, got nil")
	}
	if callCount != 2 {
		t.Errorf("expected 2 Generate calls (1 empty + 1 retry), got %d", callCount)
	}
}

func TestScan_TaintMismatch_SetsFieldOnFinding(t *testing.T) {
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			return `{"exploitable":false,"cwe":"CWE-89","severity":"LOW","confidence":0.2,"explanation":"no DB calls","taint_mismatch":true}`, nil
		},
	}
	s := New(p)
	surfaces := []enrichment.EnrichedSurface{
		{Surface: targeting.Surface{ID: "s1", File: "x.go", Kind: targeting.SurfaceExternalInput}},
	}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if !findings[0].TaintMismatch {
		t.Error("want TaintMismatch=true")
	}
	if findings[0].Exploitable {
		t.Error("want Exploitable=false")
	}
}

// TestScan_FabricatedNegativeVerdict_StillDowngraded is a regression test for
// a real gap found in production: the mandatory-investigation gate only
// downgraded a fabricated exploitable=TRUE verdict. Live testing showed a
// model can just as easily fabricate a confident exploitable=FALSE verdict
// without ever calling a tool — in one real run, qwen3.5:9b was nudged for
// not investigating, still made zero tool calls, then wrote a justification
// citing a specific caller and annotation that appeared nowhere in the
// actual evidence. That direction is arguably more dangerous for a security
// tool (a real vulnerability confidently and permanently dismissed), so the
// gate must downgrade confidence regardless of which way the verdict goes.
func TestScan_FabricatedNegativeVerdict_StillDowngraded(t *testing.T) {
	provider := &mockChatProvider{responses: []llm.Message{
		// Round 0: answers immediately, no tool call.
		{Content: `{"exploitable":false,"cwe":"","severity":"LOW","confidence":0.95,"explanation":"Caller is gated by @PreAuthorize; no auth bypass."}`},
		// After the nudge: still no tool call, same fabricated claim.
		{Content: `{"exploitable":false,"cwe":"","severity":"LOW","confidence":0.95,"explanation":"Caller is gated by @PreAuthorize; no auth bypass."}`},
	}}
	s := New(provider).WithGraph(&fakeGraph{})
	surface := makeGatedSurface("s1") // ContractCWE=CWE-862 (NoSinkModel, requiresInvestigation)

	findings, err := s.Scan(context.Background(), []enrichment.EnrichedSurface{surface})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Exploitable {
		t.Error("want Exploitable=false (the model's claimed verdict, even though fabricated)")
	}
	if f.Confidence > uninvestigatedConfidenceCap {
		t.Errorf("want confidence capped at %.2f for an uninvestigated verdict, got %.2f — "+
			"a fabricated exploitable=false must be downgraded exactly like a fabricated exploitable=true, "+
			"or it can silently suppress a real DCC violation forever", uninvestigatedConfidenceCap, f.Confidence)
	}
	if !strings.Contains(f.Justification, "[uninvestigated:") {
		t.Errorf("want the uninvestigated tag on the justification, got %q", f.Justification)
	}
}

// TestScan_InvestigatedButHedgedVerdict_StillDowngraded is a regression test
// for a gap the mandatory-investigation gate does NOT cover: a model that
// DOES call a tool (so requiresInvestigation's !investigated check never
// fires) but gets back inconclusive evidence, then reports high confidence
// anyway using its own hedge words. Observed live on a real litemall scan:
// QiniuStorage.java:71 got exploitable=true, confidence=0.9, severity=HIGH,
// explanation "Caller chain includes controllers... where authorization
// checks like @PreAuthorize are typically enforced upstream." — @PreAuthorize
// appears nowhere in litemall (it uses Apache Shiro); "typically enforced"
// is the model admitting it never actually verified this. A hedge word
// modifying an auth claim is a stronger, cheaper tell than trying to parse
// tool-call evidence for grounding.
func TestScan_InvestigatedButHedgedVerdict_StillDowngraded(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "SomeController"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		// First hop alone would trip the "exploitable after only 1 hop"
		// chase-nudge (see runToolLoop) before the hedge-guard downstream
		// ever sees it — simulate the model chasing one hop further per that
		// nudge, using get_neighbours_at_depth this time so it ALSO clears
		// the dual-tool confirmation gate (2 distinct tool types used), then
		// still landing on the same hedged, self-contradictory conclusion —
		// so this test continues to exercise scanOne's hedge-guard
		// specifically, not the chase-nudge or the dual-tool gate.
		{ToolCalls: []llm.ToolCall{{ID: "call_2", Name: "get_neighbours_at_depth", Arguments: `{"function_id":"c1","depth":2}`}}},
		{Content: `{"exploitable":true,"cwe":"CWE-862","severity":"HIGH","confidence":0.9,"explanation":"Caller chain includes controllers where authorization checks like @PreAuthorize are typically enforced upstream."}`},
	}}
	s := New(provider).WithGraph(g)
	surface := makeGatedSurface("s1")
	surface.ID = "m1"

	findings, err := s.Scan(context.Background(), []enrichment.EnrichedSurface{surface})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Confidence > uninvestigatedConfidenceCap {
		t.Errorf("want confidence capped at %.2f for a hedged, self-contradictory verdict, got %.2f — "+
			"a model saying 'typically enforced' about an auth check is telling us it guessed, "+
			"even though a tool WAS called", uninvestigatedConfidenceCap, f.Confidence)
	}
	if !strings.Contains(f.Justification, "[hedged claim of an unverified guard]") {
		t.Errorf("want the hedge tag on the justification, got %q", f.Justification)
	}
}

// TestScan_HedgeGuard_FiresForNonAuthCWEs is a regression test for a real
// bug found live on a Grafana scan: the hedge-guard used to require the
// explanation to also contain "auth", so a CWE-22 (path traversal) finding
// whose explanation literally said "...this remains uncertain but leans
// toward exploitable" — a textbook self-admission of guessing — was NOT
// downgraded, because the topic gate silently exempted every non-auth CWE.
// Hedge language is topic-agnostic; this locks in that the guard fires for
// CWE-22 (and by extension any CWE) just as it does for CWE-862.
func TestScan_HedgeGuard_FiresForNonAuthCWEs(t *testing.T) {
	g := &fakeGraph{callers: map[string][]cpg_engine.Node{
		"m1": {{ID: "c1", Name: "HandleRequest"}},
	}}
	provider := &mockChatProvider{responses: []llm.Message{
		{ToolCalls: []llm.ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		{ToolCalls: []llm.ToolCall{{ID: "call_2", Name: "get_neighbours_at_depth", Arguments: `{"function_id":"c1","depth":2}`}}},
		{Content: `{"exploitable":true,"cwe":"CWE-22","severity":"HIGH","confidence":0.8,"explanation":"The taint path shows user input reaching a path-construction sink; this remains uncertain but leans toward exploitable given the lack of visible validation."}`},
	}}
	s := New(provider).WithGraph(g)
	surface := makeGatedSurface("s1")
	surface.ID = "m1"
	surface.ContractCWE = "CWE-22"

	findings, err := s.Scan(context.Background(), []enrichment.EnrichedSurface{surface})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Confidence > uninvestigatedConfidenceCap {
		t.Errorf("want confidence capped at %.2f for a hedged CWE-22 verdict with no 'auth' mention, got %.2f",
			uninvestigatedConfidenceCap, f.Confidence)
	}
	if !strings.Contains(f.Justification, "[hedged claim of an unverified guard]") {
		t.Errorf("want the hedge tag on a non-auth CWE explanation too, got %q", f.Justification)
	}
}
