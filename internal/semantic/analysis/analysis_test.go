package analysis

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
func (m *mockProvider) ModelName() string             { return "mock" }

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
	s := New(p, "mid")
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
	s := New(p, "mid")
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
	s := New(p, "mid")
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
	s := New(p, "mid")
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
	s := New(p, "mid")
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
	prompt := buildPrompt(surface, "mid")
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

func TestSurfaceDeadline(t *testing.T) {
	cases := []struct {
		mode string
		want time.Duration
	}{
		{"small", 45 * time.Second},
		{"mid", 120 * time.Second},
		{"frontier", 300 * time.Second},
		{"", 120 * time.Second},
	}
	for _, c := range cases {
		got := surfaceDeadline(c.mode)
		if got != c.want {
			t.Errorf("surfaceDeadline(%q) = %v, want %v", c.mode, got, c.want)
		}
	}
}

func TestScan_ConcurrencySmoke(t *testing.T) {
	// Mid mode uses SetLimit(2). 4 surfaces must complete without deadlock.
	var callCount int
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			callCount++
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"test"}`, nil
		},
	}
	s := New(p, "mid")
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
			// Second call returns valid verdict
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"test"}`, nil
		},
	}
	s := New(p, "mid")
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
	s := New(p, "mid")
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
