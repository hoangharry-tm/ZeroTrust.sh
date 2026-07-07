package analysis

import (
	"context"
	"strings"
	"testing"

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

func TestScan_NonExploitableVerdict_Dropped(t *testing.T) {
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
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(findings))
	}
}

func TestScan_MalformedJSON_Dropped(t *testing.T) {
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
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(findings))
	}
}

func TestScan_BatchPreservesOrder(t *testing.T) {
	// Exploitable surfaces at indices 0, 2, 4; non-exploitable at 1, 3.
	// Prompts differ by CWE (auth→CWE-862 exploitable, sink→CWE-327 safe).
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
	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(findings))
	}
	// Input indices 0, 2, 4 → output order must be files a.go, c.go, e.go.
	if findings[0].Path != "a.go" {
		t.Errorf("finding 0: want a.go, got %s", findings[0].Path)
	}
	if findings[1].Path != "c.go" {
		t.Errorf("finding 1: want c.go, got %s", findings[1].Path)
	}
	if findings[2].Path != "e.go" {
		t.Errorf("finding 2: want e.go, got %s", findings[2].Path)
	}
}

func TestScan_PerSurfaceErrorSkipped(t *testing.T) {
	var callCount int
	p := &mockProvider{
		generateFunc: func(_ context.Context, _ string, _ *llm.Options) (string, error) {
			callCount++
			if callCount == 1 {
				return "", assertAnError("llm error")
			}
			return `{"exploitable":true,"cwe":"CWE-89","severity":"HIGH","confidence":0.85,"explanation":"ok"}`, nil
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
	prompt := buildPrompt(surface)
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

func TestParseVerdict_ProseWrappedJSON(t *testing.T) {
	raw := `Sure! Here's my analysis: {"exploitable":true,"cwe":"CWE-22","severity":"HIGH","confidence":0.9,"explanation":"path traversal"}`
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
}
