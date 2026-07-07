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
	"fmt"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestRulebookCompleteness(t *testing.T) {
	expectedCWEs := []string{
		"CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-94",
		"CWE-918", "CWE-862", "CWE-327", "CWE-502",
	}

	if len(Rulebook) != len(expectedCWEs) {
		t.Errorf("Rulebook has %d entries, expected %d", len(Rulebook), len(expectedCWEs))
	}

	for _, cwe := range expectedCWEs {
		inv, ok := Rulebook[cwe]
		if !ok {
			t.Errorf("missing rulebook entry for %s", cwe)
			continue
		}
		if len(inv.SinkAnchors) == 0 {
			t.Errorf("CWE %s: SinkAnchors is empty", cwe)
		}
		if inv.Reference == "" {
			t.Errorf("CWE %s: Reference is empty", cwe)
		}
		if inv.Name == "" {
			t.Errorf("CWE %s: Name is empty", cwe)
		}
	}
}

func TestSafeNodesNonEmptyExceptCWE94(t *testing.T) {
	for cwe, inv := range Rulebook {
		switch cwe {
		case "CWE-94":
			if inv.SafeNodes != nil {
				t.Errorf("CWE-94 should have nil SafeNodes, got %v", inv.SafeNodes)
			}
		default:
			if len(inv.SafeNodes) == 0 {
				t.Errorf("CWE %s: SafeNodes should be non-empty", cwe)
			}
		}
	}
}

func surfaceWith(kind targeting.SurfaceKind, sinkNodes, callPath []string) enrichment.EnrichedSurface {
	return enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-surface",
			Kind: kind,
		},
		SinkNodes: sinkNodes,
		CallPath:  callPath,
	}
}

func TestVerdictSafe(t *testing.T) {
	tests := []struct {
		name    string
		surface enrichment.EnrichedSurface
	}{
		{
			name:    "SQLi with parameterized query",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"db.Query"}, []string{"paramQuery"}),
		},
		{
			name:    "OS command with shell escape",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"os.exec"}, []string{"shellEscape"}),
		},
		{
			name:    "Path traversal with path clean",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"file.open"}, []string{"pathClean"}),
		},
		{
			name:    "XSS with HTML escape",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"response.write"}, []string{"htmlEscape"}),
		},
		{
			name:    "SSRF with URL allowlist",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"http.Get"}, []string{"urlAllowlist"}),
		},
		{
			name:    "Missing auth with auth check",
			surface: surfaceWith(targeting.SurfaceAuthBoundary, []string{"api.handler"}, []string{"authCheck"}),
		},
		{
			name:    "Missing auth IDOR with auth middleware",
			surface: surfaceWith(targeting.SurfaceIDORCandidate, []string{"route.Handle"}, []string{"authMiddleware"}),
		},
		{
			name:    "Broken crypto with SHA256",
			surface: surfaceWith(targeting.SurfaceDangerousSink, []string{"crypto.MD5"}, []string{"sha256"}),
		},
		{
			name:    "Deserialization with type filter",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"pickle.load"}, []string{"typeFilter"}),
		},
	}

	c := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Check(context.Background(), tt.surface)
			if result.Verdict != VerdictSafe {
				t.Errorf("expected VerdictSafe, got %s (CWE=%q, evidence=%q)",
					result.Verdict, result.CWE, result.Evidence)
			}
			if result.CWE != "" {
				t.Errorf("expected empty CWE for safe verdict, got %q", result.CWE)
			}
		})
	}
}

func TestVerdictViolation(t *testing.T) {
	tests := []struct {
		name    string
		surface enrichment.EnrichedSurface
		wantCWE string
	}{
		{
			name:    "SQLi violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"db.Query"}, []string{"userInput", "concat"}),
			wantCWE: "CWE-89",
		},
		{
			name:    "OS command violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"exec.Command"}, []string{"userInput"}),
			wantCWE: "CWE-78",
		},
		{
			name:    "Path traversal violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"fopen"}, []string{"userInput"}),
			wantCWE: "CWE-22",
		},
		{
			name:    "XSS violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"innerHTML"}, []string{"userInput"}),
			wantCWE: "CWE-79",
		},
		{
			name:    "Code injection violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"eval"}, []string{"userInput"}),
			wantCWE: "CWE-94",
		},
		{
			name:    "SSRF violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"fetch"}, []string{"userInput"}),
			wantCWE: "CWE-918",
		},
		{
			name:    "Missing auth violation",
			surface: surfaceWith(targeting.SurfaceAuthBoundary, []string{"api.handler"}, []string{"externalInput"}),
			wantCWE: "CWE-862",
		},
		{
			name:    "IDOR violation",
			surface: surfaceWith(targeting.SurfaceIDORCandidate, []string{"endpoint"}, []string{"userParam"}),
			wantCWE: "CWE-862",
		},
		{
			name:    "Broken crypto violation",
			surface: surfaceWith(targeting.SurfaceDangerousSink, []string{"crypto.MD5"}, []string{"data"}),
			wantCWE: "CWE-327",
		},
		{
			name:    "Deserialization violation",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"yaml.load"}, []string{"userInput"}),
			wantCWE: "CWE-502",
		},
	}

	c := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Check(context.Background(), tt.surface)
			if result.Verdict != VerdictViolation {
				t.Errorf("expected VerdictViolation, got %s", result.Verdict)
			}
			if result.CWE != tt.wantCWE {
				t.Errorf("expected CWE %q, got %q", tt.wantCWE, result.CWE)
			}
			if result.Evidence == "" {
				t.Error("expected non-empty evidence")
			}
		})
	}
}

func TestVerdictInconclusive(t *testing.T) {
	tests := []struct {
		name    string
		surface enrichment.EnrichedSurface
	}{
		{
			name:    "SQLi sink matched but empty call path",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"db.Query"}, nil),
		},
		{
			name:    "OS command sink matched but empty call path",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"exec"}, nil),
		},
		{
			name:    "Missing auth sink matched but empty call path",
			surface: surfaceWith(targeting.SurfaceIDORCandidate, []string{"route.Handle"}, nil),
		},
	}

	c := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.Check(context.Background(), tt.surface)
			if result.Verdict != VerdictInconclusive {
				t.Errorf("expected VerdictInconclusive, got %s", result.Verdict)
			}
		})
	}
}

func TestDefaultInconclusive(t *testing.T) {
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"some.unknown.sink"}, []string{"userInput"})
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive for no-matching-anchor, got %s", result.Verdict)
	}
	if result.CWE != "" {
		t.Errorf("expected empty CWE for default inconclusive, got %q", result.CWE)
	}
}

func TestDefaultInconclusiveUnknownKind(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "unknown-kind",
			Kind: targeting.SurfaceKind("unknown"),
		},
		SinkNodes: []string{"exec"},
		CallPath:  []string{"userInput"},
	}
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive for unknown kind, got %s", result.Verdict)
	}
}

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictSafe, "SAFE"},
		{VerdictViolation, "VIOLATION"},
		{VerdictInconclusive, "INCONCLUSIVE"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.v.String() != tt.want {
				t.Errorf("expected %q, got %q", tt.want, tt.v.String())
			}
			if tt.v.String() == "" {
				t.Error("String() returned empty")
			}
		})
	}
}

func TestCheckAllOrderPreservation(t *testing.T) {
	surfaces := make([]enrichment.EnrichedSurface, 10)
	for i := 0; i < 10; i++ {
		sink := fmt.Sprintf("sink-%d", i)
		surfaces[i] = enrichment.EnrichedSurface{
			Surface: targeting.Surface{
				ID:   fmt.Sprintf("surface-%d", i),
				Kind: targeting.SurfaceExternalInput,
			},
			SinkNodes: []string{sink},
			CallPath:  []string{"userInput"},
		}
	}

	c := New()
	results := c.CheckAll(context.Background(), surfaces)

	if len(results) != 10 {
		t.Fatalf("expected 10 results, got %d", len(results))
	}

	for i, r := range results {
		expectedID := fmt.Sprintf("surface-%d", i)
		if r.Surface.ID != expectedID {
			t.Errorf("position %d: expected surface ID %q, got %q", i, expectedID, r.Surface.ID)
		}
	}
}

func TestViolationTiebreakByCWENumber(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "multi-cwe",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"exec.Command", "db.Query", "fopen"},
		CallPath:  []string{"userInput"},
	}
	c := New()
	result := c.Check(context.Background(), surface)

	if result.Verdict != VerdictViolation {
		t.Fatalf("expected VerdictViolation, got %s", result.Verdict)
	}
	if result.CWE != "CWE-22" {
		t.Errorf("expected CWE-22 (first by numeric order), got %q", result.CWE)
	}
}

func TestUnknownVerdictString(t *testing.T) {
	var v Verdict = 99
	if v.String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for invalid verdict, got %q", v.String())
	}
}

func TestEmptySurfacesCheckAll(t *testing.T) {
	c := New()
	results := c.CheckAll(context.Background(), nil)
	if results != nil {
		t.Errorf("expected nil for empty input, got %v", results)
	}

	results = c.CheckAll(context.Background(), []enrichment.EnrichedSurface{})
	if results != nil {
		t.Errorf("expected nil for empty slice, got %v", results)
	}
}
