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
		if len(inv.SinkAnchors) == 0 && !inv.NoSinkModel {
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
		switch {
		case cwe == "CWE-94", inv.NoSinkModel:
			if inv.SafeNodes != nil {
				t.Errorf("CWE %s should have nil SafeNodes, got %v", cwe, inv.SafeNodes)
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
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"exec.Command"}, []string{"shellEscape"}),
		},
		{
			name:    "Path traversal with path clean",
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"FileWriter"}, []string{"pathClean"}),
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
			name:    "Broken crypto with SHA256",
			surface: surfaceWith(targeting.SurfaceDangerousSink, []string{"md5"}, []string{"sha256"}),
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
			surface: surfaceWith(targeting.SurfaceExternalInput, []string{"new File"}, []string{"userInput"}),
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
			name:    "Broken crypto violation",
			surface: surfaceWith(targeting.SurfaceDangerousSink, []string{"md5"}, []string{"data"}),
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
			surface: surfaceWith(targeting.SurfaceIDORCandidate, []string{"isUserInRole"}, nil),
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

func TestApplicableCWEs_AuthBoundaryIncludesInjection(t *testing.T) {
	cwes := applicableCWEs(targeting.SurfaceAuthBoundary)
	expected := []string{"CWE-862", "CWE-89", "CWE-78"}
	if len(cwes) != len(expected) {
		t.Fatalf("applicableCWEs(SurfaceAuthBoundary) = %v, want %v", cwes, expected)
	}
	for i, cwe := range expected {
		if cwes[i] != cwe {
			t.Errorf("position %d: want %s, got %s", i, cwe, cwes[i])
		}
	}
}

func TestDefaultInconclusive(t *testing.T) {
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"some.unknown.sink"}, []string{"userInput"})
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive for no-matching-anchor, got %s", result.Verdict)
	}
	if result.CWE != "CWE-22" {
		t.Errorf("expected CWE-22 (first applicable for ExternalInput), got %q", result.CWE)
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
		SinkNodes: []string{"exec.Command", "db.Query", "new File"},
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

// ── Fix 1 tests: best==nil branch returns primary CWE ──────────────────────

func TestBestIsNil_ExternalInput_ReturnsCWEMinus22(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "no-sink-surface",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive, got %s", result.Verdict)
	}
	if result.CWE != "CWE-22" {
		t.Errorf("expected CWE-22 (first applicable for ExternalInput), got %q", result.CWE)
	}
	if result.Evidence != "no sink anchor matched for any applicable CWE" {
		t.Errorf("expected 'no sink anchor matched' evidence, got %q", result.Evidence)
	}
}

func TestBestIsNil_AuthBoundary_ReturnsCWEMinus862(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "no-sink-auth",
			Kind: targeting.SurfaceAuthBoundary,
		},
	}
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive, got %s", result.Verdict)
	}
	if result.CWE != "CWE-862" {
		t.Errorf("expected CWE-862 (first applicable for AuthBoundary), got %q", result.CWE)
	}
}

func TestBestIsNil_UnknownKind_ReturnsEmptyCWE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "unknown-kind-surface",
			Kind: targeting.SurfaceKind("unknown"),
		},
	}
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictInconclusive {
		t.Errorf("expected VerdictInconclusive, got %s", result.Verdict)
	}
	if result.CWE != "" {
		t.Errorf("expected empty CWE for unknown kind, got %q", result.CWE)
	}
}

func TestBestIsNil_WithMatchingAnchor_ExistingBehaviorUnchanged(t *testing.T) {
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"db.Query"}, []string{"userInput", "concat"})
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Errorf("expected VerdictViolation when anchor matches, got %s", result.Verdict)
	}
	if result.CWE != "CWE-89" {
		t.Errorf("expected CWE-89 for SQLi, got %q", result.CWE)
	}
}

// ── H3: CWE-22 sink anchor completeness (Spring/Servlet file sinks) ─────────

func TestCWE22SinkAnchors_ContainsSpringFileSinks(t *testing.T) {
	inv, ok := Rulebook["CWE-22"]
	if !ok {
		t.Fatal("CWE-22 missing from Rulebook")
	}
	required := []string{
		"FileWriter", "FileOutputStream", "Files.copy", "Files.write",
		"transferTo", "file.transferTo", "ZipEntry", "ZipInputStream",
		"OutputStream.write", "Files.createFile", "Files.createTempFile", "Files.move",
	}
	anchors := make(map[string]bool, len(inv.SinkAnchors))
	for _, a := range inv.SinkAnchors {
		anchors[a] = true
	}
	for _, want := range required {
		if !anchors[want] {
			t.Errorf("CWE-22 SinkAnchors missing %q (needed for Spring/Servlet file upload sinks)", want)
		}
	}
}

func TestCWE22_TransferToSinkTriggersViolation(t *testing.T) {
	// Spring MultipartFile.transferTo is a real file write sink — must fire the DCC.
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"transferTo"}, []string{"file", "transferTo"})
	surface.ContractCWE = "CWE-22"
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Errorf("transferTo should trigger CWE-22 violation, got verdict=%s cwe=%s evidence=%s",
			result.Verdict, result.CWE, result.Evidence)
	}
}

func TestCWE22_FileTransferToSinkTriggersViolation(t *testing.T) {
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"file.transferTo"}, []string{"file", "file.transferTo"})
	surface.ContractCWE = "CWE-22"
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Errorf("file.transferTo should trigger CWE-22 violation, got verdict=%s", result.Verdict)
	}
}

// ── P1-A: CWE-862 has no keyword sink model ───────────────────────────────
//
// CWE-862 (Missing Authorization) has no fixed dangerous-API signature to
// keyword-match — unlike SQLi/exec/eval, its "sink" is whatever operation
// the surface performs, and false-positive-prone auth-function-name
// keyword matching (e.g. "getAttribute" matching ordinary getAttributes())
// was removed. Contracts now always defers CWE-862 to B4/B5, except when
// the CPG's own structural taint taxonomy (Sanitized) says otherwise.

func TestCWE862_NoSinkModel(t *testing.T) {
	inv, ok := Rulebook["CWE-862"]
	if !ok {
		t.Fatal("CWE-862 missing from Rulebook")
	}
	if !inv.NoSinkModel {
		t.Error("CWE-862 should have NoSinkModel=true")
	}
	if len(inv.SinkAnchors) != 0 {
		t.Errorf("CWE-862 SinkAnchors should be empty, got %v", inv.SinkAnchors)
	}
	if len(inv.SafeNodes) != 0 {
		t.Errorf("CWE-862 SafeNodes should be empty, got %v", inv.SafeNodes)
	}
}

func TestCWE862_DefersToLLMWhenNotSanitized(t *testing.T) {
	c := New()
	for _, kind := range []targeting.SurfaceKind{targeting.SurfaceAuthBoundary, targeting.SurfaceIDORCandidate} {
		surface := surfaceWith(kind, []string{"doFilter"}, []string{"externalInput"})
		result := c.Check(context.Background(), surface)
		if result.Verdict != VerdictInconclusive {
			t.Errorf("%s: expected VerdictInconclusive (defer to LLM), got %s", kind, result.Verdict)
		}
		if result.CWE != "CWE-862" {
			t.Errorf("%s: expected CWE-862, got %q", kind, result.CWE)
		}
	}
}

func TestCWE862_SafeWhenStructurallySanitized(t *testing.T) {
	c := New()
	surface := surfaceWith(targeting.SurfaceIDORCandidate, []string{"doFilter"}, []string{"externalInput"})
	surface.Sanitized = true
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictSafe {
		t.Errorf("expected VerdictSafe when CPG taint taxonomy confirms sanitization, got %s", result.Verdict)
	}
}

func TestCWE862_FictitiousAnchorsRemoved(t *testing.T) {
	inv, ok := Rulebook["CWE-862"]
	if !ok {
		t.Fatal("CWE-862 missing from Rulebook")
	}
	fictitious := []string{"api.handler", "route.Handle", "endpoint", "http.HandlerFunc", "resourceAccess"}
	anchors := make(map[string]bool, len(inv.SinkAnchors))
	for _, a := range inv.SinkAnchors {
		anchors[a] = true
	}
	for _, f := range fictitious {
		if anchors[f] {
			t.Errorf("CWE-862 should no longer contain fictitious anchor %q", f)
		}
	}
}

// ── P2-B: CWE-22 method call aliases ──────────────────────────────────────

func TestCWE22_WriteMethodMatchesAnchor(t *testing.T) {
	inv, ok := Rulebook["CWE-22"]
	if !ok {
		t.Fatal("CWE-22 missing from Rulebook")
	}
	anchors := make(map[string]bool, len(inv.SinkAnchors))
	for _, a := range inv.SinkAnchors {
		anchors[a] = true
	}
	if !anchors["OutputStream.write"] {
		t.Error("CWE-22 SinkAnchors missing OutputStream.write (method-call form)")
	}
}

func TestCWE22_CreateFileMatchesAnchor(t *testing.T) {
	inv, ok := Rulebook["CWE-22"]
	if !ok {
		t.Fatal("CWE-22 missing from Rulebook")
	}
	anchors := make(map[string]bool, len(inv.SinkAnchors))
	for _, a := range inv.SinkAnchors {
		anchors[a] = true
	}
	if !anchors["Files.createFile"] {
		t.Error("CWE-22 SinkAnchors missing Files.createFile")
	}
}

func TestCWE22_LegacyFileWriterSinkStillWorks(t *testing.T) {
	// Regression: existing FileWriter anchor must not be broken by new additions.
	surface := surfaceWith(targeting.SurfaceExternalInput, []string{"FileWriter"}, []string{"userPath", "FileWriter"})
	c := New()
	result := c.Check(context.Background(), surface)
	if result.Verdict != VerdictViolation {
		t.Errorf("FileWriter should still trigger CWE-22 violation, got verdict=%s", result.Verdict)
	}
}

// ── Root Cause 2a: overly-broad anchors ────────────────────────────────────

func TestFalsePositiveAnchors_PrintStackTraceDoesNotFireCWE79(t *testing.T) {
	// "print" as a 5-char anchor matched printStackTrace. Now qualified.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-printstacktrace",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"executeQuery"},
		CallPath:  []string{"userInput", "executeQuery"},
		Code:      `e.printStackTrace();`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE == "CWE-79" {
		t.Errorf("printStackTrace must NOT fire CWE-79 (no qualified anchor matches): verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
	if result.CWE == "CWE-89" && result.Verdict != VerdictViolation {
		t.Errorf("SQLi should still fire as VIOLATION, got verdict=%s", result.Verdict)
	}
}

func TestFalsePositiveAnchors_PatternCompileDoesNotFireCWE94(t *testing.T) {
	// "compile" is now qualified — Pattern.compile must NOT match CWE-94.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-pattern-compile",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"executeQuery"},
		CallPath:  []string{"userInput", "executeQuery"},
		Code:      `Pattern.compile("[0-9]+");`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE == "CWE-94" {
		t.Errorf("Pattern.compile must NOT fire CWE-94: verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
}

func TestFalsePositiveAnchors_FunctionInterfaceDoesNotFireCWE94(t *testing.T) {
	// "Function" anchor removed — java.util.function.Function must not match.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-function-interface",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"executeQuery"},
		CallPath:  []string{"userInput", "executeQuery"},
		Code:      `Function<String, Response> handler = (s) -> service.call(s);`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE == "CWE-94" {
		t.Errorf("Function<String,Response> must NOT fire CWE-94: verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
}

// ── Root Cause 2c: CWE-502 false positives ─────────────────────────────────

func TestFalsePositiveAnchors_ReadObjectJDBCDoesNotFireCWE502(t *testing.T) {
	// "readObject" (unqualified) removed — ResultSet.readObject must NOT match.
	// CWE-89 should still fire via executeQuery sink node.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-readobject-jdbc",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"readObject", "executeQuery"},
		CallPath:  []string{"userInput", "executeQuery"},
	}
	result := c.Check(context.Background(), surface)
	if result.CWE == "CWE-502" {
		t.Errorf("ResultSet.readObject must NOT fire CWE-502 after removal of unqualified anchor: verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
}

// ── Root Cause 2d: comment/string stripping ────────────────────────────────

func TestFalsePositiveAnchors_DeserializeInComment(t *testing.T) {
	// "deserialize" in a comment must not fire CWE-502 after comment stripping.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-deserialize-comment",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{},
		CallPath:  []string{},
		Code:      `// 3 deserializes via the all-args constructor`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE == "CWE-502" {
		t.Errorf("deserialize in comment must NOT fire CWE-502 after stripCode: verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
}

// ── Root Cause 3: sinkMatched priority ─────────────────────────────────────

func TestApplicableCWEs_AuthBoundaryDoesNotIncludeCWE22(t *testing.T) {
	cwes := applicableCWEs(targeting.SurfaceAuthBoundary)
	for _, c := range cwes {
		if c == "CWE-22" {
			t.Error("SurfaceAuthBoundary must not include CWE-22: path traversal is not an auth-boundary concern")
		}
	}
}

// TestApplicableCWEs_IDORCandidateIncludesCWE22 is a regression test for a
// real gap found live: CWE-22 used to be entirely absent from
// SurfaceIDORCandidate's applicable list — a bug, not a deliberate
// exclusion, contrary to what an earlier version of this test asserted.
// Found on a real Grafana scan: getPluginAssets (CVE-2021-43798) is exactly
// this shape — a resource-ID parameter (pluginID) used both to look up a
// resource (why targeting classifies it IDOR) and to construct a file path
// passed to os.Open (a real CWE-22 sink). Since CWE-22 was never in this
// list, the surface could only ever be checked against CWE-862, and B5's
// real, correctly-investigated exploitable=true verdict for it got
// classified under the wrong CWE regardless of how good the reasoning was.
// A resource-ID-to-file-path lookup is one of the most common
// IDOR-adjacent patterns there is, not an edge case.
func TestApplicableCWEs_IDORCandidateIncludesCWE22(t *testing.T) {
	cwes := applicableCWEs(targeting.SurfaceIDORCandidate)
	found := false
	for _, c := range cwes {
		if c == "CWE-22" {
			found = true
		}
	}
	if !found {
		t.Error("SurfaceIDORCandidate must include CWE-22: an IDOR-classified surface (resource-ID lookup) commonly also reaches a path-traversal sink (file path built from that same ID)")
	}
}

func TestSinkMatchedPrecedenceOverCodeMatch(t *testing.T) {
	// Surface has both a code-only XSS match and a sink-node SQLi match.
	// CWE-89 (sinkMatched=true) must win over CWE-79 (code-only, lower number).
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-sink-priority",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{"executeQuery"},
		CallPath:  []string{"userInput", "executeQuery"},
		Code:      `response.getWriter().println("hello");`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE != "CWE-89" {
		t.Errorf("CWE-89 (sinkMatched) should beat CWE-79 (code-only, lower number): got cwe=%s verdict=%s", result.CWE, result.Verdict)
	}
	if result.Verdict != VerdictViolation {
		t.Errorf("expected VIOLATION for sink-matched SQLi, got %s", result.Verdict)
	}
}
