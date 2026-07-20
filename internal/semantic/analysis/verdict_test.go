package analysis

import (
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestVerdictToFinding_SetsExploitableAndTaintMismatch(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-42",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	v := Verdict{
		Exploitable:   true,
		CWE:           "CWE-89",
		Severity:      "HIGH",
		Confidence:    0.85,
		Explanation:   "direct SQL concat",
		TaintMismatch: false,
	}
	f := verdictToFinding(surface, v)
	if !f.Exploitable {
		t.Error("want Exploitable=true")
	}
	if f.TaintMismatch {
		t.Error("want TaintMismatch=false")
	}
	if f.SurfaceID != "node-42" {
		t.Errorf("want SurfaceID='node-42', got %q", f.SurfaceID)
	}
}

func TestVerdictToFinding_SurfaceIDPopulated(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-42",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	v := Verdict{Exploitable: false}
	f := verdictToFinding(surface, v)
	if f.SurfaceID != "node-42" {
		t.Errorf("want SurfaceID='node-42', got %q", f.SurfaceID)
	}
}

func TestVerdictToFinding_TaintMismatchTrue(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-99",
			File: "test.go",
		},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
	}
	f := verdictToFinding(surface, v)
	if !f.TaintMismatch {
		t.Error("want TaintMismatch=true")
	}
	if f.Exploitable {
		t.Error("want Exploitable=false")
	}
}

func TestVerdictToFinding_TaintMismatchCriticalCappedToLow(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{ID: "node-1", File: "Foo.java"},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
		Severity:      "CRITICAL",
		Confidence:    1.0,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityLow {
		t.Errorf("want SeverityLow for TaintMismatch+CRITICAL, got %v", f.SeverityLabel)
	}
	if !f.TaintMismatch {
		t.Error("want TaintMismatch=true preserved")
	}
}

func TestVerdictToFinding_LineRangeFromSurface(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{Line: 77, File: "Bar.java"},
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.8}
	f := verdictToFinding(surface, v)
	if f.LineRange.Start != 77 {
		t.Errorf("want LineRange.Start=77, got %d", f.LineRange.Start)
	}
}

func TestVerdictToFinding_CVEFromCVEMatches(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Bar.java"},
		CVEMatches: []enrichment.CVEMatch{
			{CVE: "CVE-2022-1234", CVSS: 8.5},
		},
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.8}
	f := verdictToFinding(surface, v)
	if f.CVE != "CVE-2022-1234" {
		t.Errorf("want CVE-2022-1234, got %q", f.CVE)
	}
	if f.CVSS != 8.5 {
		t.Errorf("want CVSS=8.5, got %f", f.CVSS)
	}
}

func TestVerdictToFinding_TaintMismatchSetsPinned(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Foo.java"},
	}
	v := Verdict{
		Exploitable:   false,
		TaintMismatch: true,
		Severity:      "CRITICAL",
		Confidence:    0.95,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityLow {
		t.Errorf("want SeverityLow, got %v", f.SeverityLabel)
	}
	if !f.SeverityPinned {
		t.Error("want SeverityPinned=true for TaintMismatch cap")
	}
}

func TestVerdictToFinding_MatchedCodeFromSurfaceCode(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Bar.java", Line: 20},
		Code:    "void bar() {\n  exec(input);\n}",
	}
	v := Verdict{Exploitable: true, Severity: "HIGH", Confidence: 0.9}
	f := verdictToFinding(surface, v)
	if f.MatchedCode == "" {
		t.Error("want MatchedCode populated from surface.Code")
	}
	if !strings.Contains(f.MatchedCode, "exec(input)") {
		t.Errorf("want source code in MatchedCode, got %q", f.MatchedCode)
	}
}

func TestVerdictToFinding_DefaultSeverity(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "node-1",
			File: "x.go",
		},
	}
	v := Verdict{
		Exploitable: true,
		Severity:    "UNKNOWN",
		Confidence:  0.9,
	}
	f := verdictToFinding(surface, v)
	if f.SeverityLabel != finding.SeverityMedium {
		t.Errorf("want MEDIUM for unknown severity, got %v", f.SeverityLabel)
	}
}
