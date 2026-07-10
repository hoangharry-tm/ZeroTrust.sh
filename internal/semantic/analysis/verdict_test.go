package analysis

import (
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
