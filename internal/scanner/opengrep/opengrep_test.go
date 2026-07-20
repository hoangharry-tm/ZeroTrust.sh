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

package opengrep

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// ─── confidenceFromMetadata ──────────────────────────────────────────────────

func TestConfidenceHigh(t *testing.T) {
	got := confidenceFromMetadata(map[string]any{"confidence": "HIGH"}, "ERROR")
	if got != 0.90 {
		t.Errorf("expected 0.90, got %v", got)
	}
}

func TestConfidenceMedium(t *testing.T) {
	got := confidenceFromMetadata(map[string]any{"confidence": "MEDIUM"}, "WARNING")
	if got != 0.65 {
		t.Errorf("expected 0.65, got %v", got)
	}
}

func TestConfidenceLow(t *testing.T) {
	got := confidenceFromMetadata(map[string]any{"confidence": "LOW"}, "INFO")
	if got != 0.40 {
		t.Errorf("expected 0.40, got %v", got)
	}
}

func TestConfidenceCaseInsensitive(t *testing.T) {
	got := confidenceFromMetadata(map[string]any{"confidence": "high"}, "INFO")
	if got != 0.90 {
		t.Errorf("expected 0.90, got %v", got)
	}
}

func TestConfidenceFallsBackToSeverity(t *testing.T) {
	cases := []struct {
		severity string
		want     float64
	}{
		{"ERROR", 0.65},
		{"WARNING", 0.40},
		{"INFO", 0.40},
		{"", 0.40},
	}
	for _, tc := range cases {
		got := confidenceFromMetadata(map[string]any{}, tc.severity)
		if got != tc.want {
			t.Errorf("severity %q: expected %v, got %v", tc.severity, tc.want, got)
		}
	}
}

// ─── cweFromMetadata ─────────────────────────────────────────────────────────

func TestCWEString(t *testing.T) {
	got := cweFromMetadata(map[string]any{"cwe": "CWE-89"})
	if got != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", got)
	}
}

func TestCWESlice(t *testing.T) {
	got := cweFromMetadata(map[string]any{"cwe": []any{"CWE-94", "CWE-116"}})
	if got != "CWE-94" {
		t.Errorf("expected CWE-94 (first element), got %q", got)
	}
}

func TestCWEMissing(t *testing.T) {
	got := cweFromMetadata(map[string]any{})
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ─── normalise ───────────────────────────────────────────────────────────────

func TestNormalisePopulatesFields(t *testing.T) {
	raw := RawFinding{
		RuleID: "PY-001",
		Path:   "api/auth.py",
		Start:  RawPosition{Line: 42, Col: 1},
		End:    RawPosition{Line: 42, Col: 20},
		Extra: RawExtra{
			Message:  "SQL injection via string formatting",
			Severity: "ERROR",
			Metadata: map[string]any{"confidence": "HIGH", "cwe": "CWE-89"},
			Lines:    `cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)`,
		},
	}

	f := normalise(raw)

	if f.Path != "api/auth.py" {
		t.Errorf("Path: got %q", f.Path)
	}
	if f.LineRange.Start != 42 || f.LineRange.End != 42 {
		t.Errorf("LineRange: got %+v", f.LineRange)
	}
	if f.CWE != "CWE-89" {
		t.Errorf("CWE: got %q", f.CWE)
	}
	if f.Confidence != 0.90 {
		t.Errorf("Confidence: got %v", f.Confidence)
	}
	if f.SeverityLabel != finding.SeverityHigh {
		t.Errorf("SeverityLabel: got %s", f.SeverityLabel)
	}
	if f.SourcePath != finding.SourcePattern {
		t.Errorf("SourcePath: got %s", f.SourcePath)
	}
	if f.RuleID != "PY-001" {
		t.Errorf("RuleID: got %q", f.RuleID)
	}
	if f.ID == "" {
		t.Error("ID must not be empty")
	}
	if f.Summary != "SQL injection via string formatting" {
		t.Errorf("Summary: got %q, want 'SQL injection via string formatting'", f.Summary)
	}
}

func TestNormaliseHighConfidenceGetsHighScore(t *testing.T) {
	raw := RawFinding{
		Extra: RawExtra{
			Metadata: map[string]any{"confidence": "HIGH"},
			Severity: "ERROR",
		},
	}
	f := normalise(raw)
	if f.Confidence < 0.85 {
		t.Errorf("HIGH confidence must produce score ≥ 0.85, got %v", f.Confidence)
	}
}

func TestKeepFinding_DropsDjangoCsrfOnJavaFile(t *testing.T) {
	f := finding.New(
		"src/main/java/com/example/Foo.java",
		finding.LineRange{Start: 10, End: 10},
		"CWE-352", "csrf",
		finding.WithRuleID("python.django.security.django-no-csrf-token.detected"),
	)
	if keepFinding(f) {
		t.Error("want keepFinding=false for python rule on .java file")
	}
}

func TestKeepFinding_KeepsJavaSpringRuleOnJavaFile(t *testing.T) {
	f := finding.New(
		"src/main/java/com/example/Controller.java",
		finding.LineRange{Start: 10, End: 10},
		"CWE-352", "csrf",
		finding.WithRuleID("java.spring.security.unrestricted-request-mapping.foo"),
	)
	if !keepFinding(f) {
		t.Error("want keepFinding=true for java rule on .java file")
	}
}

func TestKeepFinding_DropsGitHubActionsPath(t *testing.T) {
	f := finding.New(
		".github/workflows/ci.yml",
		finding.LineRange{Start: 5, End: 5},
		"", "mutable tag",
		finding.WithRuleID("generic.ci.mutable-action"),
	)
	if keepFinding(f) {
		t.Error("want keepFinding=false for .github/ path")
	}
}

func TestKeepFinding_DropsDjangoRuleOnHtmlFile(t *testing.T) {
	f := finding.New(
		"resources/lessons/authbypass/html/AuthBypass.html",
		finding.LineRange{Start: 10, End: 10},
		"CWE-352", "csrf",
		finding.WithRuleID("python.django.security.django-no-csrf-token.django-no-csrf-token"),
	)
	if keepFinding(f) {
		t.Error("want keepFinding=false for python django rule on .html file")
	}
}

func TestKeepFinding_KeepsGenericRule(t *testing.T) {
	f := finding.New(
		"src/main/java/Foo.java",
		finding.LineRange{Start: 1, End: 1},
		"CWE-200", "info",
		finding.WithRuleID("generic.secrets.security.detected-jwt-token"),
	)
	if !keepFinding(f) {
		t.Error("want keepFinding=true for generic rule (language-agnostic)")
	}
}

func TestNormaliseTwoDistinctFindingsGetDifferentIDs(t *testing.T) {
	r1 := RawFinding{RuleID: "PY-001", Path: "a.py", Extra: RawExtra{Lines: "x", Metadata: map[string]any{"cwe": "CWE-89"}}}
	r2 := RawFinding{RuleID: "PY-001", Path: "b.py", Extra: RawExtra{Lines: "x", Metadata: map[string]any{"cwe": "CWE-89"}}}
	f1 := normalise(r1)
	f2 := normalise(r2)
	if f1.ID == f2.ID {
		t.Error("different file paths must produce different IDs")
	}
}
