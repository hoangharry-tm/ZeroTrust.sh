// Copyright 2026 hoangharry-tm
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

package astgrep

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// ─── FilterFiles ─────────────────────────────────────────────────────────────

func TestFilterFilesKeepsRust(t *testing.T) {
	in := []string{"src/main.rs", "main.go", "api/auth.py"}
	got := FilterFiles(in)
	if len(got) != 1 || got[0] != "src/main.rs" {
		t.Errorf("expected [src/main.rs], got %v", got)
	}
}

func TestFilterFilesKeepsDartSwiftKotlinCSharp(t *testing.T) {
	in := []string{"lib/widget.dart", "ios/Auth.swift", "android/Main.kt", "service/App.cs"}
	got := FilterFiles(in)
	if len(got) != 4 {
		t.Errorf("expected 4 files, got %v", got)
	}
}

func TestFilterFilesExcludesOpenGrepLanguages(t *testing.T) {
	in := []string{"api.py", "Main.java", "index.js", "handler.go", "app.rb", "controller.php"}
	got := FilterFiles(in)
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestFilterFilesEmpty(t *testing.T) {
	got := FilterFiles(nil)
	if len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %v", got)
	}
}

func TestFilterFilesCaseInsensitiveExt(t *testing.T) {
	in := []string{"main.RS", "lib.Dart"}
	got := FilterFiles(in)
	if len(got) != 2 {
		t.Errorf("expected 2 files (case-insensitive ext), got %v", got)
	}
}

// ─── astgrepOwns ─────────────────────────────────────────────────────────────

func TestAstgrepOwnsKnownExtensions(t *testing.T) {
	for _, ext := range []string{".rs", ".dart", ".swift", ".kt", ".kts", ".cs"} {
		if !astgrepOwns(ext) {
			t.Errorf("expected %q to be owned by ast-grep", ext)
		}
	}
}

func TestAstgrepDoesNotOwnOpenGrepExtensions(t *testing.T) {
	for _, ext := range []string{".py", ".java", ".js", ".ts", ".go", ".rb", ".php"} {
		if astgrepOwns(ext) {
			t.Errorf("expected %q to NOT be owned by ast-grep", ext)
		}
	}
}

// ─── confidenceFromSeverity ───────────────────────────────────────────────────

func TestConfidenceFromSeverityError(t *testing.T) {
	got := confidenceFromSeverity("error")
	if got != 0.90 {
		t.Errorf("expected 0.90, got %v", got)
	}
}

func TestConfidenceFromSeverityWarning(t *testing.T) {
	got := confidenceFromSeverity("warning")
	if got != 0.65 {
		t.Errorf("expected 0.65, got %v", got)
	}
}

func TestConfidenceFromSeverityInfo(t *testing.T) {
	got := confidenceFromSeverity("info")
	if got != 0.40 {
		t.Errorf("expected 0.40, got %v", got)
	}
}

func TestConfidenceFromSeverityCaseInsensitive(t *testing.T) {
	if confidenceFromSeverity("ERROR") != 0.90 {
		t.Error("severity matching must be case-insensitive")
	}
}

// ─── cweFromRuleID ───────────────────────────────────────────────────────────

func TestCWEFromRuleIDPresent(t *testing.T) {
	got := cweFromRuleID("AG-001-cwe-78-rust-command-injection")
	if got != "CWE-78" {
		t.Errorf("expected CWE-78, got %q", got)
	}
}

func TestCWEFromRuleIDMissing(t *testing.T) {
	got := cweFromRuleID("AG-005-rust-path-traversal")
	if got != "" {
		t.Errorf("expected empty string when no cwe segment, got %q", got)
	}
}

func TestCWEFromRuleIDCaseInsensitive(t *testing.T) {
	got := cweFromRuleID("AG-003-CWE-94-dart-eval")
	if got != "CWE-94" {
		t.Errorf("expected CWE-94, got %q", got)
	}
}

// ─── normalise ───────────────────────────────────────────────────────────────

func TestNormaliseLineNumbersConverted(t *testing.T) {
	raw := RawMatch{
		RuleID:   "AG-001-cwe-78-rust-cmd",
		File:     "src/main.rs",
		Severity: "error",
		Message:  "command injection via user input",
		Range: RawRange{
			Start: RawPos{Line: 9, Column: 0},  // 0-based → should be 10
			End:   RawPos{Line: 11, Column: 5}, // 0-based → should be 12
		},
	}

	f := normalise(raw)

	if f.LineRange.Start != 10 {
		t.Errorf("Start line: expected 10 (0→1 based), got %d", f.LineRange.Start)
	}
	if f.LineRange.End != 12 {
		t.Errorf("End line: expected 12 (0→1 based), got %d", f.LineRange.End)
	}
}

func TestNormalisePopulatesAllFields(t *testing.T) {
	raw := RawMatch{
		RuleID:   "AG-002-cwe-89-dart-sqli",
		File:     "lib/db.dart",
		Severity: "error",
		Message:  "SQL injection",
		Range:    RawRange{Start: RawPos{Line: 4}, End: RawPos{Line: 4}},
		Labels:   map[string]string{"__match__": "db.query(input)"},
	}

	f := normalise(raw)

	if f.CWE != "CWE-89" {
		t.Errorf("CWE: got %q", f.CWE)
	}
	if f.SourcePath != finding.SourcePattern {
		t.Errorf("SourcePath: got %s", f.SourcePath)
	}
	if f.RuleID != "AG-002-cwe-89-dart-sqli" {
		t.Errorf("RuleID: got %q", f.RuleID)
	}
	if f.MatchedCode != "db.query(input)" {
		t.Errorf("MatchedCode: got %q", f.MatchedCode)
	}
	if f.ID == "" {
		t.Error("ID must not be empty")
	}
}

// ─── severityFromScore ───────────────────────────────────────────────────────

func TestSeverityFromScoreThresholds(t *testing.T) {
	cases := []struct {
		score float64
		want  finding.SeverityLabel
	}{
		{0.95, finding.SeverityBlock},
		{0.92, finding.SeverityBlock},
		{0.91, finding.SeverityHigh},
		{0.75, finding.SeverityHigh},
		{0.74, finding.SeverityMedium},
		{0.60, finding.SeverityMedium},
		{0.59, finding.SeverityLow},
		{0.30, finding.SeverityLow},
		{0.29, finding.SeveritySuppressed},
	}
	for _, tc := range cases {
		got := severityFromScore(tc.score)
		if got != tc.want {
			t.Errorf("score %.2f: expected %s, got %s", tc.score, tc.want, got)
		}
	}
}
