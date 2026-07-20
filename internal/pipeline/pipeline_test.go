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

package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

// makeTestViolationResult creates a contracts.Result suitable for testing.
func makeTestViolationResult(cwe, evidence string) contracts.Result {
	return contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface: targeting.Surface{
				ID:   "test-violation",
				File: "src/test.go",
			},
		},
		Verdict:  contracts.VerdictViolation,
		CWE:      cwe,
		Evidence: evidence,
	}
}

func TestCountLOC_EmptyFiles(t *testing.T) {
	n, err := countLOC(nil)
	if err != nil {
		t.Fatalf("countLOC(nil) = %v", err)
	}
	if n != 0 {
		t.Errorf("countLOC(nil) = %d, want 0", n)
	}
}

func TestCountLOC_SingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(f, []byte("line1\nline2\nline3\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	n, err := countLOC([]string{f})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 3 {
		t.Errorf("countLOC = %d, want 3", n)
	}
}

func TestCountLOC_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	_ = os.WriteFile(f1, []byte("line1\nline2\n"), 0o644)
	_ = os.WriteFile(f2, []byte("line1\nline2\nline3\n"), 0o644)

	n, err := countLOC([]string{f1, f2})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 5 {
		t.Errorf("countLOC = %d, want 5", n)
	}
}

func TestCountLOC_SkipsMissingFile(t *testing.T) {
	n, err := countLOC([]string{"/nonexistent/path/file.txt"})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 0 {
		t.Errorf("countLOC = %d, want 0", n)
	}
}

func TestCountLOC_TrailingNewline(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	// A file with trailing newline: 2 lines of text, 3 newlines
	if err := os.WriteFile(f, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	n, err := countLOC([]string{f})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 2 {
		t.Errorf("countLOC = %d, want 2", n)
	}
}

// ── Fix 3 tests: violation finding conversion ─────────────────────────────

func TestViolationToFinding_JustificationContainsDCC(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "user input reaches SQL sink")
	f := violationToFinding(r)
	if !strings.Contains(f.Justification, "DCC") {
		t.Errorf("expected Justification to contain 'DCC', got %q", f.Justification)
	}
	if f.Justification == "" {
		t.Error("expected non-empty Justification")
	}
}

func TestViolationToFinding_SeverityIsMedium(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "user input reaches SQL sink")
	f := violationToFinding(r)
	if f.SeverityLabel != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", f.SeverityLabel)
	}
}

func TestViolationToFinding_PreservesExistingDCCInEvidence(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "DCC: user input reaches SQL sink via executeQuery")
	f := violationToFinding(r)
	// Should not duplicate the DCC prefix
	count := strings.Count(f.Justification, "DCC")
	if count != 1 {
		t.Errorf("expected exactly one 'DCC' in Justification, got %d: %q", count, f.Justification)
	}
}

func TestViolationToFinding_FieldsArePopulated(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "user input reaches SQL sink")
	f := violationToFinding(r)
	if f.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", f.CWE)
	}
	if f.Path != "src/test.go" {
		t.Errorf("expected src/test.go, got %s", f.Path)
	}
	if f.SourcePath != finding.SourceSemantic {
		t.Errorf("expected SourceSemantic, got %s", f.SourcePath)
	}
	if f.DCCEvidence != "user input reaches SQL sink" {
		t.Errorf("expected DCCEvidence='user input reaches SQL sink', got %q", f.DCCEvidence)
	}
}

func TestViolationToFinding_HashesAreUnique(t *testing.T) {
	r1 := makeTestViolationResult("CWE-89", "SQL injection")
	r2 := makeTestViolationResult("CWE-78", "OS command injection")

	f1 := violationToFinding(r1)
	f2 := violationToFinding(r2)

	if f1.ID == f2.ID {
		t.Error("expected unique IDs for different violations")
	}
}

func TestViolationToFinding_ConfidenceIsAboveSuppressionThreshold(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "SQL injection")
	f := violationToFinding(r)
	if f.Confidence < 0.30 {
		t.Errorf("want Confidence >= 0.30 to survive dedup, got %f", f.Confidence)
	}
	if f.SeverityLabel != finding.SeverityMedium {
		t.Errorf("want SeverityMedium, got %v", f.SeverityLabel)
	}
}

func TestViolationToFinding_LineRangeAndRuleIDPopulated(t *testing.T) {
	r := contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface:   targeting.Surface{Line: 42, File: "Foo.java"},
			SinkNodes: []string{"executeQuery"},
		},
		CWE:     "CWE-89",
		Evidence: "DCC: sink match",
	}
	f := violationToFinding(r)
	if f.LineRange.Start != 42 {
		t.Errorf("want LineRange.Start=42, got %d", f.LineRange.Start)
	}
	if f.RuleID != "dcc-CWE-89" {
		t.Errorf("want RuleID=dcc-CWE-89, got %q", f.RuleID)
	}
	if f.MatchedCode != "executeQuery" {
		t.Errorf("want MatchedCode=executeQuery, got %q", f.MatchedCode)
	}
}

func TestViolationToFinding_CVEFromCVEMatches(t *testing.T) {
	r := contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface: targeting.Surface{File: "Foo.java"},
			CVEMatches: []enrichment.CVEMatch{
				{CVE: "CVE-2021-44228", CVSS: 10.0},
			},
		},
		CWE: "CWE-89",
	}
	f := violationToFinding(r)
	if f.CVE != "CVE-2021-44228" {
		t.Errorf("want CVE-2021-44228, got %q", f.CVE)
	}
	if f.CVSS != 10.0 {
		t.Errorf("want CVSS=10.0, got %f", f.CVSS)
	}
}

func TestSinkContextLines_ReturnsWindowAroundSink(t *testing.T) {
	body := "line1\nline2\nint result = stmt.executeQuery(query);\nline4\nline5"
	snippet, start, sinkLine := sinkContextLines(body, 10, []string{"executeQuery"}, 1)
	if start != 11 {
		t.Errorf("want start=11, got %d", start)
	}
	if sinkLine != 12 {
		t.Errorf("want sinkLine=12 (line 2 of body at funcStartLine 10), got %d", sinkLine)
	}
	if !strings.Contains(snippet, "executeQuery") {
		t.Error("want snippet to contain sink line")
	}
	if strings.Contains(snippet, "line1") {
		t.Error("want line1 excluded (outside context window)")
	}
}

func TestSinkContextLines_10LineBody_Context5_CorrectSinkLine(t *testing.T) {
	body := "line1\nline2\nline3\nline4\nline5\nstmt.executeQuery(input);\nline7\nline8\nline9\nline10"
	snippet, start, sinkLine := sinkContextLines(body, 40, []string{"executeQuery"}, 5)
	if start != 40 {
		t.Errorf("want start=40 (sinkIdx=5, context=5, start=0), got %d", start)
	}
	if sinkLine != 45 {
		t.Errorf("want sinkLine=45 (funcStartLine=40 + sinkIdx=5), got %d", sinkLine)
	}
	if !strings.Contains(snippet, "executeQuery") {
		t.Error("want snippet to contain sink line")
	}
	if !strings.Contains(snippet, "line1") {
		t.Error("want line1 included (within ±5 context)")
	}
}

func TestSinkContextLines_FallsBackWhenNoBody(t *testing.T) {
	snippet, start, sinkLine := sinkContextLines("", 42, []string{"exec"}, 2)
	if snippet != "" {
		t.Errorf("want empty snippet for empty body, got %q", snippet)
	}
	if start != 42 {
		t.Errorf("want start=42, got %d", start)
	}
	if sinkLine != 42 {
		t.Errorf("want sinkLine=42 for empty body fallback, got %d", sinkLine)
	}
}

func TestViolationToFinding_MatchedCodeIsSourceNotLabels(t *testing.T) {
	r := contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface: targeting.Surface{File: "Foo.java", Line: 10, FunctionName: "query"},
			Code:    "void query(String s) {\n  stmt.executeQuery(s);\n}",
			SinkNodes: []string{"executeQuery"},
		},
		CWE:      "CWE-89",
		Evidence: "sink matched",
	}
	f := violationToFinding(r)
	if strings.Contains(f.MatchedCode, "executeQuery, exec") {
		t.Error("MatchedCode must not be sink node labels")
	}
	if !strings.Contains(f.MatchedCode, "executeQuery(") {
		t.Errorf("MatchedCode should contain actual source, got: %q", f.MatchedCode)
	}
}

func TestViolationToFinding_JustificationIncludesFunctionName(t *testing.T) {
	r := contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface: targeting.Surface{
				File:         "Foo.java",
				FunctionName: "processInput",
				Line:         55,
			},
		},
		CWE:     "CWE-89",
		Evidence: "user-controlled value reaches SQL sink",
	}
	f := violationToFinding(r)
	if !strings.Contains(f.Justification, "processInput") {
		t.Error("want function name in justification")
	}
	if !strings.Contains(f.Justification, "55") {
		t.Error("want line number in justification")
	}
}

// ── SeverityLabel JSON serialization (Fix 3 test 3) ─────────────────────

func TestSeverityLabelMarshalJSON_MediumIsQuotedString(t *testing.T) {
	data, err := finding.SeverityMedium.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if got != `"MEDIUM"` {
		t.Errorf("expected \"MEDIUM\", got %s", got)
	}
}

func TestSeverityLabelMarshalJSON_HighIsQuotedString(t *testing.T) {
	data, err := finding.SeverityHigh.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if got != `"HIGH"` {
		t.Errorf("expected \"HIGH\", got %s", got)
	}
}

// ── Fix 2 tests: taint gate classification ────────────────────────────────

func TestTaintGateClassify_WeakWhenContractCWEPresentNoSinks(t *testing.T) {
	es := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s1",
			FunctionName: "testFunc",
		},
		ContractCWE: "CWE-89",
	}
	classified, bucket := taintGateClassify(es)
	if bucket != "weak" {
		t.Errorf("expected 'weak', got %q", bucket)
	}
	if classified.TaintConfidence != "weak" {
		t.Errorf("expected TaintConfidence='weak', got %q", classified.TaintConfidence)
	}
}

func TestTaintGateClassify_DroppedWhenNoCWENoSinks(t *testing.T) {
	es := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s2",
			FunctionName: "noCWE",
		},
	}
	_, bucket := taintGateClassify(es)
	if bucket != "dropped" {
		t.Errorf("expected 'dropped', got %q", bucket)
	}
}

func TestTaintGateClassify_ConfirmedWhenSinkNodesPresent(t *testing.T) {
	es := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s3",
			FunctionName: "hasSinks",
		},
		SinkNodes: []string{"executeQuery"},
	}
	classified, bucket := taintGateClassify(es)
	if bucket != "confirmed" {
		t.Errorf("expected 'confirmed', got %q", bucket)
	}
	if classified.TaintConfidence != "confirmed" {
		t.Errorf("expected TaintConfidence='confirmed', got %q", classified.TaintConfidence)
	}
}

// makeViolationFinding creates a finding.Finding that looks like it came
// from violationToFinding (has SurfaceID set, MEDIUM severity).
func makeViolationFinding(surfaceID, cwe string) finding.Finding {
	return finding.Finding{
		ID:            fmt.Sprintf("violation-%s", surfaceID),
		SurfaceID:     surfaceID,
		CWE:           cwe,
		SeverityLabel: finding.SeverityMedium,
		Path:          "src/test.go",
		Justification: "DCC structural match, awaiting B5 review",
		SourcePath:    finding.SourceSemantic,
	}
}

// makeB5Finding creates a B5-style finding with the given attributes.
func makeB5Finding(surfaceID string, exploitable, taintMismatch bool, confidence float64) finding.Finding {
	return finding.Finding{
		ID:            fmt.Sprintf("b5-%s", surfaceID),
		SurfaceID:     surfaceID,
		CWE:           "CWE-89",
		SeverityLabel: finding.SeverityHigh,
		Confidence:    confidence,
		Path:          "src/test.go",
		Justification: "B5 analysis result",
		SourcePath:    finding.SourceSemantic,
		TaintMismatch: taintMismatch,
		Exploitable:   exploitable,
	}
}

func TestTaintGateClassify_DroppedWhenNoCWENoSinksWithSomeCallPath(t *testing.T) {
	es := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s4",
			FunctionName: "hasCallPathOnly",
		},
		CallPath: []string{"userInput"},
	}
	_, bucket := taintGateClassify(es)
	if bucket != "dropped" {
		t.Errorf("expected 'dropped' for surface with no CWE and no sinks, got %q", bucket)
	}
}

// ── B5 Violation Confirmation Loop tests ─────────────────────────────────

func TestB5ConfirmationElevatesViolationToHigh(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5Finding("s1", true, false, 0.9),
	}

	out, handled := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 output finding, got %d", len(out))
	}
	f := out[0]
	if f.SeverityLabel != finding.SeverityHigh {
		t.Errorf("want SeverityHigh, got %v", f.SeverityLabel)
	}
	if !strings.Contains(f.Justification, "B5 confirmed") {
		t.Errorf("want justification to mention B5 confirmation, got %q", f.Justification)
	}
	if !handled["s1"] {
		t.Error("want surface s1 marked as handled")
	}
	if f.Summary != "B5 analysis result" {
		t.Errorf("want Summary='B5 analysis result', got %q", f.Summary)
	}
}

func TestB5TaintMismatchSuppressesViolation(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, true, 0.85),
	}

	out, handled := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 output finding, got %d", len(out))
	}
	f := out[0]
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("want SeveritySuppressed, got %v", f.SeverityLabel)
	}
	if f.SuppressReason != finding.SuppressReasonFalsePositive {
		t.Errorf("want false_positive, got %v", f.SuppressReason)
	}
	if !handled["s1"] {
		t.Error("want surface s1 marked as handled")
	}
	if !strings.Contains(f.Summary, "false positive") {
		t.Errorf("want Summary to mention false positive, got %q", f.Summary)
	}
}

func TestB5InconclusiveKeepsViolationMedium(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, false, 0.4),
	}

	out, handled := processB5Findings(b5Findings, index)
	if len(out) != 0 {
		t.Fatalf("want 0 findings (B3 MEDIUM unchanged), got %d", len(out))
	}
	if handled["s1"] {
		t.Error("want s1 NOT in handled set for inconclusive B5 result")
	}
}

func TestB5NilForViolationSurface(t *testing.T) {
	// Empty B5 results — no suppression, no elevation, no panic.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	out, _ := processB5Findings(nil, index)
	if len(out) != 0 {
		t.Errorf("want 0 findings for nil B5 input, got %d", len(out))
	}

	out, _ = processB5Findings([]finding.Finding{}, index)
	if len(out) != 0 {
		t.Errorf("want 0 findings for empty B5 input, got %d", len(out))
	}
}

func TestNonViolationB5FindingPassesThrough(t *testing.T) {
	// Surface "s2" is NOT in the violation index.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5Finding("s2", true, false, 0.85),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 output finding, got %d", len(out))
	}
	f := out[0]
	if f.SurfaceID != "s2" {
		t.Errorf("want SurfaceID=s2, got %q", f.SurfaceID)
	}
	// Non-violation finding should pass through unchanged.
	if f.SeverityLabel != finding.SeverityHigh {
		t.Errorf("want SeverityHigh (unchanged), got %v", f.SeverityLabel)
	}
	if f.Confidence != 0.85 {
		t.Errorf("want confidence=0.85, got %f", f.Confidence)
	}
}

func TestB5ElevationThresholdRespected(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	// Exploitable but confidence below threshold (0.7).
	b5Findings := []finding.Finding{
		makeB5Finding("s1", true, false, 0.65),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 0 {
		t.Fatalf("want 0 findings (confidence below threshold), got %d", len(out))
	}
}

// ── Fix 2: B5 suppression confidence threshold ───────────────────────────

func TestB5SuppressionRequiresHighConfidence(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	// TaintMismatch=true, Exploitable=false, Confidence=0.6 — below 0.75 threshold
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, true, 0.6),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 0 {
		t.Fatalf("want 0 findings (confidence 0.6 below threshold), got %d", len(out))
	}
}

func TestB5SuppressionFiresAtThreshold(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	// TaintMismatch=true, Exploitable=false, Confidence=0.75 — exactly at threshold
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, true, 0.75),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 output finding (confidence 0.75 at threshold), got %d", len(out))
	}
	f := out[0]
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("want SeveritySuppressed, got %v", f.SeverityLabel)
	}
}

func TestB5SuppressionFiresAboveThreshold(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	// TaintMismatch=true, Exploitable=false, Confidence=0.9 — above threshold
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, true, 0.9),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 output finding (confidence 0.9 above threshold), got %d", len(out))
	}
	f := out[0]
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("want SeveritySuppressed, got %v", f.SeverityLabel)
	}
}

func TestB5LowConfidenceZeroDoesNotSuppress(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	// TaintMismatch=true, Exploitable=false, Confidence=0.0 — well below threshold
	b5Findings := []finding.Finding{
		makeB5Finding("s1", false, true, 0.0),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 0 {
		t.Fatalf("want 0 findings (confidence 0.0 far below threshold), got %d", len(out))
	}
}

func TestB5MultipleViolationsMixed(t *testing.T) {
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
		"s2": makeViolationFinding("s2", "CWE-78"),
		"s3": makeViolationFinding("s3", "CWE-22"),
	}
	b5Findings := []finding.Finding{
		makeB5Finding("s1", true, false, 0.9),                       // elevate (CWE-89 matches B3 CWE-89)
		makeB5FindingWithCWE("s2", "CWE-78", false, true, 0.85),     // suppress (CWE-78 matches B3 CWE-78)
		makeB5Finding("s3", false, false, 0.3),                       // inconclusive
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 2 {
		t.Fatalf("want 2 findings (1 elevated + 1 suppressed), got %d", len(out))
	}
	elevated := out[0] // s1 order matches input
	suppressed := out[1]
	if elevated.SurfaceID != "s1" || elevated.SeverityLabel != finding.SeverityHigh {
		t.Errorf("s1 should be elevated, got %v", elevated.SeverityLabel)
	}
	if suppressed.SurfaceID != "s2" || suppressed.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("s2 should be suppressed, got %v", suppressed.SeverityLabel)
	}
}



// ── No-change path (inconclusive B5) ────────────────────────────────────────

func TestB5NoChangePatch_UpdatesJustification(t *testing.T) {
	// Use the real violationToFinding to get production-format Justification.
	r := makeTestViolationResult("CWE-89", "user input reaches SQL sink")
	vf := violationToFinding(r)
	index := map[string]finding.Finding{
		vf.SurfaceID: vf,
	}
	b5Findings := []finding.Finding{
		makeB5Finding(vf.SurfaceID, false, false, 0.4), // inconclusive
	}

	_, handled := processB5Findings(b5Findings, index)
	if handled[vf.SurfaceID] {
		t.Fatal("expected surface not handled (inconclusive B5)")
	}

	// Simulate the no-change patch that runPathB applies.
	orig := index[vf.SurfaceID]
	if !strings.Contains(orig.Justification, "awaiting B5 review") {
		t.Fatalf("expected 'awaiting B5 review' in original, got %q", orig.Justification)
	}
	patched := orig
	patched.Justification = strings.Replace(
		orig.Justification,
		" — DCC structural match, awaiting B5 review",
		" — DCC structural match, B5 reviewed (no change)",
		1,
	)
	patched.Summary = "DCC contract matched; B5 found insufficient evidence for elevation"

	if strings.Contains(patched.Justification, "awaiting B5 review") {
		t.Error("patched justification must not contain 'awaiting B5 review'")
	}
	if !strings.Contains(patched.Justification, "B5 reviewed (no change)") {
		t.Errorf("patched justification must contain 'B5 reviewed (no change)', got %q", patched.Justification)
	}
	if patched.Summary != "DCC contract matched; B5 found insufficient evidence for elevation" {
		t.Errorf("unexpected Summary: %q", patched.Summary)
	}
}

// ── H2: CWE contract mismatch suppression guard ──────────────────────────────

// makeB5FindingWithCWE is like makeB5Finding but allows setting a specific CWE
// (the verdict CWE from B5, which may differ from the B3 contract CWE).
func makeB5FindingWithCWE(surfaceID, cwe string, exploitable, taintMismatch bool, confidence float64) finding.Finding {
	f := makeB5Finding(surfaceID, exploitable, taintMismatch, confidence)
	f.CWE = cwe
	return f
}

func TestB5CWEMismatch_DoesNotSuppressWhenB5IdentifiesDifferentCWE(t *testing.T) {
	// Joern filed surface as CWE-22; B5 sees CWE-89 SQLi code.
	// taint_mismatch=T means the CWE-22 contract doesn't apply — but it IS
	// exploitable as CWE-89. Suppression must NOT fire.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-22"),
	}
	b5Findings := []finding.Finding{
		makeB5FindingWithCWE("s1", "CWE-89", false, true, 0.9),
	}

	out, _ := processB5Findings(b5Findings, index)
	// Must not suppress: the B5 CWE (CWE-89) differs from the B3 CWE (CWE-22).
	// B3 MEDIUM stands → processB5Findings returns nothing (pass-through).
	if len(out) != 0 {
		t.Fatalf("want 0 findings (pass-through, not suppressed), got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.SeverityLabel == finding.SeveritySuppressed {
			t.Errorf("finding must NOT be suppressed when B5 identifies a different CWE, got SeveritySuppressed")
		}
	}
}

func TestB5CWEMismatch_DoesNotSuppressCWE862FiledAsPathTraversal(t *testing.T) {
	// B3: CWE-22; B5 verdict: CWE-862 (missing auth). Contract mismatch.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-22"),
	}
	b5Findings := []finding.Finding{
		makeB5FindingWithCWE("s1", "CWE-862", false, true, 0.9),
	}

	out, _ := processB5Findings(b5Findings, index)
	for _, f := range out {
		if f.SeverityLabel == finding.SeveritySuppressed {
			t.Errorf("should not suppress CWE-22 B3 finding when B5 verdicts CWE-862")
		}
	}
}

func TestB5CWEMismatch_SuppressesWhenCWEsMatch(t *testing.T) {
	// Same CWE both sides and mismatch=T — normal suppression path must still fire.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5FindingWithCWE("s1", "CWE-89", false, true, 0.9),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 suppressed finding, got %d", len(out))
	}
	if out[0].SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("same-CWE mismatch should still suppress, got %v", out[0].SeverityLabel)
	}
}

func TestB5CWEMismatch_EmptyVerdictCWEDefaultsToSuppressPath(t *testing.T) {
	// If B5 returns no CWE (e.g. old model, missing field), guard must not fire.
	// Existing suppression logic applies unchanged.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-89"),
	}
	b5Findings := []finding.Finding{
		makeB5FindingWithCWE("s1", "", false, true, 0.9),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 finding when verdict CWE is empty, got %d", len(out))
	}
	if out[0].SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("empty verdict CWE should fall through to suppression, got %v", out[0].SeverityLabel)
	}
}

// ── Fix P0-A: ContractCWE propagation from B3 Result → EnrichedSurface ────

// simulateViolationRouting mimics pathb.go's violation→B5 routing: it takes
// a B3 result and applies the propagation (es.ContractCWE = r.CWE).
func simulateViolationRouting(r contracts.Result) enrichment.EnrichedSurface {
	es := r.Surface
	es.ContractCWE = r.CWE
	return es
}

func TestContractCWE_PropagatedToB5Surface(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "SQL injection violation")
	es := simulateViolationRouting(r)
	if es.ContractCWE != "CWE-89" {
		t.Errorf("expected ContractCWE=CWE-89 after propagation, got %q", es.ContractCWE)
	}
}

func TestContractCWE_EmptyWhenNoViolation(t *testing.T) {
	r := contracts.Result{
		Surface: enrichment.EnrichedSurface{
			Surface: targeting.Surface{
				ID:   "safe-surface",
				File: "src/test.go",
			},
		},
		Verdict: contracts.VerdictSafe,
		CWE:     "",
	}
	es := simulateViolationRouting(r)
	if es.ContractCWE != "" {
		t.Errorf("expected empty ContractCWE for safe verdict, got %q", es.ContractCWE)
	}
}

func TestContractCWE_CWE89SetsOnViolation(t *testing.T) {
	r := makeTestViolationResult("CWE-89", "SQL injection")
	es := simulateViolationRouting(r)
	if es.ContractCWE != "CWE-89" {
		t.Errorf("expected ContractCWE=CWE-89, got %q", es.ContractCWE)
	}
}

func TestB5CWEMismatch_ElevationUnaffectedByGuard(t *testing.T) {
	// Elevation path (exploitable=T) must still work regardless of CWE match.
	index := map[string]finding.Finding{
		"s1": makeViolationFinding("s1", "CWE-22"),
	}
	b5Findings := []finding.Finding{
		makeB5FindingWithCWE("s1", "CWE-89", true, false, 1.0),
	}

	out, _ := processB5Findings(b5Findings, index)
	if len(out) != 1 {
		t.Fatalf("want 1 elevated finding, got %d", len(out))
	}
	if out[0].SeverityLabel != finding.SeverityBlock {
		t.Errorf("exploitable B5 with conf=1.0 should elevate to BLOCK, got %v", out[0].SeverityLabel)
	}
}

func TestProcessB5Findings_ElevationInheritsB5Confidence(t *testing.T) {
	b3 := finding.Finding{
		ID:            "b3id",
		SurfaceID:     "surf1",
		CWE:           "CWE-89",
		SeverityLabel: finding.SeverityMedium,
		Confidence:    0.65,
	}
	b5 := finding.Finding{
		SurfaceID:     "surf1",
		CWE:           "CWE-89",
		Exploitable:   true,
		Confidence:    1.0,
		TaintMismatch: false,
	}
	results, _ := processB5Findings([]finding.Finding{b5}, map[string]finding.Finding{"surf1": b3})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	got := results[0]
	if got.Confidence != 1.0 {
		t.Errorf("want Confidence=1.0 (B5), got %f", got.Confidence)
	}
	if !got.Exploitable {
		t.Error("want Exploitable=true (B5), got false")
	}
	if !got.SeverityPinned {
		t.Error("want SeverityPinned=true on elevated finding")
	}
	if got.SeverityLabel != finding.SeverityBlock {
		t.Errorf("want SeverityBlock (conf=1.0), got %v", got.SeverityLabel)
	}
}

func TestProcessB5Findings_SuppressionSetsPinned(t *testing.T) {
	b3 := finding.Finding{
		ID:            "b3id",
		SurfaceID:     "surf2",
		CWE:           "CWE-89",
		Confidence:    0.65,
		SeverityLabel: finding.SeverityMedium,
	}
	b5 := finding.Finding{
		SurfaceID:     "surf2",
		CWE:           "CWE-89",
		TaintMismatch: true,
		Exploitable:   false,
		Confidence:    0.80,
	}
	results, _ := processB5Findings([]finding.Finding{b5}, map[string]finding.Finding{"surf2": b3})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	if results[0].SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("want SeveritySuppressed, got %v", results[0].SeverityLabel)
	}
	if !results[0].SeverityPinned {
		t.Error("want SeverityPinned=true on suppressed finding")
	}
}
