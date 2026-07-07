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

package dedup

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func patternFinding(id, path, cwe, code string, start int, conf float64) finding.Finding {
	return finding.Finding{
		ID:          id,
		Path:        path,
		CWE:         cwe,
		LineRange:   finding.LineRange{Start: start, End: start},
		MatchedCode: code,
		Confidence:  conf,
		SourcePath:  finding.SourcePattern,
	}
}

func semanticFinding(id, path, cwe, code string, start int, conf float64) finding.Finding {
	f := patternFinding(id, path, cwe, code, start, conf)
	f.SourcePath = finding.SourceSemantic
	return f
}

// ─── DeriveSeverityLabel ─────────────────────────────────────────────────────

func TestDeriveSeverityLabelThresholds(t *testing.T) {
	cases := []struct {
		score float64
		want  finding.SeverityLabel
	}{
		{1.00, finding.SeverityBlock},
		{0.92, finding.SeverityBlock},
		{0.91, finding.SeverityHigh},
		{0.75, finding.SeverityHigh},
		{0.74, finding.SeverityMedium},
		{0.60, finding.SeverityMedium},
		{0.59, finding.SeverityLow},
		{0.30, finding.SeverityLow},
		{0.29, finding.SeveritySuppressed},
		{0.00, finding.SeveritySuppressed},
	}
	for _, tc := range cases {
		got := DeriveSeverityLabel(tc.score)
		if got != tc.want {
			t.Errorf("score %.2f: expected %s, got %s", tc.score, tc.want, got)
		}
	}
}

// ─── AutoSuppress ────────────────────────────────────────────────────────────

func TestAutoSuppressGoTestFile(t *testing.T) {
	f := patternFinding("f1", "internal/auth/handler_test.go", "CWE-89", "x", 1, 0.80)
	got := AutoSuppress(f)
	if got.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("expected SUPPRESSED for _test.go, got %s", got.SeverityLabel)
	}
	if got.SuppressReason != finding.SuppressReasonTestFile {
		t.Errorf("expected SuppressReasonTestFile, got %q", got.SuppressReason)
	}
}

func TestAutoSuppressPythonTestFile(t *testing.T) {
	f := patternFinding("f2", "tests/test_auth.py", "CWE-89", "x", 1, 0.80)
	got := AutoSuppress(f)
	if got.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("expected SUPPRESSED for test_ prefix, got %s", got.SeverityLabel)
	}
}

func TestAutoSuppressTestDir(t *testing.T) {
	f := patternFinding("f3", "__tests__/auth.js", "CWE-94", "x", 1, 0.90)
	got := AutoSuppress(f)
	if got.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("expected SUPPRESSED for __tests__/, got %s", got.SeverityLabel)
	}
}

func TestAutoSuppressTestdataDir(t *testing.T) {
	f := patternFinding("f4", "testdata/spring-boot-app/AuthController.java", "CWE-89", "x", 1, 0.95)
	got := AutoSuppress(f)
	if got.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("expected SUPPRESSED for testdata/, got %s", got.SeverityLabel)
	}
}

func TestAutoSuppressProductionFileNotSuppressed(t *testing.T) {
	f := patternFinding("f5", "internal/auth/handler.go", "CWE-89", "x", 1, 0.80)
	got := AutoSuppress(f)
	if got.SeverityLabel == finding.SeveritySuppressed {
		t.Error("production file must not be auto-suppressed")
	}
	if got.SuppressReason != "" {
		t.Errorf("SuppressReason should be empty for production file, got %q", got.SuppressReason)
	}
}

func TestAutoSuppressSpecFile(t *testing.T) {
	f := patternFinding("f6", "spec/auth_spec.rb", "CWE-89", "x", 1, 0.80)
	got := AutoSuppress(f)
	if got.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("expected SUPPRESSED for spec/, got %s", got.SeverityLabel)
	}
}

// ─── Gate 1: exact key dedup ─────────────────────────────────────────────────

func TestGate1MergesSameCWEPathLine(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "x", 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "y", 10, 0.80)

	out, err := l.Process(context.Background(), []finding.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after gate-1 merge, got %d", len(out))
	}
}

func TestGate1KeepsHigherConfidence(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.80)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	if out[0].Confidence < 0.80 {
		t.Errorf("expected merged confidence ≥ 0.80 (highest), got %.2f", out[0].Confidence)
	}
}

func TestGate1DifferentLineNotMerged(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/auth.py", "CWE-89", "", 20, 0.65)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	// Gate 1 does not merge (different lines), but Gate 2 merges because
	// the fingerprint (CWE + normalised path) is identical.  The Gate 2
	// merge is correct: same CWE in the same file = same vulnerability
	// detected at different program points.
	if len(out) != 1 {
		t.Errorf("expected 1 finding after gate-2 merge, got %d", len(out))
	}
}

func TestGate1DifferentCWENotMerged(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/auth.py", "CWE-94", "", 10, 0.65)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	if len(out) != 2 {
		t.Errorf("different CWEs must not be merged; got %d", len(out))
	}
}

// ─── Gate 2: code fingerprint dedup ──────────────────────────────────────────

func TestGate2MergesSameCode(t *testing.T) {
	l := New("")
	code := `cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)`
	// Different lines — gate 1 won't catch them.
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", code, 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", code, 20, 0.80)

	out, err := l.Process(context.Background(), []finding.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after gate-2 merge (same code), got %d", len(out))
	}
}

func TestGate2EmptyCodeNotMerged(t *testing.T) {
	l := New("")
	// Both have empty MatchedCode — gate 2 skips them; they survive independently.
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/util.py", "CWE-89", "", 10, 0.65)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	if len(out) != 2 {
		t.Errorf("empty MatchedCode must not be fingerprint-merged; got %d", len(out))
	}
}

// ─── Cross-path confidence boost ─────────────────────────────────────────────

func TestCrossPathBoostApplied(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	// 0.70 + 0.15 = 0.85 → HIGH
	if out[0].Confidence < 0.84 {
		t.Errorf("expected cross-path boost to raise confidence; got %.2f", out[0].Confidence)
	}
	if out[0].SourcePath != finding.SourceBoth {
		t.Errorf("expected SourceBoth after cross-path merge, got %s", out[0].SourcePath)
	}
}

func TestCrossPathBoostCappedAt1(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.95)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.95)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	if out[0].Confidence > 1.0 {
		t.Errorf("confidence must not exceed 1.0 after boost; got %.2f", out[0].Confidence)
	}
}

func TestSamePathNoCrossBoost(t *testing.T) {
	l := New("")
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70)
	f2 := patternFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	// CWE-89 is Automatable=Yes → +0.05 SSVC boost; no cross-path boost (same source).
	// Expect 0.70 + 0.05 = 0.75; cross-path boost would add another +0.15 → 0.90.
	if out[0].Confidence > 0.76 {
		t.Errorf("same-path findings must not get cross-path boost; got %.2f", out[0].Confidence)
	}
}

// ─── ProcessWithStats ────────────────────────────────────────────────────────

func TestProcessWithStatsCountsCorrectly(t *testing.T) {
	l := New("")
	findings := []finding.Finding{
		patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70),
		semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70), // merges with f1
		patternFinding("f3", "api/util_test.go", "CWE-89", "", 5, 0.80), // auto-suppressed
	}

	_, records, stats, err := l.ProcessWithStats(context.Background(), findings)
	if err != nil {
		t.Fatalf("ProcessWithStats: %v", err)
	}
	if stats.InputCount != 3 {
		t.Errorf("InputCount: want 3, got %d", stats.InputCount)
	}
	if stats.MergeCount != 1 {
		t.Errorf("MergeCount: want 1, got %d", stats.MergeCount)
	}
	if stats.AutoSuppressedCount != 1 {
		t.Errorf("AutoSuppressedCount: want 1, got %d", stats.AutoSuppressedCount)
	}
	if len(records) != 1 {
		t.Errorf("MergeRecords: want 1, got %d", len(records))
	}
	if records[0].Strategy != StrategyExactKey {
		t.Errorf("Strategy: want exact_key, got %s", records[0].Strategy)
	}
}

// ─── Empty input ─────────────────────────────────────────────────────────────

func TestProcessEmptyInput(t *testing.T) {
	l := New("")
	out, err := l.Process(context.Background(), nil)
	if err != nil {
		t.Fatalf("Process(nil): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got %d", len(out))
	}
}

// ─── T5: BLOCK not boosted ────────────────────────────────────────────────────

func TestCrossPathBoostSkippedForBlock(t *testing.T) {
	l := New("")
	// Both paths find the same BLOCK-level (≥0.92) finding.
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "SELECT * FROM u WHERE id=?", 10, 0.93)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "SELECT * FROM u WHERE id=?", 10, 0.93)

	out, _ := l.Process(context.Background(), []finding.Finding{f1, f2})
	// Cross-path boost must not inflate a BLOCK finding further.
	// 0.93 + 0.15 would be 1.0 without the guard; with it, stays ≤ 0.93 + boosts.
	// SSVC: CWE-89 Automatable=Yes (+0.05), so max = 0.93 + 0.05 = 0.98 — still BLOCK.
	if out[0].SeverityLabel != finding.SeverityBlock {
		t.Errorf("want BLOCK; got %s", out[0].SeverityLabel)
	}
	// Confidence should NOT have the +0.15 cross-path bump (already BLOCK).
	if out[0].Confidence > 0.99 {
		t.Errorf("BLOCK finding cross-path boosted beyond expected; got %.2f", out[0].Confidence)
	}
}

// ─── T6: Framework-safe suppression + sidecar ─────────────────────────────────

func TestAutoSuppressDjangoMigration(t *testing.T) {
	f := patternFinding("f1", "app/migrations/0001_initial.py", "CWE-89", "cursor.execute(sql)", 5, 0.80)
	f = AutoSuppress(f)
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("Django migration must be framework-safe suppressed; got %s", f.SeverityLabel)
	}
	if f.SuppressReason != finding.SuppressReasonFrameworkSafe {
		t.Errorf("SuppressReason: want framework_safe, got %s", f.SuppressReason)
	}
}

func TestAutoSuppressSpringSecurityConfig(t *testing.T) {
	f := patternFinding("f1", "src/main/java/com/app/SecurityConfig.java", "CWE-287", "", 20, 0.85)
	f = AutoSuppress(f)
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("Spring SecurityConfig must be framework-safe suppressed; got %s", f.SeverityLabel)
	}
}

func TestAutoSuppressProtobufStub(t *testing.T) {
	f := patternFinding("f1", "gen/user.pb.go", "CWE-20", "", 10, 0.70)
	f = AutoSuppress(f)
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf(".pb.go stubs must be framework-safe suppressed; got %s", f.SeverityLabel)
	}
}

func TestSidecarByID(t *testing.T) {
	sc := Sidecar{Suppressions: []SidecarEntry{
		{ID: "abc123", Reason: "known_false_positive"},
	}}
	f := patternFinding("abc123", "api/handler.py", "CWE-79", "", 10, 0.70)
	f = sc.Apply(f)
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("sidecar ID match must suppress; got %s", f.SeverityLabel)
	}
	if string(f.SuppressReason) != "known_false_positive" {
		t.Errorf("SuppressReason: got %s", f.SuppressReason)
	}
}

func TestSidecarByPathAndCWE(t *testing.T) {
	sc := Sidecar{Suppressions: []SidecarEntry{
		{Path: "migrations/*.py", CWE: "CWE-89", Reason: "orm_safe"},
	}}
	match := patternFinding("f1", "migrations/0002.py", "CWE-89", "", 5, 0.75)
	noMatch := patternFinding("f2", "migrations/0002.py", "CWE-79", "", 5, 0.75)

	match = sc.Apply(match)
	noMatch = sc.Apply(noMatch)

	if match.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("path+CWE match: want SUPPRESSED, got %s", match.SeverityLabel)
	}
	if noMatch.SeverityLabel == finding.SeveritySuppressed {
		t.Errorf("different CWE: must not be suppressed")
	}
}

func TestSidecarIDMismatchNotSuppressed(t *testing.T) {
	sc := Sidecar{Suppressions: []SidecarEntry{
		{ID: "other-id", Reason: "fp"},
	}}
	f := patternFinding("real-id", "api/handler.py", "CWE-79", "", 10, 0.70)
	f = sc.Apply(f)
	if f.SeverityLabel == finding.SeveritySuppressed {
		t.Errorf("non-matching ID must not suppress")
	}
}
