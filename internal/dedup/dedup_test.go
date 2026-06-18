package dedup

import (
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
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "x", 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "y", 10, 0.80)

	out, err := l.Process([]finding.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after gate-1 merge, got %d", len(out))
	}
}

func TestGate1KeepsHigherConfidence(t *testing.T) {
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.80)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if out[0].Confidence < 0.80 {
		t.Errorf("expected merged confidence ≥ 0.80 (highest), got %.2f", out[0].Confidence)
	}
}

func TestGate1DifferentLineNotMerged(t *testing.T) {
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/auth.py", "CWE-89", "", 20, 0.65)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if len(out) != 2 {
		t.Errorf("different lines must not be merged; got %d", len(out))
	}
}

func TestGate1DifferentCWENotMerged(t *testing.T) {
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/auth.py", "CWE-94", "", 10, 0.65)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if len(out) != 2 {
		t.Errorf("different CWEs must not be merged; got %d", len(out))
	}
}

// ─── Gate 2: code fingerprint dedup ──────────────────────────────────────────

func TestGate2MergesSameCode(t *testing.T) {
	l := New()
	code := `cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)`
	// Different lines — gate 1 won't catch them.
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", code, 10, 0.65)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", code, 20, 0.80)

	out, err := l.Process([]finding.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after gate-2 merge (same code), got %d", len(out))
	}
}

func TestGate2EmptyCodeNotMerged(t *testing.T) {
	l := New()
	// Both have empty MatchedCode — gate 2 skips them; they survive independently.
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.65)
	f2 := patternFinding("f2", "api/util.py", "CWE-89", "", 10, 0.65)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if len(out) != 2 {
		t.Errorf("empty MatchedCode must not be fingerprint-merged; got %d", len(out))
	}
}

// ─── Cross-path confidence boost ─────────────────────────────────────────────

func TestCrossPathBoostApplied(t *testing.T) {
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70)

	out, _ := l.Process([]finding.Finding{f1, f2})
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
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.95)
	f2 := semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.95)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if out[0].Confidence > 1.0 {
		t.Errorf("confidence must not exceed 1.0 after boost; got %.2f", out[0].Confidence)
	}
}

func TestSamePathNoCrossBoost(t *testing.T) {
	l := New()
	f1 := patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70)
	f2 := patternFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70)

	out, _ := l.Process([]finding.Finding{f1, f2})
	if out[0].Confidence > 0.71 {
		t.Errorf("same-path findings must not get cross-path boost; got %.2f", out[0].Confidence)
	}
}

// ─── ProcessWithStats ────────────────────────────────────────────────────────

func TestProcessWithStatsCountsCorrectly(t *testing.T) {
	l := New()
	findings := []finding.Finding{
		patternFinding("f1", "api/auth.py", "CWE-89", "", 10, 0.70),
		semanticFinding("f2", "api/auth.py", "CWE-89", "", 10, 0.70), // merges with f1
		patternFinding("f3", "api/util_test.go", "CWE-89", "", 5, 0.80), // auto-suppressed
	}

	_, records, stats, err := l.ProcessWithStats(findings)
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
	l := New()
	out, err := l.Process(nil)
	if err != nil {
		t.Fatalf("Process(nil): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got %d", len(out))
	}
}
