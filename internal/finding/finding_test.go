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

package finding

import (
	"strings"
	"testing"
)

// ─── SeverityFromConfidence ───────────────────────────────────────────────────

func TestSeverityFromConfidence_Block(t *testing.T) {
	for _, score := range []float64{1.0, 0.92} {
		if got := SeverityFromConfidence(score); got != SeverityBlock {
			t.Errorf("score %.2f: want BLOCK, got %s", score, got)
		}
	}
}

func TestSeverityFromConfidence_BlockBoundaryExact(t *testing.T) {
	// 0.92 is the inclusive lower bound of BLOCK.
	if got := SeverityFromConfidence(0.92); got != SeverityBlock {
		t.Errorf("0.92 must be BLOCK, got %s", got)
	}
	// 0.91 is the inclusive upper bound of HIGH.
	if got := SeverityFromConfidence(0.91); got != SeverityHigh {
		t.Errorf("0.91 must be HIGH, got %s", got)
	}
}

func TestSeverityFromConfidence_High(t *testing.T) {
	for _, score := range []float64{0.91, 0.80, 0.75} {
		if got := SeverityFromConfidence(score); got != SeverityHigh {
			t.Errorf("score %.2f: want HIGH, got %s", score, got)
		}
	}
}

func TestSeverityFromConfidence_HighBoundaryExact(t *testing.T) {
	if got := SeverityFromConfidence(0.75); got != SeverityHigh {
		t.Errorf("0.75 must be HIGH, got %s", got)
	}
	if got := SeverityFromConfidence(0.74); got != SeverityMedium {
		t.Errorf("0.74 must be MEDIUM, got %s", got)
	}
}

func TestSeverityFromConfidence_Medium(t *testing.T) {
	for _, score := range []float64{0.74, 0.65, 0.60} {
		if got := SeverityFromConfidence(score); got != SeverityMedium {
			t.Errorf("score %.2f: want MEDIUM, got %s", score, got)
		}
	}
}

func TestSeverityFromConfidence_MediumBoundaryExact(t *testing.T) {
	if got := SeverityFromConfidence(0.60); got != SeverityMedium {
		t.Errorf("0.60 must be MEDIUM, got %s", got)
	}
	if got := SeverityFromConfidence(0.59); got != SeverityLow {
		t.Errorf("0.59 must be LOW, got %s", got)
	}
}

func TestSeverityFromConfidence_Low(t *testing.T) {
	for _, score := range []float64{0.59, 0.40, 0.30} {
		if got := SeverityFromConfidence(score); got != SeverityLow {
			t.Errorf("score %.2f: want LOW, got %s", score, got)
		}
	}
}

func TestSeverityFromConfidence_LowBoundaryExact(t *testing.T) {
	if got := SeverityFromConfidence(0.30); got != SeverityLow {
		t.Errorf("0.30 must be LOW, got %s", got)
	}
	if got := SeverityFromConfidence(0.29); got != SeveritySuppressed {
		t.Errorf("0.29 must be SUPPRESSED, got %s", got)
	}
}

func TestSeverityFromConfidence_Suppressed(t *testing.T) {
	for _, score := range []float64{0.29, 0.01, 0.00} {
		if got := SeverityFromConfidence(score); got != SeveritySuppressed {
			t.Errorf("score %.2f: want SUPPRESSED, got %s", score, got)
		}
	}
}

// Thresholds in finding.go and dedup.DeriveSeverityLabel must agree.
// This table mirrors dedup_test.go TestDeriveSeverityLabelThresholds so that any
// divergence between the two implementations shows up as a test failure here.
func TestSeverityFromConfidence_AgreesWithDedupThresholds(t *testing.T) {
	cases := []struct {
		score float64
		want  SeverityLabel
	}{
		{1.00, SeverityBlock},
		{0.92, SeverityBlock},
		{0.91, SeverityHigh},
		{0.75, SeverityHigh},
		{0.74, SeverityMedium},
		{0.60, SeverityMedium},
		{0.59, SeverityLow},
		{0.30, SeverityLow},
		{0.29, SeveritySuppressed},
		{0.00, SeveritySuppressed},
	}
	for _, tc := range cases {
		got := SeverityFromConfidence(tc.score)
		if got != tc.want {
			t.Errorf("SeverityFromConfidence(%.2f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

// ─── ComputeID ────────────────────────────────────────────────────────────────

func TestComputeID_ReturnsHex64Chars(t *testing.T) {
	id := ComputeID("CWE-89", "src/db.go", 12)
	if len(id) != 64 {
		t.Errorf("expected 64-char hex, got len=%d: %q", len(id), id)
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex character %q in ID %q", c, id)
		}
	}
}

func TestComputeID_DeterministicAcrossCalls(t *testing.T) {
	const n = 100
	first := ComputeID("CWE-78", "internal/exec/runner.go", 42)
	for i := 0; i < n; i++ {
		if got := ComputeID("CWE-78", "internal/exec/runner.go", 42); got != first {
			t.Fatalf("ComputeID not deterministic on call %d: got %q, want %q", i, got, first)
		}
	}
}

func TestComputeID_DifferentCWEProducesDifferentID(t *testing.T) {
	id1 := ComputeID("CWE-89", "src/db.go", 1)
	id2 := ComputeID("CWE-78", "src/db.go", 1)
	if id1 == id2 {
		t.Error("different CWE must produce different ID")
	}
}

func TestComputeID_DifferentPathProducesDifferentID(t *testing.T) {
	id1 := ComputeID("CWE-89", "src/auth.go", 1)
	id2 := ComputeID("CWE-89", "src/db.go", 1)
	if id1 == id2 {
		t.Error("different path must produce different ID")
	}
}

func TestComputeID_DifferentLineProducesDifferentID(t *testing.T) {
	id1 := ComputeID("CWE-89", "src/db.go", 10)
	id2 := ComputeID("CWE-89", "src/db.go", 20)
	if id1 == id2 {
		t.Error("different line must produce different ID")
	}
}

// TestComputeID_SameLocationStableAcrossDifferentCode is a regression test
// for a real bug found live: the ID used to be keyed on matchedCode (an
// LLM-extracted code snippet that isn't byte-identical across runs even for
// the same surface), so the same file:line accumulated multiple,
// contradictory, permanently-coexisting rows across re-scans (observed on
// litemall's StorageService.java:71 — BLOCK, LOW, and HIGH verdicts all
// simultaneously live for one location). Keying on line instead means two
// different extracted-code-text variants for the SAME cwe+file+line collapse
// to the SAME ID, so a re-scan's UPSERT overwrites the prior verdict instead
// of appending a sibling row.
func TestComputeID_SameLocationStableAcrossDifferentCode(t *testing.T) {
	id1 := ComputeID("CWE-862", "storage/StorageService.java", 71)
	id2 := ComputeID("CWE-862", "storage/StorageService.java", 71)
	if id1 != id2 {
		t.Errorf("same cwe+file+line must produce the same ID regardless of any code-text variation: %q vs %q", id1, id2)
	}
}

// Two callers (opengrep and Reasoning) passing the same (cwe, path, line) must
// produce the same ID so Gate 1 dedup can merge them.
func TestComputeID_SameInputsFromDifferentCallersMatch(t *testing.T) {
	cwe, path, line := "CWE-89", "api/auth.py", 7

	fromPathA := ComputeID(cwe, path, line)
	fromPathB := ComputeID(cwe, path, line)

	if fromPathA != fromPathB {
		t.Errorf("same inputs produced different IDs: %q vs %q", fromPathA, fromPathB)
	}
}

func TestComputeID_EmptyInputsDoNotPanic(t *testing.T) {
	// Must not panic; result just needs to be a valid 64-char hex.
	id := ComputeID("", "", 0)
	if len(id) != 64 {
		t.Errorf("expected 64-char hex for empty inputs, got %q", id)
	}
}

// TestComputeID_KnownHash pins the SHA-256 formula to a pre-computed value.
// If the formula (cwe + ":" + path + ":" + line) or hash algorithm changes,
// this test fails — intentionally. Verify with:
//
//	echo -n 'CWE-89:src/db.go:5' | sha256sum
func TestComputeID_KnownHash(t *testing.T) {
	const want = "3a401d2a4906ec4566eb8d503195465cef93ba66609529dd6bba4b4eeaddc6a8"
	got := ComputeID("CWE-89", "src/db.go", 5)
	if got != want {
		t.Errorf("ComputeID formula changed:\n got  %s\n want %s", got, want)
	}
}

// ─── SeverityLabel.String ────────────────────────────────────────────────────

func TestSeverityLabelString(t *testing.T) {
	tests := []struct {
		label SeverityLabel
		want  string
	}{
		{SeverityBlock, "BLOCK"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeveritySuppressed, "SUPPRESSED"},
		{SeverityLabel(99), "UNKNOWN"},
	}
	for _, tc := range tests {
		got := tc.label.String()
		if got != tc.want {
			t.Errorf("SeverityLabel(%d).String() = %q, want %q", int(tc.label), got, tc.want)
		}
	}
}
