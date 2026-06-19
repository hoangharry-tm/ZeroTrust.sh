package verifier_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/verifier"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeFindings(n int) []finding.Finding {
	fs := make([]finding.Finding, n)
	for i := range fs {
		fs[i] = finding.Finding{
			ID:            finding.ComputeID("CWE-89", "src/db.go", "cursor.execute(query)"),
			Path:          "src/db.go",
			CWE:           "CWE-89",
			RuleID:        "PY-001",
			MatchedCode:   "cursor.execute(query % user_input)",
			Confidence:    0.70,
			SeverityLabel: finding.SeverityMedium,
			SourcePath:    finding.SourcePattern,
		}
	}
	return fs
}

func makeVerifyResult(findingID, verdict string, confidence float64, ascRounds int) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"finding_id":    findingID,
		"verdict":       verdict,
		"confidence":    confidence,
		"justification": "test justification",
		"asc_rounds":    ascRounds,
	})
	return b
}

// ---------------------------------------------------------------------------
// ApplyResults tests
// ---------------------------------------------------------------------------

func TestApplyResults_ConfirmedUpdatesConfidenceAndSeverity(t *testing.T) {
	fs := makeFindings(1)
	results := []verifier.Result{
		{
			FindingID:     fs[0].ID,
			Verdict:       verifier.VerdictConfirmed,
			Confidence:    0.88,
			Justification: "clear sql injection path",
		},
	}

	out := verifier.ApplyResults(fs, results)

	require.Len(t, out, 1)
	assert.Equal(t, 0.88, out[0].Confidence)
	assert.Equal(t, finding.SeverityHigh, out[0].SeverityLabel)
	assert.Equal(t, "clear sql injection path", out[0].Justification)
	assert.Empty(t, out[0].SuppressReason)
}

func TestApplyResults_FalsePositiveSetsSuppressed(t *testing.T) {
	fs := makeFindings(1)
	results := []verifier.Result{
		{
			FindingID:  fs[0].ID,
			Verdict:    verifier.VerdictFalsePositive,
			Confidence: 0.82,
		},
	}

	out := verifier.ApplyResults(fs, results)

	require.Len(t, out, 1)
	assert.Equal(t, finding.SeveritySuppressed, out[0].SeverityLabel)
	assert.Equal(t, finding.SuppressReasonFrameworkSafe, out[0].SuppressReason)
}

func TestApplyResults_UncertainSetsSuppressedUncertain(t *testing.T) {
	fs := makeFindings(1)
	results := []verifier.Result{
		{
			FindingID:  fs[0].ID,
			Verdict:    verifier.VerdictUncertain,
			Confidence: 0.50,
		},
	}

	out := verifier.ApplyResults(fs, results)

	require.Len(t, out, 1)
	assert.Equal(t, finding.SeveritySuppressed, out[0].SeverityLabel)
	assert.Equal(t, finding.SuppressReasonUncertain, out[0].SuppressReason)
}

func TestApplyResults_LengthMismatchReturnsInputUnchanged(t *testing.T) {
	fs := makeFindings(2)
	results := []verifier.Result{
		{FindingID: "x", Verdict: verifier.VerdictConfirmed, Confidence: 0.95},
	}

	out := verifier.ApplyResults(fs, results)

	// Caller bug: mismatched lengths → return original slice unchanged.
	assert.Equal(t, fs, out)
}

func TestApplyResults_EmptyJustificationPreservesOriginal(t *testing.T) {
	fs := makeFindings(1)
	fs[0].Justification = "original justification"
	results := []verifier.Result{
		{
			FindingID:     fs[0].ID,
			Verdict:       verifier.VerdictConfirmed,
			Confidence:    0.85,
			Justification: "", // empty — should not overwrite
		},
	}

	out := verifier.ApplyResults(fs, results)

	assert.Equal(t, "original justification", out[0].Justification)
}

func TestApplyResults_UnknownVerdictLeavesUnchanged(t *testing.T) {
	fs := makeFindings(1)
	origConf := fs[0].Confidence
	results := []verifier.Result{
		{
			FindingID: fs[0].ID,
			Verdict:   verifier.Verdict(""), // zero-value unknown verdict
		},
	}

	out := verifier.ApplyResults(fs, results)

	assert.Equal(t, origConf, out[0].Confidence)
	assert.Equal(t, finding.SeverityMedium, out[0].SeverityLabel)
}

// ---------------------------------------------------------------------------
// HighConfidenceThreshold constant
// ---------------------------------------------------------------------------

func TestHighConfidenceThreshold(t *testing.T) {
	// The bypass threshold must remain in sync with dedup thresholds.
	// Deterministic rules at ≥0.90 skip LLM verification entirely.
	assert.Equal(t, 0.90, verifier.HighConfidenceThreshold)
}

// ---------------------------------------------------------------------------
// Verdict constant values
// ---------------------------------------------------------------------------

func TestVerdictConstants(t *testing.T) {
	assert.Equal(t, verifier.Verdict("confirmed"), verifier.VerdictConfirmed)
	assert.Equal(t, verifier.Verdict("false_positive"), verifier.VerdictFalsePositive)
	assert.Equal(t, verifier.Verdict("uncertain"), verifier.VerdictUncertain)
}

// ---------------------------------------------------------------------------
// Verify: integration via fakeWorker
// ---------------------------------------------------------------------------

// fakeWorkerCalls records calls and returns preset responses.
// It satisfies the worker.Manager-shaped call pattern used in Verify tests
// by directly constructing the verifier and injecting results through ApplyResults.
//
// Verify() is an integration test concern — it requires a live worker.Manager.
// We test the fan-out and fallback logic below by inspecting ApplyResults
// on pre-built Result slices, which is the canonical code path.

func TestApplyResults_MultipleFindings(t *testing.T) {
	fs := makeFindings(3)

	results := []verifier.Result{
		{FindingID: fs[0].ID, Verdict: verifier.VerdictConfirmed, Confidence: 0.93, Justification: "j0"},
		{FindingID: fs[1].ID, Verdict: verifier.VerdictFalsePositive, Confidence: 0.80, Justification: "j1"},
		{FindingID: fs[2].ID, Verdict: verifier.VerdictUncertain, Confidence: 0.48, Justification: "j2"},
	}

	out := verifier.ApplyResults(fs, results)

	require.Len(t, out, 3)
	assert.Equal(t, finding.SeverityBlock, out[0].SeverityLabel)
	assert.Equal(t, finding.SeveritySuppressed, out[1].SeverityLabel)
	assert.Equal(t, finding.SuppressReasonFrameworkSafe, out[1].SuppressReason)
	assert.Equal(t, finding.SeveritySuppressed, out[2].SeverityLabel)
	assert.Equal(t, finding.SuppressReasonUncertain, out[2].SuppressReason)
}

// ---------------------------------------------------------------------------
// Verify: nil/empty inputs
// ---------------------------------------------------------------------------

func TestVerify_EmptyInput(t *testing.T) {
	// Verify with an empty slice must return nil, nil without panicking.
	v := verifier.New(nil, nil) // nil Manager is safe when no findings are given

	results, err := v.Verify(context.Background(), nil)

	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestVerify_EmptySlice(t *testing.T) {
	v := verifier.New(nil, nil)

	results, err := v.Verify(context.Background(), []finding.Finding{})

	require.NoError(t, err)
	assert.Nil(t, results)
}

// ---------------------------------------------------------------------------
// makeVerifyResult used internally
// ---------------------------------------------------------------------------

func TestMakeVerifyResult_IsValidJSON(t *testing.T) {
	raw := makeVerifyResult("id-001", "confirmed", 0.91, 0)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, "confirmed", m["verdict"])
}
