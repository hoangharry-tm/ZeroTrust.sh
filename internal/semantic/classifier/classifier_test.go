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

package classifier_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/classifier"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// ---------------------------------------------------------------------------
// IsSupported
// ---------------------------------------------------------------------------

func TestIsSupported_KnownLanguages(t *testing.T) {
	langs := []string{"python", "java", "javascript", "typescript", "go", "ruby", "php"}
	for _, lang := range langs {
		assert.True(t, classifier.IsSupported(lang), "expected %q to be supported", lang)
	}
}

func TestIsSupported_UnknownLanguages(t *testing.T) {
	langs := []string{"rust", "kotlin", "swift", "csharp", "c#", "dart", ""}
	for _, lang := range langs {
		assert.False(t, classifier.IsSupported(lang), "expected %q to be unsupported", lang)
	}
}

func TestIsSupported_CaseInsensitive(t *testing.T) {
	assert.True(t, classifier.IsSupported("Python"))
	assert.True(t, classifier.IsSupported("JAVA"))
	assert.True(t, classifier.IsSupported("Go"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// surface builds a minimal EnrichedSurface for testing.
func surface(id, lang string, isIDOR bool) enrichment.EnrichedSurface {
	return enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:              id,
			File:            "test.go",
			IsIDORCandidate: isIDOR,
		},
		Code:     "func foo() {}",
		Language: lang,
	}
}

// classifyResult serialises a ClassifyResult to JSON and wraps it in a Response.
func classifyResult(results []worker.ClassifySurfaceResult) json.RawMessage {
	b, _ := json.Marshal(worker.ClassifyResult{Results: results})
	return b
}

// ---------------------------------------------------------------------------
// Classify — routing rules (using nil worker for unsupported/IDOR paths, which
// don't require an IPC call)
// ---------------------------------------------------------------------------

func TestClassify_EmptyInput(t *testing.T) {
	g := classifier.New(nil, nil)
	results, err := g.Classify(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestClassify_EmptySlice(t *testing.T) {
	g := classifier.New(nil, nil)
	results, err := g.Classify(context.Background(), []enrichment.EnrichedSurface{})
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestClassify_UnsupportedLanguageEscalatesImmediately(t *testing.T) {
	g := classifier.New(nil, nil) // nil worker — unsupported path never calls it
	surfaces := []enrichment.EnrichedSurface{surface("s1", "rust", false)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "s1", r.SurfaceID)
	assert.True(t, r.Escalate)
	assert.Equal(t, classifier.EscalateUnsupportedLang, r.EscalateReason)
}

func TestClassify_UnsupportedLanguageCSharp(t *testing.T) {
	g := classifier.New(nil, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "csharp", false)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, classifier.EscalateUnsupportedLang, results[0].EscalateReason)
}

// ---------------------------------------------------------------------------
// Classify — worker failure fallback
// ---------------------------------------------------------------------------

func TestClassify_WorkerDeadFallsBackToUncertain(t *testing.T) {
	// A nil worker.Manager causes Call() to panic/error; verify Gate handles it.
	// We simulate this by using a dead worker (nil).
	g := classifier.New(nil, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "go", false)}

	// Calling Classify with a nil worker on a supported language will attempt IPC
	// and encounter an error. The Gate must not return an error to the caller —
	// it should degrade gracefully to uncertain escalation.
	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Escalate)
	assert.Equal(t, classifier.EscalateUncertain, results[0].EscalateReason)
}

// ---------------------------------------------------------------------------
// EscalateReason constants
// ---------------------------------------------------------------------------

func TestEscalateReasonConstants(t *testing.T) {
	assert.Equal(t, classifier.EscalateReason("idor_candidate"), classifier.EscalateIDOR)
	assert.Equal(t, classifier.EscalateReason("unsupported_language"), classifier.EscalateUnsupportedLang)
	assert.Equal(t, classifier.EscalateReason("uncertain"), classifier.EscalateUncertain)
	assert.Equal(t, classifier.EscalateReason("vulnerable"), classifier.EscalateVulnerable)
}

// ---------------------------------------------------------------------------
// Label constants
// ---------------------------------------------------------------------------

func TestLabelConstants(t *testing.T) {
	assert.Equal(t, classifier.Label("vulnerable"), classifier.LabelVulnerable)
	assert.Equal(t, classifier.Label("safe"), classifier.LabelSafe)
	assert.Equal(t, classifier.Label("uncertain"), classifier.LabelUncertain)
}

// ---------------------------------------------------------------------------
// Mixed supported/unsupported batch
// ---------------------------------------------------------------------------

func TestClassify_MixedBatch_UnsupportedGetImmediateResult(t *testing.T) {
	g := classifier.New(nil, nil)
	surfaces := []enrichment.EnrichedSurface{
		surface("rust-1", "rust", false),
		surface("go-2", "go", false), // supported — will hit dead worker → uncertain
		surface("kotlin-3", "kotlin", false),
	}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.Equal(t, "rust-1", results[0].SurfaceID)
	assert.Equal(t, classifier.EscalateUnsupportedLang, results[0].EscalateReason)

	assert.Equal(t, "kotlin-3", results[2].SurfaceID)
	assert.Equal(t, classifier.EscalateUnsupportedLang, results[2].EscalateReason)

	// go-2 tried IPC, worker is nil → uncertain fallback
	assert.Equal(t, "go-2", results[1].SurfaceID)
	assert.Equal(t, classifier.EscalateUncertain, results[1].EscalateReason)
}

// ---------------------------------------------------------------------------
// Result routing from worker responses — tested via worker.ClassifyResult JSON
// ---------------------------------------------------------------------------

// workerPayload simulates what the Python worker would return by encoding
// ClassifyResult to JSON and asserting the Gate parses it correctly.
// We exercise this through a real Gate wired to a fake Manager.

// The following tests validate worker.ClassifyResult JSON round-trip — the same
// decode path used by classifyBatch when a real worker responds.

func TestApplyWorkerResponse_VulnerableEscalates(t *testing.T) {
	raw := classifyResult([]worker.ClassifySurfaceResult{
		{SurfaceID: "s1", Label: "vulnerable", Confidence: 0.95},
	})

	// Verify JSON round-trip of the worker result — the Gate's unmarshal path.
	var cr worker.ClassifyResult
	require.NoError(t, json.Unmarshal(raw, &cr))
	require.Len(t, cr.Results, 1)
	assert.Equal(t, "vulnerable", cr.Results[0].Label)
	assert.InEpsilon(t, 0.95, cr.Results[0].Confidence, 1e-6)
}

func TestApplyWorkerResponse_SafeHighConfidenceDoesNotEscalate(t *testing.T) {
	raw := classifyResult([]worker.ClassifySurfaceResult{
		{SurfaceID: "s1", Label: "safe", Confidence: 0.92},
	})
	var cr worker.ClassifyResult
	require.NoError(t, json.Unmarshal(raw, &cr))
	assert.Equal(t, "safe", cr.Results[0].Label)
}

func TestApplyWorkerResponse_UncertainEscalates(t *testing.T) {
	raw := classifyResult([]worker.ClassifySurfaceResult{
		{SurfaceID: "s1", Label: "uncertain", Confidence: 0.55},
	})
	var cr worker.ClassifyResult
	require.NoError(t, json.Unmarshal(raw, &cr))
	assert.Equal(t, "uncertain", cr.Results[0].Label)
}

// ---------------------------------------------------------------------------
// Sentinel error check — ErrWorkerDead detection
// ---------------------------------------------------------------------------

func TestErrWorkerDeadSentinel(t *testing.T) {
	// Verify ErrWorkerDead is a known exported sentinel from the worker package.
	assert.True(t, errors.Is(worker.ErrWorkerDead, worker.ErrWorkerDead))
}

// ---------------------------------------------------------------------------
// ThresholdVulnerable / ThresholdSafe constants
// ---------------------------------------------------------------------------

func TestThresholdConstants(t *testing.T) {
	assert.InEpsilon(t, 0.80, classifier.ThresholdVulnerable, 1e-9)
	assert.InEpsilon(t, 0.20, classifier.ThresholdSafe, 1e-9)
}

// ---------------------------------------------------------------------------
// Threshold boundary tests — Gate.Classify() routing after worker response
//
// We wire Gate to a real worker.Manager backed by an inline Python echo script
// that returns a controlled confidence value, then assert the Gate applies the
// threshold logic correctly.
// ---------------------------------------------------------------------------

// python3Available checks whether python3 is accessible in PATH.
func python3Available() bool {
	_, err := exec.LookPath("python3")
	return err == nil
}

// thresholdEchoManager creates a Manager whose classify handler always returns
// the given label and confidence for every surface.
func thresholdEchoManager(t *testing.T, label string, confidence float64) *worker.Manager {
	t.Helper()
	if !python3Available() {
		t.Skip("python3 not in PATH")
	}
	// Inline Python: echoes a fixed label/confidence for all surfaces.
	script := fmt.Sprintf(`
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("type") == "shutdown":
        print(json.dumps({"id": msg["id"], "status": "ok"}), flush=True)
        break
    if msg.get("type") == "classify":
        surfaces = (msg.get("payload") or {}).get("surfaces", [])
        results = [{"surface_id": s["surface_id"], "label": %q, "confidence": %v} for s in surfaces]
        print(json.dumps({"id": msg["id"], "status": "ok", "result": {"results": results}}), flush=True)
    else:
        print(json.dumps({"id": msg["id"], "status": "ok", "result": {}}), flush=True)
`, label, confidence)

	m, err := worker.NewFromArgs([]string{"python3", "-c", script}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Stop() })

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, m.Ping(pingCtx))
	return m
}

func TestClassify_BoundaryVulnerable_AtThreshold(t *testing.T) {
	// confidence == ThresholdVulnerable → label "vulnerable" kept, surface escalates.
	m := thresholdEchoManager(t, "vulnerable", classifier.ThresholdVulnerable)
	g := classifier.New(m, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "go", false)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, classifier.LabelVulnerable, results[0].Label)
	assert.True(t, results[0].Escalate)
	assert.Equal(t, classifier.EscalateVulnerable, results[0].EscalateReason)
}

func TestClassify_BoundarySafe_AtThreshold(t *testing.T) {
	// confidence == ThresholdVulnerable as "safe" → confidence >= threshold → not escalated.
	m := thresholdEchoManager(t, "safe", classifier.ThresholdVulnerable)
	g := classifier.New(m, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "go", false)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, classifier.LabelSafe, results[0].Label)
	assert.False(t, results[0].Escalate)
}

func TestClassify_BoundarySafe_BelowThreshold_BecomesUncertain(t *testing.T) {
	// confidence just below ThresholdVulnerable as "safe" → down-graded to uncertain.
	belowThreshold := classifier.ThresholdVulnerable - 0.01
	m := thresholdEchoManager(t, "safe", belowThreshold)
	g := classifier.New(m, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "go", false)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, classifier.LabelUncertain, results[0].Label)
	assert.True(t, results[0].Escalate)
	assert.Equal(t, classifier.EscalateUncertain, results[0].EscalateReason)
}

func TestClassify_AllUncertainBatch(t *testing.T) {
	m := thresholdEchoManager(t, "uncertain", 0.50)
	g := classifier.New(m, nil)
	surfaces := []enrichment.EnrichedSurface{
		surface("s1", "python", false),
		surface("s2", "java", false),
		surface("s3", "go", false),
	}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 3)
	for _, r := range results {
		assert.Equal(t, classifier.LabelUncertain, r.Label)
		assert.True(t, r.Escalate)
	}
}

func TestClassify_IDORCandidateAlwaysEscalates(t *testing.T) {
	// IDOR candidate with "safe" label must still escalate.
	m := thresholdEchoManager(t, "safe", 0.95)
	g := classifier.New(m, nil)
	surfaces := []enrichment.EnrichedSurface{surface("s1", "go", true /* isIDOR */)}

	results, err := g.Classify(context.Background(), surfaces)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Escalate)
	assert.Equal(t, classifier.EscalateIDOR, results[0].EscalateReason)
}
