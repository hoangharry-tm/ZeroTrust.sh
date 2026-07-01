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
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/classifier"
)

// cs builds a ClassifiedSurface for table-driven tests.
func cs(surfaceID, file string, label classifier.Label, conf float64, escalate bool, reason classifier.EscalateReason) classifier.ClassifiedSurface {
	return classifier.ClassifiedSurface{
		Result: classifier.Result{
			SurfaceID:      surfaceID,
			Label:          label,
			Confidence:     conf,
			Escalate:       escalate,
			EscalateReason: reason,
		},
		File: file,
	}
}

// ---------------------------------------------------------------------------
// Route — T4: band routing
// ---------------------------------------------------------------------------

func TestRoute_VulnerableGoesToDedup(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "main.go", classifier.LabelVulnerable, 0.92, true, classifier.EscalateVulnerable),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToDedup, 1)
	assert.Empty(t, r.ToAssembler)
	assert.Empty(t, r.Dismissed)
	assert.Equal(t, "s1", r.ToDedup[0].SurfaceID)
}

func TestRoute_SafeHighConfidenceGetsDismissed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "util.go", classifier.LabelSafe, 0.90, false, ""),
	}
	r := classifier.Route(surfaces)
	assert.Empty(t, r.ToDedup)
	assert.Empty(t, r.ToAssembler)
	require.Len(t, r.Dismissed, 1)
	assert.Equal(t, "s1", r.Dismissed[0].SurfaceID)
}

func TestRoute_UncertainGoesToAssembler(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "handler.go", classifier.LabelUncertain, 0.55, true, classifier.EscalateUncertain),
	}
	r := classifier.Route(surfaces)
	assert.Empty(t, r.ToDedup)
	assert.Empty(t, r.Dismissed)
	require.Len(t, r.ToAssembler, 1)
}

func TestRoute_SafeBelowThresholdGoesToAssembler(t *testing.T) {
	// "safe" but confidence below ThresholdVulnerable — treated as uncertain.
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "dao.go", classifier.LabelSafe, config.C.ClassifierVulnerableThreshold-0.01, true, classifier.EscalateUncertain),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.Empty(t, r.ToDedup)
	assert.Empty(t, r.Dismissed)
}

// ---------------------------------------------------------------------------
// Route — T4: IDOR override
// ---------------------------------------------------------------------------

func TestRoute_IDORAlwaysGoesToAssembler_EvenIfSafe(t *testing.T) {
	// IDOR candidate with a "safe" label must still escalate to Assembler.
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "resource.go", classifier.LabelSafe, 0.95, true, classifier.EscalateIDOR),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.Empty(t, r.ToDedup)
	assert.Empty(t, r.Dismissed)
	assert.Equal(t, classifier.EscalateIDOR, r.ToAssembler[0].EscalateReason)
}

func TestRoute_IDORAlwaysGoesToAssembler_EvenIfVulnerable(t *testing.T) {
	// IDOR with "vulnerable" — IDOR rule takes priority over band routing.
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "resource.go", classifier.LabelVulnerable, 0.95, true, classifier.EscalateIDOR),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.Empty(t, r.ToDedup)
}

// ---------------------------------------------------------------------------
// Route — T5: unsupported-language bypass
// ---------------------------------------------------------------------------

func TestRoute_RustGoesToAssemblerBypassed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "src/main.rs", classifier.LabelSafe, 0.99, false, ""),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.True(t, r.ToAssembler[0].BypassedClassifier)
	assert.Empty(t, r.Dismissed)
}

func TestRoute_KotlinGoesToAssemblerBypassed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "app/Service.kt", classifier.LabelUncertain, 0.5, true, classifier.EscalateUnsupportedLang),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.True(t, r.ToAssembler[0].BypassedClassifier)
}

func TestRoute_SwiftGoesToAssemblerBypassed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "Views/Main.swift", classifier.LabelSafe, 0.95, false, ""),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.True(t, r.ToAssembler[0].BypassedClassifier)
}

func TestRoute_CSharpGoesToAssemblerBypassed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "Controller.cs", classifier.LabelSafe, 0.95, false, ""),
	}
	r := classifier.Route(surfaces)
	require.Len(t, r.ToAssembler, 1)
	assert.True(t, r.ToAssembler[0].BypassedClassifier)
}

func TestRoute_SupportedLanguageNotBypassed(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "handler.py", classifier.LabelSafe, 0.92, false, ""),
	}
	r := classifier.Route(surfaces)
	// Python is supported — safe+high-confidence → dismissed, not bypassed.
	require.Len(t, r.Dismissed, 1)
	assert.False(t, r.Dismissed[0].BypassedClassifier)
}

// ---------------------------------------------------------------------------
// Route — mixed batch
// ---------------------------------------------------------------------------

func TestRoute_MixedBatch(t *testing.T) {
	surfaces := []classifier.ClassifiedSurface{
		cs("vuln", "auth.go", classifier.LabelVulnerable, 0.92, true, classifier.EscalateVulnerable),
		cs("safe", "util.go", classifier.LabelSafe, 0.90, false, ""),
		cs("idor", "resource.go", classifier.LabelSafe, 0.95, true, classifier.EscalateIDOR),
		cs("rust", "lib.rs", classifier.LabelSafe, 0.99, false, ""),
		cs("unc", "svc.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
	}
	r := classifier.Route(surfaces)

	assert.Len(t, r.ToDedup, 1, "only 'vuln' goes to dedup")
	assert.Len(t, r.Dismissed, 1, "only 'safe' is dismissed")
	assert.Len(t, r.ToAssembler, 3, "idor + rust + unc go to assembler")

	assemblerIDs := make([]string, len(r.ToAssembler))
	for i, s := range r.ToAssembler {
		assemblerIDs[i] = s.SurfaceID
	}
	assert.ElementsMatch(t, []string{"idor", "rust", "unc"}, assemblerIDs)
}

// ---------------------------------------------------------------------------
// Route — empty input
// ---------------------------------------------------------------------------

func TestRoute_EmptyInput(t *testing.T) {
	r := classifier.Route(nil)
	assert.Empty(t, r.ToDedup)
	assert.Empty(t, r.ToAssembler)
	assert.Empty(t, r.Dismissed)
}

// ---------------------------------------------------------------------------
// RouteAndLog — funnel stats logging (T7.1)
// ---------------------------------------------------------------------------

// captureLogger returns a slog.Logger that writes to a buffer and the buffer.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, &buf
}

func TestRouteAndLog_LogsFunnelStats(t *testing.T) {
	logger, buf := captureLogger()
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "handler.go", classifier.LabelVulnerable, 0.92, true, classifier.EscalateVulnerable),
		cs("s2", "util.go", classifier.LabelSafe, 0.91, false, ""),
		cs("s3", "svc.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
		cs("s4", "api.go", classifier.LabelSafe, 0.92, false, ""),
	}
	r := classifier.RouteAndLog(surfaces, logger)

	// Routing correctness preserved.
	assert.Len(t, r.ToDedup, 1)
	assert.Len(t, r.Dismissed, 2)
	assert.Len(t, r.ToAssembler, 1)

	// Funnel stats logged.
	logged := buf.String()
	assert.Contains(t, logged, "classifier funnel")
	assert.Contains(t, logged, "total=4")
	assert.Contains(t, logged, "to_dedup=1")
	assert.Contains(t, logged, "to_assembler=1")
	assert.Contains(t, logged, "dismissed=2")
}

func TestRouteAndLog_WarnWhenEscalationExceedsCap(t *testing.T) {
	logger, buf := captureLogger()
	// 4 surfaces all go to Assembler/Dedup → 100% escalation rate > 25%.
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "a.go", classifier.LabelVulnerable, 0.92, true, classifier.EscalateVulnerable),
		cs("s2", "b.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
		cs("s3", "c.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
		cs("s4", "d.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
	}
	classifier.RouteAndLog(surfaces, logger)

	assert.True(t, strings.Contains(buf.String(), "escalation rate exceeds cap"),
		"expected escalation warning in log output: %s", buf.String())
}

func TestRouteAndLog_NoWarnWhenBelowCap(t *testing.T) {
	logger, buf := captureLogger()
	// Only 1 of 5 surfaces escalates (20% ≤ 25%).
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "a.go", classifier.LabelSafe, 0.92, false, ""),
		cs("s2", "b.go", classifier.LabelSafe, 0.92, false, ""),
		cs("s3", "c.go", classifier.LabelSafe, 0.92, false, ""),
		cs("s4", "d.go", classifier.LabelSafe, 0.92, false, ""),
		cs("s5", "e.go", classifier.LabelUncertain, 0.50, true, classifier.EscalateUncertain),
	}
	classifier.RouteAndLog(surfaces, logger)

	assert.NotContains(t, buf.String(), "escalation rate exceeds cap")
}

func TestRouteAndLog_EmptyInput_NoLog(t *testing.T) {
	logger, buf := captureLogger()
	classifier.RouteAndLog(nil, logger)
	assert.Empty(t, buf.String())
}

func TestRouteAndLog_NilLogger_UsesDefault(t *testing.T) {
	// nil logger must not panic.
	surfaces := []classifier.ClassifiedSurface{
		cs("s1", "a.go", classifier.LabelSafe, 0.92, false, ""),
	}
	assert.NotPanics(t, func() { classifier.RouteAndLog(surfaces, nil) })
}
