//go:build integration

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

// Integration tests for the UniXcoder classifier gate.
//
// These tests require a live Python worker (worker/main.py) with the
// UniXcoder model downloaded. Run with:
//
//	make test-integration
//
// Prerequisites:
//  1. Python worker deps installed: cd worker && uv sync
//  2. UniXcoder model downloaded: microsoft/unixcoder-base-nine
//     (auto-downloaded on first run by HuggingFace; ~500 MB)
//  3. ZEROTRUST_PYTHON set if not using uv (default: uv)
//
// The test starts the worker itself; you do not need to pre-start it.
package classifier_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/classifier"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// extToLang maps file extension → language name for the classifier.
var extToLang = map[string]string{
	".py":   "python",
	".java": "java",
	".go":   "go",
	".ts":   "typescript",
	".js":   "javascript",
	".rb":   "ruby",
	".php":  "php",
	".rs":   "rust",
	".kt":   "kotlin",
	".swift": "swift",
	".cs":   "csharp",
	".dart": "dart",
}

// demoAppDir returns the absolute path to tests/integration/demo-app.
func demoAppDir(t *testing.T) string {
	t.Helper()
	// Walk up from the package directory to the repo root.
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "could not find repo root")
		dir = parent
	}
	return filepath.Join(dir, "tests", "integration", "demo-app")
}

// startWorker spawns the Python worker and returns a Manager.
// The worker is stopped via t.Cleanup.
func startWorker(t *testing.T) *worker.Manager {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "could not find repo root")
		dir = parent
	}
	workerPath := filepath.Join(dir, "worker", "main.py")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	m, err := worker.Start(ctx, workerPath, slog.Default())
	require.NoError(t, err, "worker.Start: ensure worker deps are installed (cd worker && uv sync)")
	t.Cleanup(func() { _ = m.Stop() })
	return m
}

// loadDemoAppSurfaces reads all source files in demo-app and returns one
// EnrichedSurface per file. No real CPG is needed — the classifier only needs
// file, language, and source code.
func loadDemoAppSurfaces(t *testing.T, appDir string) []enrichment.EnrichedSurface {
	t.Helper()
	entries, err := os.ReadDir(appDir)
	require.NoError(t, err)

	var surfaces []enrichment.EnrichedSurface
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		lang, ok := extToLang[ext]
		if !ok {
			continue
		}
		fullPath := filepath.Join(appDir, e.Name())
		code, err := os.ReadFile(fullPath)
		require.NoError(t, err)

		surfaces = append(surfaces, enrichment.EnrichedSurface{
			Surface: targeting.Surface{
				ID:   e.Name(),
				File: e.Name(),
			},
			Code:     string(code),
			Language: lang,
		})
	}
	require.NotEmpty(t, surfaces, "no source files found in demo-app — check path")
	return surfaces
}

// TestIntegration_ClassifierFunnel_DemoApp runs the full Gate.Classify +
// RouteAndLog pipeline on demo-app source files and records funnel stats.
//
// Assertions:
//   - Route buckets are exhaustive (total = dedup + assembler + dismissed).
//   - A funnel doc is written to docs/benchmarks/tier2_funnel.md.
func TestIntegration_ClassifierFunnel_DemoApp(t *testing.T) {
	appDir := demoAppDir(t)
	m := startWorker(t)

	surfaces := loadDemoAppSurfaces(t, appDir)
	t.Logf("loaded %d surfaces from demo-app", len(surfaces))

	gate := classifier.New(m, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	results, err := gate.Classify(ctx, surfaces)
	require.NoError(t, err)
	require.Len(t, results, len(surfaces))

	// Build ClassifiedSurface slice for routing.
	classified := make([]classifier.ClassifiedSurface, len(results))
	for i, r := range results {
		classified[i] = classifier.ClassifiedSurface{
			Result: r,
			File:   surfaces[i].File,
		}
	}

	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := classifier.RouteAndLog(classified, logger)

	total := len(classified)
	toDedup := len(r.ToDedup)
	toAssembler := len(r.ToAssembler)
	dismissed := len(r.Dismissed)

	// Buckets must be exhaustive.
	assert.Equal(t, total, toDedup+toAssembler+dismissed,
		"route buckets must account for all surfaces")

	// Funnel stats were logged.
	assert.Contains(t, buf.String(), "classifier funnel")

	escalationRate := float64(toDedup+toAssembler) / float64(total)
	t.Logf("funnel: total=%d to_dedup=%d to_assembler=%d dismissed=%d escalation_rate=%.2f",
		total, toDedup, toAssembler, dismissed, escalationRate)

	writeFunnelDoc(t, total, toDedup, toAssembler, dismissed, escalationRate)
}

// writeFunnelDoc appends the measured funnel stats to docs/benchmarks/tier2_funnel.md.
func writeFunnelDoc(t *testing.T, total, toDedup, toAssembler, dismissed int, escalationRate float64) {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Log("writeFunnelDoc: could not find repo root, skipping doc write")
			return
		}
		dir = parent
	}
	docPath := filepath.Join(dir, "docs", "benchmarks", "tier2_funnel.md")

	metCap := "✅ within cap (≤25%)"
	if escalationRate > 0.25 {
		metCap = "⚠️ exceeds cap (>25%)"
	}

	content := fmt.Sprintf(`# Tier 2 Classifier Funnel Stats

**Test codebase**: tests/integration/demo-app
**Model**: microsoft/unixcoder-base-nine (high-recall mode, A-18 pending)
**Date**: %s

## Results

| Metric | Value |
|--------|-------|
| Total surfaces | %d |
| → Dedup (vulnerable) | %d |
| → Assembler (uncertain/IDOR/unsupported) | %d |
| → Dismissed (safe) | %d |
| Escalation rate (dedup+assembler)/total | %.1f%% |
| Design target | ≤25%% |
| Status | %s |

## Notes

- A-18: UniXcoder operates in high-recall mode (ThresholdVulnerable=0.80).
  Without CVEFixes fine-tuning, the model rarely commits to "safe" — expect
  a high escalation rate until A-18 is resolved.
- "Surfaces" here are full source files, not CPG function nodes. Real funnel
  stats (post-ML3.1) will be lower once Heuristic Targeting pre-filters to
  ~5%% of files before the classifier runs.
- Unsupported-language files (.rs, .kt, .swift, .cs) are counted in
  ToAssembler with BypassedClassifier=true.
`,
		time.Now().Format("2006-01-02"),
		total, toDedup, toAssembler, dismissed,
		escalationRate*100,
		metCap,
	)

	require.NoError(t, os.WriteFile(docPath, []byte(content), 0o644))
	t.Logf("funnel doc written to %s", docPath)
}
