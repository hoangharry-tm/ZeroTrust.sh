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

// Package dedup implements the Dedup + Confidence Scoring layer.
//
// The Layer receives findings from both detection paths, deduplicates them through
// a cost-cascaded gate strategy, applies SSVC-inspired confidence scoring, and
// emits a scored finding set for the HTML report and PoE layer.
//
// Gate cascade (cheapest first — later gates only run when prior gates miss):
//
//  1. Exact key: SHA-256(CWE + "|" + Path + "|" + StartLine) — O(1) map lookup.
//  2. Code fingerprint: SHA-256(CWE + ":" + Path) — O(1) map lookup; catches
//     same CWE at different lines within the same file.
//  3. Embedding cosine similarity via MiniLM-L6-v2 (Python worker, ~0.5 ms/pair)
//     — ponytail: stub awaiting Go embedding client.
//  4. AST edit distance via Zhang-Shasha (last resort) — ponytail: stub.
//
// Cross-path boost: when Path A and Path B independently confirm the same
// finding (merged SourcePath becomes BOTH), confidence receives a +15 pp
// additive boost, capped at 1.0.
//
// Auto-suppression: findings in test file patterns or under framework-safe
// library paths are suppressed without LLM involvement. SuppressReason is
// always set; no finding is ever silently dropped.
//
// SSVC dimension sourcing:
//   - Exploitation: CISA KEV + EPSS + NVD (via Trivy enrichment) — G4.
//   - Automatable: static CWE→automatable lookup table — G4.
//   - TechnicalImpact: CVSS base score + CWE impact map — G4.
package dedup

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// Strategy identifies which dedup gate resolved a duplicate pair.
type Strategy string

const (
	// StrategyExactKey means gate 1 (CWE + file + line) resolved the duplicate.
	StrategyExactKey Strategy = "exact_key"
	// StrategyFingerprint means gate 2 (CWE + normalised path) resolved it.
	StrategyFingerprint Strategy = "fingerprint"
	// StrategyEmbedding means gate 3 (MiniLM embedding similarity) resolved it.
	StrategyEmbedding Strategy = "embedding"
	// StrategyEditDistance means gate 4 (AST edit distance) resolved it.
	StrategyEditDistance Strategy = "edit_distance"
)

// MergeRecord describes how two findings were merged during deduplication.
type MergeRecord struct {
	// KeptID is the finding.Finding.ID of the surviving record.
	KeptID string
	// DroppedID is the finding.Finding.ID of the duplicate that was merged.
	DroppedID string
	// Strategy is the gate that identified the duplicate.
	Strategy Strategy
	// CrossPathBoostApplied is true when one finding was from Path A and the
	// other from Path B, triggering the +15 pp confidence boost.
	CrossPathBoostApplied bool
}

// Stats describes the dedup pass outcome for reporting in the scan header.
type Stats struct {
	InputCount          int
	OutputCount         int
	MergeCount          int
	AutoSuppressedCount int
}

// Layer deduplicates and scores the merged finding set from both detection paths.
type Layer struct {
	root string
	sc   *Sidecar
	db   *sqlite.DB
	projectID string
}

// New returns a dedup Layer.
func New(root string) *Layer {
	sc := LoadSidecar(root)
	return &Layer{root: root, sc: &sc}
}

// SetDB attaches an optional SQLite store for cross-scan finding dedup.
// When set, findings whose finding_id already exists in the DB are skipped
// before entering the gate cascade. projectID is the project identifier used
// to scope the DB queries.
func (l *Layer) SetDB(db *sqlite.DB, projectID string) {
	l.db = db
	l.projectID = projectID
}

// Process deduplicates findings through all active gates, applies cross-path
// confidence boost, SSVC sourcing, and severity derivation.
func (l *Layer) Process(ctx context.Context, findings []finding.Finding) ([]finding.Finding, error) {
	out, _, _, err := l.process(ctx, findings)
	return out, err
}

// ProcessWithStats is identical to Process but also returns dedup statistics.
func (l *Layer) ProcessWithStats(ctx context.Context, findings []finding.Finding) ([]finding.Finding, []MergeRecord, Stats, error) {
	return l.process(ctx, findings)
}

func (l *Layer) process(ctx context.Context, input []finding.Finding) ([]finding.Finding, []MergeRecord, Stats, error) {
	slog.Debug("dedup process started", "component", "dedup", "input_count", len(input))
	stats := Stats{InputCount: len(input)}
	var records []MergeRecord

	survivors := input
	if l.db != nil && l.projectID != "" {
		s, recs, merged := l.dedupHistorical(ctx, input)
		records = append(records, recs...)
		stats.MergeCount += merged
		survivors = s
		slog.Debug("dedup: cross-scan historical dedup complete",
			"component", "dedup",
			"before", len(input),
			"after", len(survivors),
			"merged", merged,
		)
	}

	// ── Gate 1: exact key (CWE + path + start line) ──────────────────────────
	keyMap := make(map[string]int, len(survivors))
	g1out := make([]finding.Finding, 0, len(survivors))

	for _, f := range survivors {
		k := gate1Key(f)
		if idx, dup := keyMap[k]; dup {
			merged, rec := merge(g1out[idx], f, StrategyExactKey)
			g1out[idx] = merged
			records = append(records, rec)
			stats.MergeCount++
		} else {
			keyMap[k] = len(g1out)
			g1out = append(g1out, f)
		}
	}
	survivors = g1out

	// ── Gate 2: code fingerprint (CWE + normalised path) ────────────────────
	fpMap := make(map[string]int, len(survivors))
	survivors2 := make([]finding.Finding, 0, len(survivors))

	for _, f := range survivors {
		k := gate2Key(f)
		if idx, dup := fpMap[k]; dup {
			merged, rec := merge(survivors2[idx], f, StrategyFingerprint)
			survivors2[idx] = merged
			records = append(records, rec)
			stats.MergeCount++
		} else {
			fpMap[k] = len(survivors2)
			survivors2 = append(survivors2, f)
		}
	}

	// ── Gate 3: embedding cosine similarity (MiniLM-L6-v2) ──────────────────
	survivors3, recs3, mergeCount3, nearMissPairs := l.gate3(ctx, survivors2)
	records = append(records, recs3...)
	stats.MergeCount += mergeCount3

	// ── Gate 4: AST token edit distance (last resort; near-miss pairs only) ──
	survivors4, recs4, mergeCount4 := l.gate4(ctx, survivors3, nearMissPairs)
	records = append(records, recs4...)
	stats.MergeCount += mergeCount4

	// ── SSVC sourcing + cross-path boost + severity derivation ────────────────
	out := make([]finding.Finding, 0, len(survivors4))
	for _, f := range survivors4 {
		f = DeriveSSVC(ctx, f)
		f = applyBoostAndScore(f)
		f = AutoSuppress(f)
		if l.sc != nil && f.SeverityLabel != finding.SeveritySuppressed {
			f = l.sc.Apply(f)
		}
		if f.SeverityLabel == finding.SeveritySuppressed {
			stats.AutoSuppressedCount++
		}
		out = append(out, f)
	}

	stats.OutputCount = len(out)
	slog.Info("dedup process complete",
		"component", "dedup",
		"input", stats.InputCount,
		"output", stats.OutputCount,
		"merged", stats.MergeCount,
		"suppressed", stats.AutoSuppressedCount,
	)
	return out, records, stats, nil
}

// dedupHistorical skips findings that already exist in the SQLite store
// (matched by finding_id). Streams finding IDs through a cursor to avoid
// loading all IDs into a single slice.
//
// Returns the survivors (findings not found in the DB), merge records for
// skipped findings, and the count of skipped duplicates.
func (l *Layer) dedupHistorical(ctx context.Context, input []finding.Finding) ([]finding.Finding, []MergeRecord, int) {
	known := make(map[string]struct{})
	if err := l.db.WalkFindingIDs(ctx, l.projectID, func(id string) error {
		known[id] = struct{}{}
		return nil
	}); err != nil {
		slog.Warn("dedup: cross-scan query failed, proceeding without historical dedup",
			"component", "dedup", "err", err)
		return input, nil, 0
	}

	var survivors []finding.Finding
	var records []MergeRecord
	var mergeCount int

	for _, f := range input {
		if _, exists := known[f.ID]; exists {
			records = append(records, MergeRecord{
				KeptID:    f.ID,
				DroppedID: f.ID,
				Strategy:  "historical",
			})
			mergeCount++
		} else {
			survivors = append(survivors, f)
		}
	}
	return survivors, records, mergeCount
}

// applyBoostAndScore applies scoring adjustments in order:
//  1. Cross-path +15 pp boost (SourcePath == BOTH).
//  2. CVE CVSS floor: if f.CVSS > 0, confidence = max(cvss/10.0, confidence).
//  3. SSVC boost: Active exploitation +0.10; Automatable=Yes +0.05; capped at 1.0.
//  4. Path A bypass MEDIUM floor: PATTERN findings cannot fall below 0.60.
//  5. Derive SeverityLabel from final confidence.
func applyBoostAndScore(f finding.Finding) finding.Finding {
	if f.SourcePath == finding.SourceBoth && f.Confidence < config.C.ConfBlock {
		f.Confidence = min(f.Confidence+config.C.BoostCrossPath, 1.0)
	}
	if f.CVSS > 0 {
		floor := f.CVSS / 10.0
		if floor > f.Confidence {
			f.Confidence = floor
		}
	}
	if f.Exploitable || f.SourcePath == finding.SourceBoth {
		if f.SSVC.Exploitation == "Active" {
			f.Confidence = min(f.Confidence+config.C.BoostSSVCActive, 1.0)
		}
		if f.SSVC.Automatable == "Yes" {
			f.Confidence = min(f.Confidence+config.C.BoostSSVCAutomatable, 1.0)
		}
	}
	if f.SourcePath == finding.SourcePattern && f.Confidence < config.C.FloorPatternPath {
		f.Confidence = config.C.FloorPatternPath
	}
	if !f.SeverityPinned {
		f.SeverityLabel = finding.SeverityFromConfidence(f.Confidence)
	}
	return f
}

// testPatterns are glob-style suffix patterns for test file auto-suppression.
var testPatterns = []string{
	"_test.go",
	"_test.py",
	"test_.py",
	"_spec.rb",
	"_spec.js",
	"_spec.ts",
	".test.js",
	".test.ts",
	".test.jsx",
	".test.tsx",
	".spec.js",
	".spec.ts",
}

// testDirs are directory name components that indicate a test tree.
var testDirs = map[string]bool{
	"__tests__": true,
	"testdata":  true,
	"tests":     true,
	"test":      true,
	"spec":      true,
}

// AutoSuppress applies test-file and framework-safe suppression rules to f.
// Returns the finding with SeverityLabel and SuppressReason updated if
// suppression applies; returns it unchanged otherwise.
func AutoSuppress(f finding.Finding) finding.Finding {
	p := filepath.ToSlash(f.Path)

	lower := strings.ToLower(p)
	for _, pat := range testPatterns {
		if strings.HasSuffix(lower, pat) {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonTestFile
			return f
		}
	}

	for part := range strings.SplitSeq(p, "/") {
		if testDirs[strings.ToLower(part)] {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonTestFile
			return f
		}
	}

	return applyFrameworkSafe(f)
}

// DeriveSeverityLabel maps a Confidence score to the corresponding SeverityLabel.
// Delegates to finding.SeverityFromConfidence, which owns the canonical thresholds.
func DeriveSeverityLabel(confidence float64) finding.SeverityLabel {
	return finding.SeverityFromConfidence(confidence)
}
