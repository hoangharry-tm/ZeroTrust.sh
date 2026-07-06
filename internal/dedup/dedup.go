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
//  2. Code fingerprint: SHA-256(MatchedCode) — O(1) map lookup; skipped when MatchedCode is empty.
//  3. Embedding cosine similarity via MiniLM-L6-v2 (Python worker, ~0.5 ms/pair) — G4.
//  4. AST edit distance via Zhang-Shasha (last resort) — G4.
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
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
	// StrategyFingerprint means gate 2 (SHA-256 of MatchedCode) resolved it.
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
	// root is the project root used to load .zerotrust-suppressions.yaml.
	root string
	// sc is the sidecar loaded once per Layer from root. Nil when root is empty.
	sc *Sidecar

	// db is an optional SQLite connection for cross-scan dedup.
	db *sqlite.DB

	// projectID identifies the current project in the SQLite store.
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
//
// This is the preferred way to enable cross-scan dedup without changing the
// Process signature.
func (l *Layer) SetDB(db *sqlite.DB, projectID string) {
	l.db = db
	l.projectID = projectID
}

// Process deduplicates findings through all active gates, applies cross-path
// confidence boost, SSVC sourcing, and severity derivation.
//
// Parameters:
//   - ctx: used for SSVC network calls and (if worker present) embedding IPC.
//   - findings: merged finding list from both paths (Path A + Path B).
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

	// ── Cross-scan dedup: skip findings already persisted from prior scans ──
	// Uses a single targeted query per project (finding_id only, no full rows)
	// instead of loading the entire findings table into memory.
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
	keyMap := make(map[string]int, len(survivors)) // key → index in survivors
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

	// ── Gate 2: code fingerprint (SHA-256 of MatchedCode) ────────────────────
	fpMap := make(map[string]int, len(survivors))
	survivors2 := make([]finding.Finding, 0, len(survivors))

	for _, f := range survivors {
		if f.MatchedCode == "" {
			// Can't fingerprint an empty snippet — carry forward unchanged.
			survivors2 = append(survivors2, f)
			continue
		}
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

	// ── Gate 3: embedding cosine similarity (MiniLM-L6-v2) ───────────────────
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

// gate3 runs embedding cosine similarity on findings with MatchedCode.
// Returns: survivors after gate 3, merge records, merge count, and near-miss
// index pairs (0.85 ≤ sim < 0.95) that gate 4 should evaluate.
func (l *Layer) gate3(ctx context.Context, survivors []finding.Finding) (
	[]finding.Finding, []MergeRecord, int, [][2]int,
) {
	slog.Debug("dedup gate3 (embedding) started", "component", "dedup", "candidates", len(survivors))
	// ponytail: gate3 embedding skipped — Python worker removed; re-enable when Go embedding client exists
	if len(survivors) == 0 {
		return survivors, nil, 0, nil
	}
	// ponytail: gate3 (embedding cosine similarity) skipped — Python worker removed.
	// Re-enable when a Go embedding client is added to pkg/embedding.
	return survivors, nil, 0, nil
}

// gate4 evaluates near-miss pairs using AST token edit distance.
func (l *Layer) gate4(_ context.Context, survivors []finding.Finding, nearMiss [][2]int) (
	[]finding.Finding, []MergeRecord, int,
) {
	slog.Debug("dedup gate4 (AST edit) started", "component", "dedup", "near_miss_pairs", len(nearMiss))
	// ponytail: gate4 (AST edit distance) skipped — Python worker removed.
	// Re-enable when a Go AST diff client is added to pkg/astdiff.
	return survivors, nil, 0
}

// cosineSimilarity returns the cosine similarity between two float64 vectors.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	denom := math.Sqrt(na * nb)
	if denom == 0 {
		return 0
	}
	return dot / denom
}

// gate1Key returns the Gate 1 dedup key for f.
// Key = first 8 bytes (64-bit) of SHA-256(CWE + "|" + Path + "|" + StartLine).
// 8 bytes gives a 2^64 birthday bound — negligible collision probability for
// the thousands of findings expected per scan. Gate 3 (embedding) catches the
// rare case where two distinct findings hash to the same key.
func gate1Key(f finding.Finding) string {
	raw := fmt.Sprintf("%s|%s|%d", f.CWE, f.Path, f.LineRange.Start)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

// gate2Key returns the Gate 2 dedup key for f.
// Key = first 8 bytes of SHA-256(MatchedCode) — caller must check MatchedCode != "".
// Truncation rationale: same as gate1Key above.
func gate2Key(f finding.Finding) string {
	sum := sha256.Sum256([]byte(f.MatchedCode))
	return hex.EncodeToString(sum[:8])
}

// merge combines two findings that have been identified as duplicates.
// The surviving finding receives the higher confidence and, if the two
// findings came from different paths, SourcePath is upgraded to BOTH.
func merge(a, b finding.Finding, strategy Strategy) (finding.Finding, MergeRecord) {
	crossPath := (a.SourcePath == finding.SourcePattern && b.SourcePath == finding.SourceSemantic) ||
		(a.SourcePath == finding.SourceSemantic && b.SourcePath == finding.SourcePattern) ||
		a.SourcePath == finding.SourceBoth || b.SourcePath == finding.SourceBoth

	// Keep the finding with higher confidence as the base.
	winner, loser := a, b
	if b.Confidence > a.Confidence {
		winner, loser = b, a
	}

	if crossPath {
		winner.SourcePath = finding.SourceBoth
	}

	rec := MergeRecord{
		KeptID:                winner.ID,
		DroppedID:             loser.ID,
		Strategy:              strategy,
		CrossPathBoostApplied: crossPath,
	}
	return winner, rec
}

// applyBoostAndScore applies scoring adjustments in order:
//  1. Cross-path +15 pp boost (SourcePath == BOTH).
//  2. CVE CVSS floor: if f.CVSS > 0, confidence = max(cvss/10.0, confidence).
//  3. SSVC boost: Active exploitation +0.10; Automatable=Yes +0.05; capped at 1.0.
//  4. Path A bypass MEDIUM floor: PATTERN findings cannot fall below 0.60.
//  5. Derive SeverityLabel from final confidence.
func applyBoostAndScore(f finding.Finding) finding.Finding {
	// 1. Cross-path boost (+15 pp, capped at 1.0; skipped when already BLOCK).
	if f.SourcePath == finding.SourceBoth && f.Confidence < config.C.ConfBlock {
		f.Confidence = min(f.Confidence+config.C.BoostCrossPath, 1.0)
	}

	// 2. CVE CVSS floor.
	if f.CVSS > 0 {
		floor := f.CVSS / 10.0
		if floor > f.Confidence {
			f.Confidence = floor
		}
	}

	// 3. SSVC boost.
	if f.SSVC.Exploitation == "Active" {
		f.Confidence = min(f.Confidence+config.C.BoostSSVCActive, 1.0)
	}
	if f.SSVC.Automatable == "Yes" {
		f.Confidence = min(f.Confidence+config.C.BoostSSVCAutomatable, 1.0)
	}

	// 4. Path A bypass MEDIUM floor.
	if f.SourcePath == finding.SourcePattern && f.Confidence < config.C.FloorPatternPath {
		f.Confidence = config.C.FloorPatternPath
	}

	f.SeverityLabel = finding.SeverityFromConfidence(f.Confidence)
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

	// Test file extension patterns.
	lower := strings.ToLower(p)
	for _, pat := range testPatterns {
		if strings.HasSuffix(lower, pat) {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonTestFile
			return f
		}
	}

	// Test directory components.
	for part := range strings.SplitSeq(p, "/") {
		if testDirs[strings.ToLower(part)] {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = finding.SuppressReasonTestFile
			return f
		}
	}

	// Framework-safe path patterns (Django migrations, Spring Security config, etc.).
	return applyFrameworkSafe(f)
}

// DeriveSeverityLabel maps a Confidence score to the corresponding SeverityLabel.
// Delegates to finding.SeverityFromConfidence, which owns the canonical thresholds.
func DeriveSeverityLabel(confidence float64) finding.SeverityLabel {
	return finding.SeverityFromConfidence(confidence)
}
