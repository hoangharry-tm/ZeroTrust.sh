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
	"math"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
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

// embeddingThreshold is the cosine similarity above which two findings are
// considered duplicates by Gate 3 (MiniLM-L6-v2 embedding).
const embeddingThreshold = 0.95

// astEditThreshold is the token-sequence similarity above which Gate 4
// (AST edit distance) classifies two findings as duplicates.
const astEditThreshold = 0.85

// embeddingNearMiss is the lower bound of the "near-miss" range that triggers
// Gate 4 escalation when Gate 3 similarity is below embeddingThreshold.
const embeddingNearMiss = 0.85

// Layer deduplicates and scores the merged finding set from both detection paths.
type Layer struct {
	// w is the Python worker used for Gate 3 (embedding) and Gate 4 (AST edit).
	// nil → gates 3 and 4 are skipped.
	w *worker.Manager
	// root is the project root used to load .zerotrust-suppressions.yaml.
	// Empty string → sidecar not loaded.
	root string
	// sc is the sidecar loaded once per Layer from root. Nil when root is empty.
	sc *Sidecar
}

// New returns a Layer ready to process findings (Gates 3+4 skipped; no sidecar).
func New() *Layer { return &Layer{} }

// NewWithRoot returns a Layer that loads the .zerotrust-suppressions.yaml sidecar
// from root once at construction time.
func NewWithRoot(root string) *Layer {
	sc := LoadSidecar(root)
	return &Layer{root: root, sc: &sc}
}

// NewWithWorker returns a Layer that uses w for Gate 3 (embedding similarity)
// and Gate 4 (AST edit distance), and loads the sidecar from root.
func NewWithWorker(w *worker.Manager, root string) *Layer {
	sc := LoadSidecar(root)
	return &Layer{w: w, root: root, sc: &sc}
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
	stats := Stats{InputCount: len(input)}
	var records []MergeRecord

	// ── Gate 1: exact key (CWE + path + start line) ──────────────────────────
	keyMap := make(map[string]int, len(input)) // key → index in survivors
	survivors := make([]finding.Finding, 0, len(input))

	for _, f := range input {
		k := gate1Key(f)
		if idx, dup := keyMap[k]; dup {
			merged, rec := merge(survivors[idx], f, StrategyExactKey)
			survivors[idx] = merged
			records = append(records, rec)
			stats.MergeCount++
		} else {
			keyMap[k] = len(survivors)
			survivors = append(survivors, f)
		}
	}

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
	return out, records, stats, nil
}

// gate3 runs embedding cosine similarity on findings with MatchedCode.
// Returns: survivors after gate 3, merge records, merge count, and near-miss
// index pairs (0.85 ≤ sim < 0.95) that gate 4 should evaluate.
func (l *Layer) gate3(ctx context.Context, survivors []finding.Finding) (
	[]finding.Finding, []MergeRecord, int, [][2]int,
) {
	if l.w == nil || len(survivors) == 0 {
		return survivors, nil, 0, nil
	}

	// Collect codes for findings that have MatchedCode.
	codeIdx := make([]int, 0, len(survivors)) // idx into survivors for each code
	codes := make([]string, 0, len(survivors))
	for i, f := range survivors {
		if f.MatchedCode != "" {
			codeIdx = append(codeIdx, i)
			codes = append(codes, f.MatchedCode)
		}
	}
	if len(codes) == 0 {
		return survivors, nil, 0, nil
	}

	vecs, err := l.w.Embed(ctx, codes)
	if err != nil || len(vecs) != len(codes) {
		// Best-effort: skip gate 3 on worker error.
		return survivors, nil, 0, nil
	}

	// Pairwise cosine similarity — O(N²) on gate-2 survivors (expected N < 50).
	merged := make([]bool, len(survivors))
	var records []MergeRecord
	var mergeCount int
	var nearMiss [][2]int // indices into survivors

	for a := 0; a < len(codeIdx); a++ {
		if merged[codeIdx[a]] {
			continue
		}
		for b := a + 1; b < len(codeIdx); b++ {
			if merged[codeIdx[b]] {
				continue
			}
			sim := cosineSimilarity(vecs[a], vecs[b])
			si, sj := codeIdx[a], codeIdx[b]
			switch {
			case sim >= embeddingThreshold:
				m, rec := merge(survivors[si], survivors[sj], StrategyEmbedding)
				survivors[si] = m
				records = append(records, rec)
				merged[sj] = true
				mergeCount++
			case sim >= embeddingNearMiss:
				nearMiss = append(nearMiss, [2]int{si, sj})
			}
		}
	}

	// Build post-gate3 slice and a remap from pre-gate3 index → post-gate3 index.
	newIdx := make(map[int]int, len(survivors))
	out := make([]finding.Finding, 0, len(survivors))
	for i, f := range survivors {
		if !merged[i] {
			newIdx[i] = len(out)
			out = append(out, f)
		}
	}
	// Remap nearMiss to post-gate3 indices; drop pairs where either side was merged.
	remapped := nearMiss[:0]
	for _, pair := range nearMiss {
		ni, oki := newIdx[pair[0]]
		nj, okj := newIdx[pair[1]]
		if oki && okj {
			remapped = append(remapped, [2]int{ni, nj})
		}
	}
	return out, records, mergeCount, remapped
}

// gate4 evaluates near-miss pairs (identified by gate3) using AST token edit distance.
// nearMiss contains post-gate3 index pairs; only those specific pairs are evaluated.
func (l *Layer) gate4(ctx context.Context, survivors []finding.Finding, nearMiss [][2]int) (
	[]finding.Finding, []MergeRecord, int,
) {
	if l.w == nil || len(nearMiss) == 0 {
		return survivors, nil, 0
	}

	merged := make([]bool, len(survivors))
	var records []MergeRecord
	var mergeCount int

	// Only evaluate the near-miss pairs flagged by gate3 — O(|nearMiss|) IPC calls.
	for _, pair := range nearMiss {
		i, j := pair[0], pair[1]
		if i >= len(survivors) || j >= len(survivors) {
			continue
		}
		if merged[i] || merged[j] {
			continue
		}
		if survivors[i].MatchedCode == "" || survivors[j].MatchedCode == "" {
			continue
		}
		lang := finding.LangFromPath(survivors[i].Path)
		sim, err := l.w.ASTEditSimilarity(ctx, survivors[i].MatchedCode, survivors[j].MatchedCode, lang)
		if err != nil {
			continue
		}
		if sim >= astEditThreshold {
			m, rec := merge(survivors[i], survivors[j], StrategyEditDistance)
			survivors[i] = m
			records = append(records, rec)
			merged[j] = true
			mergeCount++
		}
	}

	out := make([]finding.Finding, 0, len(survivors))
	for i, f := range survivors {
		if !merged[i] {
			out = append(out, f)
		}
	}
	return out, records, mergeCount
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
	if f.SourcePath == finding.SourceBoth && f.Confidence < 0.92 {
		f.Confidence = min(f.Confidence+0.15, 1.0)
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
		f.Confidence = min(f.Confidence+0.10, 1.0)
	}
	if f.SSVC.Automatable == "Yes" {
		f.Confidence = min(f.Confidence+0.05, 1.0)
	}

	// 4. Path A bypass MEDIUM floor.
	if f.SourcePath == finding.SourcePattern && f.Confidence < 0.60 {
		f.Confidence = 0.60
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
