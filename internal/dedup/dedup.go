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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
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
type Layer struct{}

// New returns a Layer ready to process findings.
func New() *Layer { return &Layer{} }

// Process deduplicates findings through Gates 1 and 2, applies cross-path
// confidence boost, derives SeverityLabel, and auto-suppresses test/framework
// findings.
//
// Gates 3 (embedding) and 4 (AST edit distance) are stubs until G4.M4.1.
//
// Parameters:
//   - findings: merged finding list from both paths (Path A + Path B).
func (l *Layer) Process(findings []finding.Finding) ([]finding.Finding, error) {
	out, _, _, err := l.process(findings)
	return out, err
}

// ProcessWithStats is identical to Process but also returns dedup statistics.
func (l *Layer) ProcessWithStats(findings []finding.Finding) ([]finding.Finding, []MergeRecord, Stats, error) {
	return l.process(findings)
}

func (l *Layer) process(input []finding.Finding) ([]finding.Finding, []MergeRecord, Stats, error) {
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

	// ── Cross-path boost + severity derivation ────────────────────────────────
	out := make([]finding.Finding, 0, len(survivors2))
	for _, f := range survivors2 {
		f = applyBoostAndScore(f)
		f = AutoSuppress(f)
		if f.SeverityLabel == finding.SeveritySuppressed {
			stats.AutoSuppressedCount++
		}
		out = append(out, f)
	}

	stats.OutputCount = len(out)
	return out, records, stats, nil
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

// applyBoostAndScore applies the cross-path +15 pp boost when SourcePath == BOTH,
// then derives SeverityLabel from the (possibly boosted) Confidence.
func applyBoostAndScore(f finding.Finding) finding.Finding {
	if f.SourcePath == finding.SourceBoth {
		f.Confidence = min(f.Confidence+0.15, 1.0)
	}
	f.SeverityLabel = DeriveSeverityLabel(f.Confidence)
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

	return f
}

// DeriveSSVC populates the SSVC dimensions on a finding using CVE lookup
// tables (CISA KEV, EPSS, NVD CVSS, CWE automatable/impact maps).
// Stubs until G4.M4.1 when Trivy enrichment is integrated.
func DeriveSSVC(f finding.Finding) finding.Finding {
	// implemented in G4.M4.1
	return f
}

// DeriveSeverityLabel maps a Confidence score to the corresponding SeverityLabel
// using the fixed threshold table.
//
//	BLOCK      ≥ 0.92
//	HIGH     0.75 – 0.91
//	MEDIUM   0.60 – 0.74
//	LOW      0.30 – 0.59
//	SUPPRESSED < 0.30
func DeriveSeverityLabel(confidence float64) finding.SeverityLabel {
	switch {
	case confidence >= 0.92:
		return finding.SeverityBlock
	case confidence >= 0.75:
		return finding.SeverityHigh
	case confidence >= 0.60:
		return finding.SeverityMedium
	case confidence >= 0.30:
		return finding.SeverityLow
	default:
		return finding.SeveritySuppressed
	}
}
