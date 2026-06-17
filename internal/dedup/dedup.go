// Package dedup implements the Dedup + Confidence Scoring layer.
//
// The Layer receives findings from both detection paths, deduplicates them through
// a cost-cascaded 4-gate strategy, applies SSVC-inspired confidence scoring, and
// emits a scored finding set for the HTML report and PoE layer.
//
// Dedup gate cascade (cheapest first — later gates are only invoked when prior
// gates do not produce a match):
//
//  1. CWE hash + file path + line range overlap (O(1), exact match).
//  2. Code snippet SHA-256 fingerprint (O(1), exact match on MatchedCode).
//  3. Embedding cosine similarity via MiniLM-L6-v2 (Python worker, ~0.5 ms/pair).
//  4. AST edit distance via Zhang-Shasha (last resort, expensive).
//
// Cross-path boost: when Path A and Path B independently confirm the same
// finding (merged SourcePath becomes BOTH), confidence receives a +15 pp
// additive boost, capped at 1.0.
//
// Auto-suppression: findings in test file patterns or under framework-safe
// library paths are suppressed without LLM involvement. The SuppressReason
// field is always set; no finding is ever silently dropped.
//
// SSVC dimension sourcing:
//   - Exploitation: CISA KEV + EPSS + NVD (via Trivy enrichment).
//   - Automatable: static CWE→automatable lookup table.
//   - TechnicalImpact: CVSS base score + CWE impact map.
package dedup

import "github.com/hoangharry-tm/zerotrust/internal/finding"

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
	// CrossPathBoostApplied is true when one finding was from Path A and the other
	// from Path B, triggering the +15 pp confidence boost.
	CrossPathBoostApplied bool
}

// Stats describes the dedup pass outcome for reporting in the scan header.
type Stats struct {
	// InputCount is the total number of findings submitted to Process.
	InputCount int
	// OutputCount is the number of unique findings after dedup.
	OutputCount int
	// MergeCount is the number of duplicate pairs that were merged.
	MergeCount int
	// AutoSuppressedCount is the number of findings auto-suppressed by test/framework rules.
	AutoSuppressedCount int
}

// Layer deduplicates and scores the merged finding set from both detection paths.
type Layer struct{}

// New returns a Layer ready to process findings.
func New() *Layer { return &Layer{} }

// Process deduplicates findings through the 4-gate cascade and applies
// SSVC-inspired confidence scoring.
//
// Processing steps:
//  1. Auto-suppress findings in test file patterns or framework-safe paths.
//  2. Gate 1: group by CWE + filepath + line range overlap → merge.
//  3. Gate 2: group survivors by SHA-256(MatchedCode) → merge.
//  4. Gate 3: embedding similarity ≥ 0.92 (MiniLM, Python worker) → merge.
//  5. Gate 4: AST edit distance (Zhang-Shasha, last resort) → merge.
//  6. Apply cross-path +15 pp confidence boost where SourcePath == BOTH.
//  7. Derive SeverityLabel from Confidence using the threshold table.
//  8. Populate SSVC dimensions from the CVE / CWE lookup tables.
//
// Parameters:
//   - findings: merged finding list from both paths (Path A + Path B).
//
// Returns:
//   - []finding.Finding: deduplicated, SSVC-scored findings.
//   - error: non-nil only if the Python worker embedding call fails (gate 3).
func (l *Layer) Process(findings []finding.Finding) ([]finding.Finding, error) {
	// implemented in G4.M4.1
	return findings, nil
}

// ProcessWithStats is identical to Process but also returns dedup statistics.
// Use this when the scan report should include dedup metadata.
//
// Parameters:
//   - findings: merged finding list from both paths.
//
// Returns:
//   - []finding.Finding: deduplicated, SSVC-scored findings.
//   - []MergeRecord: one record per merged pair.
//   - Stats: aggregate dedup statistics.
//   - error: non-nil if the Python worker embedding call fails.
func (l *Layer) ProcessWithStats(findings []finding.Finding) ([]finding.Finding, []MergeRecord, Stats, error) {
	// implemented in G4.M4.1
	return nil, nil, Stats{}, nil
}

// AutoSuppress applies test-file and framework-safe suppression rules to a
// single finding. Returns the finding with SeverityLabel and SuppressReason
// updated if suppression applies; returns it unchanged otherwise.
//
// Suppression rules:
//   - File path matches a test pattern (e.g. *_test.go, test_*.py, spec/**).
//   - File path is under a known framework-safe vendor/dependency directory.
//
// Parameters:
//   - f: the finding to evaluate.
func AutoSuppress(f finding.Finding) finding.Finding {
	// implemented in G4.M4.1
	return f
}

// DeriveSSVC populates the SSVC dimensions on a finding using the CVE lookup
// tables (CISA KEV, EPSS, NVD CVSS, CWE automatable/impact maps).
//
// Parameters:
//   - f: the finding to score (modified in-place).
//
// Returns the finding with SSVC fields populated.
func DeriveSSVC(f finding.Finding) finding.Finding {
	// implemented in G4.M4.1
	return f
}

// DeriveSeverityLabel maps a Confidence score to the corresponding SeverityLabel
// using the fixed threshold table:
//
//	BLOCK      ≥ 0.92
//	HIGH     0.75 – 0.91
//	MEDIUM   0.60 – 0.74
//	LOW      0.30 – 0.59
//	SUPPRESSED < 0.30
//
// Parameters:
//   - confidence: the composite confidence score (0.0–1.0).
func DeriveSeverityLabel(confidence float64) finding.SeverityLabel {
	// implemented in G4.M4.1
	return finding.SeveritySuppressed
}
