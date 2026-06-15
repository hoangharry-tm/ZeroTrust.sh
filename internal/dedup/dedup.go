// Package dedup implements the Dedup + Confidence Scoring layer.
// It receives findings from both detection paths, deduplicates them through a
// cost-cascaded 4-gate strategy, derives SSVC dimension values, and emits a
// scored finding set for the HTML report and PoE layer.
package dedup

import "github.com/hoangharry-tm/zerotrust/internal/finding"

// Layer deduplicates and scores the merged finding set from both detection paths.
type Layer struct{}

// New returns a Layer ready to process findings.
func New() *Layer { return &Layer{} }

// Process deduplicates findings through the 4-gate cascade and applies
// SSVC-inspired confidence scoring.
//
// Gate order (cheapest first):
//  1. CWE hash + file path + line range overlap
//  2. Code snippet MD5 fingerprint
//  3. Embedding similarity (MiniLM-L6-v2, Python worker)
//  4. AST edit distance (Zhang-Shasha, last resort)
func (l *Layer) Process(findings []finding.Finding) ([]finding.Finding, error) {
	// implemented in G4.M4.1
	return findings, nil
}
