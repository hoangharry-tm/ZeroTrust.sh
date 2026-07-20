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

package dedup

import (
	"context"
	"crypto/sha256" // FIPS 180-4
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// gate1Key returns the Gate 1 dedup key for f.
//
// Gate 1 is an exact-match key covering (CWE, file path, start line).
// This catches the common case where both Path A and Path B independently
// identify the same vulnerability at the same location — the two findings
// are merged into one with SourcePath = BOTH and a +15 pp confidence boost.
//
// Formula: hex(SHA-256(CWE + "|" + file path + "|" + start line))
// We use the first 8 bytes (64-bit) for map indexing; the 2^64 birthday
// bound means negligible collision probability for the thousands of
// findings expected per scan. Gate 3 (embedding) would catch the rare
// hash collision.
//
// Reference: FIPS PUB 180-4, Secure Hash Standard (SHS).
func gate1Key(f finding.Finding) string {
	raw := fmt.Sprintf("%s|%s|%d", f.CWE, f.Path, f.LineRange.Start)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

// gate2Key returns the Gate 2 dedup key for f.
//
// Gate 2 is a location-anchored fingerprint using (CWE, normalised file path).
// Unlike Gate 1 (which requires exact line match), Gate 2 treats findings at
// different lines in the same file as duplicates. This catches the case where
// Path A's pattern rule matches one invocation on line 10 while Path B's
// semantic analysis finds the same CWE at line 20 in the same function.
//
// The normalised path is already repo-relative when the finding is constructed
// (the scanner strips the project root prefix). The fingerprint includes CWE
// to avoid conflating distinct vulnerability types in the same file.
//
// Formula: hex(SHA-256(CWE + ":" + Path))
// Reference: Kamiya, T., Kusumoto, S., & Inoue, K. (2002). CCFinder: a
// multilinguistic token-based code clone detection system for large scale
// source code. IEEE Transactions on Software Engineering, 28(7), 654-670.
func gate2Key(f finding.Finding) string {
	raw := fmt.Sprintf("%s:%s", f.CWE, f.Path)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

// merge combines two findings that have been identified as duplicates.
// The surviving finding receives the higher confidence and, if the two
// findings came from different paths, SourcePath is upgraded to BOTH.
func merge(a, b finding.Finding, strategy Strategy) (finding.Finding, MergeRecord) {
	crossPath := (a.SourcePath == finding.SourcePattern && b.SourcePath == finding.SourceSemantic) ||
		(a.SourcePath == finding.SourceSemantic && b.SourcePath == finding.SourcePattern) ||
		a.SourcePath == finding.SourceBoth || b.SourcePath == finding.SourceBoth

	winner, loser := a, b
	if b.Confidence > a.Confidence {
		winner, loser = b, a
	}

	if crossPath {
		winner.SourcePath = finding.SourceBoth
	}

	// Preserve SeverityPinned: if either candidate has a pinned severity,
	// the merged result must keep that SeverityLabel and remain pinned.
	if loser.SeverityPinned {
		winner.SeverityLabel = loser.SeverityLabel
		winner.SeverityPinned = true
	}

	rec := MergeRecord{
		KeptID:                winner.ID,
		DroppedID:             loser.ID,
		Strategy:              strategy,
		CrossPathBoostApplied: crossPath,
	}
	return winner, rec
}

// gate3 runs embedding cosine similarity on findings with MatchedCode.
// Returns: survivors after gate 3, merge records, merge count, and near-miss
// index pairs (0.85 ≤ sim < 0.95) that gate 4 should evaluate.
//
// ponytail: gate3 embedding skipped — Python worker removed; re-enable when
// Go embedding client exists (pkg/embedding).
func (l *Layer) gate3(ctx context.Context, survivors []finding.Finding) (
	[]finding.Finding, []MergeRecord, int, [][2]int,
) {
	slog.Debug("dedup gate3 (embedding) started", "component", "dedup", "candidates", len(survivors))
	if len(survivors) == 0 {
		return survivors, nil, 0, nil
	}
	return survivors, nil, 0, nil
}

// gate4 evaluates near-miss pairs using AST token edit distance.
//
// ponytail: gate4 (AST edit distance) skipped — Python worker removed.
// Re-enable when a Go AST diff client is added to pkg/astdiff.
func (l *Layer) gate4(_ context.Context, survivors []finding.Finding, nearMiss [][2]int) (
	[]finding.Finding, []MergeRecord, int,
) {
	slog.Debug("dedup gate4 (AST edit) started", "component", "dedup", "near_miss_pairs", len(nearMiss))
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
