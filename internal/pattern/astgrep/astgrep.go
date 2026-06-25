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

// Package astgrep wraps the ast-grep CLI (MIT, Tree-sitter-based).
//
// ast-grep covers languages where OpenGrep has weak or absent community rule packs:
// Dart, Swift, Rust, Kotlin, and C#. Language routing is strictly partitioned —
// OpenGrep and ast-grep never run the same rules on the same files.
//
// Rule directories follow the layout in rules/astgrep/:
//
//	rules/astgrep/AG-001-rust-command-injection.yaml
//	rules/astgrep/AG-002-go-sql-sprintf.yaml   (Go supplemental rules only)
//
// ast-grep outputs a JSON array when invoked with --json. Each element is decoded
// into a RawMatch and normalised into a finding.Finding before being returned.
package astgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// RawMatch is a single JSON object in ast-grep's JSON output array.
type RawMatch struct {
	// RuleID is the ast-grep rule identifier (e.g. "AG-002").
	RuleID string `json:"ruleId"`
	// File is the source file path as reported by ast-grep.
	File string `json:"file"`
	// Range describes the matched text span.
	Range RawRange `json:"range"`
	// Labels contains named capture groups from the rule (e.g. {"QUERY": "..."}).
	Labels map[string]string `json:"labels"`
	// Message is the rendered rule message with capture group substitutions.
	Message string `json:"message"`
	// Severity is the rule-declared severity: "error" | "warning" | "info".
	Severity string `json:"severity"`
}

// RawRange is the byte and line/column span of a match.
type RawRange struct {
	// ByteOffset is the [start, end) byte range within the file.
	ByteOffset [2]int `json:"byteOffset"`
	// Start is the starting line/column (0-based).
	Start RawPos `json:"start"`
	// End is the ending line/column (0-based).
	End RawPos `json:"end"`
}

// RawPos is a line/column position within a source file.
type RawPos struct {
	// Line is the 0-based line number.
	Line int `json:"line"`
	// Column is the 0-based column number.
	Column int `json:"column"`
}

// Runner invokes ast-grep as a subprocess against a language-filtered file set.
type Runner struct {
	// binaryPath is the absolute or PATH-resolved path to the ast-grep binary.
	binaryPath string
	// rulesDir is the directory containing ast-grep YAML rule files.
	rulesDir string
}

// New returns a Runner using the ast-grep binary at binaryPath and rules at rulesDir.
//
// Parameters:
//   - binaryPath: path to the ast-grep binary (e.g. "ast-grep" for PATH lookup).
//   - rulesDir: path to the ast-grep rules/ subdirectory (e.g. "rules/astgrep/").
func New(binaryPath, rulesDir string) *Runner {
	return &Runner{binaryPath: binaryPath, rulesDir: rulesDir}
}

// Scan runs ast-grep against files and returns normalised findings.
//
// It invokes: ast-grep scan --json --config <rulesDir> <files...>
// stdout is decoded as a JSON array; each RawMatch is normalised into a finding.Finding.
//
// Parameters:
//   - ctx: cancellation context; the subprocess is killed if ctx is cancelled.
//   - files: relative file paths to scan (pre-filtered to ast-grep's language set via FilterFiles).
//
// Returns:
//   - []finding.Finding: normalised findings from all matched rules.
//   - error: non-nil if the subprocess fails to start or produces unparseable output.
func (r *Runner) Scan(ctx context.Context, files []string) ([]finding.Finding, error) {
	if len(files) == 0 {
		return nil, nil
	}
	slog.Debug("ast-grep scan starting", slog.Int("files", len(files)))

	args := append([]string{"scan", "--json", "--config", r.rulesDir}, files...)
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// ast-grep exits 0 on success regardless of whether findings exist
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// some versions exit 1 when findings found; treat as success
		} else {
			slog.Error("ast-grep subprocess failed", "err", err, slog.String("stderr", stderr.String()))
			return nil, fmt.Errorf("ast-grep: %w (stderr: %s)", err, stderr.String())
		}
	}

	// Output is a JSON array of RawMatch objects.
	raw := stdout.Bytes()
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}

	var matches []RawMatch
	if err := json.Unmarshal(raw, &matches); err != nil {
		slog.Error("ast-grep: failed to parse output", "err", err)
		return nil, fmt.Errorf("ast-grep: parse output: %w", err)
	}

	slog.Info("ast-grep scan complete", slog.Int("raw_matches", len(matches)))
	findings := make([]finding.Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, normalise(m))
	}
	return findings, nil
}

// FilterFiles returns the subset of files that ast-grep owns based on file extension.
// Owned languages: Rust (.rs), Dart (.dart), Swift (.swift), Kotlin (.kt), C# (.cs).
// This enforces the strict language partitioning between OpenGrep and ast-grep.
//
// Parameters:
//   - files: the full changed file list from ChangeSet.Changed.
//
// Returns:
//   - []string: files whose language falls in ast-grep's ownership set.
func FilterFiles(files []string) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		if astgrepOwns(filepath.Ext(f)) {
			out = append(out, f)
		}
	}
	return out
}

// Version returns the ast-grep binary version string (e.g. "0.26.0").
// Used at startup to log the tool version in the scan header.
//
// Parameters:
//   - ctx: cancellation context.
func (r *Runner) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, r.binaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ast-grep --version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// astgrepExts lists file extensions ast-grep owns for language routing.
// OpenGrep owns Python/Java/JS/TS/Go/Ruby/PHP; ast-grep owns the remainder.
var astgrepExts = map[string]bool{
	".rs":   true, // Rust
	".dart": true, // Dart
	".swift": true, // Swift
	".kt":   true, // Kotlin
	".kts":  true, // Kotlin script
	".cs":   true, // C#
}

// astgrepOwns reports whether the file extension belongs to ast-grep's language set.
func astgrepOwns(ext string) bool {
	return astgrepExts[strings.ToLower(ext)]
}

// normalise converts a RawMatch into a finding.Finding.
// Line numbers are converted from 0-based (ast-grep) to 1-based (finding.LineRange).
// CWE and confidence are derived from the rule ID convention (AG-NNN-cwe-NNN) or
// fall back to severity-based defaults.
func normalise(raw RawMatch) finding.Finding {
	confidence := confidenceFromSeverity(raw.Severity)
	cwe := cweFromRuleID(raw.RuleID)

	matched := raw.Labels["__match__"] // ast-grep capture group for the matched text
	id := finding.ComputeID(cwe, raw.File, matched)

	// ast-grep uses 0-based lines; finding.LineRange is 1-based.
	return finding.Finding{
		ID:            id,
		Path:          raw.File,
		LineRange:     finding.LineRange{Start: raw.Range.Start.Line + 1, End: raw.Range.End.Line + 1},
		CWE:           cwe,
		Confidence:    confidence,
		SeverityLabel: severityFromScore(confidence),
		SourcePath:    finding.SourcePattern,
		Justification: raw.Message,
		MatchedCode:   matched,
		RuleID:        raw.RuleID,
	}
}

// confidenceFromSeverity maps the ast-grep severity string to a confidence score.
//
//	"error"   → 0.90 (treated as HIGH confidence)
//	"warning" → 0.65 (treated as MEDIUM confidence)
//	"info"    → 0.40 (treated as LOW confidence)
func confidenceFromSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "error":
		return 0.90
	case "warning":
		return 0.65
	}
	return 0.40
}

// cweFromRuleID attempts to extract a CWE identifier from the rule ID.
// Rule ID convention: AG-NNN[-cwe-NNN][-description].
// Example: "AG-001-cwe-78-rust-command-injection" → "CWE-78".
func cweFromRuleID(ruleID string) string {
	parts := strings.Split(strings.ToLower(ruleID), "-")
	for i, p := range parts {
		if p == "cwe" && i+1 < len(parts) {
			return "CWE-" + parts[i+1]
		}
	}
	return ""
}

// severityFromScore maps a confidence score to an SSVC-inspired SeverityLabel.
func severityFromScore(score float64) finding.SeverityLabel {
	switch {
	case score >= 0.92:
		return finding.SeverityBlock
	case score >= 0.75:
		return finding.SeverityHigh
	case score >= 0.60:
		return finding.SeverityMedium
	case score >= 0.30:
		return finding.SeverityLow
	default:
		return finding.SeveritySuppressed
	}
}
