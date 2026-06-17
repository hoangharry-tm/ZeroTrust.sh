// Package astgrep wraps the ast-grep CLI (MIT, Tree-sitter-based).
//
// ast-grep covers languages where OpenGrep has weak or absent community rule packs:
// Dart, Swift, Rust, and newer languages. Language routing is strictly partitioned —
// OpenGrep and ast-grep never run the same rules on the same files.
//
// Rule directories follow the layout in rules/astgrep/:
//
//	rules/astgrep/AG-001-rust-command-injection.yaml
//	rules/astgrep/AG-002-go-sql-sprintf.yaml   (Go supplemental rules only)
//
// ast-grep outputs NDJSON (one JSON object per match). Each line is decoded into
// a RawMatch and normalised into a finding.Finding before being returned to the caller.
package astgrep

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// RawMatch is a single JSON object in ast-grep's NDJSON output stream.
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
// It invokes: ast-grep scan --json <files...> --config <rulesDir>
// stdout is decoded as NDJSON; each RawMatch is normalised into a finding.Finding.
//
// Parameters:
//   - ctx: cancellation context; the subprocess is killed if ctx is cancelled.
//   - files: relative file paths to scan (the ChangeSet.Changed list, pre-filtered
//     to languages that ast-grep owns per the language routing table).
//
// Returns:
//   - []finding.Finding: normalised findings from all matched rules.
//   - error: non-nil if the subprocess fails to start or produces unparseable output.
func (r *Runner) Scan(ctx context.Context, files []string) ([]finding.Finding, error) {
	// implemented in G2.M2.4
	return nil, nil
}

// FilterFiles returns the subset of files that ast-grep owns based on file extension.
// Languages: Rust (.rs), Dart (.dart), Swift (.swift), and any language not claimed
// by OpenGrep. This enforces the strict language partitioning between the two tools.
//
// Parameters:
//   - files: the full changed file list from ChangeSet.Changed.
//
// Returns:
//   - []string: files whose language falls in ast-grep's ownership set.
func FilterFiles(files []string) []string {
	// implemented in G2.M2.4
	return nil
}

// Version returns the ast-grep binary version string (e.g. "0.26.0").
// Used at startup to log the tool version in the scan header.
//
// Parameters:
//   - ctx: cancellation context.
func (r *Runner) Version(ctx context.Context) (string, error) {
	// implemented in G2.M2.4
	return "", nil
}

// normalise converts a RawMatch into a finding.Finding.
// Line numbers are converted from 0-based (ast-grep) to 1-based (finding.LineRange).
// CWE and confidence metadata are read from the rule's YAML metadata block.
func normalise(raw RawMatch) finding.Finding {
	// implemented in G2.M2.4
	return finding.Finding{}
}
