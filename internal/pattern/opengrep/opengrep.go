// Package opengrep wraps the OpenGrep CLI (LGPL-2.1, Semgrep CE fork).
//
// OpenGrep runs against the changed file set from the Differential Indexer and
// emits structural pattern findings routed to the LLM Verifier.
//
// Language routing: OpenGrep owns its strong language rule packs (Python, Java,
// JavaScript/TypeScript, Go, Ruby, PHP). ast-grep handles the gaps (Dart, Swift,
// Rust, newer languages). The same file is never scanned by both tools.
//
// High-confidence rules (tagged confidence: high in the rule YAML) bypass the
// LLM Verifier and are sent directly to the dedup layer as confirmed findings.
// All other findings pass through the Verifier for false-positive filtering.
//
// Rule directories follow the layout in rules/:
//
//	rules/python/    PY-001–PY-010
//	rules/java/      JV-001–JV-009
//	rules/generic/   AI agent instruction file rules
package opengrep

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// RawFinding is the JSON structure emitted by OpenGrep's --json output.
// It is unmarshalled from the subprocess stdout before normalisation.
type RawFinding struct {
	// RuleID is the OpenGrep rule identifier (e.g. "PY-001").
	RuleID string `json:"check_id"`
	// Path is the source file path as reported by OpenGrep.
	Path string `json:"path"`
	// Start and End locate the match within the file.
	Start RawPosition `json:"start"`
	End   RawPosition `json:"end"`
	// Extra contains the match message, severity, and metadata.
	Extra RawExtra `json:"extra"`
}

// RawPosition is the line/column location within a source file.
type RawPosition struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// RawExtra contains the per-rule metadata fields from OpenGrep JSON output.
type RawExtra struct {
	// Message is the human-readable description from the rule's `message:` field.
	Message string `json:"message"`
	// Severity is the rule-declared severity: "ERROR" | "WARNING" | "INFO".
	Severity string `json:"severity"`
	// Metadata contains arbitrary key-value pairs from the rule's `metadata:` block.
	// Expected keys: cwe, confidence, owasp.
	Metadata map[string]interface{} `json:"metadata"`
	// Lines is the matched source snippet.
	Lines string `json:"lines"`
}

// ScanOutput is the top-level JSON structure produced by `opengrep --json`.
type ScanOutput struct {
	Results []RawFinding `json:"results"`
	Errors  []RawError   `json:"errors"`
}

// RawError is an OpenGrep execution error (e.g. parse failure on a source file).
type RawError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

// Runner invokes OpenGrep as a subprocess against a file set.
type Runner struct {
	// binaryPath is the absolute or PATH-resolved path to the opengrep binary.
	binaryPath string
	// rulesDir is the directory containing the YAML rule files for OpenGrep.
	rulesDir string
}

// New returns a Runner using the OpenGrep binary at binaryPath and rules at rulesDir.
//
// Parameters:
//   - binaryPath: path to the opengrep binary (e.g. "opengrep" for PATH lookup).
//   - rulesDir: path to the rules/ directory (e.g. "rules/").
func New(binaryPath, rulesDir string) *Runner {
	return &Runner{binaryPath: binaryPath, rulesDir: rulesDir}
}

// Scan runs OpenGrep against files and returns normalised findings.
//
// It invokes: opengrep --json --config <rulesDir> <files...>
// The subprocess stdout is parsed as ScanOutput JSON and each RawFinding is
// normalised into a finding.Finding.
//
// Parameters:
//   - ctx: cancellation context; the subprocess is killed if ctx is cancelled.
//   - files: relative file paths to scan (the ChangeSet.Changed list).
//
// Returns:
//   - []finding.Finding: normalised findings from all matched rules.
//   - error: non-nil if the subprocess fails to start or returns a non-zero exit code.
func (r *Runner) Scan(ctx context.Context, files []string) ([]finding.Finding, error) {
	// implemented in G2.M2.4
	return nil, nil
}

// ScanHighConfidence runs a scan restricted to rules tagged confidence: high.
// Results are intended to bypass the LLM Verifier and go directly to dedup.
//
// Parameters:
//   - ctx: cancellation context.
//   - files: relative file paths to scan.
//
// Returns:
//   - []finding.Finding: only findings from high-confidence rules.
//   - error: non-nil on subprocess or parse failure.
func (r *Runner) ScanHighConfidence(ctx context.Context, files []string) ([]finding.Finding, error) {
	// implemented in G2.M2.4
	return nil, nil
}

// Version returns the opengrep binary version string (e.g. "1.87.0").
// Used at startup to log the tool version in the scan header.
//
// Parameters:
//   - ctx: cancellation context.
func (r *Runner) Version(ctx context.Context) (string, error) {
	// implemented in G2.M2.4
	return "", nil
}

// normalise converts a RawFinding into a finding.Finding.
// The CWE, confidence, and OWASP category are extracted from Extra.Metadata.
func normalise(raw RawFinding) finding.Finding {
	// implemented in G2.M2.4
	return finding.Finding{}
}
