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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

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
	Metadata map[string]any `json:"metadata"`
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
	logger   *slog.Logger
}

// New returns a Runner using the OpenGrep binary at binaryPath and rules at rulesDir.
// If logger is nil, slog.Default() is used.
//
// Parameters:
//   - binaryPath: path to the opengrep binary (e.g. "opengrep" for PATH lookup).
//   - rulesDir: path to the rules/ directory (e.g. "rules/").
//   - logger: structured logger for per-file parse errors.
func New(binaryPath, rulesDir string, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{binaryPath: binaryPath, rulesDir: rulesDir, logger: logger}
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
	if len(files) == 0 {
		return nil, nil
	}
	out, err := r.run(ctx, files)
	if err != nil {
		return nil, err
	}
	for _, e := range out.Errors {
		r.logger.Warn("opengrep: parse error, file excluded from results",
			"component", "opengrep",
			"path", e.Path,
			"code", e.Code,
			"message", e.Message,
		)
	}
	findings := make([]finding.Finding, 0, len(out.Results))
	for _, raw := range out.Results {
		findings = append(findings, normalise(raw))
	}
	return findings, nil
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
	all, err := r.Scan(ctx, files)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, f := range all {
		if f.Confidence >= 0.85 {
			out = append(out, f)
		}
	}
	return out, nil
}

// Version returns the opengrep binary version string (e.g. "1.87.0").
// Used at startup to log the tool version in the scan header.
//
// Parameters:
//   - ctx: cancellation context.
func (r *Runner) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, r.binaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("opengrep --version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// run invokes opengrep and returns parsed JSON output.
// Exit code 0 (no findings) and exit code 1 (findings found) are both treated
// as success. Exit codes ≥ 2 indicate a real error.
func (r *Runner) run(ctx context.Context, files []string) (*ScanOutput, error) {
	args := append([]string{"--json", "--config", r.rulesDir}, files...)
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit code 1 means findings were found — not an error
		} else {
			return nil, fmt.Errorf("opengrep: %w (stderr: %s)", err, stderr.String())
		}
	}

	var out ScanOutput
	if decErr := json.Unmarshal(stdout.Bytes(), &out); decErr != nil {
		return nil, fmt.Errorf("opengrep: parse output: %w", decErr)
	}
	return &out, nil
}

// normalise converts a RawFinding into a finding.Finding.
// The CWE, confidence, and OWASP category are extracted from Extra.Metadata.
func normalise(raw RawFinding) finding.Finding {
	confidence := confidenceFromMetadata(raw.Extra.Metadata, raw.Extra.Severity)
	cwe := cweFromMetadata(raw.Extra.Metadata)

	id := finding.ComputeID(cwe, raw.Path, raw.Extra.Lines)

	return finding.Finding{
		ID:            id,
		Path:          raw.Path,
		LineRange:     finding.LineRange{Start: raw.Start.Line, End: raw.End.Line},
		CWE:           cwe,
		Confidence:    confidence,
		SeverityLabel: severityFromScore(confidence),
		SourcePath:    finding.SourcePattern,
		Justification: raw.Extra.Message,
		MatchedCode:   raw.Extra.Lines,
		RuleID:        raw.RuleID,
	}
}

// confidenceFromMetadata maps the rule's metadata.confidence string and severity
// to a numeric confidence score used in SSVC-inspired scoring.
//
//	HIGH   → 0.90  (bypasses LLM Verifier at ≥ 0.85)
//	MEDIUM → 0.65
//	LOW    → 0.40
//
// Falls back to severity-based defaults when confidence is not in metadata.
func confidenceFromMetadata(meta map[string]any, severity string) float64 {
	if v, ok := meta["confidence"]; ok {
		switch strings.ToUpper(fmt.Sprint(v)) {
		case "HIGH":
			return 0.90
		case "MEDIUM":
			return 0.65
		case "LOW":
			return 0.40
		}
	}
	switch strings.ToUpper(severity) {
	case "ERROR":
		return 0.65
	case "WARNING":
		return 0.40
	}
	return 0.40
}

// cweFromMetadata extracts the CWE string from the rule metadata.
// Handles both string and slice values (some rules list multiple CWEs).
func cweFromMetadata(meta map[string]any) string {
	v, ok := meta["cwe"]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			return fmt.Sprint(t[0])
		}
	}
	return fmt.Sprint(v)
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
