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

// Package opengrep wraps the OpenGrep CLI (LGPL-2.1, Semgrep CE fork).
// Implements scanner.Scanner via Name/Supports/Scan.
// When no custom rule dirs are configured, Supports() injects language-specific
// Semgrep registry packs (p/python, p/go, etc.) based on the detected stack.
package opengrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/scanner"
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

var _ scanner.Scanner = (*Runner)(nil)

// Runner invokes OpenGrep as a subprocess against a file set.
type Runner struct {
	// binaryPath is the absolute or PATH-resolved path to the opengrep binary.
	binaryPath string
	// ruleDirs are the directories containing opengrep-compatible YAML rule files.
	// Use multiple dirs to exclude non-opengrep rule formats (e.g. rules/astgrep/).
	ruleDirs []string
	// excludePatterns are opengrep --exclude patterns (glob or directory name).
	// Files matching any pattern are skipped during scanning.
	excludePatterns []string
	logger          *slog.Logger
}

// New returns a Runner using the binary identified by spec and rules at rulesDir.
// If logger is nil, slog.Default() is used.
func New(spec scanner.BinarySpec, rulesDir string, logger *slog.Logger) *Runner {
	return NewMulti(spec, logger, rulesDir)
}

// NewMulti returns a Runner that passes each dir as a separate --config flag.
// Use this to exclude non-opengrep rule formats (e.g. rules/astgrep/).
func NewMulti(spec scanner.BinarySpec, logger *slog.Logger, ruleDirs ...string) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		binaryPath:       spec.Executable(),
		ruleDirs:         ruleDirs,
		excludePatterns:  []string{".github"},
		logger:           logger,
	}
}

// WithExclude sets the exclude patterns for opengrep --exclude flags.
// Each pattern is a glob or directory name. Files matching any pattern are
// skipped. Replaces any previously set patterns. Pass no arguments to clear.
func (r *Runner) WithExclude(patterns ...string) *Runner {
	r.excludePatterns = patterns
	return r
}

// langToPack maps a detected language to its Semgrep registry rule pack.
// Falls back to p/owasp-top-ten when no language-specific pack is available.
var langToPack = map[string]string{
	"python":     "p/python",
	"go":         "p/golang",
	"javascript": "p/javascript",
	"typescript": "p/typescript",
	"java":       "p/java",
	"ruby":       "p/ruby",
	"php":        "p/php",
	"rust":       "p/rust",
	"csharp":     "p/csharp",
	"kotlin":     "p/kotlin",
}

// Name implements scanner.Scanner.
func (r *Runner) Name() string { return "opengrep" }

// Supports implements scanner.Scanner. Always true — opengrep covers every
// language via the owasp-top-ten fallback pack, and adds language-specific
// packs for any detected language.
func (r *Runner) Supports(_ detector.StackProfile) bool { return true }

// ruleLanguagePrefix extracts the language prefix from a Semgrep rule ID.
// e.g. "python.django.security.foo" → "python"
//      "java.spring.security.bar"   → "java"
//      "generic.secrets.foo"        → "generic" (always kept)
func ruleLanguagePrefix(ruleID string) string {
	if i := strings.IndexByte(ruleID, '.'); i > 0 {
		return ruleID[:i]
	}
	return ""
}

// fileLanguage returns the broad language tag for a source file based on extension.
func fileLanguage(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".java", ".kt", ".scala":
		return "java"
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".cs":
		return "csharp"
	case ".html", ".htm":
		return "html"
	}
	return ""
}

// keepFinding returns false for findings that should be discarded:
//  1. Rule language prefix doesn't match the target file's language.
//  2. File is inside a CI/CD config path out of scope for application security.
func keepFinding(f finding.Finding) bool {
	lp := strings.ToLower(f.Path)
	if strings.Contains(lp, "/.github/") || strings.HasPrefix(lp, ".github/") ||
		strings.Contains(lp, "/.circleci/") || strings.Contains(lp, "/bitbucket-pipelines") {
		return false
	}
	ruleLang := ruleLanguagePrefix(f.RuleID)
	if ruleLang == "" || ruleLang == "generic" {
		return true
	}
	fileLang := fileLanguage(f.Path)
	if fileLang == "" {
		return true
	}
	return ruleLang == fileLang
}

// Scan implements scanner.Scanner. It detects the stack from target,
// dynamically selects rule packs, then runs opengrep against the whole target dir.
func (r *Runner) Scan(ctx context.Context, target string) ([]finding.Finding, error) {
	// Derive rule flags: prefer configured dirs; fall back to registry packs.
	configs := r.ruleDirs
	if len(configs) == 0 {
		stack, err := detector.Detect(target)
		if err != nil {
			return nil, fmt.Errorf("opengrep detect stack: %w", err)
		}
		seen := make(map[string]struct{})
		for lang := range stack.Languages {
			if pack, ok := langToPack[lang]; ok {
				if _, dup := seen[pack]; !dup {
					configs = append(configs, pack)
					seen[pack] = struct{}{}
				}
			}
		}
		if len(configs) == 0 {
			configs = []string{"p/owasp-top-ten"}
		}
	}

	// Build args: --json --no-git-ignore [--exclude <pat>]... [--config <cfg>]... <target>
	args := []string{"--json", "--no-git-ignore"}
	for _, p := range r.excludePatterns {
		args = append(args, "--exclude", p)
	}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	args = append(args, target)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// exit 1 with JSON output = findings found; not an error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && stdout.Len() > 0 {
			// fall through to parse
		} else {
			return nil, fmt.Errorf("opengrep: %w (stderr: %s)", err, stderr.String())
		}
	}

	var out ScanOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("opengrep decode: %w", err)
	}
	findings := make([]finding.Finding, 0, len(out.Results))
	for _, raw := range out.Results {
		findings = append(findings, normalise(raw))
	}
	filtered := findings[:0]
	for _, f := range findings {
		if keepFinding(f) {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

// ScanFiles runs OpenGrep against a specific file list and returns normalised findings.
// Used by the legacy runDeterministic incremental flow.
func (r *Runner) ScanFiles(ctx context.Context, files []string) ([]finding.Finding, error) {
	if len(files) == 0 {
		return nil, nil
	}
	// ponytail: opengrep crashes (exit 2) on dotfiles like .gitkeep — skip them
	var scannable []string
	for _, f := range files {
		if base := filepath.Base(f); !strings.HasPrefix(base, ".") {
			scannable = append(scannable, f)
		}
	}
	if len(scannable) == 0 {
		return nil, nil
	}
	out, err := r.run(ctx, scannable)
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
	filtered := findings[:0]
	for _, f := range findings {
		if keepFinding(f) {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

// ponytail: reserved for the Deterministic high-confidence fast path. Not currently
// wired in the pipeline; callers should gate on f.Confidence >= 0.85 instead.
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
	all, err := r.ScanFiles(ctx, files)
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
	args := []string{"--json", "--no-git-ignore"}
	for _, p := range r.excludePatterns {
		args = append(args, "--exclude", p)
	}
	for _, d := range r.ruleDirs {
		args = append(args, "--config", d)
	}
	args = append(args, files...)
	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			// exit 1 = findings found; exit 7 = rule parse errors but still produces JSON
			if code != 1 && code != 7 {
				return nil, fmt.Errorf("opengrep: %w (stderr: %s)", err, stderr.String())
			}
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
	f := finding.New(
		raw.Path,
		finding.LineRange{Start: raw.Start.Line, End: raw.End.Line},
		cweFromMetadata(raw.Extra.Metadata),
		raw.Extra.Message,
		finding.WithMatchedCode(raw.Extra.Lines),
		finding.WithConfidence(confidenceFromMetadata(raw.Extra.Metadata, raw.Extra.Severity)),
		finding.WithSourcePath(finding.SourcePattern),
		finding.WithRuleID(raw.RuleID),
	)
	f.Summary = raw.Extra.Message
	if f.Summary == "" {
		f.Summary = f.RuleID
	}
	if len(f.Summary) > 120 {
		f.Summary = f.Summary[:117] + "..."
	}
	return f
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

