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

// Package finding defines the canonical Finding type and the channel through which
// all pipeline stages communicate. This interface is locked before G2 begins;
// both detection paths and the dedup layer depend on it.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Confidence thresholds that map a score to a SeverityLabel.
// Inline here so finding stays independent of tuning/policy packages.
const (
	confBlock  = 0.92
	confHigh   = 0.75
	confMedium = 0.60
	confLow    = 0.30
)

// SeverityLabel is the SSVC-inspired five-tier output label.
//
// Threshold mapping (confidence scores):
//
//	BLOCK      ≥ 0.92
//	HIGH     0.75 – 0.91
//	MEDIUM   0.60 – 0.74
//	LOW      0.30 – 0.59
//	SUPPRESSED < 0.30 (or explicit suppression)
//
// A cross-path boost of +15 pp (capped at 1.0) is applied when both Path A
// and Path B confirm the same finding.
type SeverityLabel int

// SeverityLabel constants ordered from highest to lowest severity.
const (
	SeverityBlock SeverityLabel = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeveritySuppressed
)

// String returns the canonical uppercase string representation.
func (s SeverityLabel) String() string {
	switch s {
	case SeverityBlock:
		return "BLOCK"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeveritySuppressed:
		return "SUPPRESSED"
	default:
		return "UNKNOWN"
	}
}

// GoString returns the qualified Go-style identifier for debugging.
func (s SeverityLabel) GoString() string {
	switch s {
	case SeverityBlock:
		return "finding.SeverityBlock"
	case SeverityHigh:
		return "finding.SeverityHigh"
	case SeverityMedium:
		return "finding.SeverityMedium"
	case SeverityLow:
		return "finding.SeverityLow"
	case SeveritySuppressed:
		return "finding.SeveritySuppressed"
	default:
		return "finding.SeverityLabel(" + strings.TrimPrefix(
			fmt.Sprintf("%d", int(s)), "",
		) + ")"
	}
}

// MarshalJSON keeps JSON output as the canonical uppercase string.
func (s SeverityLabel) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON reads from the canonical uppercase string.
func (s *SeverityLabel) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "BLOCK":
		*s = SeverityBlock
	case "HIGH":
		*s = SeverityHigh
	case "MEDIUM":
		*s = SeverityMedium
	case "LOW":
		*s = SeverityLow
	case "SUPPRESSED":
		*s = SeveritySuppressed
	}
	return nil
}

// SourcePath identifies which detection path produced a finding.
type SourcePath string

// SourcePath constants identifying which detection path(s) produced a finding.
const (
	SourcePattern  SourcePath = "PATTERN"  // Path A only
	SourceSemantic SourcePath = "SEMANTIC" // Path B only
	SourceBoth     SourcePath = "BOTH"     // confirmed by both paths
)

// SuppressReason describes why a finding was suppressed rather than reported.
// It is always set when SeverityLabel == SeveritySuppressed.
type SuppressReason string

const (
	// SuppressReasonUncertain means the LLM returned an uncertain verdict.
	SuppressReasonUncertain SuppressReason = "uncertain"
	// Deprecated: budget controller no longer gates analysis — surfaces are never
	// suppressed for budget exhaustion. This constant remains for backward
	// compatibility with existing DB records.
	SuppressReasonBudgetExhausted SuppressReason = "budget_exhausted"
	// SuppressReasonTestFile means the finding is in a recognised test file pattern.
	SuppressReasonTestFile SuppressReason = "test_file"
	// SuppressReasonFrameworkSafe means a framework-level control was detected.
	SuppressReasonFrameworkSafe SuppressReason = "framework_safe"
	// SuppressReasonUserAck means the user manually acknowledged this finding.
	SuppressReasonUserAck SuppressReason = "user_acknowledged"
	// SuppressReasonSafe means the LLM concluded the surface is not vulnerable.
	SuppressReasonSafe SuppressReason = "safe"
	// SuppressReasonFalsePositive means the LLM Verifier determined the finding is a false positive.
	SuppressReasonFalsePositive SuppressReason = "false_positive"
)

// PoEStatus tracks the outcome of the Proof-of-Exploitability attempt (Approach 3).
type PoEStatus string

// PoEStatus constants for the seven possible exploitation attempt outcomes.
const (
	PoENotAttempted        PoEStatus = "not_attempted"        // not BLOCK/HIGH or CWE not eligible
	PoESuccess             PoEStatus = "success"              // exploit triggered the vulnerable path
	PoEFailedNoEffect      PoEStatus = "failed_no_effect"     // exploit ran but caused no observable effect
	PoEFailedSandbox       PoEStatus = "failed_sandbox"       // sandbox execution error; static evidence only
	PoEFailedTimeout       PoEStatus = "failed_timeout"       // exceeded 3-attempt / time limit
	PoEInconclusive        PoEStatus = "inconclusive"         // result is ambiguous
	PoELanguageUnsupported PoEStatus = "language_unsupported" // no sandbox runner for this language
)

// LineRange is an inclusive line span within a source file.
type LineRange struct {
	// Start is the first line of the finding (1-based).
	Start int
	// End is the last line (1-based). Equal to Start for single-line findings.
	End int
}

// SSVCDimensions carries the three SSVC-inspired scoring inputs for a finding.
// Values are sourced from CISA KEV / EPSS / NVD (Exploitation),
// a CWE automatable-exploitation table (Automatable), and CVSS / CWE map (TechnicalImpact).
type SSVCDimensions struct {
	// Exploitation reflects active exploitation evidence: "Active" | "PoC" | "None".
	Exploitation string
	// Automatable reflects whether exploitation can be scripted: "Yes" | "No".
	Automatable string
	// TechnicalImpact reflects the worst-case outcome: "Total" | "Partial".
	TechnicalImpact string
}

// PoeContext carries the structured exploit context consumed by Approach 3's
// PoE Eligibility Classifier and Red Team Agent.
type PoeContext struct {
	// SourceNode is the CPG identifier of the untrusted data source.
	SourceNode string
	// SinkNode is the CPG identifier of the dangerous data sink.
	SinkNode string
	// TaintPathSummary is a human-readable description of the taint propagation path.
	TaintPathSummary string
	// RequiredConditions lists the preconditions an attacker must satisfy to reach the sink.
	RequiredConditions string
}

// PoEResult is the Proof-of-Exploitability output from Approach 3's sandbox layer.
type PoEResult struct {
	// Status describes the outcome of the exploitation attempt.
	Status PoEStatus
	// ExploitInput is the crafted input used in the final attempt (may be empty).
	ExploitInput string
	// Confidence is the Red Team Agent's self-reported confidence (0.0–1.0).
	Confidence float64
	// BusinessImpactTier is the constrained enum for the executive summary:
	// "Critical" | "High" | "Medium" | "Low".
	BusinessImpactTier string
	// DevTrace is the technical exploit trace for developers.
	DevTrace string
	// ExecSummary is the constrained natural-language summary for managers.
	ExecSummary string
}

// Finding is the normalised vulnerability record produced by both detection paths
// and consumed by the dedup layer, the HTML report, and the PoE layer.
//
// A Finding is immutable after it is emitted onto a Channel. The dedup layer
// creates new Finding values when merging duplicates (e.g. upgrading SourcePath
// from PATTERN to BOTH and applying the +15 pp cross-path confidence boost).
type Finding struct {
	// ID is the stable dedup hash: hex(SHA-256(CWE + ":" + Path + ":" + CodeFingerprint)).
	ID string `json:"ID"`
	// SurfaceID is the CPG node ID of the surface that produced this finding.
	// Used to correlate B5 LLM findings back to their B3 violation origin.
	// Empty for Path A findings.
	SurfaceID string `json:"SurfaceID"`
	// Path is the file path relative to the project root.
	Path string `json:"Path"`
	// LineRange is the inclusive line span of the vulnerable code.
	LineRange LineRange `json:"LineRange"`
	// CWE is the primary CWE identifier (e.g. "CWE-89" for SQL injection).
	CWE string `json:"CWE"`
	// SeverityLabel is the SSVC-inspired five-tier output label.
	SeverityLabel SeverityLabel `json:"SeverityLabel"`
	// Confidence is the composite score (0.0–1.0) used to derive SeverityLabel.
	Confidence float64 `json:"Confidence"`
	// SourcePath identifies which detection path(s) produced this finding.
	SourcePath SourcePath `json:"SourcePath"`
	// SuppressReason is set when SeverityLabel == SeveritySuppressed; empty otherwise.
	SuppressReason SuppressReason `json:"SuppressReason"`
	// Justification is the human-readable explanation of the finding.
	Justification string `json:"Justification"`
	// DCCEvidence is the raw DCC structural contract match string (pipeline-internal).
	// Stored separately from Justification so the report can display them independently.
	// Empty for Path A findings.
	DCCEvidence string `json:"DCCEvidence"`
	// Summary is the short human-readable one-sentence description of the finding
	// for use as the report card title. For Path B findings this is the B5 LLM
	// explanation (≤25 words). For Path A findings this is the rule description.
	// Falls back to the first sentence of Justification if empty.
	Summary string `json:"Summary"`
	// MatchedCode is the source snippet at the finding location.
	MatchedCode string `json:"MatchedCode"`
	// RuleID is the OpenGrep / ast-grep rule identifier that matched (Path A only).
	// Empty for Path B findings.
	RuleID string `json:"RuleID"`
	// CVE is the primary CVE identifier (e.g. "CVE-2021-44228"); empty when no CVE match.
	// Populated for Path B findings that passed through the enrichment stage.
	CVE string `json:"CVE"`
	// CVSS is the CVSS v3 base score (0.0–10.0) for the primary CVE; 0.0 when no CVE match.
	CVSS float64 `json:"CVSS"`
	// SSVC carries the three SSVC-inspired scoring dimensions.
	SSVC SSVCDimensions `json:"SSVC"`
	// PoeContext carries the structured exploit context (non-nil from Approach 2+).
	PoeContext *PoeContext `json:"PoeContext"`
	// PoEResult is the sandbox exploitation result (Approach 3 only; nil otherwise).
	PoEResult *PoEResult `json:"PoEResult"`
	// Patch is the zero-shot unified diff fix suggestion (empty when not generated).
	Patch string `json:"Patch"`
	// PatchStatus is the validation result: "ok" | "malformed" | "" (not generated).
	PatchStatus string `json:"PatchStatus"`
	// PatchScope is the diff scope label: "single_hunk" | "multi_hunk" | "multi_file" | "".
	PatchScope string `json:"PatchScope"`
	// TaintMismatch is true when the LLM found no taint path in code despite
	// the static analysis claim. Used by the B5 violation confirmation loop
	// to suppress false-positive B3 violations.
	TaintMismatch bool `json:"TaintMismatch"`
	// Exploitable is the LLM's binary verdict on exploitability.
	Exploitable bool `json:"Exploitable"`
	// SeverityPinned is true when an upstream stage has explicitly set SeverityLabel
	// and dedup must not recalculate it from confidence.
	SeverityPinned bool `json:"-"`
}

// Channel is a typed channel through which pipeline stages emit findings.
// Producers should constrain their parameter to chan<- Finding (send-only);
// consumers should constrain theirs to <-chan Finding (receive-only).
// Producers close the channel when they have no more findings to emit.
type Channel chan Finding

// SeverityFromConfidence maps a composite confidence score (0.0–1.0) to the
// canonical SSVC-inspired five-tier SeverityLabel. All pipeline stages that
// need to derive a label from a score must use this function so the thresholds
// stay in exactly one place.
func SeverityFromConfidence(confidence float64) SeverityLabel {
	switch {
	case confidence >= confBlock:
		return SeverityBlock
	case confidence >= confHigh:
		return SeverityHigh
	case confidence >= confMedium:
		return SeverityMedium
	case confidence >= confLow:
		return SeverityLow
	default:
		return SeveritySuppressed
	}
}

// LangFromPath returns the canonical language name for a source file path.
// Used by dedup (tree-sitter AST edit distance) and enrichment (classifier routing).
// Returns "unknown" for unrecognised extensions; callers that need a non-empty
// fallback (e.g. tree-sitter) should substitute their own default.
func LangFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".go":
		return "go"
	case ".js", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".rs":
		return "rust"
	case ".kt", ".kts":
		return "kotlin"
	case ".swift":
		return "swift"
	case ".cs":
		return "csharp"
	default:
		return "unknown"
	}
}

// Option is a functional option for New.
type Option func(*Finding)

// WithCVE sets the CVE identifier.
func WithCVE(cve string) Option { return func(f *Finding) { f.CVE = cve } }

// WithCVSS sets the CVSS v3 base score.
func WithCVSS(score float64) Option { return func(f *Finding) { f.CVSS = score } }

// WithRuleID sets the RuleID field.
func WithRuleID(id string) Option { return func(f *Finding) { f.RuleID = id } }

// WithMatchedCode stores the code snippet that triggered the finding.
func WithMatchedCode(code string) Option { return func(f *Finding) { f.MatchedCode = code } }

// WithConfidence overrides the default confidence score.
func WithConfidence(c float64) Option {
	return func(f *Finding) {
		f.Confidence = c
		f.SeverityLabel = SeverityFromConfidence(c)
	}
}

// WithSourcePath sets the detection path label.
func WithSourcePath(sp SourcePath) Option { return func(f *Finding) { f.SourcePath = sp } }

// WithSSVC sets the SSVC scoring dimensions.
func WithSSVC(dims SSVCDimensions) Option { return func(f *Finding) { f.SSVC = dims } }

// WithPoeContext sets the taint path context for PoE analysis.
func WithPoeContext(pc *PoeContext) Option { return func(f *Finding) { f.PoeContext = pc } }

// New constructs a Finding with the given path, line range, CWE, and
// justification message. Optional metadata is applied via opts.
// SeverityLabel defaults to SeverityLow; use WithConfidence to update both.
func New(path string, lr LineRange, cwe, justification string, opts ...Option) Finding {
	f := Finding{
		Path:          path,
		LineRange:     lr,
		CWE:           cwe,
		Justification: justification,
		Confidence:    confLow,
		SeverityLabel: SeverityLow,
	}
	f.ID = ComputeID(cwe, path, "")
	for _, o := range opts {
		o(&f)
	}
	// Recompute ID after opts may have set MatchedCode.
	f.ID = ComputeID(f.CWE, f.Path, f.MatchedCode)
	return f
}

// ComputeID returns the canonical stable dedup hash for a finding.
// All producers (opengrep, ast-grep, Path B) must use this function so that
// Gate 1 dedup and cross-path confidence boosting recognise the same finding
// regardless of which path produced it.
//
// Formula: hex(SHA-256(CWE + ":" + path + ":" + matchedCode))
func ComputeID(cwe, path, matchedCode string) string {
	sum := sha256.Sum256([]byte(cwe + ":" + path + ":" + matchedCode))
	return hex.EncodeToString(sum[:])
}
