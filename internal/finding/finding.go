// Package finding defines the canonical Finding type and the channel through which
// all pipeline stages communicate. This interface is locked before G2 begins;
// both detection paths and the dedup layer depend on it.
package finding

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
type SeverityLabel string

// SeverityLabel constants ordered from highest to lowest severity.
const (
	SeverityBlock      SeverityLabel = "BLOCK"
	SeverityHigh       SeverityLabel = "HIGH"
	SeverityMedium     SeverityLabel = "MEDIUM"
	SeverityLow        SeverityLabel = "LOW"
	SeveritySuppressed SeverityLabel = "SUPPRESSED"
)

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
	// SuppressReasonBudgetExhausted means the surface exceeded the token budget cap.
	SuppressReasonBudgetExhausted SuppressReason = "budget_exhausted"
	// SuppressReasonTestFile means the finding is in a recognised test file pattern.
	SuppressReasonTestFile SuppressReason = "test_file"
	// SuppressReasonFrameworkSafe means a framework-level control was detected.
	SuppressReasonFrameworkSafe SuppressReason = "framework_safe"
	// SuppressReasonUserAck means the user manually acknowledged this finding.
	SuppressReasonUserAck SuppressReason = "user_acknowledged"
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
	ID string
	// Path is the file path relative to the project root.
	Path string
	// LineRange is the inclusive line span of the vulnerable code.
	LineRange LineRange
	// CWE is the primary CWE identifier (e.g. "CWE-89" for SQL injection).
	CWE string
	// SeverityLabel is the SSVC-inspired five-tier output label.
	SeverityLabel SeverityLabel
	// Confidence is the composite score (0.0–1.0) used to derive SeverityLabel.
	Confidence float64
	// SourcePath identifies which detection path(s) produced this finding.
	SourcePath SourcePath
	// SuppressReason is set when SeverityLabel == SeveritySuppressed; empty otherwise.
	SuppressReason SuppressReason
	// Justification is the human-readable explanation of the finding.
	Justification string
	// MatchedCode is the source snippet at the finding location.
	MatchedCode string
	// RuleID is the OpenGrep / ast-grep rule identifier that matched (Path A only).
	// Empty for Path B findings.
	RuleID string
	// SSVC carries the three SSVC-inspired scoring dimensions.
	SSVC SSVCDimensions
	// PoeContext carries the structured exploit context (non-nil from Approach 2+).
	PoeContext *PoeContext
	// PoEResult is the sandbox exploitation result (Approach 3 only; nil otherwise).
	PoEResult *PoEResult
}

// Channel is the typed channel through which pipeline stages emit findings.
// Producers close the channel when they have no more findings to emit.
type Channel chan Finding
