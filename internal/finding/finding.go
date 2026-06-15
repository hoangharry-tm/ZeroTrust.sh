// Package finding defines the canonical Finding type and the channel through which
// all pipeline stages communicate. This interface is locked before G2 begins;
// both detection paths and the dedup layer depend on it.
package finding

// SeverityLabel is the SSVC-inspired five-tier output label.
type SeverityLabel string

const (
	SeverityBlock      SeverityLabel = "BLOCK"
	SeverityHigh       SeverityLabel = "HIGH"
	SeverityMedium     SeverityLabel = "MEDIUM"
	SeverityLow        SeverityLabel = "LOW"
	SeveritySuppressed SeverityLabel = "SUPPRESSED"
)

// SourcePath identifies which detection path produced this finding.
type SourcePath string

const (
	SourcePattern  SourcePath = "PATTERN"
	SourceSemantic SourcePath = "SEMANTIC"
	SourceBoth     SourcePath = "BOTH"
)

// LineRange is an inclusive line span within a source file.
type LineRange struct {
	Start int
	End   int
}

// SSVCDimensions carries the three SSVC-inspired scoring inputs for this finding.
type SSVCDimensions struct {
	Exploitation    string // "Active" | "PoC" | "None"
	Automatable     string // "Yes" | "No"
	TechnicalImpact string // "Total" | "Partial"
}

// PoeContext carries the structured exploit context consumed by Approach 3's
// PoE Eligibility Classifier and Red Team Agent.
type PoeContext struct {
	SourceNode         string
	SinkNode           string
	TaintPathSummary   string
	RequiredConditions string
}

// Finding is the normalised vulnerability record produced by both detection paths
// and consumed by the dedup layer, the HTML report, and the PoE layer.
type Finding struct {
	ID            string
	Path          string
	LineRange     LineRange
	CWE           string
	SeverityLabel SeverityLabel
	Confidence    float64
	SourcePath    SourcePath
	Reason        string // populated when SeverityLabel == SeveritySuppressed
	Justification string
	MatchedCode   string
	SSVC          SSVCDimensions
	PoeContext    *PoeContext // nil for Approaches 1–2
}

// Channel is the typed channel through which pipeline stages emit findings.
type Channel chan Finding
