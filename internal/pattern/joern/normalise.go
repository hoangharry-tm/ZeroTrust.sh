package joern

import (
	"fmt"
	"os"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// TaintPathToFinding converts a Joern taint path into a canonical Finding.
// The language is used for sink kind → CWE mapping.
// Returns a HIGH-confidence finding (0.75) for Joern-detected taint flows.
func TaintPathToFinding(path cpg.TaintPath, lang Language) finding.Finding {
	cwe := cweForSinkKind(path.Sink.Kind, lang)

	sourceInfo := fmt.Sprintf("%s (%s:%d)", path.Source.Kind, path.Source.File, path.Source.Line)
	sinkInfo := fmt.Sprintf("%s (%s:%d)", string(path.Sink.Kind), path.Sink.File, path.Sink.Line)
	justification := fmt.Sprintf("Taint flow from %s to sink %s", sourceInfo, sinkInfo)
	if path.Sanitized {
		justification += " [sanitized path]"
	}

	// Extract source snippet from the sink file at the sink line.
	matchedCode := extractSnippet(path.Sink.File, path.Sink.Line)

	confidence := 0.75
	severityLabel := finding.SeverityFromConfidence(confidence)

	return finding.Finding{
		Path:      path.Sink.File,
		LineRange: finding.LineRange{Start: path.Sink.Line, End: path.Sink.Line},
		CWE:       cwe,
		SeverityLabel: severityLabel,
		Confidence:    confidence,
		SourcePath:    finding.SourcePattern,
		Justification: justification,
		MatchedCode:   matchedCode,
		RuleID:        fmt.Sprintf("JOERN-TAINT-%s", string(path.Sink.Kind)),
		SSVC: finding.SSVCDimensions{
			Exploitation:    "None",
			Automatable:     ssvcAutomatable(path.Sink.Kind),
			TechnicalImpact: ssvcTechnicalImpact(path.Sink.Kind),
		},
		PoeContext: &finding.PoeContext{
			SourceNode: path.Source.NodeID,
			SinkNode:   path.Sink.NodeID,
			TaintPathSummary: fmt.Sprintf("source (%s:%d) → sink (%s:%d) via %d intermediate nodes",
				path.Source.File, path.Source.Line,
				path.Sink.File, path.Sink.Line,
				len(path.IntermediateNodes)),
			RequiredConditions: fmt.Sprintf("Untrusted input reaches %s sink without validation",
				string(path.Sink.Kind)),
		},
	}
}

// ssvcAutomatable maps a sink kind to its SSVC Automatable dimension.
// SQL injection, command injection, and eval are scriptable ("Yes").
// File writes and deserialization require context-specific payloads ("No").
func ssvcAutomatable(kind cpg.SinkKind) string {
	switch kind {
	case cpg.SinkSQL, cpg.SinkCommand, cpg.SinkEval:
		return "Yes"
	case cpg.SinkFileWrite, cpg.SinkDeserialization, cpg.SinkTemplate, cpg.SinkRedirect:
		return "No"
	default:
		return "No"
	}
}

// ssvcTechnicalImpact maps a sink kind to its SSVC Technical Impact dimension.
func ssvcTechnicalImpact(kind cpg.SinkKind) string {
	switch kind {
	case cpg.SinkSQL, cpg.SinkCommand, cpg.SinkDeserialization, cpg.SinkEval:
		return "Total"
	default:
		return "Partial"
	}
}

// extractSnippet reads a single line from a source file. Returns empty string
// if the file cannot be read or the line is out of range.
func extractSnippet(filePath string, line int) string {
	if filePath == "" || line < 1 {
		return ""
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(content), "\n")
	if line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}

// TaintPathsToFindings converts a slice of Joern taint paths into Findings.
// The ID is computed after conversion using ComputeID.
func TaintPathsToFindings(paths []cpg.TaintPath, lang Language) []finding.Finding {
	if len(paths) == 0 {
		return nil
	}
	result := make([]finding.Finding, 0, len(paths))
	for _, p := range paths {
		f := TaintPathToFinding(p, lang)
		f.ID = finding.ComputeID(f.CWE, f.Path, f.Justification)
		result = append(result, f)
	}
	return result
}

// cweForSinkKind maps a SinkKind to a CWE identifier.
// First checks the language-specific sink definitions; falls back to a
// language-agnostic default.
func cweForSinkKind(kind cpg.SinkKind, lang Language) string {
	// For paths produced by the taxonomy, the CWE is embedded in the sink
	// definition. For paths produced by Joern's default dataflow, we guess
	// from the SinkKind.
	if lang != "" {
		cfg, ok := TaintConfigs[lang]
		if ok {
			for _, s := range cfg.Sinks {
				if s.Kind == kind {
					return s.CWE
				}
			}
		}
	}
	switch kind {
	case cpg.SinkSQL:
		return "CWE-89"
	case cpg.SinkCommand:
		return "CWE-78"
	case cpg.SinkDeserialization:
		return "CWE-502"
	case cpg.SinkFileWrite:
		return "CWE-22"
	case cpg.SinkTemplate:
		return "CWE-1336"
	case cpg.SinkRedirect:
		return "CWE-601"
	case cpg.SinkEval:
		return "CWE-94"
	default:
		return "CWE-200"
	}
}
