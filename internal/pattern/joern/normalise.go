package joern

import (
	"fmt"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// TaintPathToFinding converts a Joern taint path into a canonical Finding.
// The language is used for sink kind → CWE mapping.
// Returns a HIGH-confidence finding (0.75) for Joern-detected taint flows.
func TaintPathToFinding(path cpg.TaintPath, lang Language) finding.Finding {
	// Determine CWE from the sink kind via the language's sink definitions.
	cwe := cweForSinkKind(path.Sink.Kind, lang)

	// Build a concise justification.
	sourceInfo := fmt.Sprintf("%s (%s:%d)", path.Source.Kind, path.Source.File, path.Source.Line)
	sinkInfo := fmt.Sprintf("%s (%s:%d)", string(path.Sink.Kind), path.Sink.File, path.Sink.Line)
	justification := fmt.Sprintf("Taint flow from %s to sink %s", sourceInfo, sinkInfo)
	if path.Sanitized {
		justification += " [sanitized path]"
	}

	return finding.Finding{
		Path:      path.Sink.File,
		LineRange: finding.LineRange{Start: path.Sink.Line, End: path.Sink.Line},
		CWE:       cwe,
		SeverityLabel: finding.SeverityHigh,
		Confidence:    0.75,
		SourcePath:    finding.SourcePattern,
		Justification: justification,
		MatchedCode:   "",
		RuleID:        fmt.Sprintf("JOERN-TAINT-%s", string(path.Sink.Kind)),
		SSVC: finding.SSVCDimensions{
			Exploitation:    "None",
			Automatable:     "Yes",
			TechnicalImpact: "Partial",
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
