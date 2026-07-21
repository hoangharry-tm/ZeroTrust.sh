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

package cpg_engine

import (
	"fmt"
	"os"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// TaintPathToFinding converts a Joern taint path into a canonical Finding.
// The language is used for sink kind → CWE mapping.
// Returns a HIGH-confidence finding (0.75) for Joern-detected taint flows.
func TaintPathToFinding(path TaintPath, lang Language) finding.Finding {
	cwe := cweForSinkKind(path.Sink.Kind, lang)

	sourceInfo := fmt.Sprintf("%s (%s:%d)", path.Source.Kind, path.Source.File, path.Source.Line)
	sinkInfo := fmt.Sprintf("%s (%s:%d)", string(path.Sink.Kind), path.Sink.File, path.Sink.Line)
	justification := fmt.Sprintf("Taint flow from %s to sink %s", sourceInfo, sinkInfo)
	if path.Sanitized {
		justification += " [sanitized path]"
	}

	matchedCode := extractSnippet(path.Sink.File, path.Sink.Line)

	return finding.New(
		path.Sink.File,
		finding.LineRange{Start: path.Sink.Line, End: path.Sink.Line},
		cwe,
		justification,
		finding.WithConfidence(0.75),
		finding.WithSourcePath(finding.SourcePattern),
		finding.WithRuleID(fmt.Sprintf("JOERN-TAINT-%s", string(path.Sink.Kind))),
		finding.WithMatchedCode(matchedCode),
		finding.WithSSVC(finding.SSVCDimensions{
			Exploitation:    "None",
			Automatable:     ssvcAutomatable(path.Sink.Kind),
			TechnicalImpact: ssvcTechnicalImpact(path.Sink.Kind),
		}),
		finding.WithPoeContext(&finding.PoeContext{
			SourceNode: path.Source.NodeID,
			SinkNode:   path.Sink.NodeID,
			TaintPathSummary: fmt.Sprintf("source (%s:%d) → sink (%s:%d) via %d intermediate nodes",
				path.Source.File, path.Source.Line,
				path.Sink.File, path.Sink.Line,
				len(path.IntermediateNodes)),
			RequiredConditions: fmt.Sprintf("Untrusted input reaches %s sink without validation",
				string(path.Sink.Kind)),
		}),
	)
}

// ssvcAutomatable maps a sink kind to its SSVC Automatable dimension.
// SQL injection, command injection, and eval are scriptable ("Yes").
// File writes and deserialization require context-specific payloads ("No").
func ssvcAutomatable(kind SinkKind) string {
	switch kind {
	case SinkSQL, SinkCommand, SinkEval:
		return "Yes"
	case SinkFileWrite, SinkDeserialization, SinkTemplate, SinkRedirect:
		return "No"
	default:
		return "No"
	}
}

// ssvcTechnicalImpact maps a sink kind to its SSVC Technical Impact dimension.
func ssvcTechnicalImpact(kind SinkKind) string {
	switch kind {
	case SinkSQL, SinkCommand, SinkDeserialization, SinkEval:
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
func TaintPathsToFindings(paths []TaintPath, lang Language) []finding.Finding {
	if len(paths) == 0 {
		return nil
	}
	result := make([]finding.Finding, 0, len(paths))
	for _, p := range paths {
		result = append(result, TaintPathToFinding(p, lang))
	}
	return result
}

// cweForSinkKind maps a SinkKind to a CWE identifier.
// First checks the language-specific sink definitions; falls back to a
// language-agnostic default.
func cweForSinkKind(kind SinkKind, lang Language) string {
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
	case SinkSQL:
		return "CWE-89"
	case SinkCommand:
		return "CWE-78"
	case SinkDeserialization:
		return "CWE-502"
	case SinkFileWrite:
		return "CWE-22"
	case SinkTemplate:
		return "CWE-1336"
	case SinkRedirect:
		return "CWE-601"
	case SinkEval:
		return "CWE-94"
	default:
		return "CWE-200"
	}
}
