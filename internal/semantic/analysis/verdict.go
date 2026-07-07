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

package analysis

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
)

// Verdict is the structured JSON response from the LLM for one surface.
type Verdict struct {
	Exploitable bool    `json:"exploitable"`
	CWE         string  `json:"cwe"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}

// parseVerdict extracts the JSON verdict from a raw LLM response.
// Handles leading/trailing prose by scanning for the first '{' and last '}'.
// On parse failure returns a default safe verdict (Exploitable: false) and logs a warning.
func parseVerdict(raw string) Verdict {
	start := strings.IndexByte(raw, '{')
	end := strings.LastIndexByte(raw, '}')
	if start == -1 || end == -1 || start >= end {
		slog.Warn("analysis: no JSON object found in LLM response", "raw", raw)
		return Verdict{Exploitable: false}
	}

	var v Verdict
	if err := json.Unmarshal([]byte(raw[start:end+1]), &v); err != nil {
		slog.Warn("analysis: failed to parse verdict JSON", "err", err, "raw", raw)
		return Verdict{Exploitable: false}
	}
	return v
}

// verdictToFinding converts an exploitable Verdict + surface into a finding.Finding.
func verdictToFinding(surface enrichment.EnrichedSurface, v Verdict) finding.Finding {
	cwe := v.CWE
	if cwe == "" {
		cwe = applicableCWE(surface.Kind)
	}

	severity := severityFromLabel(v.Severity)
	confidence := v.Confidence
	if confidence <= 0 {
		confidence = 0.5
	}

	return finding.Finding{
		ID:            newRunID(),
		CWE:           cwe,
		SeverityLabel: severity,
		Confidence:    confidence,
		Path:          surface.File,
		Justification: v.Explanation,
		SourcePath:    finding.SourceSemantic,
	}
}

// newRunID generates a short unique identifier for a finding.
func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// severityFromLabel maps a verdict severity string to a finding.SeverityLabel.
func severityFromLabel(label string) finding.SeverityLabel {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return finding.SeverityBlock
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}
