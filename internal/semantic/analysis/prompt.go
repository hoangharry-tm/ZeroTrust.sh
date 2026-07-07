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

// Package analysis implements Path B Tier 3 — LLM Semantic Reasoning.
package analysis

import (
	"fmt"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

// Prompt structure: SCL+CFP+AIP evidence injection per Tegrity et al. 2023
// "Augmenting LLM Security Analysis with Static Program Analysis Context"
// (USENIX Security Workshop on LLMs for Security).

// buildSCL builds the Security Contract Layer prompt section.
func buildSCL(surface enrichment.EnrichedSurface) string {
	cwe := applicableCWE(surface.Kind)
	if cwe == "" {
		return "=== SECURITY CONTRACT ===\nNo applicable CWE for surface kind " + string(surface.Kind)
	}

	inv, ok := contracts.Rulebook[cwe]
	if !ok {
		return "=== SECURITY CONTRACT ===\nRulebook entry missing for " + cwe
	}

	sinkAnchors := inv.SinkAnchors
	if len(sinkAnchors) > 3 {
		sinkAnchors = sinkAnchors[:3]
	}
	safeNodes := inv.SafeNodes
	if len(safeNodes) > 3 {
		safeNodes = safeNodes[:3]
	}

	var sb strings.Builder
	sb.WriteString("=== SECURITY CONTRACT ===\n")
	sb.WriteString(fmt.Sprintf("CWE: %s — %s\n", inv.CWE, inv.Name))
	sb.WriteString(fmt.Sprintf("Invariant: A %s surface is vulnerable when a user-controlled value reaches %s with no %s on the taint path.\n",
		surface.Kind, sinkAnchors[0], strings.Join(safeNodes, ", ")))
	sb.WriteString(fmt.Sprintf("Reference: %s\n", inv.Reference))
	return sb.String()
}

// buildCFP builds the Control Flow Predicate prompt section.
func buildCFP(surface enrichment.EnrichedSurface) string {
	sinkNodes := surface.SinkNodes
	if len(sinkNodes) > 3 {
		sinkNodes = sinkNodes[:3]
	}

	callPath := surface.CallPath
	if len(callPath) > 10 {
		callPath = callPath[:10]
	}

	sourceFile := surface.File
	if sourceFile == "" {
		sourceFile = "unknown"
	}

	var sb strings.Builder
	sb.WriteString("=== CONTROL FLOW EVIDENCE ===\n")
	sb.WriteString(fmt.Sprintf("Surface kind: %s\n", surface.Kind))
	sb.WriteString(fmt.Sprintf("Source file: %s\n", sourceFile))
	sb.WriteString(fmt.Sprintf("Sink nodes: %s\n", strings.Join(sinkNodes, ", ")))
	sb.WriteString(fmt.Sprintf("Taint path (%d nodes): %s\n", len(surface.CallPath), strings.Join(callPath, " → ")))
	sb.WriteString(fmt.Sprintf("CVE matches: %d (%s)\n", len(surface.CVEMatches), firstOrNone(surface.CVEMatches)))
	sb.WriteString(fmt.Sprintf("IDOR flows: %d detected\n", len(surface.ResourceIDFlows)))
	return sb.String()
}

// buildAIP builds the AI Failure Profile prompt section.
func buildAIP(surface enrichment.EnrichedSurface) string {
	cwe := applicableCWE(surface.Kind)
	profile, ok := aipProfiles[cwe]
	if !ok {
		profile = "No specific failure profile for this CWE."
	}

	var sb strings.Builder
	sb.WriteString("=== AI FAILURE PROFILE ===\n")
	sb.WriteString(profile + "\n")
	return sb.String()
}

// buildPrompt assembles SCL + CFP + AIP into the final prompt.
func buildPrompt(surface enrichment.EnrichedSurface) string {
	scl := buildSCL(surface)
	cfp := buildCFP(surface)
	aip := buildAIP(surface)

	var sb strings.Builder
	sb.WriteString("You are a senior application security engineer performing a code review.\n")
	sb.WriteString("Analyze the following surface for a real, exploitable vulnerability.\n")
	sb.WriteString("Answer ONLY with a JSON object — no prose, no markdown.\n\n")
	sb.WriteString(scl + "\n\n")
	sb.WriteString(cfp + "\n\n")
	sb.WriteString(aip + "\n\n")
	sb.WriteString("Based on the evidence above, is this surface exploitable?\n\n")
	sb.WriteString("Respond with exactly:\n")
	sb.WriteString(`{"exploitable": true|false, "cwe": "<CWE-ID>", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "explanation": "<25 words max>"}`)
	return sb.String()
}

// applicableCWE derives the applicable CWE from SurfaceKind using the same mapping as contracts/check.go.
func applicableCWE(kind targeting.SurfaceKind) string {
	switch kind {
	case targeting.SurfaceExternalInput:
		return "CWE-89"
	case targeting.SurfaceAuthBoundary, targeting.SurfaceIDORCandidate:
		return "CWE-862"
	case targeting.SurfaceDangerousSink:
		return "CWE-327"
	default:
		return ""
	}
}

func firstOrNone(cves []enrichment.CVEMatch) string {
	if len(cves) == 0 {
		return "none"
	}
	return cves[0].CVE
}

var aipProfiles = map[string]string{
	"CWE-89":  "AI models frequently miss second-order SQL injection where user input is stored then later concatenated into a query. Check for indirect taint paths through persistence layers.",
	"CWE-79":  "AI models miss stored XSS where input is persisted and rendered in a different request context. Check for cross-request taint.",
	"CWE-22":  "AI models miss path traversal when normalization appears to happen but uses a non-canonical form (e.g. URL decode after path check). Verify canonicalization order.",
	"CWE-918": "AI models miss SSRF when the URL is constructed from multiple user-controlled fragments. Check for partial taint (host vs path vs query).",
	"CWE-862": "AI models miss broken auth when authorization check is present but applied to the wrong principal or resource type.",
	"CWE-327": "AI models miss weak crypto when a strong algorithm is configured by default but overridden by a user-supplied parameter.",
	"CWE-502": "AI models miss unsafe deserialization when the deserializer appears safe (e.g. Jackson) but is configured with a polymorphic type resolver.",
	"CWE-94":  "AI models miss code injection through template engines or scripting APIs that appear to be data-only interfaces.",
	"CWE-78":  "AI models miss OS command injection through indirect execution (e.g. ProcessBuilder with array args where one element is user-controlled).",
}