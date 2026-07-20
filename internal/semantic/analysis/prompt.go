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
	"os"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

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

// Prompt structure: SCL+CFP+AIP evidence injection per Tegrity et al. 2023
// "Augmenting LLM Security Analysis with Static Program Analysis Context"
// (USENIX Security Workshop on LLMs for Security).

// buildSCL builds the Security Contract Layer prompt section.
func buildSCL(surface enrichment.EnrichedSurface) string {
	cwe := surface.ContractCWE
	if cwe == "" {
		cwe = applicableCWE(surface.Kind)
	}
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
	fmt.Fprintf(&sb, "CWE: %s — %s\n", inv.CWE, inv.Name)
	fmt.Fprintf(&sb, "Invariant: A %s surface is vulnerable when a user-controlled value reaches %s with no %s on the taint path.\n",
	surface.Kind, sinkAnchors[0], strings.Join(safeNodes, ", "))
	fmt.Fprintf(&sb, "Reference: %s\n", inv.Reference)
	return sb.String()
}

// buildCFP builds the Control Flow Predicate prompt section.
// Sink nodes are filtered to only those relevant to the surface's contract CWE,
// preventing cross-CWE contamination (e.g. executeQuery appearing in CWE-862 prompts).
func buildCFP(surface enrichment.EnrichedSurface) string {
	sinkNodes := filterSinksByCWE(surface.SinkNodes, surface.ContractCWE)
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
	fmt.Fprintf(&sb, "Surface kind: %s\n", surface.Kind)
	fmt.Fprintf(&sb, "Source file: %s\n", shortPath(sourceFile))
	if len(sinkNodes) > 0 {
		fmt.Fprintf(&sb, "Sink nodes: %s\n", strings.Join(sinkNodes, ", "))
	}
	fmt.Fprintf(&sb, "Taint path (%d nodes): %s\n", len(surface.CallPath), strings.Join(callPath, " → "))
	fmt.Fprintf(&sb, "CVE matches: %d (%s)\n", len(surface.CVEMatches), firstOrNone(surface.CVEMatches))
	fmt.Fprintf(&sb, "IDOR flows: %d detected\n", len(surface.ResourceIDFlows))
	return sb.String()
}

// filterSinksByCWE returns only the sink nodes that are relevant to the given
// CWE contract. A sink node is relevant if it contains (case-insensitive substring
// match) any of the CWE's registered SinkAnchors. If cwe is empty or unknown,
// all sinks are returned unfiltered. If the intersection is empty, nil is returned
// so the caller can omit the sink line entirely.
func filterSinksByCWE(sinks []string, cwe string) []string {
	if len(sinks) == 0 {
		return nil
	}
	inv, ok := contracts.Rulebook[cwe]
	if !ok || len(inv.SinkAnchors) == 0 {
		return sinks
	}
	var filtered []string
	for _, sink := range sinks {
		sinkLower := strings.ToLower(sink)
		for _, anchor := range inv.SinkAnchors {
			if strings.Contains(sinkLower, strings.ToLower(anchor)) {
				filtered = append(filtered, sink)
				break
			}
		}
	}
	return filtered
}

// buildAIP builds the AI Failure Profile prompt section.
func buildAIP(surface enrichment.EnrichedSurface) string {
	cwe := surface.ContractCWE
	if cwe == "" {
		cwe = applicableCWE(surface.Kind)
	}
	profile, ok := aipProfiles[cwe]
	if !ok {
		profile = "No specific failure profile for this CWE."
	}

	var sb strings.Builder
	sb.WriteString("=== AI FAILURE PROFILE ===\n")
	sb.WriteString(profile)
	sb.WriteString("\n")
	return sb.String()
}

// buildPrompt assembles the mode-appropriate prompt for the given surface.
func buildPrompt(surface enrichment.EnrichedSurface, mode, root string) string {
	switch mode {
	case "small":
		return buildPromptSmall(surface, root)
	case "frontier":
		return buildPromptFrontier(surface, root)
	default:
		return buildPromptMid(surface, root)
	}
}

// buildPromptSmall builds a minimal prompt for ≤7B models — no SCL/AIP overhead.
func buildPromptSmall(surface enrichment.EnrichedSurface, root string) string {
	var sb strings.Builder
	sb.WriteString("Does this function contain an exploitable security vulnerability?\n")
	sb.WriteString("Do NOT use knowledge of the project name or framework.\n")
	sb.WriteString("Base your answer ONLY on the code below.\n\n")
	sb.WriteString("taint_mismatch: set true ONLY IF the sink method is absent from BOTH the\n")
	sb.WriteString("  function source code AND the sink context block (if provided above).\n")
	sb.WriteString("  If a 'SINK CONTEXT' block is shown, the taint reaches that code — do NOT\n")
	sb.WriteString("  set taint_mismatch=true based on the function body alone.\n\n")
	if surface.Code != "" {
		code := stripIndent(surface.Code)
		if len(code) > 500 {
			code = code[:500] + "\n...[truncated]"
		}
		sb.WriteString("```\n")
		sb.WriteString(code)
		sb.WriteString("\n```\n\n")
	}
	if surface.SinkFile != "" && surface.SinkLine > 0 {
		sinkCode := readSinkContext(root, surface.SinkFile, surface.SinkLine, 5)
		if sinkCode != "" {
			sb.WriteString("=== SINK CONTEXT (where tainted data is consumed) ===\n")
			sb.WriteString(sinkCode)
			sb.WriteString("\n")
		}
	}
	sb.WriteString(`Reply with exactly: {"exploitable": true|false, "cwe": "<CWE-ID>", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "explanation": "<25 words max>", "taint_mismatch": true|false}`)
	return sb.String()
}

// buildPromptMid builds a prompt with externalized step scaffold for 7B–30B models.
func buildPromptMid(surface enrichment.EnrichedSurface, root string) string {
	scl := buildSCL(surface)
	cfp := buildCFP(surface)
	aip := buildAIP(surface)

	var sb strings.Builder
	sb.WriteString("You are a senior application security engineer performing a code review.\n")
	sb.WriteString("Analyze the following surface for a real, exploitable vulnerability.\n")
	sb.WriteString("Base your answer ONLY on the source code and static analysis evidence provided below.\n")
	sb.WriteString("Do NOT use prior knowledge about the project name, framework reputation, or codebase.\n")
	sb.WriteString("If the provided evidence is insufficient to confirm exploitability, return exploitable=false.\n")
	sb.WriteString("Answer ONLY with a JSON object — no prose, no markdown.\n\n")
	sb.WriteString(scl)
	sb.WriteString("\n\n")
	sb.WriteString(cfp)
	sb.WriteString("\n\n")
	if surface.Code != "" {
		code := stripIndent(surface.Code)
		if len(code) > 2000 {
			code = code[:2000] + "\n... [truncated]"
		}
		sb.WriteString("=== FUNCTION SOURCE CODE ===\n")
		sb.WriteString(code)
		sb.WriteString("\n\n")
	}
	if surface.SinkFile != "" && surface.SinkLine > 0 {
		sinkCode := readSinkContext(root, surface.SinkFile, surface.SinkLine, 5)
		if sinkCode != "" {
			sb.WriteString("=== SINK CONTEXT (where tainted data is consumed) ===\n")
			sb.WriteString(sinkCode)
			sb.WriteString("\n")
		}
	}
	sb.WriteString(aip)
	sb.WriteString("\n\n")
	if surface.TaintConfidence == "weak" {
		sb.WriteString("NOTE: No inter-procedural taint path was confirmed for this surface. ")
		sb.WriteString("Reason from code structure and the CWE-")
		sb.WriteString(surface.ContractCWE)
		sb.WriteString(" contract only.\n\n")
	}
	sb.WriteString("Follow these steps in order — do NOT skip any:\n")
	sb.WriteString("Step 1: Read the Security Contract. What is the CWE and invariant?\n")
	sb.WriteString("Step 2: Check the Taint Path. Does it reach a sink anchor listed in the contract?\n")
	sb.WriteString("Step 3: Read the Source Code. Does the code confirm OR contradict the taint path?\n")
	sb.WriteString("  - taint_mismatch: set true ONLY IF the sink method is absent from BOTH the\n")
	sb.WriteString("    function source code AND the sink context block (if provided above).\n")
	sb.WriteString("    If a 'SINK CONTEXT' block is shown, the taint reaches that code — do NOT\n")
	sb.WriteString("    set taint_mismatch=true based on the function body alone.\n")
	sb.WriteString("  - If code confirms taint path: continue to Step 4\n")
	sb.WriteString("Step 4: Check for safe nodes. Is there a sanitizer/guard on the taint path in the code?\n")
	sb.WriteString("Step 5: Emit your verdict as JSON.\n\n")
	sb.WriteString("IMPORTANT: Base your answer ONLY on the evidence above. Do NOT use prior knowledge about the project name, framework, or codebase. If evidence is insufficient, return exploitable=false.\n\n")
	sb.WriteString(`Respond with exactly: {"exploitable": true|false, "cwe": "<CWE-ID>", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "explanation": "<25 words max>", "taint_mismatch": true|false}`)
	return sb.String()
}

// buildPromptFrontier builds a full prompt for frontier models (>30B or API)
// with CoT, few-shot examples, and Think & Verify instruction.
func buildPromptFrontier(surface enrichment.EnrichedSurface, root string) string {
	scl := buildSCL(surface)
	cfp := buildCFP(surface)
	aip := buildAIP(surface)

	var sb strings.Builder
	sb.WriteString("You are a senior application security engineer performing a code review.\n")
	sb.WriteString("Analyze the following surface for a real, exploitable vulnerability.\n")
	sb.WriteString("Base your answer ONLY on the source code and static analysis evidence provided below.\n")
	sb.WriteString("Do NOT use prior knowledge about the project name, framework reputation, or codebase.\n")
	sb.WriteString("If the provided evidence is insufficient to confirm exploitability, return exploitable=false.\n")
	sb.WriteString("Answer ONLY with a JSON object — no prose, no markdown.\n\n")
	sb.WriteString(scl)
	sb.WriteString("\n\n")
	sb.WriteString(cfp)
	sb.WriteString("\n\n")
	if surface.Code != "" {
		code := stripIndent(surface.Code)
		if len(code) > 2000 {
			code = code[:2000] + "\n... [truncated]"
		}
		sb.WriteString("=== FUNCTION SOURCE CODE ===\n")
		sb.WriteString(code)
		sb.WriteString("\n\n")
	}
	if surface.SinkFile != "" && surface.SinkLine > 0 {
		sinkCode := readSinkContext(root, surface.SinkFile, surface.SinkLine, 5)
		if sinkCode != "" {
			sb.WriteString("=== SINK CONTEXT (where tainted data is consumed) ===\n")
			sb.WriteString(sinkCode)
			sb.WriteString("\n")
		}
	}
	sb.WriteString(aip)
	sb.WriteString("\n\n")
	if surface.TaintConfidence == "weak" {
		sb.WriteString("NOTE: No inter-procedural taint path was confirmed for this surface. ")
		sb.WriteString("Reason from code structure and the CWE-")
		sb.WriteString(surface.ContractCWE)
		sb.WriteString(" contract only.\n\n")
	}
	sb.WriteString("taint_mismatch: set true ONLY IF the sink method is absent from BOTH the\n")
	sb.WriteString("  function source code AND the sink context block (if provided above).\n")
	sb.WriteString("  If a 'SINK CONTEXT' block is shown, the taint reaches that code — do NOT\n")
	sb.WriteString("  set taint_mismatch=true based on the function body alone.\n\n")
	sb.WriteString("=== FEW-SHOT EXAMPLES ===\n")
	sb.WriteString("Example 1 (TRUE POSITIVE):\n")
	sb.WriteString("Code: stmt.executeQuery(\"SELECT * FROM users WHERE id='\" + userId + \"'\")\n")
	sb.WriteString("Verdict: {\"exploitable\":true,\"cwe\":\"CWE-89\",\"severity\":\"HIGH\",\"confidence\":0.95,\"explanation\":\"User input directly concatenated into SQL query.\",\"taint_mismatch\":false}\n\n")
	sb.WriteString("Example 2 (TAINT MISMATCH — sink absent from code):\n")
	sb.WriteString("Code: return ResponseEntity.ok(user.getProfile());\n")
	sb.WriteString("Taint path claims sink: executeQuery\n")
	sb.WriteString("Verdict: {\"exploitable\":false,\"cwe\":\"\",\"severity\":\"LOW\",\"confidence\":0.95,\n")
	sb.WriteString("\"explanation\":\"executeQuery not present in source; taint path mis-attributed.\",\n")
	sb.WriteString("\"taint_mismatch\":true}\n\n")
	sb.WriteString("Example 3 (NOT exploitable, but NOT a mismatch — use low confidence):\n")
	sb.WriteString("Code: stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");\n")
	sb.WriteString("      stmt.setString(1, userId);\n")
	sb.WriteString("Verdict: {\"exploitable\":false,\"cwe\":\"CWE-89\",\"severity\":\"LOW\",\"confidence\":0.95,\n")
	sb.WriteString("\"explanation\":\"Parameterized query correctly prevents SQL injection.\",\n")
	sb.WriteString("\"taint_mismatch\":false}\n\n")
	sb.WriteString("IMPORTANT: Base your answer ONLY on the evidence above. Do NOT use prior knowledge about the project name, framework reputation, or codebase. Treat this as anonymous code.\n\n")
	sb.WriteString(`Respond with exactly: {"exploitable": true|false, "cwe": "<CWE-ID>", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "explanation": "<25 words max>", "taint_mismatch": true|false}`)
	return sb.String()
}

// obfuscateCode strips structural identity signals from code before LLM injection.
// It removes package declarations, import blocks, line/block comments, and blanks
// string literal contents — eliminating project-name leakage without knowing the
// project name. Language-agnostic: works on Java, Go, Python, JS, etc.
func obfuscateCode(code string) string {
	var out strings.Builder
	lines := strings.Split(code, "\n")
	inBlockComment := false
	inImportBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track block comment state (/* ... */)
		if inBlockComment {
			if strings.Contains(trimmed, "*/") {
				inBlockComment = false
			}
			continue
		}
		if strings.Contains(trimmed, "/*") && !strings.Contains(trimmed, "*/") {
			inBlockComment = true
			continue
		}

		// Strip package declarations (Java: "package x.y.z;", Go: "package foo")
		if strings.HasPrefix(trimmed, "package ") {
			continue
		}

		// Strip import blocks (Java multi-line: "import (", Go single: "import x")
		if strings.HasPrefix(trimmed, "import ") || trimmed == "import (" {
			inImportBlock = trimmed == "import ("
			continue
		}
		if inImportBlock {
			if trimmed == ")" {
				inImportBlock = false
			}
			continue
		}

		// Strip line comments: // and # (any language), -- only when followed by
		// a space (SQL convention). "--identifier" is a decrement op, not a comment.
		isComment := strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "-- ")
		if isComment {
			continue
		}
		if trimmed == "" {
			continue
		}

		// Blank string literal contents while preserving structure.
		// "hello world" → ""   'x' → ''
		// Keeps quotes so concatenation patterns remain visible.
		line = blankStringLiterals(line)

		out.WriteString(line)
		out.WriteByte('\n')
	}
	return strings.TrimSpace(out.String())
}

// blankStringLiterals replaces the contents of double and single-quoted string
// literals with empty strings, preserving the quote characters themselves.
// This removes project-identifying string values (log messages, URLs, class names
// embedded in strings) while keeping the structural shape of the code.
func blankStringLiterals(line string) string {
	var out strings.Builder
	i := 0
	for i < len(line) {
		ch := line[i]
		// Detect start of string literal
		if ch == '"' || ch == '\'' {
			quote := ch
			out.WriteByte(quote) // opening quote
			i++
			// Skip content until closing (unescaped) quote
			for i < len(line) {
				c := line[i]
				if c == '\\' {
					i += 2 // skip escape sequence
					continue
				}
				if c == quote {
					break
				}
				i++
			}
			if i < len(line) {
				out.WriteByte(quote) // closing quote
				i++
			}
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

// readSinkContext returns ±contextLines lines around lineNum in filePath.
// Returns "" on any read error (best-effort). The sink line is prefixed with →.
func readSinkContext(root, filePath string, lineNum, contextLines int) string {
	if root != "" && !filepath.IsAbs(filePath) {
		filePath = filepath.Join(root, filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	start := max(0, lineNum-1-contextLines)
	end := min(len(lines), lineNum+contextLines)
	var out strings.Builder
	for i := start; i < end; i++ {
		marker := "  "
		if i == lineNum-1 {
			marker = "→ "
		}
		fmt.Fprintf(&out, "%s%d: %s\n", marker, i+1, lines[i])
	}
	return out.String()
}

// applicableCWE derives the applicable CWE from SurfaceKind using the same mapping as contracts/check.go.
func applicableCWE(kind targeting.SurfaceKind) string {
	switch kind {
	case targeting.SurfaceExternalInput:
		return "CWE-89"
	case targeting.SurfaceIDORCandidate:
		return "CWE-862"
	case targeting.SurfaceAuthBoundary:
		return "CWE-862"
	case targeting.SurfaceDangerousSink:
		return "CWE-327"
	default:
		return ""
	}
}

// stripIndent removes leading whitespace from each line to cut prompt token waste.
func stripIndent(code string) string {
	lines := strings.Split(code, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimLeft(l, " \t")
	}
	return strings.Join(lines, "\n")
}

// shortPath returns the last 2 path segments joined by "/".
// If the path has fewer than 2 segments, it is returned as-is.
func shortPath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) <= 2 {
		return p
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

func firstOrNone(cves []enrichment.CVEMatch) string {
	if len(cves) == 0 {
		return "none"
	}
	return cves[0].CVE
}

