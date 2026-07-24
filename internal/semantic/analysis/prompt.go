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

// Package analysis implements Reasoning Tier 3 — LLM Semantic Reasoning.
package analysis

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

// Prompt text lives in prompts/*.md(.tmpl) — edit those files, not this one.
// b5Tmpl is the full B5 analysis prompt scaffold (instructions, step-by-step
// reasoning, few-shot examples); aipProfilesMD holds one CWE-keyed section
// per AI-failure-mode note, parsed once at init.
//
//go:embed prompts/b5_analysis.md.tmpl
var b5PromptSrc string

//go:embed prompts/aip_profiles.md
var aipProfilesMD string

var b5Tmpl = template.Must(template.New("b5_analysis").Parse(b5PromptSrc))

var aipSectionHeader = regexp.MustCompile(`(?m)^## (CWE-[0-9]+)\s*$`)

// parseAIPProfiles splits aip_profiles.md on "## CWE-NNN" headers into a
// CWE -> profile-text map. Panics on a malformed file (init-time, no valid
// production run reaches here without a well-formed prompts/aip_profiles.md).
func parseAIPProfiles(md string) map[string]string {
	locs := aipSectionHeader.FindAllStringSubmatchIndex(md, -1)
	if len(locs) == 0 {
		panic("analysis: prompts/aip_profiles.md has no \"## CWE-NNN\" sections")
	}
	profiles := make(map[string]string, len(locs))
	for i, loc := range locs {
		cwe := md[loc[2]:loc[3]]
		bodyStart := loc[1]
		bodyEnd := len(md)
		if i+1 < len(locs) {
			bodyEnd = locs[i+1][0]
		}
		profiles[cwe] = strings.TrimSpace(md[bodyStart:bodyEnd])
	}
	return profiles
}

var aipProfiles = parseAIPProfiles(aipProfilesMD)

// Prompt structure: SCL+CFP+AIP evidence injection per Tegrity et al. 2023
// "Augmenting LLM Security Analysis with Static Program Analysis Context"
// (USENIX Security Workshop on LLMs for Security).

// buildSCL builds the Security Contract Layer prompt section.
func buildSCL(surface enrichment.EnrichedSurface) string {
	slog.Debug("building SCL prompt section",
		"surface_id", surface.ID, "cwe", surface.ContractCWE)
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

	var sb strings.Builder
	sb.WriteString("=== SECURITY CONTRACT ===\n")
	fmt.Fprintf(&sb, "CWE: %s — %s\n", inv.CWE, inv.Name)
	if inv.NoSinkModel {
		// No fixed dangerous-API signature for this CWE class (see
		// contracts.Invariant.NoSinkModel doc) — describe the invariant in
		// terms of what Targeting already established structurally, instead
		// of a sink-anchor list that doesn't exist for this CWE.
		fmt.Fprintf(&sb, "Invariant: A %s surface is vulnerable when a user-controlled value reaches this surface's operation with no authorization check confirmed on the path INTO this surface (by this function or any caller). There is no fixed dangerous-API signature for %s — reason from the actual code and call chain, not a keyword list.\n",
			surface.Kind, cwe)
	} else {
		sinkAnchors := inv.SinkAnchors
		if len(sinkAnchors) > 3 {
			sinkAnchors = sinkAnchors[:3]
		}
		safeNodes := inv.SafeNodes
		if len(safeNodes) > 3 {
			safeNodes = safeNodes[:3]
		}
		fmt.Fprintf(&sb, "Invariant: A %s surface is vulnerable when a user-controlled value reaches %s with no %s on the taint path.\n",
			surface.Kind, sinkAnchors[0], strings.Join(safeNodes, ", "))
	}
	fmt.Fprintf(&sb, "Reference: %s\n", inv.Reference)
	return sb.String()
}

// buildCFP builds the Control Flow Predicate prompt section.
// Sink nodes are filtered to only those relevant to the surface's contract CWE,
// preventing cross-CWE contamination (e.g. executeQuery appearing in CWE-862 prompts).
func buildCFP(surface enrichment.EnrichedSurface) string {
	slog.Debug("building CFP prompt section",
		"surface_id", surface.ID, "sink_count", len(surface.SinkNodes))
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
	// This surface's own CPG node ID — required so a get_callers/get_callees
	// tool call actually resolves. Without this, the model has no way to know
	// the real ID (a raw CPG identifier, not a file:function-name string) and
	// will guess a plausible-looking wrong one, silently getting an empty
	// result back and mistaking "the tool call was malformed" for "no callers
	// exist" (observed in a live end-to-end test against a real Ollama server
	// and cached CPG data before this line was added).
	if surface.ID != "" {
		fmt.Fprintf(&sb, "This surface's CPG node ID: %s (use this exact value as function_id when calling get_callers/get_callees on this surface itself)\n", surface.ID)
	}
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
// all sinks are returned unfiltered. If the CWE has NoSinkModel (no dangerous-API
// signature — e.g. CWE-862), sinks are dropped entirely rather than shown
// unfiltered: generic sink names like executeQuery/readObject are Joern's
// global taint-sink taxonomy, not evidence relevant to missing-authorization
// reasoning, and showing them implies a relevance that isn't there. If the
// intersection is empty, nil is returned so the caller can omit the sink line.
func filterSinksByCWE(sinks []string, cwe string) []string {
	if len(sinks) == 0 {
		return nil
	}
	inv, ok := contracts.Rulebook[cwe]
	if !ok {
		return sinks
	}
	if inv.NoSinkModel {
		return nil
	}
	if len(inv.SinkAnchors) == 0 {
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
	slog.Debug("building AIP prompt section",
		"surface_id", surface.ID, "cwe", surface.ContractCWE)
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

// b5PromptData is the template data for prompts/b5_analysis.md.tmpl.
type b5PromptData struct {
	SCL                   string
	CFP                   string
	Code                  string
	SinkContext           string
	AIP                   string
	WeakTaintNote         bool
	ContractCWE           string
	RequiresInvestigation bool
	SurfaceID             string
}

// buildPrompt assembles the B5 analysis prompt: SCL+CFP+AIP evidence injected
// into the externalized scaffold at prompts/b5_analysis.md.tmpl (instructions,
// step-by-step reasoning, few-shot examples). This is the one prompt strategy
// — no per-model tiers. Edit prompts/b5_analysis.md.tmpl to change wording;
// this function only supplies the dynamic evidence fields.
func buildPrompt(surface enrichment.EnrichedSurface, root string) string {
	slog.Debug("building B5 analysis prompt",
		"surface_id", surface.ID, "has_code", surface.Code != "")

	data := b5PromptData{
		SCL:                   buildSCL(surface),
		CFP:                   buildCFP(surface),
		AIP:                   buildAIP(surface),
		WeakTaintNote:         surface.TaintConfidence == "weak",
		ContractCWE:           surface.ContractCWE,
		RequiresInvestigation: requiresInvestigation(surface.ContractCWE),
		SurfaceID:             surface.ID,
	}

	if surface.Code != "" {
		code := minifyCode(stripIndent(surface.Code))
		const budget = 4000 // headroom raised alongside NumCtx=16384 (analysisOpts)
		if len(code) > budget {
			// Prefer a window centred on the sink line over blind head-truncation
			// — a long function with its vulnerable call near the end would
			// otherwise have the actual sink cut off entirely while the model
			// still confidently reasons about the (irrelevant) surviving head.
			if surface.SinkFile == surface.File && surface.SinkLine > 0 && surface.SinkLine >= surface.Line {
				code = truncateAroundLine(code, surface.SinkLine-surface.Line, budget)
			} else {
				code = truncateUTF8(code, budget) + "\n... [truncated]"
			}
		}
		data.Code = code
	}

	if surface.SinkFile != "" && surface.SinkLine > 0 {
		data.SinkContext = readSinkContext(root, surface.SinkFile, surface.SinkLine, 5)
	}

	var sb strings.Builder
	if err := b5Tmpl.Execute(&sb, data); err != nil {
		// Template is embedded and validated at init (template.Must); a
		// runtime execution error here means a code/template field mismatch,
		// not bad input — fail loudly rather than send a broken prompt.
		panic("analysis: b5_analysis.md.tmpl execute: " + err.Error())
	}
	return sb.String()
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

// truncateUTF8 returns the first n bytes of s, backing up to the nearest
// rune boundary if n would otherwise split a multi-byte UTF-8 character.
// Plain code[:n] byte-slicing corrupts non-ASCII text — comments/strings in
// Chinese, Japanese, Vietnamese etc. are common in real codebases — sending
// a truncated multi-byte sequence to the LLM as invalid UTF-8 mid-token.
func truncateUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// minifyCode drops blank lines and comment-only lines (a line that, after
// trimming, is entirely a // or # line comment) to cut token waste without
// touching anything that could carry vulnerability-relevant meaning.
//
// Deliberately conservative — this is NOT a general code minifier:
//   - Trailing inline comments (`x := f() // note`) are left alone: safely
//     detecting where code ends and a comment begins without a real
//     per-language tokenizer risks mangling string literals containing "//"
//     or "#" (URLs, regexes, shell one-liners).
//   - Block comments (/* ... */, docstrings) are left alone for the same
//     reason — no cheap, safe way to detect them without a real parser.
//   - Log/print statements are deliberately NOT stripped. They're sometimes
//     the actual sink (CWE-532 sensitive-data-in-logs; format-string bugs in
//     some ecosystems), and stripping them risks deleting the exact
//     vulnerability being searched for to save a handful of tokens — not a
//     trade worth making.
//
// Comment-only and blank lines are unconditionally safe to drop: Chinese/
// Japanese/Vietnamese comment-heavy codebases (litemall, this session's
// benchmark target, is a good example) can be 20-30% comment-only lines,
// and dropping them is pure token savings with zero information loss.
func minifyCode(code string) string {
	lines := strings.Split(code, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// truncateAroundLine returns a budget-byte window of code centred on
// targetLine (0-indexed), rather than the head of the string. A long
// function whose sink call is near the end would otherwise have the actual
// vulnerable line silently cut off by a naive head-truncation while the
// model still confidently reasons over the (now irrelevant) surviving head.
func truncateAroundLine(code string, targetLine, budget int) string {
	lines := strings.Split(code, "\n")
	if targetLine < 0 {
		targetLine = 0
	}
	if targetLine >= len(lines) {
		targetLine = len(lines) - 1
	}

	// Expand outward from targetLine, alternating tail/head, until the
	// window would exceed budget bytes.
	lo, hi := targetLine, targetLine
	size := len(lines[targetLine])
	for {
		grew := false
		if hi+1 < len(lines) && size+len(lines[hi+1])+1 <= budget {
			hi++
			size += len(lines[hi]) + 1
			grew = true
		}
		if lo-1 >= 0 && size+len(lines[lo-1])+1 <= budget {
			lo--
			size += len(lines[lo]) + 1
			grew = true
		}
		if !grew {
			break
		}
	}

	var sb strings.Builder
	if lo > 0 {
		sb.WriteString("... [truncated head]\n")
	}
	sb.WriteString(strings.Join(lines[lo:hi+1], "\n"))
	if hi < len(lines)-1 {
		sb.WriteString("\n... [truncated tail]")
	}
	return sb.String()
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
