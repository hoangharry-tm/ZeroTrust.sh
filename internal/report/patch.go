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

package report

import (
	"context"
	"fmt"
	"strings"

	"github.com/bluekeyes/go-gitdiff/gitdiff"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/ollama"
)

// PatchStatus constants for patch validation results.
const (
	PatchStatusOK       = "ok"
	PatchStatusMalformed = "malformed"
)

// PatchScope constants for diff size labels (rates from PatchEval benchmark).
const (
	PatchScopeSingleHunk = "single_hunk" // ~22% of LLM-generated patches
	PatchScopeMultiHunk  = "multi_hunk"  // ~12%
	PatchScopeMultiFile  = "multi_file"  // 0–7.7%
)

// ValidatePatch parses patch with go-gitdiff and classifies its scope.
// Returns (PatchStatusMalformed, "", err) if hunk headers are invalid.
// Returns (PatchStatusOK, scope, nil) on success.
func ValidatePatch(patch string) (status, scope string, err error) {
	files, _, parseErr := gitdiff.Parse(strings.NewReader(patch))
	if parseErr != nil {
		return PatchStatusMalformed, "", parseErr
	}
	if len(files) == 0 {
		return PatchStatusMalformed, "", fmt.Errorf("patch contains no file sections")
	}

	fileCount := len(files)
	hunkCount := 0
	for _, f := range files {
		hunkCount += len(f.TextFragments)
	}

	switch {
	case fileCount > 1:
		scope = PatchScopeMultiFile
	case hunkCount > 1:
		scope = PatchScopeMultiHunk
	default:
		scope = PatchScopeSingleHunk
	}
	return PatchStatusOK, scope, nil
}

// GeneratePatch asks Ollama for a zero-shot unified diff fixing f.
// For BLOCK/HIGH findings with a CVE, the CVE and CVSS score are injected
// as few-shot context before the fix request.
// Returns an empty string if patch generation fails or Ollama is unavailable.
func GeneratePatch(ctx context.Context, client *ollama.Client, f finding.Finding) (string, error) {
	resp, err := client.Generate(ctx, buildPatchPrompt(f), &ollama.Options{
		Temperature: 0.1,
		NumPredict:  512,
	})
	if err != nil {
		return "", fmt.Errorf("patch generate: %w", err)
	}
	return extractDiff(resp), nil
}

func buildPatchPrompt(f finding.Finding) string {
	var sb strings.Builder
	if f.CVE != "" && (f.SeverityLabel == finding.SeverityBlock || f.SeverityLabel == finding.SeverityHigh) {
		fmt.Fprintf(&sb, "CVE: %s (CVSS %.1f)\n\n", f.CVE, f.CVSS)
	}
	fmt.Fprintf(&sb,
		"Generate a minimal unified diff (--- a/file +++ b/file format) that fixes this %s security finding.\n",
		f.SeverityLabel,
	)
	fmt.Fprintf(&sb, "File: %s\nCWE: %s\nIssue: %s\n", f.Path, f.CWE, f.Justification)
	if f.MatchedCode != "" {
		fmt.Fprintf(&sb, "Vulnerable code:\n```\n%s\n```\n", f.MatchedCode)
	}
	sb.WriteString("Output ONLY the unified diff, no explanation.")
	return sb.String()
}

// extractDiff returns the first unified diff block from raw LLM output.
// Accepts fenced ```diff blocks or bare --- prefixed output.
func extractDiff(raw string) string {
	if idx := strings.Index(raw, "```"); idx != -1 {
		rest := raw[idx+3:]
		if nl := strings.Index(rest, "\n"); nl != -1 {
			rest = rest[nl+1:]
		}
		if end := strings.Index(rest, "```"); end != -1 {
			return strings.TrimSpace(rest[:end])
		}
	}
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "---") {
		return trimmed
	}
	return strings.TrimSpace(raw)
}
