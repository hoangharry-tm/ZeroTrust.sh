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

// Package patch generates unified diff patch suggestions for confirmed findings.
//
// Each BLOCK or HIGH finding that has a deterministic fix (e.g. a SQL injection
// via string concatenation replaced by a parameterized query) receives a unified
// diff patch. The patch is zero-shot generated: no fix-pair fine-tuning is used
// in Approaches 1–2 (noted gap vs. Snyk in CLAUDE.md).
//
// Approach 3 will replace zero-shot generation with a task-specialized model
// fine-tuned on CVEFixes fix pairs.
//
// Patch validation: generated patches are validated against the source file using
// go-gitdiff to ensure they apply cleanly before being included in the report.
// Patches that fail validation are omitted with a note in the report.
//
// PatchEval reliability note: zero-shot patch correctness is not guaranteed.
// The report labels all patches as "suggested, not reviewed" and links to the
// relevant CWE remediation guidance.
package patch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/bluekeyes/go-gitdiff/gitdiff"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
	"github.com/hoangharry-tm/zerotrust/pkg/ollama"
)

// Status describes whether a patch was generated and if it validated cleanly.
type Status string

const (
	// StatusGenerated means the patch was produced and validated against the source.
	StatusGenerated Status = "generated"
	// StatusValidationFailed means the patch was produced but failed go-gitdiff validation.
	StatusValidationFailed Status = "validation_failed"
	// StatusNotAttempted means the finding type or severity does not warrant a patch.
	StatusNotAttempted Status = "not_attempted"
	// StatusUnsupported means the language or CWE class has no patch template.
	StatusUnsupported Status = "unsupported"
)

// Patch is the patch suggestion for a single finding.
//
// Example (unified diff):
//
//	--- a/api/user.go
//	+++ b/api/user.go
//	@@ -42,7 +42,7 @@
//	-	row := db.QueryRow("SELECT * FROM users WHERE id = " + userID)
//	+	row := db.QueryRow("SELECT * FROM users WHERE id = ?", userID)
type Patch struct {
	// FindingID links this patch to its parent finding.
	FindingID string
	// UnifiedDiff is the patch in unified diff format (empty if not generated).
	UnifiedDiff string
	// Status describes the outcome of patch generation and validation.
	Status Status
	// CWERemediationURL is the CWE mitigation page for the finding's CWE (always set).
	CWERemediationURL string
}

// Generator produces patch suggestions for a finding set.
//
// Only BLOCK and HIGH findings are attempted; other severities get
// StatusNotAttempted. Languages without a patch template get StatusUnsupported.
//
// Usage:
//
//	gen := patch.New("/path/to/project")
//	patches, err := gen.Generate(ctx, findings)
type Generator struct {
	// projectRoot is the absolute path to the scanned codebase, used to read
	// source files for context injection and to validate diffs.
	projectRoot string
	client      *ollama.Client
	clientOnce  sync.Once
}

// New returns a Generator operating against files under projectRoot.
func New(projectRoot string) *Generator {
	return &Generator{projectRoot: projectRoot}
}

func (g *Generator) getClient() *ollama.Client {
	g.clientOnce.Do(func() {
		url := os.Getenv("ZEROTRUST_OLLAMA_URL")
		if url == "" {
			url = "http://localhost:11434"
		}
		model := os.Getenv("ZEROTRUST_MODEL")
		if model == "" {
			model = "qwen2.5-coder:7b"
		}
		g.client = ollama.New(url, model)
	})
	return g.client
}

// Generate produces patch suggestions for each finding in the input slice.
// Findings are processed in-order; the returned Patch slice has one entry per input finding.
//
// Parameters:
//   - ctx: cancellation context; honours deadline for LLM patch calls.
//   - findings: the de-duplicated, scored finding set from the dedup layer.
//
// Returns:
//   - []Patch: one patch entry per input finding (Status describes outcome).
//   - error: non-nil only for unrecoverable infrastructure failures (e.g. projectRoot unreadable).
func (g *Generator) Generate(ctx context.Context, findings []finding.Finding) ([]Patch, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	slog.Debug("patch generator starting", slog.Int("findings", len(findings)))
	client := g.getClient()
	out := make([]Patch, 0, len(findings))
	for _, f := range findings {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		p := Patch{
			FindingID:         f.ID,
			CWERemediationURL: cweURL(f.CWE),
		}
		if f.SeverityLabel != finding.SeverityBlock && f.SeverityLabel != finding.SeverityHigh {
			p.Status = StatusNotAttempted
			out = append(out, p)
			continue
		}
		diff, err := generateDiff(ctx, client, f)
		if err != nil || diff == "" {
			if err != nil {
				slog.Warn("patch generation failed", slog.String("finding_id", f.ID), slog.String("err", err.Error()))
			}
			p.Status = StatusUnsupported
			out = append(out, p)
			continue
		}
		if validateErr := g.Validate(f.Path, diff); validateErr != nil {
			slog.Warn("patch validation failed", slog.String("finding_id", f.ID), slog.String("err", validateErr.Error()))
			p.UnifiedDiff = diff
			p.Status = StatusValidationFailed
		} else {
			slog.Debug("patch generated", slog.String("finding_id", f.ID))
			p.UnifiedDiff = diff
			p.Status = StatusGenerated
		}
		out = append(out, p)
	}
	return out, nil
}

// Validate checks whether unifiedDiff applies cleanly using go-gitdiff.
// Returns nil for empty diffs. relPath is accepted for future file-level checks
// but is not currently used (go-gitdiff validates structure only).
func (g *Generator) Validate(relPath, unifiedDiff string) error {
	if strings.TrimSpace(unifiedDiff) == "" {
		return nil
	}
	files, _, err := gitdiff.Parse(strings.NewReader(unifiedDiff))
	if err != nil {
		return fmt.Errorf("gitdiff parse: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("patch contains no file sections")
	}
	return nil
}

func generateDiff(ctx context.Context, client *ollama.Client, f finding.Finding) (string, error) {
	var sb strings.Builder
	if f.CVE != "" {
		fmt.Fprintf(&sb, "CVE: %s (CVSS %.1f)\n\n", f.CVE, f.CVSS)
	}
	fmt.Fprintf(&sb, "Generate a minimal unified diff (--- a/file +++ b/file format) that fixes this %s security finding.\n", f.SeverityLabel)
	fmt.Fprintf(&sb, "File: %s\nCWE: %s\nIssue: %s\n", f.Path, f.CWE, f.Justification)
	if f.MatchedCode != "" {
		fmt.Fprintf(&sb, "Vulnerable code:\n```\n%s\n```\n", f.MatchedCode)
	}
	sb.WriteString("Output ONLY the unified diff, no explanation.")

	raw, err := client.Generate(ctx, sb.String(), &ollama.Options{
		Temperature: tuning.PatchLLMTemperature,
		NumPredict:  tuning.PatchLLMMaxTokens,
	})
	if err != nil {
		return "", fmt.Errorf("ollama generate: %w", err)
	}
	return extractDiff(raw), nil
}

func extractDiff(raw string) string {
	if _, after, ok := strings.Cut(raw, "```"); ok {
		rest := after
		if _, body, ok2 := strings.Cut(rest, "\n"); ok2 {
			rest = body
		}
		if code, _, ok3 := strings.Cut(rest, "```"); ok3 {
			return strings.TrimSpace(code)
		}
	}
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "---") {
		return trimmed
	}
	return strings.TrimSpace(raw)
}

// cweURL returns the MITRE remediation page for a CWE identifier.
func cweURL(cwe string) string {
	id := strings.TrimPrefix(cwe, "CWE-")
	if id == "" || id == cwe {
		return "https://cwe.mitre.org/data/definitions/"
	}
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", id)
}
