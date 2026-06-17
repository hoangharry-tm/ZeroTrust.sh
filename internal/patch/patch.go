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

	"github.com/hoangharry-tm/zerotrust/internal/finding"
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
}

// New returns a Generator operating against files under projectRoot.
func New(projectRoot string) *Generator {
	return &Generator{projectRoot: projectRoot}
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
	// implemented in G4.M4.2
	return nil, nil
}

// Validate checks whether unifiedDiff applies cleanly to the file at relPath
// (relative to projectRoot) using go-gitdiff. Returns nil on success.
//
// Parameters:
//   - relPath: file path relative to projectRoot.
//   - unifiedDiff: the diff string to validate.
func (g *Generator) Validate(relPath, unifiedDiff string) error {
	// implemented in G4.M4.2
	return nil
}
