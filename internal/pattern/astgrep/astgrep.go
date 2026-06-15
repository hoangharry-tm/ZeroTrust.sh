// Package astgrep wraps the ast-grep CLI (MIT, Tree-sitter-based).
// ast-grep covers languages where OpenGrep has weak community rule packs
// (Dart, Swift, Rust, newer languages). Language routing is partitioned:
// OpenGrep and ast-grep never run the same rules on the same files.
package astgrep

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// Runner invokes ast-grep as a subprocess against a language-filtered file set.
type Runner struct {
	binaryPath string
	rulesDir   string
}

// New returns a Runner using the ast-grep binary at binaryPath and rules at rulesDir.
func New(binaryPath, rulesDir string) *Runner {
	return &Runner{binaryPath: binaryPath, rulesDir: rulesDir}
}

// Scan runs ast-grep against files and returns normalised findings.
func (r *Runner) Scan(ctx context.Context, files []string) ([]finding.Finding, error) {
	// implemented in G2.M2.4
	return nil, nil
}
