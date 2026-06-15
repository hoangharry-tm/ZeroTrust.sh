// Package opengrep wraps the OpenGrep CLI (LGPL-2.1, Semgrep CE fork).
// OpenGrep runs against the changed file set from the Differential Indexer and
// emits structural pattern findings routed to the LLM Verifier.
package opengrep

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// Runner invokes OpenGrep as a subprocess against a file set.
type Runner struct {
	binaryPath string
	rulesDir   string
}

// New returns a Runner using the OpenGrep binary at binaryPath and rules at rulesDir.
func New(binaryPath, rulesDir string) *Runner {
	return &Runner{binaryPath: binaryPath, rulesDir: rulesDir}
}

// Scan runs OpenGrep against files and returns normalised findings.
func (r *Runner) Scan(ctx context.Context, files []string) ([]finding.Finding, error) {
	// implemented in G2.M2.4
	return nil, nil
}
