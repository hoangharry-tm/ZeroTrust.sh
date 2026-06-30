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

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// GitleaksScanner wraps the gitleaks binary for hardcoded-secret detection.
type GitleaksScanner struct {
	binaryPath string
}

// NewGitleaks returns a GitleaksScanner using the resolved binary from spec.
func NewGitleaks(spec BinarySpec) *GitleaksScanner {
	return &GitleaksScanner{binaryPath: spec.Executable()}
}

// Name implements Scanner.
func (g *GitleaksScanner) Name() string { return "gitleaks" }

// Supports implements Scanner. Gitleaks scans for secrets in any codebase.
func (g *GitleaksScanner) Supports(_ detector.StackProfile) bool { return true }

// gitleaksFinding is the JSON shape emitted by `gitleaks detect --report-format json`.
type gitleaksFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Secret      string `json:"Secret"`
}

// Scan implements Scanner. Runs `gitleaks detect --source target --report-format json
// --no-git` and converts the output to findings.
func (g *GitleaksScanner) Scan(ctx context.Context, target string) ([]finding.Finding, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.binaryPath,
		"detect",
		"--source", target,
		"--report-format", "json",
		"--no-git",
		"--exit-code", "0", // don't exit 1 on findings
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitleaks: %w (stderr: %s)", err, stderr.String())
	}
	if stdout.Len() == 0 {
		return nil, nil
	}
	var raw []gitleaksFinding
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("gitleaks decode: %w", err)
	}
	out := make([]finding.Finding, 0, len(raw))
	for _, r := range raw {
		f := finding.New(
			r.File,
			finding.LineRange{Start: r.StartLine, End: r.EndLine},
			"CWE-798",
			r.Description,
			finding.WithRuleID(r.RuleID),
			finding.WithConfidence(0.90),
			finding.WithSourcePath(finding.SourcePattern),
		)
		out = append(out, f)
	}
	return out, nil
}
