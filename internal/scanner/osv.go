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
	"path/filepath"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// OSVScanner wraps the osv-scanner binary for dependency vulnerability scanning.
type OSVScanner struct {
	binaryPath string
}

// NewOSV returns an OSVScanner using the given binary path.
// Pass "osv-scanner" to rely on PATH resolution.
func NewOSV(binaryPath string) *OSVScanner {
	return &OSVScanner{binaryPath: binaryPath}
}

// Name implements Scanner.
func (o *OSVScanner) Name() string { return "osv-scanner" }

// Supports implements Scanner. Returns true only when a package manifest
// lockfile was detected — there is nothing to scan without one.
func (o *OSVScanner) Supports(stack detector.StackProfile) bool {
	lockfiles := []string{
		"go.sum", "cargo.lock", "package-lock.json", "yarn.lock",
		"pipfile.lock", "poetry.lock", "gemfile.lock", "mix.lock",
	}
	for _, lf := range lockfiles {
		if stack.HasManifest(lf) {
			return true
		}
	}
	return false
}

// osvOutput mirrors the osv-scanner JSON report structure we care about.
type osvOutput struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID      string  `json:"id"`
				Summary string  `json:"summary"`
				CVSS    float64 `json:"cvss_score,omitempty"`
				CWEs    []struct {
					CWE string `json:"cwe_id"`
				} `json:"cwe_ids,omitempty"`
			} `json:"vulnerabilities"`
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
		} `json:"packages"`
	} `json:"results"`
}

// Scan implements Scanner. Runs `osv-scanner --json --recursive target` and
// converts the vulnerability report to findings.
func (o *OSVScanner) Scan(ctx context.Context, target string) ([]finding.Finding, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, o.binaryPath,
		"--json",
		"--recursive",
		target,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// osv-scanner exits 1 when vulnerabilities are found; check for JSON output.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("osv-scanner: %w (stderr: %s)", err, stderr.String())
		}
	}
	if stdout.Len() == 0 {
		return nil, nil
	}
	var out osvOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("osv-scanner decode: %w", err)
	}

	var findings []finding.Finding
	for _, result := range out.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				cwe := "CWE-1035" // using vulnerable component
				if len(vuln.CWEs) > 0 {
					cwe = vuln.CWEs[0].CWE
				}
				srcPath := pkg.Source.Path
				if srcPath == "" {
					srcPath = filepath.Join(target, "go.sum") // fallback
				}
				opts := []finding.Option{
					finding.WithCVE(vuln.ID),
					finding.WithConfidence(0.85),
				}
				if vuln.CVSS > 0 {
					opts = append(opts, finding.WithCVSS(vuln.CVSS))
				}
				f := finding.New(
					srcPath,
					finding.LineRange{Start: 1, End: 1},
					cwe,
					fmt.Sprintf("%s@%s: %s", pkg.Package.Name, pkg.Package.Version, vuln.Summary),
					opts...,
				)
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}
