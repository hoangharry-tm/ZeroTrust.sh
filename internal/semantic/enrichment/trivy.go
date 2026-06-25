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

package enrichment

// trivy.go implements L3.1.T4 (Trivy CVE subprocess wrapper) and L3.1.T5
// (CVE auto-flag logic).
//
// Trivy is invoked as a subprocess with `fs` subcommand against the project
// root. It scans dependency manifests (go.sum, requirements.txt, pom.xml,
// package-lock.json, etc.) and emits a JSON report of known CVEs from the OSV,
// NVD, and GitHub Advisory databases.
//
// Source code never leaves the machine — Trivy operates entirely on manifests.
// In offline mode (--offline-scan --skip-db-update) all network calls are
// suppressed; Trivy uses its locally cached vulnerability DB.
//
// Auto-flag thresholds (L3.1.T5):
//
//	CVSS ≥ 9.0  → AutoFlagged, maps to SeverityBlock
//	CVSS 7.0–8.9 → AutoFlagged, maps to SeverityHigh
//	CVSS 4.0–6.9 → AutoFlagged, maps to SeverityMedium
//	CVSS < 4.0   → not auto-flagged (below threshold; UniXcoder still classifies)

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// trivyFSResult is the top-level JSON structure returned by `trivy fs --format json`.
type trivyFSResult struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	// Target is the manifest file path (e.g. "go.sum", "requirements.txt").
	Target          string           `json:"Target"`
	Vulnerabilities []trivyVulnEntry `json:"Vulnerabilities"`
}

type trivyVulnEntry struct {
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgName          string    `json:"PkgName"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion"`
	CVSS             trivyCVSS `json:"CVSS"`
}

// trivyCVSS holds per-source CVSS scores from the Trivy JSON output.
// We prefer nvd.V3Score, then ghsa, then the highest available.
type trivyCVSS struct {
	NVD  trivyCVSSEntry `json:"nvd"`
	Ghsa trivyCVSSEntry `json:"ghsa"`
}

type trivyCVSSEntry struct {
	V3Score float64 `json:"V3Score"`
}

// ErrTrivyDBNotInitialized is returned by RunTrivy when offline mode is
// requested but Trivy's vulnerability database has never been downloaded.
// Callers should either re-run without offline mode to bootstrap the DB, or
// skip CVE enrichment and log a warning.
var ErrTrivyDBNotInitialized = errors.New("trivy: vulnerability DB not initialised; run once without --offline-scan to bootstrap")

// trivyDBNotInitMsg is the exact substring Trivy emits to stderr on first-run
// with --skip-db-update. String inspection is confined to this constant and
// the single call site in runTrivy that converts it to ErrTrivyDBNotInitialized.
const trivyDBNotInitMsg = "--skip-db-update cannot be specified on the first run"

// RunTrivy executes the Trivy binary against projectRoot and returns all CVE
// matches keyed by lowercase package name.
//
// Returns ErrTrivyDBNotInitialized when offlineMode is true but the local
// vulnerability database has not been bootstrapped yet. The caller should
// re-run without offline mode once to initialise the DB.
func (e *Enricher) RunTrivy(ctx context.Context, projectRoot string) (map[string][]CVEMatch, error) {
	slog.Debug("running trivy", slog.String("project_root", projectRoot), slog.Bool("offline", e.offlineMode))
	args := []string{"fs", "--format", "json", "--quiet"}
	if e.offlineMode {
		args = append(args, "--offline-scan", "--skip-db-update")
	}
	args = append(args, projectRoot)

	cmd := exec.CommandContext(ctx, e.trivyPath, args...) //nolint:gosec // binary path from config
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 {
			if strings.Contains(stderr.String(), trivyDBNotInitMsg) {
				slog.Warn("trivy DB not initialised; run once without --offline-scan")
				return nil, ErrTrivyDBNotInitialized
			}
			slog.Error("trivy run failed", "err", err)
			return nil, fmt.Errorf("trivy: run failed: %w\nstderr: %s", err, stderr.String())
		}
		// Trivy exits 1 when vulnerabilities are found — non-zero with JSON output
		// is the CVE-found case; fall through to parse.
	}

	result, err := parseTrivyOutput(stdout.Bytes())
	if err != nil {
		slog.Error("trivy output parse failed", "err", err)
		return nil, err
	}
	slog.Info("trivy scan complete", slog.Int("packages_with_cves", len(result)))
	return result, nil
}

// parseTrivyOutput decodes Trivy JSON and returns CVE matches keyed by package name.
func parseTrivyOutput(data []byte) (map[string][]CVEMatch, error) {
	if len(data) == 0 {
		return make(map[string][]CVEMatch), nil
	}

	var report trivyFSResult
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: parse JSON: %w", err)
	}

	out := make(map[string][]CVEMatch)
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			cvss := bestCVSS(vuln.CVSS)
			match := CVEMatch{
				CVE:     vuln.VulnerabilityID,
				CVSS:    cvss,
				Package: vuln.PkgName,
				Version: vuln.InstalledVersion,
				FixedIn: vuln.FixedVersion,
			}
			key := strings.ToLower(vuln.PkgName)
			out[key] = append(out[key], match)
		}
	}
	return out, nil
}

// bestCVSS returns the highest-confidence CVSS v3 score from the trivy CVSS block.
// NVD is preferred; GitHub Advisory is used as fallback.
func bestCVSS(c trivyCVSS) float64 {
	if c.NVD.V3Score > 0 {
		return c.NVD.V3Score
	}
	return c.Ghsa.V3Score
}

// AutoFlagSeverity maps a CVSS score to the SSVC-inspired SeverityLabel for a
// CVE auto-flagged surface. Surfaces below tuning.AutoFlagCVSS are not auto-flagged
// and this function should not be called for them.
//
// Mapping (L3.1.T5):
//
//	≥ 9.0 → SeverityBlock
//	7.0–8.9 → SeverityHigh
//	4.0–6.9 → SeverityMedium  (below threshold — included for completeness)
//	< 4.0   → SeverityLow     (below threshold — included for completeness)
func AutoFlagSeverity(cvss float64) finding.SeverityLabel {
	switch {
	case cvss >= 9.0:
		return finding.SeverityBlock
	case cvss >= 7.0:
		return finding.SeverityHigh
	case cvss >= 4.0:
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
}

// ApplyCVEMatches enriches a surface slice with CVE data from a Trivy result map
// and sets AutoFlagged on surfaces whose highest CVSS score is ≥ tuning.AutoFlagCVSS.
//
// The match is by package name: a surface is matched to a CVE when the surface's
// source file is in a module directory that contains the vulnerable package
// (best-effort heuristic; exact module→CVE mapping requires Joern and is done
// in the full Enrich implementation).
//
// Parameters:
//   - surfaces: the EnrichedSurface slice to mutate in-place.
//   - cvesByPkg: the map returned by RunTrivy.
func ApplyCVEMatches(surfaces []EnrichedSurface, cvesByPkg map[string][]CVEMatch) {
	for i := range surfaces {
		s := &surfaces[i]
		// Extract directory components from the surface file path to match against
		// package names. This is a heuristic until full module-to-package mapping
		// is available from the CPG.
		dir := strings.ToLower(filepath.Dir(s.File))
		parts := strings.FieldsFunc(dir, func(r rune) bool {
			return r == '/' || r == '\\' || r == '.'
		})

		var matches []CVEMatch
		seen := make(map[string]struct{})
		for pkg, cves := range cvesByPkg {
			for _, part := range parts {
				if strings.Contains(part, pkg) || strings.Contains(pkg, part) {
					for _, cve := range cves {
						if _, already := seen[cve.CVE]; !already {
							matches = append(matches, cve)
							seen[cve.CVE] = struct{}{}
						}
					}
					break
				}
			}
		}

		if len(matches) == 0 {
			continue
		}

		// Sort by descending CVSS.
		sortCVEMatches(matches)
		s.CVEMatches = matches

		if matches[0].CVSS >= tuning.AutoFlagCVSS {
			s.AutoFlagged = true
		}
	}
}

// sortCVEMatches sorts a CVEMatch slice by descending CVSS score in-place.
// Uses insertion sort — CVE lists per surface are typically tiny (< 10 items).
func sortCVEMatches(matches []CVEMatch) {
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].CVSS > matches[j-1].CVSS; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
}
