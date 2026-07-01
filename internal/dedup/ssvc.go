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

package dedup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// ── Static CWE lookup tables ──────────────────────────────────────────────────

// cweAutomatable maps CWE IDs to "Yes"/"No" automatable exploitation.
// "Yes" = exploitation is scripted / toolable at scale; "No" = requires manual steps.
var cweAutomatable = map[string]string{
	"CWE-20":  "Yes", // Improper Input Validation
	"CWE-22":  "Yes", // Path Traversal
	"CWE-77":  "Yes", // Command Injection
	"CWE-78":  "Yes", // OS Command Injection
	"CWE-79":  "Yes", // XSS
	"CWE-89":  "Yes", // SQL Injection
	"CWE-90":  "Yes", // LDAP Injection
	"CWE-94":  "Yes", // Code Injection
	"CWE-119": "No",  // Buffer Errors (memory safety; typically requires local access)
	"CWE-120": "No",  // Buffer Copy Without Checking Size
	"CWE-190": "No",  // Integer Overflow
	"CWE-200": "Yes", // Information Exposure
	"CWE-287": "Yes", // Improper Authentication
	"CWE-306": "Yes", // Missing Authentication for Critical Function
	"CWE-352": "Yes", // CSRF
	"CWE-400": "Yes", // Resource Exhaustion / DoS
	"CWE-434": "Yes", // Unrestricted File Upload
	"CWE-476": "No",  // NULL Pointer Dereference
	"CWE-502": "Yes", // Deserialization of Untrusted Data
	"CWE-601": "Yes", // Open Redirect
	"CWE-611": "Yes", // XXE
	"CWE-639": "Yes", // IDOR
	"CWE-918": "Yes", // SSRF
}

// cweTechnicalImpact maps CWE IDs to "Total"/"Partial" technical impact.
// "Total" = full confidentiality/integrity/availability compromise possible.
var cweTechnicalImpact = map[string]string{
	"CWE-77":  "Total",
	"CWE-78":  "Total",
	"CWE-89":  "Total",
	"CWE-94":  "Total",
	"CWE-120": "Total",
	"CWE-190": "Partial",
	"CWE-200": "Partial",
	"CWE-287": "Total",
	"CWE-306": "Total",
	"CWE-400": "Partial",
	"CWE-502": "Total",
	"CWE-611": "Total",
	"CWE-918": "Partial",
}

// ── CISA KEV cache ────────────────────────────────────────────────────────────

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevTTL  = tuning.KEVCacheTTL
	epssURL = "https://api.first.org/data/v1/epss?cve=%s"
)

type kevStore struct {
	mu   sync.RWMutex
	data map[string]bool
	at   time.Time
}

var globalKEV = &kevStore{}

// kevContains returns true if the CVE is in the CISA KEV catalogue.
// Downloads and caches the bundle at ~/.zerotrust/kev.json; refreshes after kevTTL.
// Best-effort: returns false on any network or parse error.
func kevContains(ctx context.Context, cve string) bool {
	if cve == "" {
		return false
	}
	// Fast path: read lock if data is fresh.
	globalKEV.mu.RLock()
	if globalKEV.data != nil && time.Since(globalKEV.at) <= kevTTL {
		result := globalKEV.data[cve]
		globalKEV.mu.RUnlock()
		return result
	}
	globalKEV.mu.RUnlock()

	// Slow path: fetch outside the lock, then write.
	data, err := loadKEV(ctx)

	globalKEV.mu.Lock()
	defer globalKEV.mu.Unlock()
	// Double-check: another goroutine may have refreshed while we fetched.
	if globalKEV.data != nil && time.Since(globalKEV.at) <= kevTTL {
		return globalKEV.data[cve]
	}
	if err == nil {
		globalKEV.data = data
		globalKEV.at = time.Now()
	} else {
		slog.Warn("ssvc: KEV refresh failed", "err", err)
		if globalKEV.data == nil {
			globalKEV.data = map[string]bool{}
		}
	}
	return globalKEV.data[cve]
}

// loadKEV downloads or reads the KEV bundle and returns a set of CVE IDs.
func loadKEV(ctx context.Context) (map[string]bool, error) {
	cacheFile, _ := kevCachePath()

	// Try reading a fresh-enough cached file first (skip HTTP on offline mode).
	if cacheFile != "" {
		if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < kevTTL {
			return parseKEVFile(cacheFile)
		}
	}

	// Download fresh bundle.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return parseKEVFile(cacheFile) // fallback to stale cache
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return parseKEVFile(cacheFile)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return parseKEVFile(cacheFile)
	}

	if cacheFile != "" {
		_ = os.WriteFile(cacheFile, body, 0o600) //nolint:errcheck // best-effort cache write
	}

	return parseKEVJSON(body)
}

func kevCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".zerotrust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "kev.json"), nil
}

func parseKEVFile(path string) (map[string]bool, error) {
	if path == "" {
		return map[string]bool{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]bool{}, nil // empty set on missing file
	}
	return parseKEVJSON(data)
}

func parseKEVJSON(data []byte) (map[string]bool, error) {
	var bundle struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("kev: parse: %w", err)
	}
	out := make(map[string]bool, len(bundle.Vulnerabilities))
	for _, v := range bundle.Vulnerabilities {
		out[v.CveID] = true
	}
	return out, nil
}

// ── EPSS lookup ───────────────────────────────────────────────────────────────

// epssScore returns the EPSS probability for a CVE via the FIRST REST API.
// Returns 0.0 on error or empty CVE.
func epssScore(ctx context.Context, cve string) float64 {
	if cve == "" {
		return 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(epssURL, cve), nil)
	if err != nil {
		return 0
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close() //nolint:errcheck

	var result struct {
		Data []struct {
			EPSS string `json:"epss"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || len(result.Data) == 0 {
		return 0
	}
	var score float64
	fmt.Sscanf(result.Data[0].EPSS, "%f", &score)
	return score
}

// ── DeriveSSVC ────────────────────────────────────────────────────────────────

// DeriveSSVC fills the SSVC dimensions on f using CISA KEV, EPSS, and static
// CWE lookup tables. Network calls are best-effort; failures degrade to
// CWE-only data rather than returning errors.
func DeriveSSVC(ctx context.Context, f finding.Finding) finding.Finding {
	slog.Debug("deriving SSVC dimensions", "component", "ssvc", "cwe", f.CWE, "cve", f.CVE)
	// ── Automatable (CWE table) ──────────────────────────────────────────────
	if v, ok := cweAutomatable[f.CWE]; ok {
		f.SSVC.Automatable = v
	} else {
		f.SSVC.Automatable = "No"
	}

	// ── TechnicalImpact (CWE table + CVSS floor) ────────────────────────────
	if v, ok := cweTechnicalImpact[f.CWE]; ok {
		f.SSVC.TechnicalImpact = v
	} else if f.CVSS >= config.C.CVSSHigh {
		f.SSVC.TechnicalImpact = "Total"
	} else {
		f.SSVC.TechnicalImpact = "Partial"
	}

	// ── Exploitation (CISA KEV + EPSS; network best-effort) ──────────────────
	// Use a short timeout so we don't block the scan if the network is slow.
	netCtx, cancel := context.WithTimeout(ctx, tuning.SSVCNetTimeout)
	defer cancel()

	if f.CVE != "" && kevContains(netCtx, f.CVE) {
		f.SSVC.Exploitation = "Active"
		return f
	}

	epss := epssScore(netCtx, f.CVE)
	switch {
	case epss >= config.C.EPSSActive:
		f.SSVC.Exploitation = "Active"
	case epss >= config.C.EPSSPoC:
		f.SSVC.Exploitation = "PoC"
	default:
		f.SSVC.Exploitation = "None"
	}
	return f
}
