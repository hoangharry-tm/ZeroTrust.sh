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

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func trivyReport(vulns ...trivyVulnEntry) []byte {
	report := trivyFSResult{
		Results: []trivyResult{
			{Target: "go.sum", Vulnerabilities: vulns},
		},
	}
	b, _ := json.Marshal(report)
	return b
}

func makeVuln(cve, pkg, version string, nvdScore float64) trivyVulnEntry {
	return trivyVulnEntry{
		VulnerabilityID:  cve,
		PkgName:          pkg,
		InstalledVersion: version,
		FixedVersion:     "1.99.0",
		CVSS:             trivyCVSS{NVD: trivyCVSSEntry{V3Score: nvdScore}},
	}
}

func surfaceWithFile(file string) EnrichedSurface {
	return EnrichedSurface{Surface: targeting.Surface{File: file}}
}

// ---------------------------------------------------------------------------
// parseTrivyOutput
// ---------------------------------------------------------------------------

func TestParseTrivyOutput_EmptyReturnsEmptyMap(t *testing.T) {
	m, err := parseTrivyOutput(nil)
	require.NoError(t, err)
	assert.Empty(t, m)
}

func TestParseTrivyOutput_SingleVuln(t *testing.T) {
	data := trivyReport(makeVuln("CVE-2021-44228", "log4j-core", "2.14.1", 10.0))
	m, err := parseTrivyOutput(data)
	require.NoError(t, err)
	require.Contains(t, m, "log4j-core")
	assert.Equal(t, "CVE-2021-44228", m["log4j-core"][0].CVE)
	assert.InEpsilon(t, 10.0, m["log4j-core"][0].CVSS, 1e-6)
}

func TestParseTrivyOutput_MultipleVulnsInSamePackage(t *testing.T) {
	data := trivyReport(
		makeVuln("CVE-2022-0001", "requests", "2.26.0", 8.1),
		makeVuln("CVE-2022-0002", "requests", "2.26.0", 7.5),
	)
	m, err := parseTrivyOutput(data)
	require.NoError(t, err)
	assert.Len(t, m["requests"], 2)
}

func TestParseTrivyOutput_GHSAFallbackWhenNoNVD(t *testing.T) {
	entry := trivyVulnEntry{
		VulnerabilityID:  "GHSA-xxxx-yyyy-zzzz",
		PkgName:          "example",
		InstalledVersion: "1.0.0",
		CVSS:             trivyCVSS{Ghsa: trivyCVSSEntry{V3Score: 7.2}},
	}
	data := trivyReport(entry)
	m, err := parseTrivyOutput(data)
	require.NoError(t, err)
	assert.InEpsilon(t, 7.2, m["example"][0].CVSS, 1e-6)
}

func TestParseTrivyOutput_MalformedJSON(t *testing.T) {
	_, err := parseTrivyOutput([]byte(`{"Results": [bad json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse JSON")
}

// ---------------------------------------------------------------------------
// AutoFlagSeverity
// ---------------------------------------------------------------------------

func TestAutoFlagSeverity_Thresholds(t *testing.T) {
	tests := []struct {
		cvss     float64
		expected finding.SeverityLabel
	}{
		{10.0, finding.SeverityBlock},
		{9.0, finding.SeverityBlock},
		{8.9, finding.SeverityHigh},
		{7.0, finding.SeverityHigh},
		{6.9, finding.SeverityMedium},
		{4.0, finding.SeverityMedium},
		{3.9, finding.SeverityLow},
		{0.0, finding.SeverityLow},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.expected, AutoFlagSeverity(tt.cvss))
		})
	}
}

// ---------------------------------------------------------------------------
// ApplyCVEMatches
// ---------------------------------------------------------------------------

func TestApplyCVEMatches_SetsAutoFlaggedOnHighCVSS(t *testing.T) {
	surfaces := []EnrichedSurface{surfaceWithFile("log4j-core/main.java")}
	cvesByPkg := map[string][]CVEMatch{
		"log4j-core": {{CVE: "CVE-2021-44228", CVSS: 10.0, Package: "log4j-core"}},
	}
	ApplyCVEMatches(surfaces, cvesByPkg)
	assert.True(t, surfaces[0].AutoFlagged)
	assert.Len(t, surfaces[0].CVEMatches, 1)
}

func TestApplyCVEMatches_DoesNotAutoFlagBelowThreshold(t *testing.T) {
	surfaces := []EnrichedSurface{surfaceWithFile("requests/client.py")}
	cvesByPkg := map[string][]CVEMatch{
		"requests": {{CVE: "CVE-2022-low", CVSS: 3.5, Package: "requests"}},
	}
	ApplyCVEMatches(surfaces, cvesByPkg)
	assert.False(t, surfaces[0].AutoFlagged)
	assert.Len(t, surfaces[0].CVEMatches, 1)
}

func TestApplyCVEMatches_SortsByDescendingCVSS(t *testing.T) {
	surfaces := []EnrichedSurface{surfaceWithFile("requests/client.py")}
	cvesByPkg := map[string][]CVEMatch{
		"requests": {
			{CVE: "CVE-low", CVSS: 5.0},
			{CVE: "CVE-high", CVSS: 9.1},
			{CVE: "CVE-mid", CVSS: 7.3},
		},
	}
	ApplyCVEMatches(surfaces, cvesByPkg)
	require.Len(t, surfaces[0].CVEMatches, 3)
	assert.Equal(t, "CVE-high", surfaces[0].CVEMatches[0].CVE)
}

func TestApplyCVEMatches_NoMatchLeavesUnchanged(t *testing.T) {
	surfaces := []EnrichedSurface{surfaceWithFile("internal/auth/handler.go")}
	cvesByPkg := map[string][]CVEMatch{
		"log4j-core": {{CVE: "CVE-2021-44228", CVSS: 10.0}},
	}
	ApplyCVEMatches(surfaces, cvesByPkg)
	assert.False(t, surfaces[0].AutoFlagged)
	assert.Empty(t, surfaces[0].CVEMatches)
}

// ---------------------------------------------------------------------------
// RunTrivy (integration — skipped when binary absent)
// ---------------------------------------------------------------------------

func TestRunTrivy_ReturnsErrorWhenBinaryMissing(t *testing.T) {
	e := New(nil, "/nonexistent/trivy-binary", false)
	_, err := e.RunTrivy(context.Background(), t.TempDir())
	require.Error(t, err)
}

func TestRunTrivy_OfflineUsesEmptyJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not supported on Windows")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "trivy")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho '{\"Results\":[]}'\n"), 0o750)) //nolint:gosec // test helper shell script requires execute permission

	e := New(nil, script, true)
	m, err := e.RunTrivy(context.Background(), dir)
	require.NoError(t, err)
	assert.Empty(t, m)
}

func TestRunTrivy_ParsesValidJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not supported on Windows")
	}
	data := trivyReport(makeVuln("CVE-2023-0001", "urllib3", "1.26.0", 7.5))
	dir := t.TempDir()
	script := filepath.Join(dir, "trivy")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat <<'EOF'\n"+string(data)+"\nEOF\n"), 0o750)) //nolint:gosec // test helper shell script requires execute permission

	e := New(nil, script, false)
	m, err := e.RunTrivy(context.Background(), dir)
	require.NoError(t, err)
	assert.Contains(t, m, "urllib3")
}

func TestRunTrivy_SkipsNetworkWhenBinaryPresentAndOffline(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy binary not in PATH")
	}
	e := New(nil, "trivy", true)
	m, err := e.RunTrivy(context.Background(), t.TempDir())
	if errors.Is(err, ErrTrivyDBNotInitialized) {
		// DB has never been bootstrapped on this machine. The sentinel is the
		// correct structured response — the raw Trivy fatal must not leak through.
		return
	}
	require.NoError(t, err)
	assert.NotNil(t, m)
}

// ---------------------------------------------------------------------------
// HTTP simulation (parseTrivyOutput via network-shaped bytes)
// ---------------------------------------------------------------------------

func TestParseTrivyOutput_ViaHTTPServerSimulation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(trivyReport(makeVuln("CVE-2023-0001", "urllib3", "1.26.0", 7.5)))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	m, err := parseTrivyOutput(buf.Bytes())
	require.NoError(t, err)
	assert.Contains(t, m, "urllib3")
}
