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

package main

import "github.com/hoangharry-tm/zerotrust/internal/tuning"

// ScanConfig holds the resolved, validated configuration for a single scan run.
// It is populated from cobra flags in runScan before the pipeline is constructed.
//
// Flag → field mapping:
//
//	<directory>     → Target        (positional arg, defaults to ".")
//	--model         → ModelName     (Ollama model name, e.g. "llama3.2")
//	--offline       → Offline       (disable all network requests)
//	--output        → OutputMode    (output mode: minimal|tree|tui; default: auto-detect from TTY)
//	--report        → ReportPath    (HTML report destination, default "build/report.html")
//	--project-id    → ProjectID     (override derived project ID for scan-state cache)
//	--mode          → ScanMode      (Default | Thorough | Full; default "Default")
//	--joern-url     → JoernURL      (Joern HTTP API URL; default "http://localhost:8080")
//	--ollama-url    → OllamaURL     (Ollama HTTP API URL; default "http://localhost:11434")
//	--token-cap     → TokenCap      (token budget cap for Path B Tier 3; default 50 000)
type ScanConfig struct {
	// Target is the absolute or relative path to the codebase to scan.
	Target string

	// ModelName is the Ollama model identifier used for LLM stages.
	// Example: "llama3.2", "qwen2.5:3b".
	// If empty, LLM stages are skipped.
	ModelName string

	// Offline disables all outbound network requests.
	// When true: Trivy runs in offline mode, cosign/Rekor registry lookup is skipped,
	// and MIV defaults to StatusWarn for unrecognised models.
	Offline bool

	// OutputMode selects the CLI output renderer: "minimal", "tree", or "tui".
	// Empty string triggers auto-detection: TTY → tree, no TTY → minimal.
	OutputMode string

	// ReportPath is the file path where the self-contained HTML report is written.
	ReportPath string

	// ProjectID overrides the project identifier used to key scan state in SQLite.
	// If empty, a deterministic ID is derived from the resolved Target path.
	ProjectID string

	// ScanMode controls the CPG and Path B scope.
	//   "Default"  — working modules (git diff) + depth-2 module neighbours.
	//   "Thorough" — depth-3 neighbours + all sink-flagged modules.
	//   "Full"     — entire codebase (no scope limit).
	ScanMode string

	// JoernURL is the base URL of the Joern HTTP API server.
	// Ignored when JoernBin is non-empty (the client derives the URL from
	// JoernHost and JoernPort instead).
	JoernURL string

	// JoernBin is the path to the joern-server binary. When non-empty, the
	// pipeline spawns and manages the Joern subprocess itself. When empty,
	// the pipeline connects to the externally managed server at JoernURL.
	// Example: "/usr/local/bin/joern-server" or "joern-server" (resolved via PATH).
	JoernBin string

	// OllamaURL is the base URL of the Ollama inference server.
	OllamaURL string

	// TokenCap is the hard per-scan token budget for the Token Budget Controller.
	// Surfaces that exceed the cap are emitted as SUPPRESSED findings.
	TokenCap int

	// Verbose enables debug-level logging to stderr for both Go and the Python worker.
	Verbose bool
}

// defaults fills zero-value fields with safe production defaults.
func (c *ScanConfig) defaults() {
	if c.Target == "" {
		c.Target = "."
	}
	if c.ReportPath == "" {
		c.ReportPath = "build/report.html"
	}
	if c.ScanMode == "" {
		c.ScanMode = "Default"
	}
	if c.JoernURL == "" {
		c.JoernURL = "http://localhost:8080"
	}
	if c.OllamaURL == "" {
		c.OllamaURL = "http://localhost:11434"
	}
	if c.TokenCap <= 0 {
		c.TokenCap = tuning.DefaultTokenCap
	}
}
