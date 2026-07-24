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

package pipeline

import "log/slog"

// Config holds the resolved, validated configuration for a single scan run.
// It is populated from cobra flags in runScan before the pipeline is constructed.
//
// Flag → field mapping:
//
//	<directory>     → Target        (positional arg, defaults to ".")
//	--llm-provider  → LLMProvider   (ollama | openai; default "ollama")
//	--model         → ModelName     (model name, e.g. "llama3.2" or "gpt-4o")
//	--llm-base-url  → LLMBaseURL    (LLM API base URL; defaults to the provider's standard endpoint)
//	--llm-api-key   → LLMAPIKey     (API key; required for --llm-provider openai)
//	--db-url        → DatabaseURL   (Postgres connection string; falls back to $DATABASE_URL)
//	--project-id    → ProjectID     (override derived project ID for scan-state cache)
//
// ScanMode is fixed to "Default" — there is no scope flag; every scan covers
// working modules (git diff) plus depth-2 module neighbours.
type Config struct {
	// Target is the absolute or relative path to the codebase to scan.
	Target string

	// ModelName is the model identifier used for LLM stages.
	// Example: "llama3.2", "qwen2.5:3b" (ollama), "gpt-4o" (openai).
	// If empty, LLM stages are skipped.
	ModelName string

	// DatabaseURL is the Postgres connection string scored findings and scan
	// state are persisted to. Required — there is no report/file output;
	// the database is the product of a scan.
	DatabaseURL string

	// ProjectID overrides the project identifier used to key scan state in
	// the database. If empty, a deterministic ID is derived from the
	// resolved Target path.
	ProjectID string

	// ScanMode controls the CPG and Reasoning scope.
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

	// LLMProvider selects the LLM backend: "ollama" or "openai". Default: "ollama".
	LLMProvider string

	// LLMBaseURL is the base URL of the LLM API. Empty means the provider's
	// standard default (Ollama: localhost:11434; OpenAI: api.openai.com).
	LLMBaseURL string

	// LLMAPIKey authenticates against the LLM provider. Required for
	// LLMProvider "openai"; unused for "ollama".
	LLMAPIKey string

	// CalibrationPath is an optional path to a JSON calibration file produced by
	// scripts/calibrate.py. Empty means compile-time defaults are used.
	CalibrationPath string

	// TriageThreshold is the minimum confidence score for a surface to be
	// escalated from the LLM triage stage (B4) to the full reasoner (B5).
	// Surfaces below this threshold are dropped.
	TriageThreshold float64

	// Verbose enables debug-level logging to stderr.
	Verbose bool
}

// defaults fills zero-value fields with safe production defaults.
func (c *Config) defaults() {
	if c.Target == "" {
		c.Target = "."
		slog.Debug("config default applied", "field", "Target", "value", c.Target)
	}
	if c.ScanMode == "" {
		c.ScanMode = "Default"
		slog.Debug("config default applied", "field", "ScanMode", "value", c.ScanMode)
	}
	if c.JoernURL == "" {
		c.JoernURL = "http://localhost:8080"
		slog.Debug("config default applied", "field", "JoernURL", "value", c.JoernURL)
	}
	if c.LLMProvider == "" {
		c.LLMProvider = "ollama"
		slog.Debug("config default applied", "field", "LLMProvider", "value", c.LLMProvider)
	}
	if c.TriageThreshold <= 0 {
		c.TriageThreshold = 0.50
		slog.Debug("config default applied", "field", "TriageThreshold", "value", c.TriageThreshold)
	}
	slog.Info("config resolved",
		"target", c.Target, "scan_mode", c.ScanMode, "joern_url", c.JoernURL,
		"llm_provider", c.LLMProvider, "model", c.ModelName,
		"triage_threshold", c.TriageThreshold, "verbose", c.Verbose)
}
