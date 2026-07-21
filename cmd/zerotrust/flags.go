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

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// defineFlags registers all CLI flags on the given cobra command.
// Call this during command construction, before Execute.
func defineFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.SortFlags = false // preserve grouped registration order in --help

	// ── Scan scope ───────────────────────────────────────────────────────────
	flags.String("project-id", "", "override project ID used for scan-state caching")

	// ── LLM / model ──────────────────────────────────────────────────────────
	flags.String("llm-provider", "ollama", "LLM provider: ollama | openai")
	flags.StringP("model", "m", "", "model name (e.g. llama3.2 for ollama, gpt-4o for openai)")
	flags.String("llm-base-url", "", "LLM API base URL (defaults to the provider's standard endpoint)")
	flags.String("llm-api-key", "", "API key for the LLM provider (openai only; falls back to $OPENAI_API_KEY)")
	flags.String("calibration", "", "path to JSON calibration file from scripts/calibrate.py")
	flags.String("joern-bin", "", "path to joern-server binary")

	// ── Output ───────────────────────────────────────────────────────────────
	flags.String("report", "", "HTML report output path (default: build/report.html)")
	flags.String("json-report", "", "JSON report output path (disabled by default)")
	flags.Bool("patch", false, "generate patch suggestions for confirmed findings")
	flags.BoolP("verbose", "v", false, "enable debug-level logging to stderr")
}

// runConfig holds the CLI flags that control a scan run.
// It is a subset of pipeline.Config; this file owns flag binding so
// runScan stays thin.
type runConfig struct {
	Verbose         bool
	ModelName       string
	ReportPath      string
	JSONReportPath  string
	ProjectID       string
	JoernBin        string
	LLMProvider     string
	LLMBaseURL      string
	LLMAPIKey       string
	CalibrationPath string
	GeneratePatches bool
}

// runConfigFromCommand extracts a run configuration from a cobra command.
// It returns the resolved flag values plus any flag lookup errors.
func runConfigFromCommand(cmd *cobra.Command) (runConfig, error) {
	var cfg runConfig
	var err error

	cfg.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil {
		return cfg, fmt.Errorf("verbose: %w", err)
	}
	cfg.ModelName, err = cmd.Flags().GetString("model")
	if err != nil {
		return cfg, fmt.Errorf("model: %w", err)
	}
	cfg.ReportPath, err = cmd.Flags().GetString("report")
	if err != nil {
		return cfg, fmt.Errorf("report: %w", err)
	}
	cfg.JSONReportPath, err = cmd.Flags().GetString("json-report")
	if err != nil {
		return cfg, fmt.Errorf("json-report: %w", err)
	}
	cfg.ProjectID, err = cmd.Flags().GetString("project-id")
	if err != nil {
		return cfg, fmt.Errorf("project-id: %w", err)
	}
	cfg.JoernBin, err = cmd.Flags().GetString("joern-bin")
	if err != nil {
		return cfg, fmt.Errorf("joern-bin: %w", err)
	}
	cfg.LLMProvider, err = cmd.Flags().GetString("llm-provider")
	if err != nil {
		return cfg, fmt.Errorf("llm-provider: %w", err)
	}
	switch cfg.LLMProvider {
	case "ollama", "openai":
	default:
		return cfg, fmt.Errorf("--llm-provider must be one of: ollama, openai (got %q)", cfg.LLMProvider)
	}
	cfg.LLMBaseURL, err = cmd.Flags().GetString("llm-base-url")
	if err != nil {
		return cfg, fmt.Errorf("llm-base-url: %w", err)
	}
	cfg.LLMAPIKey, err = cmd.Flags().GetString("llm-api-key")
	if err != nil {
		return cfg, fmt.Errorf("llm-api-key: %w", err)
	}
	if cfg.LLMAPIKey == "" {
		cfg.LLMAPIKey = os.Getenv("OPENAI_API_KEY")
	}
	if cfg.LLMProvider == "openai" && cfg.LLMAPIKey == "" {
		return cfg, fmt.Errorf("--llm-api-key or $OPENAI_API_KEY is required when --llm-provider=openai")
	}
	cfg.CalibrationPath, err = cmd.Flags().GetString("calibration")
	if err != nil {
		return cfg, fmt.Errorf("calibration: %w", err)
	}
	cfg.GeneratePatches, err = cmd.Flags().GetBool("patch")
	if err != nil {
		return cfg, fmt.Errorf("patch: %w", err)
	}
	return cfg, nil
}
