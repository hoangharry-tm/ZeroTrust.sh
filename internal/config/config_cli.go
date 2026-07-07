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

package config

import (
	"fmt"

	"github.com/spf13/cobra"
)

// DefineFlags registers all CLI flags on the given cobra command.
// Call this during command construction, before Execute.
func DefineFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.Bool("native", false, "run directly with local dependencies (no Docker)")
	flags.Bool("pull", true, "pull the latest engine image before running (Docker mode)")
	flags.BoolP("offline", "o", false, "disable all network requests (Trivy offline mode)")
	flags.BoolP("verbose", "v", false, "enable debug-level logging to stderr")
	flags.String("report", "", "HTML report output path (default: build/report.html)")
	flags.String("project-id", "", "override project ID used for scan-state caching")
	flags.String("mode", "Default", "scan scope mode: Default | Thorough | Full")
	flags.String("joern-bin", "", "path to joern-server binary (native mode only)")
	flags.String("ollama-url", "http://localhost:11434", "Ollama HTTP API base URL")
	flags.String("engine-image", "ghcr.io/hoangharry-tm/zerotrust-engine:latest", "Docker image for the engine")
	flags.String("calibration", "", "path to JSON calibration file from scripts/calibrate.py")
	flags.StringP("model", "m", "", "Ollama model name (e.g. llama3.2)")
	flags.Int("token-cap", 50_000, "token budget cap for Path B Tier 3")
	flags.Bool("patch", false, "generate patch suggestions for confirmed findings")
}

// FromCommand extracts a pipeline run configuration from a cobra command.
// It returns the resolved flag values plus any flag lookup errors.
func FromCommand(cmd *cobra.Command) (NativeRunConfig, error) {
	var cfg NativeRunConfig
	var err error

	cfg.Native, err = cmd.Flags().GetBool("native")
	if err != nil {
		return cfg, fmt.Errorf("native: %w", err)
	}
	cfg.Pull, err = cmd.Flags().GetBool("pull")
	if err != nil {
		return cfg, fmt.Errorf("pull: %w", err)
	}
	cfg.Offline, err = cmd.Flags().GetBool("offline")
	if err != nil {
		return cfg, fmt.Errorf("offline: %w", err)
	}
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
	cfg.ProjectID, err = cmd.Flags().GetString("project-id")
	if err != nil {
		return cfg, fmt.Errorf("project-id: %w", err)
	}
	cfg.ScanMode, err = cmd.Flags().GetString("mode")
	if err != nil {
		return cfg, fmt.Errorf("mode: %w", err)
	}
	cfg.JoernBin, err = cmd.Flags().GetString("joern-bin")
	if err != nil {
		return cfg, fmt.Errorf("joern-bin: %w", err)
	}
	cfg.OllamaURL, err = cmd.Flags().GetString("ollama-url")
	if err != nil {
		return cfg, fmt.Errorf("ollama-url: %w", err)
	}
	cfg.EngineImage, err = cmd.Flags().GetString("engine-image")
	if err != nil {
		return cfg, fmt.Errorf("engine-image: %w", err)
	}
	cfg.CalibrationPath, err = cmd.Flags().GetString("calibration")
	if err != nil {
		return cfg, fmt.Errorf("calibration: %w", err)
	}
	cfg.TokenCap, err = cmd.Flags().GetInt("token-cap")
	if err != nil {
		return cfg, fmt.Errorf("token-cap: %w", err)
	}
	cfg.GeneratePatches, err = cmd.Flags().GetBool("patch")
	if err != nil {
		return cfg, fmt.Errorf("patch: %w", err)
	}
	return cfg, nil
}

// NativeRunConfig holds the CLI flags that control a native-mode scan run.
// It is a subset of pipeline.Config; the config package owns flag binding so
// main.go stays thin.
type NativeRunConfig struct {
	Native          bool
	Pull            bool
	Offline         bool
	Verbose         bool
	ModelName       string
	ReportPath      string
	ProjectID       string
	ScanMode        string
	JoernBin        string
	OllamaURL       string
	EngineImage     string
	CalibrationPath string
	TokenCap        int
	GeneratePatches bool
}
