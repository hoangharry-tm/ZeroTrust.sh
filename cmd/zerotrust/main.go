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

// Package main is the entry point for the zerotrust CLI.
//
// zerotrust is a single native binary — no Docker orchestration. Distribute
// it as a platform-specific Go build; users who want a containerised
// environment build/run the image themselves.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/pipeline"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// ExitError wraps an exit code for propagation through cobra RunE.
// This ensures deferred cleanup runs before the process exits.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

func main() {
	root := &cobra.Command{
		Use:     "zerotrust",
		Short:   "Local, privacy-first AI codebase security scanner",
		Version: version,
		Long: `zerotrust scans a codebase for security vulnerabilities. Static analysis
(pattern rules, taint tracing) always runs locally — no VCS token required.

Two detection paths run in parallel: fast pattern rules (OpenGrep, ast-grep,
instruction-file scanning) and a Joern-backed semantic taint pipeline with an
LLM verifier. The LLM stage can run against a local Ollama model or a hosted
API provider (--llm-provider). Findings are deduplicated, SSVC-scored, and
rendered to an HTML and/or JSON report.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetVersionTemplate("zerotrust {{.Version}}\n")
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("version").Shorthand = "" // free up -v for --verbose on subcommands

	scan := &cobra.Command{
		Use:   "scan [directory]",
		Short: "Scan a directory for security vulnerabilities",
		Long: `Scan a directory for security vulnerabilities.

Runs Path A (pattern rules) and Path B (semantic taint + LLM verification)
and writes a report.`,
		Example: `  zerotrust scan .
  zerotrust scan ./api --llm-provider openai --model gpt-4o
  zerotrust scan ./api --json-report ./out/findings.json
  zerotrust scan . --patch`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan,
	}
	defineFlags(scan)
	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		if exitErr, ok := errors.AsType[*ExitError](err); ok {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// runScan drives the pipeline directly on the host.
func runScan(cmd *cobra.Command, args []string) error {
	runCfg, err := runConfigFromCommand(cmd)
	if err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if _, err := config.Load(runCfg.CalibrationPath); err != nil {
		return fmt.Errorf("calibration: %w", err)
	}

	cfg := pipeline.Config{
		Target:          ".",
		ModelName:       runCfg.ModelName,
		ReportPath:      runCfg.ReportPath,
		JSONReportPath:  runCfg.JSONReportPath,
		ProjectID:       runCfg.ProjectID,
		JoernBin:        runCfg.JoernBin,
		LLMProvider:     runCfg.LLMProvider,
		LLMBaseURL:      runCfg.LLMBaseURL,
		LLMAPIKey:       runCfg.LLMAPIKey,
		CalibrationPath: runCfg.CalibrationPath,
		Verbose:         runCfg.Verbose,
		JoernURL:        "http://127.0.0.1:8080",
	}
	if len(args) > 0 {
		cfg.Target = args[0]
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			slog.Warn("signal received, shutting down", "component", "main")
			cancel()
		case <-ctx.Done():
		}
	}()

	renderer := selectRenderer()
	events := make(chan output.Event, 64)

	p, err := pipeline.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("pipeline init: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		var runErr error
		scored, err := p.StartScanProcess(ctx, events)
		if err != nil {
			runErr = err
			output.Emit(events, output.Event{Kind: output.EventError, Err: err})
		} else if runCfg.GeneratePatches {
			output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "patch"})
			scored, err = patch.GenerateForFindings(ctx, cfg.Target, scored)
			if err != nil {
				runErr = err
				output.Emit(events, output.Event{Kind: output.EventError, Err: err})
			} else {
				p.GenerateReport(time.Now(), scored)
				output.Emit(events, output.Event{
					Kind:  output.EventStageEnd,
					Stage: "patch",
					Summary: &output.StageSummary{
						Stage:  "patch",
						Detail: "Patches generated for findings",
					},
				})
			}
		}
		close(events)
		errCh <- runErr
	}()

	if err := renderer.Render(ctx, events); err != nil {
		return fmt.Errorf("render: %w", err)
	}
	if closeErr := p.Close(); closeErr != nil {
		slog.Default().Error("pipeline close", "err", closeErr)
	}
	if scanErr := <-errCh; scanErr != nil {
		return scanErr
	}
	return &ExitError{Code: renderer.ExitCode()}
}
