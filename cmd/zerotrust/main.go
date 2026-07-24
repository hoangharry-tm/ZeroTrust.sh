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
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/pipeline"
	"github.com/hoangharry-tm/zerotrust/internal/poe"
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

const (
	rootLongDesc = `zerotrust scans a codebase for security vulnerabilities. Static analysis
(pattern rules, taint tracing) always runs locally — no VCS token required.

Two detection paths run in parallel: fast pattern rules (OpenGrep, ast-grep,
instruction-file scanning) and a Joern-backed semantic taint pipeline with an
LLM verifier. The LLM stage can run against a local Ollama model or a hosted
API provider (--llm-provider). Findings are deduplicated, SSVC-scored, and
persisted to Postgres — there is no HTML/JSON report or CLI progress display;
query the database directly.`
	scanLongDesc = `Scan a directory for security vulnerabilities.

Runs Deterministic (pattern rules) and Reasoning (semantic taint + LLM verification),
then persists scored findings to Postgres (--db-url or $DATABASE_URL).`
	scanExample = `  zerotrust scan . --db-url postgres://user:pass@localhost:5432/zerotrust
  zerotrust scan ./api --llm-provider openai --model gpt-4o
  zerotrust scan . --patch
  zerotrust scan . --verify-poc --poe-artifact ./target/app.jar`
)

func main() {
	root := &cobra.Command{
		Use:           "zerotrust",
		Short:         "Local, privacy-first AI codebase security scanner",
		Version:       version,
		Long:          rootLongDesc,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetVersionTemplate("zerotrust {{.Version}}\n")
	root.InitDefaultVersionFlag()
	root.Flags().Lookup("version").Shorthand = "" // free up -v for --verbose on subcommands

	scan := &cobra.Command{
		Use:     "scan [directory]",
		Short:   "Scan a directory for security vulnerabilities",
		Long:    scanLongDesc,
		Example: scanExample,
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScan,
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

// runScan drives the pipeline directly on the host. There is no report/JSON
// output and no CLI progress renderer — findings are persisted to Postgres;
// an analyst queries the database directly. The only terminal output is
// structured logging (stderr, when --verbose) and the process exit code.
func runScan(cmd *cobra.Command, args []string) error {
	runCfg, err := runConfigFromCommand(cmd)
	if err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if _, err := config.Load(runCfg.CalibrationPath); err != nil {
		return fmt.Errorf("calibration: %w", err)
	}
	if runCfg.VerifyPoC {
		if _, err := exec.LookPath("docker"); err != nil {
			return fmt.Errorf("--verify-poc requires the docker CLI on PATH: %w", err)
		}
	}
	// Joern is on by default (--joern-bin defaults to "joern"), but a missing
	// binary is a non-fatal degradation, not a hard failure — pattern-matching
	// still runs. It must still be loud: without this, a missing joern binary
	// silently disables CPG/taint analysis (Deterministic's Joern half, all of
	// Reasoning, PoE route resolution) for the whole scan with nothing but a
	// buried build/zerotrust.log line to show for it.
	if runCfg.JoernBin != "" {
		if _, err := exec.LookPath(runCfg.JoernBin); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: joern binary %q not found on PATH — CPG/taint analysis disabled for this scan (pattern-matching only): %v\n",
				runCfg.JoernBin, err)
		}
	}

	cfg := pipeline.Config{
		Target:          ".",
		ModelName:       runCfg.ModelName,
		DatabaseURL:     runCfg.DatabaseURL,
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

	p, err := pipeline.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("pipeline init: %w", err)
	}
	defer func() {
		if closeErr := p.Close(); closeErr != nil {
			slog.Default().Error("pipeline close", "err", closeErr)
		}
	}()

	scored, err := p.StartScanProcess(ctx, nil)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if runCfg.VerifyPoC {
		verifier := poe.New(p.Provider(), p.Graph())
		verified, poeErr := verifier.Run(ctx, cfg.Target, runCfg.PoEArtifact, scored)
		if poeErr != nil {
			return fmt.Errorf("verify-poc: %w", poeErr)
		}
		scored = verified
		// persistFindings (inside StartScanProcess) already wrote a row per
		// finding, including an empty poe_results row, before PoE ran — this
		// second write is what actually lands the real PoE verdicts and any
		// PoESuccess confidence/severity boost in Postgres.
		p.PersistPoEResults(ctx, scored)
	}

	if runCfg.GeneratePatches {
		scored, err = patch.GenerateForFindings(ctx, cfg.Target, scored)
		if err != nil {
			return fmt.Errorf("patch: %w", err)
		}
	}

	return &ExitError{Code: exitCodeForFindings(scored)}
}

// exitCodeForFindings maps scored findings to the documented CI exit-code
// contract: 0 = no BLOCK/HIGH findings, 1 = one or more BLOCK/HIGH findings.
func exitCodeForFindings(scored []finding.Finding) int {
	for _, f := range scored {
		if f.SeverityLabel == finding.SeverityBlock || f.SeverityLabel == finding.SeverityHigh {
			return 1
		}
	}
	return 0
}
