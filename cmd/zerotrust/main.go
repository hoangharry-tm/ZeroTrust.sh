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
// Single binary with two execution modes:
//   - Docker mode (default): orchestrates the engine image via docker run.
//   - Native mode (--native): runs the pipeline directly on the host.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/pipeline"
)

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
		Use:           "zerotrust",
		Short:         "Local, privacy-first AI codebase security scanner",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	scan := &cobra.Command{
		Use:   "scan <directory>",
		Short: "Scan a directory for security vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runOrchestrate,
	}
	config.DefineFlags(scan)
	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// runOrchestrate routes to the appropriate execution mode based on flags.
func runOrchestrate(cmd *cobra.Command, args []string) error {
	runCfg, err := config.FromCommand(cmd)
	if err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if _, err := config.Load(runCfg.CalibrationPath); err != nil {
		return fmt.Errorf("calibration: %w", err)
	}
	if runCfg.Native {
		return runScan(cmd, args, runCfg)
	}
	return runContainer(cmd, args, runCfg)
}

// runScan drives the pipeline directly on the host (native mode).
func runScan(cmd *cobra.Command, args []string, runCfg config.NativeRunConfig) error {
	cfg := pipeline.Config{
		Target:          ".",
		ModelName:       runCfg.ModelName,
		Offline:         runCfg.Offline,
		ReportPath:      runCfg.ReportPath,
		JSONReportPath:  runCfg.JSONReportPath,
		ProjectID:       runCfg.ProjectID,
		ScanMode:        runCfg.ScanMode,
		JoernBin:        runCfg.JoernBin,
		OllamaURL:       runCfg.OllamaURL,
		TokenCap:        runCfg.TokenCap,
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
		scored, err := p.Run(ctx, events)
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
						Detail: fmt.Sprintf("Patches generated for findings"),
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

// runContainer orchestrates the engine inside a Docker container.
func runContainer(cmd *cobra.Command, args []string, runCfg config.NativeRunConfig) error {
	slog.Debug("runContainer entry", "component", "main")

	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}

	ollamaFound := ollamaReachable(runCfg.OllamaURL)

	if runCfg.Pull {
		fmt.Fprintf(os.Stderr, "  Pulling engine image  %s\n", runCfg.EngineImage)
		pullCmd := exec.Command("docker", "pull", runCfg.EngineImage)
		pullCmd.Stdout = os.Stderr
		pullCmd.Stderr = os.Stderr
		if err := pullCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  Pull failed — using cached image (%v)\n", err)
		}
		fmt.Fprintln(os.Stderr)
	}

	ollamaURL := ""
	if ollamaFound {
		ollamaURL = "http://host.docker.internal:11434"
	}

	ztState := filepath.Join(targetAbs, ".zerotrust")
	if err := os.MkdirAll(ztState, 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	giPath := filepath.Join(ztState, ".gitignore")
	if _, err := os.Stat(giPath); os.IsNotExist(err) {
		_ = os.WriteFile(giPath, []byte("scans.db\nscan_state.db\n"), 0o600)
	}

	argsDocker := []string{
		"run", "--rm",
		"--init",
		"--name", "zerotrust-scan",
		"-v", targetAbs + ":/workspace:ro",
		"-v", ztState + ":/workspace/.zerotrust",
		"-e", "ZT_PROJECT_DIR=/workspace",
		"-e", "HOME=/home/zt",
	}
	if ollamaURL != "" {
		argsDocker = append(argsDocker,
			"--add-host", "host.docker.internal:host-gateway",
			"-e", "OLLAMA_URL="+ollamaURL,
		)
	}
	argsDocker = append(argsDocker, runCfg.EngineImage, "scan", "/workspace")

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dockerCmd := exec.CommandContext(ctx, "docker", argsDocker...)
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	slog.Info("launching container scan", "component", "main",
		"target", targetAbs, "image", runCfg.EngineImage, "ollama_found", ollamaFound)
	if err := dockerCmd.Run(); err != nil {
		var dockerExitErr *exec.ExitError
		if errors.As(err, &dockerExitErr) {
			return &ExitError{Code: dockerExitErr.ExitCode()}
		}
		return fmt.Errorf("container execution: %w", err)
	}
	return nil
}

func ollamaReachable(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
