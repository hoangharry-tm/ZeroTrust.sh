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
//     The binary on the host pulls and runs a container with all heavy
//     dependencies pre-installed (Joern, Python worker, OpenGrep, ast-grep).
//   - Native mode (--native): runs the pipeline directly. All dependencies
//     must be installed on the host PATH.
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
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/report"
	"github.com/hoangharry-tm/zerotrust/internal/report/mock"
)

// ExitError wraps an exit code for propagation through cobra RunE.
// This ensures deferred cleanup runs before the process exits.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

const (
	engineImage   = "ghcr.io/hoangharry-tm/zerotrust-engine:latest"
	ollamaHostURL = "http://localhost:11434"
	defaultCap    = 50_000
)

func main() {
	root := &cobra.Command{
		Use:   "zerotrust <directory>",
		Short: "Local, privacy-first AI codebase security scanner",
		Long: `ZeroTrust.sh is a local, privacy-first vulnerability scanner for source code.
It runs deep semantic analysis and outputs an HTML report with proof of exploitation.

By default, analysis runs inside a Docker container — the engine image includes
all dependencies (Joern, Python ML worker, OpenGrep, ast-grep). Use --native to
run the pipeline directly with local toolchain installations.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runOrchestrate,
	}

	root.Flags().StringP("model", "m", "", "Ollama model name (e.g. llama3.2)")
	root.Flags().BoolP("offline", "o", false, "disable all network requests (Trivy offline mode)")
	root.Flags().String("report", "", "HTML report output path (default: build/report.html)")
	root.Flags().String("project-id", "", "override project ID used for scan-state caching")
	root.Flags().String("mode", "Default", "scan scope mode: Default | Thorough | Full")
	root.Flags().String("joern-bin", "", "path to joern-server binary (native mode only)")
	root.Flags().String("ollama-url", ollamaHostURL, "Ollama HTTP API base URL")
	root.Flags().Int("token-cap", defaultCap, "token budget cap for Path B Tier 3")
	root.Flags().Bool("native", false, "run directly with local dependencies (no Docker)")
	root.Flags().Bool("pull", true, "pull the latest engine image before running (Docker mode)")
	root.Flags().String("engine-image", engineImage, "Docker image for the engine")
	root.Flags().Bool("mock", false, "render the HTML report with mock data (no scan; UI development only)")
	root.Flags().Bool("mock-large", false, "render with large mock dataset (~60 findings)")
	root.Flags().BoolP("verbose", "v", false, "enable debug-level logging to stderr")

	if err := root.Execute(); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runOrchestrate(cmd *cobra.Command, args []string) error {
	mock, _ := cmd.Flags().GetBool("mock")
	mockLarge, _ := cmd.Flags().GetBool("mock-large")
	if mock || mockLarge {
		slog.Debug("mock mode selected", "component", "main", "large", mockLarge)
		return runMock(cmd)
	}
	native, _ := cmd.Flags().GetBool("native")
	if native {
		slog.Info("native mode selected", "component", "main")
		return runScan(cmd, args)
	}
	slog.Info("docker mode selected", "component", "main")
	return runContainer(cmd, args)
}

// runMock renders the HTML report with hardcoded fixture data and opens it in the
// default browser. No scan is performed.
func runMock(cmd *cobra.Command) error {
	slog.Debug("runMock entry", "component", "main")
	reportPath, _ := cmd.Flags().GetString("report")
	if reportPath == "" {
		reportPath = "build/report.html"
	}
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o750); err != nil {
		slog.Error("failed to create report directory", "component", "main", "err", err)
		return fmt.Errorf("create report dir: %w", err)
	}
	f, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	mockLarge, _ := cmd.Flags().GetBool("mock-large")
	findings := mock.MockFindings()
	if mockLarge {
		findings = mock.MockFindingsLarge()
	}

	gen := report.New(reportPath)
	if err := gen.Render(f, mock.MockScanInfo(), findings); err != nil {
		return fmt.Errorf("render mock report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "mock report written → %s\n", reportPath)

	// ponytail: open is fire-and-forget; ignore error (user can open manually)
	opener := map[string]string{"darwin": "open", "linux": "xdg-open", "windows": "explorer"}
	if bin, ok := opener[runtime.GOOS]; ok {
		_ = exec.Command(bin, reportPath).Start()
	}
	return nil
}

// runScan builds a ScanConfig and drives the pipeline directly.
// This is the native-mode execution path.
func runScan(cmd *cobra.Command, args []string) error {
	cfg := ScanConfig{}
	if len(args) > 0 {
		cfg.Target = args[0]
	}

	var err error
	cfg.ModelName, err = cmd.Flags().GetString("model")
	if err != nil {
		return err
	}
	cfg.Offline, err = cmd.Flags().GetBool("offline")
	if err != nil {
		return err
	}
	cfg.ReportPath, err = cmd.Flags().GetString("report")
	if err != nil {
		return err
	}
	cfg.ProjectID, err = cmd.Flags().GetString("project-id")
	if err != nil {
		return err
	}
	cfg.ScanMode, err = cmd.Flags().GetString("mode")
	if err != nil {
		return err
	}
	cfg.JoernBin, err = cmd.Flags().GetString("joern-bin")
	if err != nil {
		return err
	}
	cfg.OllamaURL, err = cmd.Flags().GetString("ollama-url")
	if err != nil {
		return err
	}
	cfg.TokenCap, err = cmd.Flags().GetInt("token-cap")
	if err != nil {
		return err
	}
	cfg.Verbose, err = cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	// In native mode JoernURL can be set via --joern-bin; default points at
	// a locally running Joern server (started externally by the user).
	cfg.JoernURL = "http://127.0.0.1:8080"

	slog.Info("starting native scan",
		"component", "main",
		"target", cfg.Target,
		"mode", cfg.ScanMode,
		"report", cfg.ReportPath,
	)

	renderer := selectRenderer()
	events := make(chan output.Event, 64)

	ctx := cmd.Context()
	p, err := newPipeline(ctx, cfg)
	if err != nil {
		slog.Error("pipeline init failed", "component", "main", "err", err)
		return fmt.Errorf("pipeline init: %w", err)
	}
	defer p.close() //nolint:errcheck

	go func() {
		if scanErr := p.run(ctx, events); scanErr != nil {
			output.Emit(events, output.Event{Kind: output.EventError, Err: scanErr})
		}
		close(events)
	}()

	if err := renderer.Render(ctx, events); err != nil {
		return fmt.Errorf("render: %w", err)
	}
	return &ExitError{Code: renderer.ExitCode()}
}

// runContainer orchestrates the engine inside a Docker container.
// It is the default execution mode.
func runContainer(cmd *cobra.Command, args []string) error {
	slog.Debug("runContainer entry", "component", "main")
	flags := cmd.Flags()

	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		slog.Error("failed to resolve target path", "component", "main", "err", err)
		return fmt.Errorf("resolve target path: %w", err)
	}

	ollamaFound, err := checkDeps()
	if err != nil {
		return err
	}

	pull, _ := flags.GetBool("pull")
	if pull {
		img, _ := flags.GetString("engine-image")
		fmt.Fprintf(os.Stderr, "  Pulling engine image  %s\n", img)
		pullCmd := exec.Command("docker", "pull", img)
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
	// Ensure scans.db is never accidentally committed.
	giPath := filepath.Join(ztState, ".gitignore")
	if _, err := os.Stat(giPath); os.IsNotExist(err) {
		_ = os.WriteFile(giPath, []byte("scans.db\nscan_state.db\n"), 0o600)
	}

	img, _ := flags.GetString("engine-image")
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
		argsDocker = append(
			argsDocker,
			"--add-host", "host.docker.internal:host-gateway",
			"-e", "OLLAMA_URL="+ollamaURL,
		)
	}

	argsDocker = append(argsDocker, img, "scan", "/workspace")

	// Forward relevant flags to the engine inside the container
	addEngineFlag(&argsDocker, flags, "model", "model")
	addEngineFlag(&argsDocker, flags, "offline", "offline")
	addEngineFlag(&argsDocker, flags, "report", "report")
	addEngineFlag(&argsDocker, flags, "project-id", "project-id")
	addEngineFlag(&argsDocker, flags, "mode", "mode")
	addEngineFlag(&argsDocker, flags, "token-cap", "token-cap")

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dockerCmd := exec.CommandContext(ctx, "docker", argsDocker...)
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	slog.Info("launching container scan",
		"component", "main",
		"target", targetAbs,
		"image", img,
		"ollama_found", ollamaFound,
	)
	if err := dockerCmd.Run(); err != nil {
		var dockerExitErr *exec.ExitError
		if errors.As(err, &dockerExitErr) {
			return &ExitError{Code: dockerExitErr.ExitCode()}
		}
		slog.Error("container execution failed", "component", "main", "err", err)
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

func addEngineFlag(args *[]string, flags *pflag.FlagSet, flagName, envName string) {
	if flags.Changed(flagName) {
		val := flags.Lookup(flagName).Value.String()
		*args = append(*args, "--"+envName, val)
	}
}
