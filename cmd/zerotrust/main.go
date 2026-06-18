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
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/hoangharry-tm/zerotrust/internal/output"
)

const (
	engineImage   = "ghcr.io/hoangharry-tm/zerotrust-engine:latest"
	ollamaHostURL = "http://localhost:11434"
	scansDBPath   = ".zerotrust"
	defaultCap    = 50_000
)

func main() {
	root := &cobra.Command{
		Use:   "zerotrust <directory>",
		Short: "Local, privacy-first AI codebase security scanner",
		Long: `ZeroTrust.sh scans codebases modified by AI coding agents for security
vulnerabilities, package hallucinations, prompt injection, and AI-agent-specific
threats.

By default, analysis runs inside a Docker container — the engine image includes
all dependencies (Joern, Python ML worker, OpenGrep, ast-grep). Use --native to
run the pipeline directly with local toolchain installations.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runOrchestrate,
	}

	root.Flags().StringP("model", "m", "", "Ollama model name (e.g. llama3.2)")
	root.Flags().BoolP("offline", "o", false, "disable all network requests (Trivy offline mode)")
	root.Flags().String("output", "", "output mode: minimal|tree|tui (default: auto-detect from TTY)")
	root.Flags().String("report", "", "HTML report output path (default: build/report.html)")
	root.Flags().String("project-id", "", "override project ID used for scan-state caching")
	root.Flags().String("mode", "Default", "scan scope mode: Default | Thorough | Full")
	root.Flags().String("joern-bin", "", "path to joern-server binary (native mode only)")
	root.Flags().String("ollama-url", ollamaHostURL, "Ollama HTTP API base URL")
	root.Flags().Int("token-cap", defaultCap, "token budget cap for Path B Tier 3")
	root.Flags().Bool("native", false, "run directly with local dependencies (no Docker)")
	root.Flags().Bool("pull", true, "pull the latest engine image before running (Docker mode)")
	root.Flags().String("engine-image", engineImage, "Docker image for the engine")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runOrchestrate(cmd *cobra.Command, args []string) error {
	native, _ := cmd.Flags().GetBool("native")
	if native {
		return runScan(cmd, args)
	}
	return runContainer(cmd, args)
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
	cfg.OutputMode, err = cmd.Flags().GetString("output")
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
	// In native mode JoernURL can be set via --joern-bin; default points at
	// a locally running Joern server (started externally by the user).
	cfg.JoernURL = "http://127.0.0.1:8080"

	renderer := selectRenderer(cfg.OutputMode)
	events := make(chan output.Event, 64)

	ctx := cmd.Context()
	p, err := newPipeline(ctx, cfg)
	if err != nil {
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
	os.Exit(renderer.ExitCode())
	return nil
}

// runContainer orchestrates the engine inside a Docker container.
// It is the default execution mode.
func runContainer(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found on PATH — install Docker Desktop (macOS) or docker.io (Linux)\n  or use --native to run with local dependencies")
	}

	pull, _ := flags.GetBool("pull")
	if pull {
		img, _ := flags.GetString("engine-image")
		fmt.Fprintf(os.Stderr, "[zerotrust] pulling engine image: %s\n", img)
		pullCmd := exec.Command("docker", "pull", img)
		pullCmd.Stdout = os.Stderr
		pullCmd.Stderr = os.Stderr
		if err := pullCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[zerotrust] pull failed (using cached image): %v\n", err)
		}
	}

	// Detect Ollama on the host for GPU passthrough
	ollamaURL := ""
	if ollamaReachable(ollamaHostURL) {
		ollamaURL = "http://host.docker.internal:11434"
		fmt.Fprintf(os.Stderr, "[zerotrust] detected Ollama on host → GPU passthrough enabled\n")
	} else {
		fmt.Fprintf(os.Stderr, "[zerotrust] no Ollama detected — LLM inference will use CPU (slower)\n")
	}

	ztHome := filepath.Join(os.Getenv("HOME"), scansDBPath)
	if err := os.MkdirAll(ztHome, 0750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	img, _ := flags.GetString("engine-image")
	argsDocker := []string{
		"run", "--rm",
		"--init",
		"--name", "zerotrust-scan",
		"-v", targetAbs + ":/workspace:ro",
		"-v", ztHome + ":/home/zt/.zerotrust",
		"-e", "ZT_PROJECT_DIR=/workspace",
		"-e", "HOME=/home/zt",
	}

	if ollamaURL != "" {
		argsDocker = append(argsDocker,
			"--add-host", "host.docker.internal:host-gateway",
			"-e", "OLLAMA_URL="+ollamaURL,
		)
	}

	argsDocker = append(argsDocker, img, "scan", "/workspace")

	// Forward relevant flags to the engine inside the container
	addEngineFlag(&argsDocker, flags, "model", "model")
	addEngineFlag(&argsDocker, flags, "offline", "offline")
	addEngineFlag(&argsDocker, flags, "output", "output")
	addEngineFlag(&argsDocker, flags, "report", "report")
	addEngineFlag(&argsDocker, flags, "project-id", "project-id")
	addEngineFlag(&argsDocker, flags, "mode", "mode")
	addEngineFlag(&argsDocker, flags, "token-cap", "token-cap")

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dockerCmd := exec.CommandContext(ctx, "docker", argsDocker...)
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	if err := dockerCmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
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

func addEngineFlag(args *[]string, flags *pflag.FlagSet, flagName, envName string) {
	if flags.Changed(flagName) {
		val := flags.Lookup(flagName).Value.String()
		*args = append(*args, "--"+envName, val)
	}
}
