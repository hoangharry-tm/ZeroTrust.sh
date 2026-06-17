// Package main is the entry point for the zerotrust CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "zerotrust <directory>",
		Short: "Local, privacy-first AI codebase security scanner",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runScan,
	}

	root.Flags().StringP("model", "m", "", "Ollama model name (e.g. llama3.2)")
	root.Flags().BoolP("offline", "o", false, "disable all network requests (Trivy offline mode)")
	root.Flags().String("output", "report.html", "HTML report output path")
	root.Flags().String("project-id", "", "override project ID used for scan-state caching")
	root.Flags().String("mode", "Default", "scan scope mode: Default | Thorough | Full")
	root.Flags().String("joern-url", "http://localhost:8080", "Joern HTTP API base URL")
	root.Flags().String("ollama-url", "http://localhost:11434", "Ollama HTTP API base URL")
	root.Flags().Int("token-cap", 50_000, "token budget cap for Path B Tier 3")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
	cfg.OutputPath, err = cmd.Flags().GetString("output")
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
	cfg.JoernURL, err = cmd.Flags().GetString("joern-url")
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

	ctx := cmd.Context()
	p, err := newPipeline(ctx, cfg)
	if err != nil {
		return fmt.Errorf("pipeline init: %w", err)
	}
	defer p.close() //nolint:errcheck

	return p.run(ctx)
}
