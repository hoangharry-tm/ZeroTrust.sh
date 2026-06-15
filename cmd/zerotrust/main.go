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

	root.Flags().StringP("model", "m", "", "Ollama model name")
	root.Flags().BoolP("offline", "o", false, "disable all network requests (Trivy offline mode)")
	root.Flags().StringP("output", "", "report.html", "HTML report output path")
	root.Flags().StringP("project-id", "", "", "override project ID used for scan-state caching")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	_ = target
	// Pipeline wired in G2 (Go core + ingestion + Path A).
	return nil
}
