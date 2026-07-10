package config

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestLLMModeFlag_InvalidRejected(t *testing.T) {
	cmd := &cobra.Command{}
	DefineFlags(cmd)

	// Simulate --llm-mode invalid
	cmd.SetArgs([]string{"--llm-mode", "invalid"})
	err := cmd.Execute()
	if err != nil {
		// Expected: flag parsing happens during Execute; the error we care about is FromCommand.
		// But cobra won't validate the flag value — we do that in FromCommand.
		// So we test FromCommand directly.
	}

	// Test FromCommand with invalid value
	_, err = FromCommand(cmd)
	if err == nil {
		t.Fatal("expected error for invalid --llm-mode value")
	}
}

func TestLLMModeFlag_DefaultIsMid(t *testing.T) {
	cmd := &cobra.Command{}
	DefineFlags(cmd)

	// No --llm-mode flag set; default should be "mid"
	cfg, err := FromCommand(cmd)
	if err != nil {
		t.Fatalf("FromCommand() returned error: %v", err)
	}
	if cfg.LLMMode != "mid" {
		t.Errorf("LLMMode = %q, want %q", cfg.LLMMode, "mid")
	}
}

func TestLLMModeFlag_ValidValues(t *testing.T) {
	for _, mode := range []string{"small", "mid", "frontier"} {
		cmd := &cobra.Command{}
		DefineFlags(cmd)
		cmd.SetArgs([]string{"--llm-mode", mode})
		_ = cmd.Execute()

		cfg, err := FromCommand(cmd)
		if err != nil {
			t.Fatalf("FromCommand() for mode=%q returned error: %v", mode, err)
		}
		if cfg.LLMMode != mode {
			t.Errorf("LLMMode = %q, want %q", cfg.LLMMode, mode)
		}
	}
}
