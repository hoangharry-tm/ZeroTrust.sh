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
	"testing"

	"github.com/spf13/cobra"
)

func TestDBURLFlag_RequiredWhenUnset(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	cmd := &cobra.Command{}
	defineFlags(cmd)

	_, err := runConfigFromCommand(cmd)
	if err == nil {
		t.Fatal("expected error when --db-url and $DATABASE_URL are both unset")
	}
}

func TestDBURLFlag_FallsBackToEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	cmd := &cobra.Command{}
	defineFlags(cmd)

	cfg, err := runConfigFromCommand(cmd)
	if err != nil {
		t.Fatalf("runConfigFromCommand() returned error: %v", err)
	}
	if cfg.DatabaseURL != "postgres://test:test@localhost:5432/test" {
		t.Errorf("DatabaseURL = %q, want fallback to $DATABASE_URL", cfg.DatabaseURL)
	}
}

func TestLLMProviderFlag_InvalidRejected(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	cmd := &cobra.Command{}
	defineFlags(cmd)
	cmd.SetArgs([]string{"--llm-provider", "invalid"})
	_ = cmd.Execute()

	_, err := runConfigFromCommand(cmd)
	if err == nil {
		t.Fatal("expected error for invalid --llm-provider value")
	}
}

func TestLLMProviderFlag_DefaultIsOllama(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	cmd := &cobra.Command{}
	defineFlags(cmd)

	cfg, err := runConfigFromCommand(cmd)
	if err != nil {
		t.Fatalf("runConfigFromCommand() returned error: %v", err)
	}
	if cfg.LLMProvider != "ollama" {
		t.Errorf("LLMProvider = %q, want %q", cfg.LLMProvider, "ollama")
	}
}

func TestLLMProviderFlag_OpenAIRequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	cmd := &cobra.Command{}
	defineFlags(cmd)
	cmd.SetArgs([]string{"--llm-provider", "openai"})
	_ = cmd.Execute()

	_, err := runConfigFromCommand(cmd)
	if err == nil {
		t.Fatal("expected error when --llm-provider=openai with no API key set")
	}
}

func TestLLMProviderFlag_OpenAIAcceptsFlagKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	cmd := &cobra.Command{}
	defineFlags(cmd)
	cmd.SetArgs([]string{"--llm-provider", "openai", "--llm-api-key", "sk-test"})
	_ = cmd.Execute()

	cfg, err := runConfigFromCommand(cmd)
	if err != nil {
		t.Fatalf("runConfigFromCommand() returned error: %v", err)
	}
	if cfg.LLMAPIKey != "sk-test" {
		t.Errorf("LLMAPIKey = %q, want %q", cfg.LLMAPIKey, "sk-test")
	}
}
