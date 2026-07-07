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

// Package llm provides a provider-agnostic interface for LLM backends.
//
// The default provider is Ollama (local, offline-first). OpenAI-compatible
// endpoints are supported via Config.ProviderKind. Callers import only the
// Provider interface — never concrete client types.
package llm

import (
	"context"
	"errors"
	"time"
)

// Provider is the single integration point for all LLM backends.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Generate sends a single prompt and returns the completion text.
	Generate(ctx context.Context, prompt string, opts *Options) (string, error)

	// Chat sends a multi-turn conversation and returns the next assistant message.
	Chat(ctx context.Context, messages []Message, opts *Options) (Message, error)

	// Ping verifies the backend is reachable before a scan begins.
	Ping(ctx context.Context) error

	// ModelName returns the active model identifier (for logging and findings metadata).
	ModelName() string
}

// ErrModelBlocked is returned by Generate and Chat when the Model Integrity
// Verifier has blocked the model. All LLM calls must be skipped; CPG and
// pattern-matching continue unaffected.
var ErrModelBlocked = errors.New("llm: model blocked by integrity verifier")

// Options controls inference parameters for a single request.
// Zero values fall back to the provider's model defaults.
type Options struct {
	// Temperature controls output randomness. Use 0.0–0.1 for structured output.
	Temperature float64 `json:"temperature,omitempty"`
	// NumPredict is the maximum number of tokens to generate (max_tokens for OpenAI).
	NumPredict int `json:"num_predict,omitempty"`
	// TopP is the nucleus sampling probability threshold.
	TopP float64 `json:"top_p,omitempty"`
	// Stop lists strings that halt generation when encountered.
	Stop []string `json:"stop,omitempty"`
}

// Role identifies the speaker in a chat turn.
type Role string

// Role constants for chat turn speakers.
const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is a single turn in a multi-turn chat conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// ProviderKind identifies a supported LLM backend.
type ProviderKind string

const (
	ProviderOllama ProviderKind = "ollama"
	ProviderOpenAI ProviderKind = "openai"
)

// Config selects and configures an LLM provider at runtime.
// Ollama is the default; set ProviderKind to ProviderOpenAI for
// OpenAI-compatible endpoints.
type Config struct {
	// Provider selects the backend. Defaults to ProviderOllama if empty.
	Provider ProviderKind
	// BaseURL is the API base URL.
	//   Ollama: "http://localhost:11434" (default if empty)
	//   OpenAI: "https://api.openai.com/v1" (default if empty)
	BaseURL string
	// Model is the model identifier (e.g. "llama3.2", "gpt-4o"). Required.
	Model string
	// APIKey is the authentication key. Required for OpenAI, empty for Ollama.
	APIKey string
	// Timeout is the per-request HTTP timeout. Defaults to 120s if zero.
	Timeout time.Duration
}

// New returns the Provider selected by cfg.Provider.
// Returns an error if cfg.Model is empty or the provider kind is unknown.
func New(cfg Config) (Provider, error) {
	if cfg.Model == "" {
		return nil, errors.New("llm: model is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	switch cfg.Provider {
	case ProviderOllama, "":
		return newOllamaClient(cfg), nil
	case ProviderOpenAI:
		return newOpenAIClient(cfg)
	default:
		return nil, errors.New("llm: unknown provider: " + string(cfg.Provider))
	}
}

// SetProviderMIVBlocked marks an Ollama-backed provider as MIV-blocked.
// After this call, Generate and Chat return ErrModelBlocked.
// No-op for non-Ollama providers.
func SetProviderMIVBlocked(p Provider) {
	if oc, ok := p.(*ollamaClient); ok {
		oc.mivBlock.Store(true)
	}
}
