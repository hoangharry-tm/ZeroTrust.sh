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
	"encoding/json"
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
	// Think disables chain-of-thought reasoning for thinking models (e.g. qwen3).
	// nil = model default, boolPtr(false) = disable CoT.
	Think *bool `json:"think,omitempty"`
	// NumCtx is the context window size in tokens (Ollama: num_ctx).
	// Overrides the model's default (often 4096). Set to 2×NumPredict to give
	// thinking models room for CoT + prompt + output without hitting done_reason=length.
	NumCtx int `json:"num_ctx,omitempty"`
	// Tools lists the functions the model may call instead of (or before)
	// producing a final text answer. Empty means no tool-calling capability
	// is offered for this request — both providers ignore Tools entirely.
	//
	// json:"-" — both providers surface tools at the top level of their own
	// request bodies (OpenAI's ChatCompletionNewParams.Tools, Ollama's
	// chatRequest.Tools), not nested inside the "options"/inference-parameter
	// sub-object this struct otherwise represents on Ollama's wire format.
	Tools []ToolDef `json:"-"`
	// JSON requests constrained JSON output from the provider (Ollama's
	// top-level "format":"json", OpenAI's response_format
	// {"type":"json_object"}) instead of relying on regex/brace-slicing a
	// JSON object out of free text. Use this whenever the prompt asks for a
	// JSON verdict/object — it removes an entire class of "model wrapped the
	// JSON in prose/markdown fences" failures rather than mitigating it after
	// the fact. Do NOT set this for prompts that intentionally ask for plain
	// text (e.g. "YES"/"NO", a category word, a unified diff) — constraining
	// those to JSON would break the format they actually need.
	// json:"-" — same reason as Tools: this is a top-level wire field on both
	// providers, not an inference-parameter.
	JSON bool `json:"-"`
}

// ToolDef describes one callable function offered to the model in a Chat
// request. Parameters is a JSON Schema object (the same shape both OpenAI's
// and Ollama's tool-calling APIs expect), e.g.:
//
//	json.RawMessage(`{"type":"object","properties":{"function_id":{"type":"string"}},"required":["function_id"]}`)
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ToolCall is one function invocation the model requested instead of (or
// alongside) a text answer. Arguments is the model's raw JSON-encoded
// argument object — callers unmarshal it themselves, matching the schema
// they supplied in the corresponding ToolDef.
type ToolCall struct {
	// ID identifies this specific call — echo it back as Message.ToolCallID
	// on the tool-result message so the provider can match results to calls.
	// Ollama does not use call IDs; ID is empty for Ollama responses and the
	// caller does not need to set ToolCallID when replying to it.
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Role identifies the speaker in a chat turn.
type Role string

// Role constants for chat turn speakers.
const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	// RoleTool is a tool-result message: the caller's answer to a ToolCall
	// the model previously requested. Set ToolCallID to the ToolCall.ID it
	// answers (leave empty for Ollama, which doesn't use call IDs).
	RoleTool Role = "tool"
)

// Message is a single turn in a multi-turn chat conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
	// ToolCalls is set on an assistant response when the model chose to call
	// one or more tools instead of (or before) answering. Empty on a normal
	// text response. Callers must feed each result back as its own
	// RoleTool message before the next Chat call.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID is set on a RoleTool message to identify which ToolCall it
	// answers. Unused (leave empty) for Ollama.
	ToolCallID string `json:"tool_call_id,omitempty"`
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

// New returns the Provider selected by cfg.Provider, wrapped with the
// default retry/backoff policy (see WithRetry) so every caller gets
// resilience against transient backend errors without needing to know
// about it.
// Returns an error if cfg.Model is empty or the provider kind is unknown.
func New(cfg Config) (Provider, error) {
	if cfg.Model == "" {
		return nil, errors.New("llm: model is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	var p Provider
	switch cfg.Provider {
	case ProviderOllama, "":
		p = newOllamaClient(cfg)
	case ProviderOpenAI:
		var err error
		p, err = newOpenAIClient(cfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("llm: unknown provider: " + string(cfg.Provider))
	}
	return WithRetry(p, DefaultRetryConfig), nil
}

// SetProviderMIVBlocked marks an Ollama-backed provider as MIV-blocked.
// After this call, Generate and Chat return ErrModelBlocked.
// No-op for non-Ollama providers.
//
// Unwraps a retry-wrapped provider (New wraps every provider it returns via
// WithRetry) before the type assertion — without this, p would always be a
// *retryProvider here, the assertion to *ollamaClient would always fail, and
// MIV blocking would silently stop working the moment retry wrapping was
// introduced.
func SetProviderMIVBlocked(p Provider) {
	if rp, ok := p.(*retryProvider); ok {
		p = rp.next
	}
	if oc, ok := p.(*ollamaClient); ok {
		oc.mivBlock.Store(true)
	}
}
