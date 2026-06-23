// Copyright 2026 hoangharry-tm
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

// Package ollama provides a minimal HTTP client for the Ollama local inference API.
//
// The client is used by the LLM Verifier (Path A) and the LLM Semantic Scan (Path B)
// via the Python worker boundary. Direct Go-side calls are reserved for lightweight
// tasks (backbone capability check, ping at startup).
//
// Only the /api/generate and /api/chat endpoints are used. Streaming is disabled —
// all responses are collected in full before returning, which simplifies
// XGrammar-2-constrained JSON parsing in the Python worker.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ErrModelBlocked is returned by Generate and Chat when the Model Integrity
// Verifier has detected a known model with a hash mismatch. All LLM calls must
// be skipped; CPG and pattern-matching continue unaffected.
var ErrModelBlocked = errors.New("ollama: model blocked by integrity verifier")

const defaultBaseURL = "http://localhost:11434"

// Client wraps the Ollama REST API at a single model endpoint.
type Client struct {
	baseURL    string
	model      string
	httpClient *http.Client
	mivBlock   atomic.Bool // set by SetMIVBlocked; gates Generate and Chat
}

// Options controls inference parameters for a single request.
// Zero values fall back to Ollama's model defaults.
//
// Example:
//
//	opts := &ollama.Options{Temperature: 0.1, NumPredict: 512}
type Options struct {
	// Temperature controls output randomness. Use 0.0–0.1 for structured JSON output.
	Temperature float64 `json:"temperature,omitempty"`
	// NumPredict is the maximum number of tokens to generate.
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

// New returns a Client targeting the Ollama server at baseURL with the given model.
// If baseURL is empty, localhost:11434 is used.
//
// Example:
//
//	c := ollama.New("", "llama3.2")
//	text, err := c.Generate(ctx, "Summarize: ...", nil)
func New(baseURL, model string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:    baseURL,
		model:      model,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// ─── /api/generate ───────────────────────────────────────────────────────────

type generateRequest struct {
	Model   string   `json:"model"`
	Prompt  string   `json:"prompt"`
	Stream  bool     `json:"stream"`
	Options *Options `json:"options,omitempty"`
}

type generateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// SetMIVBlocked marks this client as blocked by the Model Integrity Verifier.
// After this call, all Generate and Chat invocations return ErrModelBlocked.
// The flag is permanent for the lifetime of the client instance.
func (c *Client) SetMIVBlocked() { c.mivBlock.Store(true) }

// Generate sends prompt to the configured model and returns the full response text.
// opts may be nil to use the server's model defaults.
//
// Parameters:
//   - ctx: cancellation/deadline context.
//   - prompt: raw text prompt sent to the model.
//   - opts: inference parameters; nil uses server defaults.
//
// Returns the model's response string, or an error if the HTTP request fails.
func (c *Client) Generate(ctx context.Context, prompt string, opts *Options) (string, error) {
	if c.mivBlock.Load() {
		return "", ErrModelBlocked
	}
	body, err := json.Marshal(generateRequest{
		Model:   c.model,
		Prompt:  prompt,
		Stream:  false,
		Options: opts,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama generate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama: unexpected status %d", resp.StatusCode)
	}

	var gr generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}
	return gr.Response, nil
}

// ─── /api/chat ───────────────────────────────────────────────────────────────

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
	Options  *Options  `json:"options,omitempty"`
}

type chatResponse struct {
	Message Message `json:"message"`
	Done    bool    `json:"done"`
}

// Chat sends a multi-turn conversation and returns the assistant reply.
// Use this for the bounded ReAct loop (Path B LLM Scan) where system context
// and prior reasoning steps must be preserved across iterations.
//
// Parameters:
//   - ctx: cancellation/deadline context.
//   - messages: ordered turns (system → user → assistant → user …).
//   - opts: inference parameters; nil uses server defaults.
//
// Returns the assistant's reply Message, or an error if the request fails.
func (c *Client) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
	if c.mivBlock.Load() {
		return Message{}, ErrModelBlocked
	}
	body, err := json.Marshal(chatRequest{
		Model:    c.model,
		Messages: messages,
		Stream:   false,
		Options:  opts,
	})
	if err != nil {
		return Message{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Message{}, fmt.Errorf("ollama chat: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("ollama chat: unexpected status %d", resp.StatusCode)
	}

	var cr chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return Message{}, fmt.Errorf("ollama chat decode: %w", err)
	}
	return cr.Message, nil
}

// ─── Utility ─────────────────────────────────────────────────────────────────

// Ping checks that the Ollama server is reachable and the configured model is loaded.
// Returns nil if the server responds with HTTP 200.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Generate(ctx, "ping", nil)
	return err
}

// BackboneCheck sends a minimal structured JSON probe and verifies that the model
// can produce valid JSON. Returns true when the model passes.
//
// Used by llmscan before each scan to decide between the full 3-step ReAct loop
// and the single-pass CoD+SCoT fallback for under-capable models.
//
// Parameters:
//   - ctx: cancellation/deadline context.
//
// Returns:
//   - bool: true if the model returns parseable JSON within two attempts.
//   - error: non-nil only for infrastructure failures (network error, server down).
func (c *Client) BackboneCheck(ctx context.Context) (bool, error) {
	const probe = `Respond with exactly this JSON and nothing else: {"ok":true}`
	opts := &Options{Temperature: 0.0, NumPredict: 32}

	for range 2 {
		resp, err := c.Generate(ctx, probe, opts)
		if err != nil {
			return false, err
		}
		var v struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(resp)), &v); err == nil && v.OK {
			return true, nil
		}
	}
	return false, nil
}

// ModelName returns the model identifier this client was configured with.
func (c *Client) ModelName() string { return c.model }
