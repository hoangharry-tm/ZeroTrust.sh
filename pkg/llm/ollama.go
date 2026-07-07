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

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

const ollamaDefaultBaseURL = "http://localhost:11434"

// ollamaClient wraps the Ollama REST API at a single model endpoint.
// It is unexported; callers interact with it through the Provider interface.
type ollamaClient struct {
	baseURL    string
	model      string
	httpClient *http.Client
	mivBlock   atomic.Bool // set by SetMIVBlocked; gates Generate and Chat
}

func newOllamaClient(cfg Config) *ollamaClient {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = ollamaDefaultBaseURL
	}
	return &ollamaClient{
		baseURL:    baseURL,
		model:      cfg.Model,
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

// generateRequest is the Ollama /api/generate request body.
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

// chatRequest is the Ollama /api/chat request body.
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

// SetMIVBlocked marks this client as blocked by the Model Integrity Verifier.
// After this call, all Generate and Chat invocations return ErrModelBlocked.
// The flag is permanent for the lifetime of the client instance.
func (c *ollamaClient) SetMIVBlocked() { c.mivBlock.Store(true) }

// Generate sends prompt to the configured model and returns the full response text.
func (c *ollamaClient) Generate(ctx context.Context, prompt string, opts *Options) (string, error) {
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

// Chat sends a multi-turn conversation and returns the assistant reply.
func (c *ollamaClient) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
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

// Ping checks that the Ollama server is reachable and the configured model is loaded.
func (c *ollamaClient) Ping(ctx context.Context) error {
	_, err := c.Generate(ctx, "ping", nil)
	return err
}

// BackboneCheck sends a minimal structured JSON probe and verifies that the model
// can produce valid JSON. Used by llmscan to decide between the full 3-step ReAct
// loop and the single-pass fallback for under-capable models.
func (c *ollamaClient) BackboneCheck(ctx context.Context) (bool, error) {
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
func (c *ollamaClient) ModelName() string { return c.model }
