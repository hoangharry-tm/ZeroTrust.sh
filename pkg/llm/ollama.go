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
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
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
	Model   string          `json:"model"`
	Prompt  string          `json:"prompt"`
	Stream  bool            `json:"stream"`
	Options *Options        `json:"options,omitempty"`
	Think   *bool           `json:"think,omitempty"`
	Format  json.RawMessage `json:"format,omitempty"`
}

type generateResponse struct {
	Response   string `json:"response"`
	Done       bool   `json:"done"`
	DoneReason string `json:"done_reason"`
	EvalCount  int    `json:"eval_count"`
}

// chatRequest is the Ollama /api/chat request body. Messages and Tools use
// Ollama's own wire shapes (ollamaMessage/ollamaTool), which differ from our
// public Message/ToolDef types in one specific way: Ollama's tool-call
// arguments are a JSON object on the wire, while our public ToolCall.Arguments
// is a JSON-encoded string (matching OpenAI's convention, which the rest of
// this package is built around) — see toOllamaMessage/fromOllamaMessage.
type chatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *Options        `json:"options,omitempty"`
	Think    *bool           `json:"think,omitempty"`
	Tools    []ollamaTool    `json:"tools,omitempty"`
	Format   json.RawMessage `json:"format,omitempty"`
}

// jsonFormat is Ollama's wire value for "format":"json" — constrains the
// model to emit valid JSON (structure/field-shape is still the model's own
// choice; this only guarantees parseable output, which is exactly what every
// JSON.RawMessage parseVerdict/jsonBlockRe call site in this codebase needs).
var jsonFormat = json.RawMessage(`"json"`)

type chatResponse struct {
	Message    ollamaMessage `json:"message"`
	Done       bool          `json:"done"`
	DoneReason string        `json:"done_reason"`
	EvalCount  int           `json:"eval_count"`
}

// ollamaMessage is Ollama's wire shape for one chat message.
type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
}

// ollamaToolCall is Ollama's wire shape for one requested tool call —
// arguments is a JSON object here, not a string (contrast with OpenAI).
type ollamaToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

// ollamaTool is Ollama's wire shape for one tool definition offered to the model.
type ollamaTool struct {
	Type     string                `json:"type"`
	Function ollamaFunctionDefWire `json:"function"`
}

type ollamaFunctionDefWire struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// toOllamaMessage converts our public Message to Ollama's wire shape.
// ToolCallID is dropped — Ollama doesn't use call IDs, a tool-result message
// is identified purely by its position (role "tool") in the conversation.
func toOllamaMessage(m Message) ollamaMessage {
	om := ollamaMessage{Role: string(m.Role), Content: m.Content}
	for _, tc := range m.ToolCalls {
		var wtc ollamaToolCall
		wtc.Function.Name = tc.Name
		// tc.Arguments is our public JSON-encoded-string convention; Ollama
		// wants the parsed object. Re-encoding a parse failure as a bare
		// string is a reasonable fallback — better than dropping the call.
		if json.Valid([]byte(tc.Arguments)) {
			wtc.Function.Arguments = json.RawMessage(tc.Arguments)
		} else {
			b, _ := json.Marshal(tc.Arguments)
			wtc.Function.Arguments = b
		}
		om.ToolCalls = append(om.ToolCalls, wtc)
	}
	return om
}

// fromOllamaMessage converts an Ollama wire message into our public Message,
// re-encoding each tool call's object-shaped arguments into our
// JSON-encoded-string convention.
func fromOllamaMessage(om ollamaMessage) Message {
	m := Message{Role: Role(om.Role), Content: om.Content}
	for _, wtc := range om.ToolCalls {
		args := string(wtc.Function.Arguments)
		if args == "" {
			args = "{}"
		}
		m.ToolCalls = append(m.ToolCalls, ToolCall{Name: wtc.Function.Name, Arguments: args})
	}
	return m
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
	gReq := generateRequest{
		Model:   c.model,
		Prompt:  prompt,
		Stream:  false,
		Options: opts,
	}
	if opts != nil {
		gReq.Think = opts.Think
		if opts.JSON {
			gReq.Format = jsonFormat
		}
	}
	body, err := json.Marshal(gReq)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	numPredict, numCtx := 0, 0
	if opts != nil {
		numPredict = opts.NumPredict
		numCtx = opts.NumCtx
	}
	start := time.Now()
	slog.Debug("ollama: generate request",
		"component", "ollama",
		"model", c.model,
		"prompt_len", len(prompt),
		"num_predict", numPredict,
		"num_ctx", numCtx,
	)

	resp, err := c.httpClient.Do(req)
	elapsed := time.Since(start)
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

	slog.Debug("ollama: generate response",
		"component", "ollama",
		"model", c.model,
		"status", resp.StatusCode,
		"eval_count", gr.EvalCount,
		"done_reason", gr.DoneReason,
		"resp_len", len(gr.Response),
		"elapsed_ms", elapsed.Milliseconds(),
	)
	return gr.Response, nil
}

// Chat sends a multi-turn conversation and returns the assistant reply.
func (c *ollamaClient) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
	if c.mivBlock.Load() {
		return Message{}, ErrModelBlocked
	}
	wireMsgs := make([]ollamaMessage, len(messages))
	for i, m := range messages {
		wireMsgs[i] = toOllamaMessage(m)
	}
	cReq := chatRequest{
		Model:    c.model,
		Messages: wireMsgs,
		Stream:   false,
		Options:  opts,
	}
	if opts != nil {
		cReq.Think = opts.Think
		if opts.JSON {
			cReq.Format = jsonFormat
		}
		for _, t := range opts.Tools {
			cReq.Tools = append(cReq.Tools, ollamaTool{
				Type: "function",
				Function: ollamaFunctionDefWire{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Parameters,
				},
			})
		}
	}
	body, err := json.Marshal(cReq)
	if err != nil {
		return Message{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	totalContentLen := 0
	for _, m := range messages {
		totalContentLen += len(m.Content)
	}
	start := time.Now()
	slog.Debug("ollama: chat request",
		"component", "ollama",
		"model", c.model,
		"msg_count", len(messages),
		"content_len", totalContentLen,
	)

	resp, err := c.httpClient.Do(req)
	elapsed := time.Since(start)
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

	slog.Debug("ollama: chat response",
		"component", "ollama",
		"model", c.model,
		"status", resp.StatusCode,
		"eval_count", cr.EvalCount,
		"done_reason", cr.DoneReason,
		"resp_len", len(cr.Message.Content),
		// content: logged in full at Debug level, matching this package's
		// existing style of logging full prompts — added after a real
		// investigation gap: without this, a model's answer on a no-tool-call
		// turn (e.g. the turn right before the investigation-gate nudge
		// fires) was never recorded anywhere, only its length, making it
		// impossible to verify whether the model had already silently
		// decided a verdict before ever being nudged to investigate.
		"content", cr.Message.Content,
		"tool_calls", len(cr.Message.ToolCalls),
		"elapsed_ms", elapsed.Milliseconds(),
	)
	return fromOllamaMessage(cr.Message), nil
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
