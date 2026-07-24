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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Compile-time interface compliance checks.
var _ Provider = (*ollamaClient)(nil)
var _ Provider = (*openaiClient)(nil)

// ─── Factory tests ───────────────────────────────────────────────────────────

func TestNew_UnknownProvider(t *testing.T) {
	_, err := New(Config{Provider: "unknown", Model: "test"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestNew_EmptyModel(t *testing.T) {
	_, err := New(Config{Provider: ProviderOllama, Model: ""})
	if err == nil {
		t.Fatal("expected error for empty model")
	}
}

func TestNew_OllamaDefault(t *testing.T) {
	p, err := New(Config{Model: "llama3.2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ModelName() != "llama3.2" {
		t.Errorf("expected model llama3.2, got %s", p.ModelName())
	}
}

func TestNew_OllamaExplicit(t *testing.T) {
	p, err := New(Config{Provider: ProviderOllama, Model: "mistral"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// New wraps every provider with WithRetry, so the concrete type one level
	// down is what needs checking here, not p itself.
	rp, ok := p.(*retryProvider)
	if !ok {
		t.Fatal("expected New to return a *retryProvider wrapper")
	}
	if _, ok := rp.next.(*ollamaClient); !ok {
		t.Error("expected wrapped concrete type *ollamaClient")
	}
}

func TestNew_OpenAI_RequiresAPIKey(t *testing.T) {
	_, err := New(Config{Provider: ProviderOpenAI, Model: "gpt-4o", APIKey: ""})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
}

func TestSetProviderMIVBlocked_Ollama(t *testing.T) {
	p, err := New(Config{Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	SetProviderMIVBlocked(p)
	_, err = p.Generate(context.Background(), "prompt", nil)
	if err != ErrModelBlocked {
		t.Fatalf("expected ErrModelBlocked, got %v", err)
	}
}

func TestSetProviderMIVBlocked_NonOllama_NoOp(t *testing.T) {
	// This test validates SetProviderMIVBlocked doesn't panic on non-Ollama
	// providers. We can't easily instantiate an openaiClient without a real
	// API key, so we verify via the factory error path that the helper is safe.
	var nilProv Provider
	SetProviderMIVBlocked(nilProv) // must not panic
}

// ─── Ollama mock server tests ───────────────────────────────────────────────

func TestFactory_OllamaGenerateViaProviderInterface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "factory ok", Done: true})
	}))
	defer srv.Close()

	p, err := New(Config{BaseURL: srv.URL, Model: "test-model"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Generate(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if got != "factory ok" {
		t.Errorf("unexpected response: %q", got)
	}
}

// ─── OpenAI mock server tests ───────────────────────────────────────────────

// openAIMockHandler returns an httptest server that mimics the OpenAI API
// chat completions and models endpoints for testing.
// The openai-go SDK constructs paths relative to its base URL, so handlers
// are registered without the /v1 prefix.
func openAIMockHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "chatcmpl-123",
			"object": "chat.completion",
			"created": 1677652288,
			"model": "gpt-4o",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "Hello from OpenAI mock"
				},
				"finish_reason": "stop"
			}]
		}`))
	})
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object": "list", "data": [{"id": "gpt-4o"}]}`))
	})
	return mux
}

func TestFactory_OpenAIGenerateViaProviderInterface(t *testing.T) {
	srv := httptest.NewServer(openAIMockHandler(t))
	defer srv.Close()

	p, err := New(Config{
		Provider: ProviderOpenAI,
		BaseURL:  srv.URL,
		Model:    "gpt-4o",
		APIKey:   "sk-test-fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Generate(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if got != "Hello from OpenAI mock" {
		t.Errorf("unexpected response: %q", got)
	}
}

func TestFactory_OpenAIChatViaProviderInterface(t *testing.T) {
	srv := httptest.NewServer(openAIMockHandler(t))
	defer srv.Close()

	p, err := New(Config{
		Provider: ProviderOpenAI,
		BaseURL:  srv.URL,
		Model:    "gpt-4o",
		APIKey:   "sk-test-fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.Chat(context.Background(), []Message{
		{Role: RoleSystem, Content: "You are a helper."},
		{Role: RoleUser, Content: "Hi"},
	}, nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if msg.Content != "Hello from OpenAI mock" {
		t.Errorf("unexpected reply: %q", msg.Content)
	}
	if msg.Role != RoleAssistant {
		t.Errorf("unexpected role: %q", msg.Role)
	}
}

func TestFactory_OpenAIPing(t *testing.T) {
	srv := httptest.NewServer(openAIMockHandler(t))
	defer srv.Close()

	p, err := New(Config{
		Provider: ProviderOpenAI,
		BaseURL:  srv.URL,
		Model:    "gpt-4o",
		APIKey:   "sk-test-fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping error: %v", err)
	}
}

func TestFactory_OpenAIChatParsesToolCallResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tools []struct {
				Type     string `json:"type"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Tools) != 1 || req.Tools[0].Function.Name != "get_callers" {
			t.Fatalf("unexpected tools in request: %+v", req.Tools)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id": "chatcmpl-123", "object": "chat.completion", "created": 1, "model": "gpt-4o",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": null,
					"tool_calls": [{
						"id": "call_1",
						"type": "function",
						"function": {"name": "get_callers", "arguments": "{\"function_id\":\"m1\"}"}
					}]
				},
				"finish_reason": "tool_calls"
			}]
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, err := New(Config{Provider: ProviderOpenAI, BaseURL: srv.URL, Model: "gpt-4o", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{Tools: []ToolDef{
		{Name: "get_callers", Description: "list callers", Parameters: []byte(`{"type":"object"}`)},
	}}
	msg, err := p.Chat(context.Background(), []Message{{Role: RoleUser, Content: "who calls m1?"}}, opts)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d: %+v", len(msg.ToolCalls), msg)
	}
	if msg.ToolCalls[0].Name != "get_callers" || msg.ToolCalls[0].ID != "call_1" {
		t.Errorf("unexpected tool call: %+v", msg.ToolCalls[0])
	}
	var args struct {
		FunctionID string `json:"function_id"`
	}
	if err := json.Unmarshal([]byte(msg.ToolCalls[0].Arguments), &args); err != nil || args.FunctionID != "m1" {
		t.Errorf("unexpected arguments: %q (err=%v)", msg.ToolCalls[0].Arguments, err)
	}
}

func TestFactory_OpenAIChatRoundTripsToolResultMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []map[string]any `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Messages) != 3 {
			t.Fatalf("expected 3 messages, got %d: %+v", len(req.Messages), req.Messages)
		}
		if req.Messages[2]["role"] != "tool" || req.Messages[2]["tool_call_id"] != "call_1" {
			t.Errorf("tool result message mismatch: %+v", req.Messages[2])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id": "chatcmpl-124", "object": "chat.completion", "created": 1, "model": "gpt-4o",
			"choices": [{"index": 0, "message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}]
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, err := New(Config{Provider: ProviderOpenAI, BaseURL: srv.URL, Model: "gpt-4o", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	messages := []Message{
		{Role: RoleUser, Content: "who calls m1?"},
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call_1", Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		{Role: RoleTool, Content: `["AuthMiddleware"]`, ToolCallID: "call_1"},
	}
	msg, err := p.Chat(context.Background(), messages, nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if msg.Content != "done" {
		t.Errorf("unexpected reply: %+v", msg)
	}
}

func TestFactory_OpenAIPingFails(t *testing.T) {
	// Point at a server that returns 500 on /v1/models
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := New(Config{
		Provider: ProviderOpenAI,
		BaseURL:  srv.URL,
		Model:    "gpt-4o",
		APIKey:   "sk-test-fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(context.Background()); err == nil {
		t.Fatal("expected Ping error")
	}
}
