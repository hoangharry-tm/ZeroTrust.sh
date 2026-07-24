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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer starts a fake Ollama HTTP server and returns the server and
// an ollamaClient pointed at it. The caller is responsible for calling srv.Close().
func newTestServer(handler http.HandlerFunc) (*httptest.Server, *ollamaClient) {
	srv := httptest.NewServer(handler)
	c := newOllamaClient(Config{BaseURL: srv.URL, Model: "test-model"})
	return srv, c
}

func TestGenerateSuccess(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req generateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Model != "test-model" {
			t.Errorf("expected model test-model, got %s", req.Model)
		}
		if req.Stream {
			t.Error("stream must be false")
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "hello world", Done: true})
	})
	defer srv.Close()

	got, err := c.Generate(context.Background(), "say hello", nil)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if got != "hello world" {
		t.Errorf("unexpected response: %q", got)
	}
}

func TestGenerateNonOKStatus(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	})
	defer srv.Close()

	_, err := c.Generate(context.Background(), "prompt", nil)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestGenerateInvalidJSON(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	})
	defer srv.Close()

	_, err := c.Generate(context.Background(), "prompt", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestGenerateContextCancelled(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		// simulate slow response — context will cancel before this returns
		time.Sleep(200 * time.Millisecond)
		json.NewEncoder(w).Encode(generateResponse{Response: "too late", Done: true})
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.Generate(ctx, "prompt", nil)
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}

func TestPingSuccess(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(generateResponse{Response: "pong", Done: true})
	})
	defer srv.Close()

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping error: %v", err)
	}
}

func TestPingFailsWhenServerDown(t *testing.T) {
	// point at a port nothing is listening on
	c := newOllamaClient(Config{BaseURL: "http://127.0.0.1:19999", Model: "test-model"})
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func TestNewDefaultBaseURL(t *testing.T) {
	c := newOllamaClient(Config{Model: "llama3"})
	if c.baseURL != ollamaDefaultBaseURL {
		t.Errorf("expected default base URL %s, got %s", ollamaDefaultBaseURL, c.baseURL)
	}
	if c.model != "llama3" {
		t.Errorf("expected model llama3, got %s", c.model)
	}
}

func TestNewCustomBaseURL(t *testing.T) {
	c := newOllamaClient(Config{BaseURL: "http://remote:11434", Model: "mistral"})
	if c.baseURL != "http://remote:11434" {
		t.Errorf("unexpected base URL: %s", c.baseURL)
	}
}

func TestGenerateSendsPromptVerbatim(t *testing.T) {
	const prompt = "Analyse this: func foo() { return }"
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Prompt != prompt {
			t.Errorf("prompt mismatch: got %q", req.Prompt)
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "ok", Done: true})
	})
	defer srv.Close()

	c.Generate(context.Background(), prompt, nil)
}

func TestGenerateSetsJSONFormatWhenRequested(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if string(req.Format) != `"json"` {
			t.Errorf("expected format=json wire field, got %q", req.Format)
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "{}", Done: true})
	})
	defer srv.Close()

	c.Generate(context.Background(), "prompt", &Options{JSON: true})
}

func TestGenerateOmitsFormatWhenNotRequested(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&raw)
		if _, ok := raw["format"]; ok {
			t.Errorf("format field should be absent from the wire request when JSON is not requested")
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "ok", Done: true})
	})
	defer srv.Close()

	c.Generate(context.Background(), "prompt", &Options{})
}

// ─── Chat ────────────────────────────────────────────────────────────────────

func TestChatSuccess(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req chatRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Stream {
			t.Error("stream must be false")
		}
		if len(req.Messages) != 1 || req.Messages[0].Content != "hello" {
			t.Errorf("unexpected messages: %+v", req.Messages)
		}
		json.NewEncoder(w).Encode(chatResponse{
			Message: ollamaMessage{Role: string(RoleAssistant), Content: "world"},
			Done:    true,
		})
	})
	defer srv.Close()

	msg, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hello"}}, nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if msg.Content != "world" || msg.Role != RoleAssistant {
		t.Errorf("unexpected reply: %+v", msg)
	}
}

func TestChatNonOKStatus(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	_, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestChatInvalidJSON(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/chat" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not json"))
		}
	})
	defer srv.Close()

	_, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ─── Tool calling ────────────────────────────────────────────────────────────

func TestChatSendsToolsInOllamaWireShape(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Tools) != 1 {
			t.Fatalf("expected 1 tool in request, got %d", len(req.Tools))
		}
		if req.Tools[0].Type != "function" || req.Tools[0].Function.Name != "get_callers" {
			t.Errorf("unexpected tool: %+v", req.Tools[0])
		}
		json.NewEncoder(w).Encode(chatResponse{
			Message: ollamaMessage{Role: string(RoleAssistant), Content: "no tool needed"},
			Done:    true,
		})
	})
	defer srv.Close()

	opts := &Options{Tools: []ToolDef{
		{Name: "get_callers", Description: "list callers of a function", Parameters: []byte(`{"type":"object"}`)},
	}}
	msg, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, opts)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if msg.Content != "no tool needed" {
		t.Errorf("unexpected reply: %+v", msg)
	}
}

func TestChatParsesToolCallResponse(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"message": {
				"role": "assistant",
				"content": "",
				"tool_calls": [{"function": {"name": "get_callers", "arguments": {"function_id": "m1"}}}]
			},
			"done": true
		}`)
	})
	defer srv.Close()

	msg, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "who calls m1?"}}, nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d: %+v", len(msg.ToolCalls), msg)
	}
	tc := msg.ToolCalls[0]
	if tc.Name != "get_callers" {
		t.Errorf("tool call name = %q, want get_callers", tc.Name)
	}
	var args struct {
		FunctionID string `json:"function_id"`
	}
	if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
		t.Fatalf("tool call Arguments not valid JSON: %v (%q)", err, tc.Arguments)
	}
	if args.FunctionID != "m1" {
		t.Errorf("arguments.function_id = %q, want m1", args.FunctionID)
	}
}

func TestChatRoundTripsToolResultMessage(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Messages) != 3 {
			t.Fatalf("expected 3 messages, got %d", len(req.Messages))
		}
		assistantMsg := req.Messages[1]
		if len(assistantMsg.ToolCalls) != 1 || assistantMsg.ToolCalls[0].Function.Name != "get_callers" {
			t.Errorf("assistant message did not round-trip its tool call: %+v", assistantMsg)
		}
		toolMsg := req.Messages[2]
		if toolMsg.Role != "tool" || toolMsg.Content != `["AuthMiddleware"]` {
			t.Errorf("tool result message mismatch: %+v", toolMsg)
		}
		json.NewEncoder(w).Encode(chatResponse{
			Message: ollamaMessage{Role: string(RoleAssistant), Content: "done"},
			Done:    true,
		})
	})
	defer srv.Close()

	messages := []Message{
		{Role: RoleUser, Content: "who calls m1?"},
		{Role: RoleAssistant, ToolCalls: []ToolCall{{Name: "get_callers", Arguments: `{"function_id":"m1"}`}}},
		{Role: RoleTool, Content: `["AuthMiddleware"]`},
	}
	msg, err := c.Chat(context.Background(), messages, nil)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if msg.Content != "done" {
		t.Errorf("unexpected reply: %+v", msg)
	}
}

// ─── BackboneCheck ───────────────────────────────────────────────────────────

func TestBackboneCheckPass(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(generateResponse{Response: `{"ok":true}`, Done: true})
	})
	defer srv.Close()

	ok, err := c.BackboneCheck(context.Background())
	if err != nil {
		t.Fatalf("BackboneCheck error: %v", err)
	}
	if !ok {
		t.Error("expected BackboneCheck to return true")
	}
}

func TestBackboneCheckFailsOnNonJSON(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(generateResponse{Response: "sorry I cannot do that", Done: true})
	})
	defer srv.Close()

	ok, err := c.BackboneCheck(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected BackboneCheck to return false for non-JSON response")
	}
}

func TestBackboneCheckRetries(t *testing.T) {
	calls := 0
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 2 {
			json.NewEncoder(w).Encode(generateResponse{Response: `{"ok":true}`, Done: true})
			return
		}
		json.NewEncoder(w).Encode(generateResponse{Response: "bad output", Done: true})
	})
	defer srv.Close()

	ok, err := c.BackboneCheck(context.Background())
	if err != nil {
		t.Fatalf("BackboneCheck error: %v", err)
	}
	if !ok {
		t.Error("expected BackboneCheck to pass on second attempt")
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

// ─── MIV gate ────────────────────────────────────────────────────────────────

func TestGenerateBlockedByMIV(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		// should never be reached
		t.Error("server called despite MIV block")
		json.NewEncoder(w).Encode(generateResponse{Response: "blocked", Done: true})
	})
	defer srv.Close()

	c.SetMIVBlocked()
	_, err := c.Generate(context.Background(), "prompt", nil)
	if !errors.Is(err, ErrModelBlocked) {
		t.Errorf("expected ErrModelBlocked, got %v", err)
	}
}

func TestChatBlockedByMIV(t *testing.T) {
	srv, c := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server called despite MIV block")
		json.NewEncoder(w).Encode(chatResponse{Message: ollamaMessage{Role: string(RoleAssistant), Content: "blocked"}})
	})
	defer srv.Close()

	c.SetMIVBlocked()
	_, err := c.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil)
	if !errors.Is(err, ErrModelBlocked) {
		t.Errorf("expected ErrModelBlocked, got %v", err)
	}
}
