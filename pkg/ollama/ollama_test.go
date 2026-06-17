package ollama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer starts a fake Ollama HTTP server and returns the server and
// a Client pointed at it. The caller is responsible for calling srv.Close().
func newTestServer(handler http.HandlerFunc) (*httptest.Server, *Client) {
	srv := httptest.NewServer(handler)
	c := New(srv.URL, "test-model")
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
	c := New("http://127.0.0.1:19999", "test-model")
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func TestNewDefaultBaseURL(t *testing.T) {
	c := New("", "llama3")
	if c.baseURL != defaultBaseURL {
		t.Errorf("expected default base URL %s, got %s", defaultBaseURL, c.baseURL)
	}
	if c.model != "llama3" {
		t.Errorf("expected model llama3, got %s", c.model)
	}
}

func TestNewCustomBaseURL(t *testing.T) {
	c := New("http://remote:11434", "mistral")
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
