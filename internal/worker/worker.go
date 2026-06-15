// Package worker manages the long-lived Python ML worker subprocess.
// All Python-side operations (LLM Verifier, UniXcoder classifier, Semantic
// Summarizer, LLM Semantic Scan) communicate through this single process
// boundary via newline-delimited JSON over stdin/stdout.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
)

// Request is an NDJSON message sent to the Python worker over stdin.
type Request struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response is an NDJSON message received from the Python worker over stdout.
type Response struct {
	ID     string          `json:"id"`
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Manager owns the long-lived Python worker subprocess.
type Manager struct {
	seq atomic.Uint64
}

// Start spawns the Python worker at workerPath and verifies it with a ping.
func Start(ctx context.Context, workerPath string) (*Manager, error) {
	// implemented in G2.M2.5
	return &Manager{}, nil
}

// Call sends a typed request to the worker and returns the decoded response.
// Safe to call from multiple goroutines.
func (m *Manager) Call(ctx context.Context, msgType string, payload any) (*Response, error) {
	// implemented in G2.M2.5
	return nil, fmt.Errorf("worker: not yet started")
}

// Stop sends a shutdown message and waits for the subprocess to exit.
func (m *Manager) Stop() error {
	// implemented in G2.M2.5
	return nil
}

func (m *Manager) newID() string {
	return fmt.Sprintf("%d", m.seq.Add(1))
}
