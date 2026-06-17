// Package worker manages the long-lived Python ML worker subprocess.
//
// All Python-side operations communicate through this single process boundary:
//   - LLM Verifier (Path A): verifies pattern findings with CoD + SCoT reasoning.
//   - UniXcoder classifier (Path B Tier 2): classifies uncertain surfaces.
//   - Semantic Function Summarizer (Path B Tier 2): converts call chains to JSON summaries.
//   - LLM Semantic Scan (Path B Tier 3): runs the bounded ReAct loop.
//
// Transport: newline-delimited JSON (NDJSON) over stdin/stdout.
// Each request has a unique ID; the worker echoes the ID in its response, allowing
// concurrent callers to match responses to outstanding requests.
//
// The worker is spawned once at pipeline startup (Start) and kept alive for the
// entire scan. Call Stop when the scan completes to send a shutdown message and
// wait for the process to exit cleanly.
//
// Message type routing (worker/main.py dispatcher):
//
//	"llm_verify"  → handlers/llm_verify.py   (Path A LLM Verifier)
//	"classify"    → handlers/classify.py      (UniXcoder classifier)
//	"summarize"   → handlers/summarize.py     (Semantic Summarizer)
//	"llm_scan"    → handlers/llm_scan.py      (LLM Semantic Scan)
//	"ping"        → built-in health check
//	"shutdown"    → graceful process exit
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
)

// MessageType is the string label that routes a request to the correct Python handler.
type MessageType string

const (
	// MsgLLMVerify routes to the Path A LLM Verifier handler.
	MsgLLMVerify MessageType = "llm_verify"
	// MsgClassify routes to the UniXcoder classifier handler.
	MsgClassify MessageType = "classify"
	// MsgSummarize routes to the Semantic Function Summarizer handler.
	MsgSummarize MessageType = "summarize"
	// MsgLLMScan routes to the LLM Semantic Scan handler.
	MsgLLMScan MessageType = "llm_scan"
	// MsgPing is a built-in health check; the worker responds immediately.
	MsgPing MessageType = "ping"
	// MsgShutdown requests a clean worker process exit.
	MsgShutdown MessageType = "shutdown"
)

// ResponseStatus is the status field in a worker Response.
type ResponseStatus string

const (
	// ResponseOK means the request was handled successfully.
	ResponseOK ResponseStatus = "ok"
	// ResponseError means the handler encountered an error; Error field is set.
	ResponseError ResponseStatus = "error"
)

// Request is an NDJSON message sent to the Python worker over stdin.
type Request struct {
	// ID is a unique string for matching this request to its response.
	ID string `json:"id"`
	// Type routes the request to the correct Python handler.
	Type MessageType `json:"type"`
	// Payload is the handler-specific JSON payload.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response is an NDJSON message received from the Python worker over stdout.
type Response struct {
	// ID matches the ID of the originating Request.
	ID string `json:"id"`
	// Status is ResponseOK or ResponseError.
	Status ResponseStatus `json:"status"`
	// Result is the handler-specific JSON result (set when Status == ResponseOK).
	Result json.RawMessage `json:"result,omitempty"`
	// Error is a human-readable error message (set when Status == ResponseError).
	Error string `json:"error,omitempty"`
}

// VerifyPayload is the JSON payload for MsgLLMVerify requests.
// It carries a single finding for false-positive classification.
type VerifyPayload struct {
	// FindingID is the finding.Finding.ID being verified.
	FindingID string `json:"finding_id"`
	// RuleID is the OpenGrep / ast-grep rule that matched.
	RuleID string `json:"rule_id"`
	// CWE is the CWE identifier from the rule metadata.
	CWE string `json:"cwe"`
	// MatchedCode is the source snippet at the finding location.
	MatchedCode string `json:"matched_code"`
	// Justification is the rule message / LLM context.
	Justification string `json:"justification"`
}

// VerifyResult is the JSON result for MsgLLMVerify responses.
type VerifyResult struct {
	// FindingID echoes the input FindingID.
	FindingID string `json:"finding_id"`
	// Verdict is "confirmed" | "false_positive" | "uncertain".
	Verdict string `json:"verdict"`
	// Confidence is the model's self-reported confidence (0.0–1.0).
	Confidence float64 `json:"confidence"`
	// Justification is the CoD reasoning summary.
	Justification string `json:"justification"`
}

// ClassifyPayload is the JSON payload for MsgClassify requests.
// Carries a batch of enriched surfaces for the UniXcoder gate.
type ClassifyPayload struct {
	// Surfaces holds the surface IDs and code snippets to classify.
	Surfaces []ClassifySurface `json:"surfaces"`
}

// ClassifySurface is one surface within a ClassifyPayload.
type ClassifySurface struct {
	// SurfaceID matches the enrichment.EnrichedSurface.ID.
	SurfaceID string `json:"surface_id"`
	// Code is the function source code to classify.
	Code string `json:"code"`
	// Language is the source language (e.g. "python", "go").
	Language string `json:"language"`
}

// ClassifyResult is the JSON result for MsgClassify responses.
type ClassifyResult struct {
	// Results holds one classification output per input surface.
	Results []ClassifySurfaceResult `json:"results"`
}

// ClassifySurfaceResult is the classifier output for one surface.
type ClassifySurfaceResult struct {
	// SurfaceID echoes the input surface ID.
	SurfaceID string `json:"surface_id"`
	// Label is "vulnerable" | "safe" | "uncertain".
	Label string `json:"label"`
	// Confidence is the model's softmax score for the winning label.
	Confidence float64 `json:"confidence"`
}

// SummarizePayload is the JSON payload for MsgSummarize requests.
// Holds a batch of call chains (up to 5 per request).
type SummarizePayload struct {
	// Chains is the batch of call chain JSON objects.
	Chains []json.RawMessage `json:"chains"`
}

// LLMScanPayload is the JSON payload for MsgLLMScan requests.
type LLMScanPayload struct {
	// SurfaceID identifies the surface being scanned.
	SurfaceID string `json:"surface_id"`
	// Summary is the JSON-serialized summarizer.Summary for this surface.
	Summary json.RawMessage `json:"summary"`
	// PriorContext is accumulated SCS inferences for this surface's neighbours.
	// Empty JSON object ({}) when no prior context is available.
	PriorContext json.RawMessage `json:"prior_context"`
	// Mode is "react" or "single_pass".
	Mode string `json:"mode"`
}

// Manager owns the long-lived Python worker subprocess and serialises all IPC.
type Manager struct {
	seq atomic.Uint64
}

// Start spawns the Python worker at workerPath, waits for it to be ready
// (via a ping/pong handshake), and returns a Manager.
//
// Parameters:
//   - ctx: cancellation context; if cancelled, the subprocess is killed.
//   - workerPath: path to the worker entry point (e.g. "worker/main.py").
//
// Returns:
//   - *Manager: ready-to-use manager.
//   - error: non-nil if the subprocess fails to start or the ping times out.
func Start(ctx context.Context, workerPath string) (*Manager, error) {
	// implemented in G2.M2.5
	return &Manager{}, nil
}

// Call sends a typed request to the worker and returns the decoded response.
// Safe to call from multiple goroutines concurrently; requests are serialised
// internally before being written to stdin.
//
// Parameters:
//   - ctx: cancellation context; a cancelled ctx will abort the pending request.
//   - msgType: the handler routing label (one of the Msg* constants).
//   - payload: the handler-specific request payload (marshalled to JSON).
//
// Returns:
//   - *Response: the decoded response from the Python worker.
//   - error: non-nil on ctx cancellation, worker crash, or JSON encode/decode failure.
func (m *Manager) Call(ctx context.Context, msgType MessageType, payload any) (*Response, error) {
	// implemented in G2.M2.5
	return nil, fmt.Errorf("worker: not yet started")
}

// Ping sends a health-check request and returns nil if the worker is alive.
//
// Parameters:
//   - ctx: cancellation context.
func (m *Manager) Ping(ctx context.Context) error {
	// implemented in G2.M2.5
	return nil
}

// Stop sends a shutdown message to the worker and waits for the subprocess to exit.
// It is safe to call Stop even if the worker is already dead.
func (m *Manager) Stop() error {
	// implemented in G2.M2.5
	return nil
}

func (m *Manager) newID() string {
	return fmt.Sprintf("%d", m.seq.Add(1))
}
