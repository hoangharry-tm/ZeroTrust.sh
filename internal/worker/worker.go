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

// Package worker manages the long-lived Python ML worker subprocess.
//
// All Python-side operations communicate through this single process boundary:
//   - LLM Verifier (Path A): verifies pattern findings with CoD + SCoT reasoning.
//   - CodeT5+ classifier (Path B Tier 2): classifies uncertain surfaces.
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
// Restart policy: if the process dies unexpectedly, one automatic restart is
// attempted. If the restart succeeds, subsequent calls work normally (pending
// calls from the crash window receive a transient error and must be retried by
// the caller). If the restart fails, ErrWorkerDead is returned to all callers;
// callers should fall back to direct Ollama HTTP.
//
// Message type routing (worker/main.py dispatcher):
//
//	"llm_verify"  → handlers/llm_verify.py    (Path A LLM Verifier)
//	"classify"    → handlers/classify.py      (CodeT5+ classifier)
//	"summarize"   → handlers/summarize.py     (Semantic Summarizer)
//	"llm_scan"    → handlers/llm_scan.py      (LLM Semantic Scan)
//	"ping"        → built-in health check
//	"shutdown"    → graceful process exit
package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// ErrWorkerDead is returned when the worker process has crashed and the
// automatic restart attempt also failed. Callers should fall back to direct
// Ollama HTTP calls instead of retrying through the worker.
var ErrWorkerDead = errors.New("worker: process dead; restart failed")

// MessageType is the string label that routes a request to the correct Python handler.
type MessageType string

const (
	// MsgLLMVerify routes to the Path A LLM Verifier handler.
	MsgLLMVerify MessageType = "llm_verify"
	// MsgClassify routes to the CodeT5+ classifier handler.
	MsgClassify MessageType = "classify"
	// MsgSummarize routes to the Semantic Function Summarizer handler.
	MsgSummarize MessageType = "summarize"
	// MsgLLMScan routes to the LLM Semantic Scan handler.
	MsgLLMScan MessageType = "llm_scan"
	// MsgEmbed routes to the MiniLM-L6-v2 embedding handler (dedup Gate 3).
	MsgEmbed MessageType = "embed"
	// MsgASTEdit routes to the AST token edit-distance handler (dedup Gate 4).
	MsgASTEdit MessageType = "ast_edit"
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
type VerifyPayload struct {
	FindingID     string `json:"finding_id"`
	RuleID        string `json:"rule_id"`
	CWE           string `json:"cwe"`
	MatchedCode   string `json:"matched_code"`
	Justification string `json:"justification"`
	// FilePath is the project-relative source file that contains the finding.
	// Included in the prompt for context; may be empty for synthetic findings.
	FilePath string `json:"file_path,omitempty"`
	// ASCMaxRounds is the maximum number of Adaptive Self-Consistency resampling
	// rounds to run on uncertain verdicts. 0 disables ASC.
	ASCMaxRounds int `json:"asc_max_rounds"`
	// ASCConfidenceThreshold is the minimum confidence that avoids ASC.
	// Verdicts with confidence below this value trigger resampling even if
	// the verdict is not "uncertain".
	ASCConfidenceThreshold float64 `json:"asc_confidence_threshold"`
}

// VerifyResult is the JSON result for MsgLLMVerify responses.
type VerifyResult struct {
	FindingID     string  `json:"finding_id"`
	Verdict       string  `json:"verdict"`
	Confidence    float64 `json:"confidence"`
	Justification string  `json:"justification"`
	// ASCRounds is the number of extra Adaptive Self-Consistency resampling
	// rounds that were executed. 0 means the initial verdict was accepted directly.
	ASCRounds int `json:"asc_rounds"`
}

// ClassifyPayload is the JSON payload for MsgClassify requests.
type ClassifyPayload struct {
	Surfaces []ClassifySurface `json:"surfaces"`
}

// ClassifySurface is one surface within a ClassifyPayload.
type ClassifySurface struct {
	SurfaceID string `json:"surface_id"`
	Code      string `json:"code"`
	Language  string `json:"language"`
}

// ClassifyResult is the JSON result for MsgClassify responses.
type ClassifyResult struct {
	Results []ClassifySurfaceResult `json:"results"`
}

// ClassifySurfaceResult is the classifier output for one surface.
type ClassifySurfaceResult struct {
	SurfaceID  string  `json:"surface_id"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
}

// EmbedPayload is the JSON payload for MsgEmbed requests.
type EmbedPayload struct {
	Codes []string `json:"codes"`
}

// EmbedResult is the JSON result for MsgEmbed responses.
type EmbedResult struct {
	Embeddings [][]float64 `json:"embeddings"`
}

// ASTEditPayload is the JSON payload for MsgASTEdit requests.
type ASTEditPayload struct {
	Code1    string `json:"code1"`
	Code2    string `json:"code2"`
	Language string `json:"language,omitempty"`
}

// ASTEditResult is the JSON result for MsgASTEdit responses.
type ASTEditResult struct {
	Similarity float64 `json:"similarity"`
}

// SummarizePayload is the JSON payload for MsgSummarize requests.
type SummarizePayload struct {
	Chains []json.RawMessage `json:"chains"`
}

// LLMScanPayload is the JSON payload for MsgLLMScan requests.
type LLMScanPayload struct {
	SurfaceID    string          `json:"surface_id"`
	Summary      json.RawMessage `json:"summary"`
	PriorContext json.RawMessage `json:"prior_context"`
	Mode         string          `json:"mode"`
}

// Manager owns the long-lived Python worker subprocess and serialises all IPC.
//
// Lock ordering (to prevent deadlocks): writeMu → pendMu → mu. Never acquire
// in reverse order.
type Manager struct {
	seq      atomic.Uint64
	args     []string // command + arguments, e.g. ["python3", "worker/main.py"]
	logger   *slog.Logger
	stopping atomic.Bool

	// writeMu serialises stdin writes and guards the m.stdin field.
	writeMu sync.Mutex
	stdin   io.WriteCloser

	// pendMu guards the pending request map.
	pendMu  sync.Mutex
	pending map[string]chan *Response

	// mu guards dead and restartAttempts.
	mu              sync.Mutex
	dead            bool
	restartAttempts int
}

// NewFromArgs spawns a Manager using an explicit command and argument list.
// Intended for tests that need a Manager backed by a custom subprocess (e.g. an
// inline Python echo script) without going through Start's file-path resolution.
// If logger is nil, slog.Default() is used.
// Returns an error if the subprocess fails to start.
func NewFromArgs(args []string, logger *slog.Logger) (*Manager, error) {
	m := newManager(args, logger)
	if err := m.spawn(); err != nil {
		return nil, fmt.Errorf("worker: spawn: %w", err)
	}
	return m, nil
}

// newManager returns an uninitialised Manager with the given spawn arguments.
// Used by Start (production) and tests (inject a custom command).
// If logger is nil, slog.Default() is used.
func newManager(args []string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		args:    args,
		logger:  logger,
		pending: make(map[string]chan *Response),
	}
}

// Start spawns the Python worker at workerPath, waits for it to be ready
// (via a ping/pong handshake), and returns a Manager.
//
// Parameters:
//   - ctx: cancellation context; if cancelled, the subprocess is killed.
//   - workerPath: path to the worker entry point (e.g. "worker/main.py").
//   - logger: structured logger; nil defaults to slog.Default().
func Start(ctx context.Context, workerPath string, logger *slog.Logger) (*Manager, error) {
	py := os.Getenv("ZEROTRUST_PYTHON")
	if py == "" {
		py = "uv"
	}
	args := []string{py, "run", "--project", filepath.Dir(workerPath), "python", workerPath}
	if py != "uv" {
		args = []string{py, workerPath}
	}
	slog.Info("starting python worker", slog.String("worker_path", workerPath), slog.String("python", py))
	m := newManager(args, logger)
	if err := m.spawn(); err != nil {
		slog.Error("worker spawn failed", "err", err)
		return nil, fmt.Errorf("worker: spawn: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, tuning.WorkerStartPingTimeout)
	defer cancel()
	if err := m.Ping(pingCtx); err != nil {
		slog.Error("worker initial ping failed", "err", err)
		_ = m.Stop()
		return nil, fmt.Errorf("worker: ping: %w", err)
	}
	slog.Info("python worker ready")
	return m, nil
}

// spawn starts the subprocess, wires its stdin/stdout, and launches the reader
// goroutine. It does NOT ping — callers are responsible for health-checking.
func (m *Manager) spawn() error {
	cmd := exec.Command(m.args[0], m.args[1:]...) //nolint:gosec

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		return fmt.Errorf("start: %w", err)
	}

	m.writeMu.Lock()
	m.stdin = stdinPipe
	m.writeMu.Unlock()

	go m.readLoop(stdoutPipe, cmd)
	return nil
}

// readLoop reads NDJSON responses from stdout and routes each one to the
// waiting caller via its pending channel. When stdout closes (process exited),
// it calls handleDeath to drain pending requests and attempt a restart.
func (m *Manager) readLoop(stdout io.Reader, cmd *exec.Cmd) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB — large LLM responses
	for scanner.Scan() {
		var resp Response
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			m.logger.Warn(
				"worker: malformed NDJSON line, skipping",
				"component", "worker",
				"err", err,
			)
			continue
		}
		m.pendMu.Lock()
		ch := m.pending[resp.ID]
		delete(m.pending, resp.ID)
		m.pendMu.Unlock()
		if ch != nil {
			ch <- &resp
		}
	}
	_ = cmd.Wait() // reap the subprocess to avoid a zombie
	m.handleDeath()
}

const maxRestartAttempts = 3

// handleDeath is called by the reader goroutine when the process exits.
// It attempts up to maxRestartAttempts automatic restarts with exponential backoff
// (attempt × 500ms). If all attempts fail, it marks the Manager as dead.
func (m *Manager) handleDeath() {
	// Clear the stdin pipe under writeMu so new writes fail immediately.
	m.writeMu.Lock()
	m.stdin = nil
	m.writeMu.Unlock()

	m.mu.Lock()
	attempts := m.restartAttempts
	isStopping := m.stopping.Load()
	m.mu.Unlock()

	if attempts < maxRestartAttempts && !isStopping {
		attempt := attempts + 1
		m.logger.Error(
			"python worker process exited unexpectedly, attempting restart",
			"component", "worker", "attempt", attempt, "max", maxRestartAttempts,
		)
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		if err := m.spawn(); err == nil {
			pingCtx, cancel := context.WithTimeout(context.Background(), tuning.WorkerRestartPingTimeout)
			defer cancel()
			if err := m.Ping(pingCtx); err == nil {
				m.logger.Info(
					"python worker restarted successfully",
					"component", "worker", "attempt", attempt,
				)
				m.mu.Lock()
				m.restartAttempts = attempt
				m.mu.Unlock()
				// Drain the crash-window requests — callers must retry.
				m.drainPending("worker restarted after crash; retry the request")
				return
			}
		}
		m.mu.Lock()
		m.restartAttempts = attempt
		m.mu.Unlock()
	}

	// Restart failed, already restarted once, or deliberate Stop: mark dead.
	if !m.stopping.Load() {
		m.logger.Error(
			"python worker restart failed; worker is permanently dead",
			"component", "worker",
		)
	}
	m.mu.Lock()
	m.dead = true
	m.mu.Unlock()
	if m.stopping.Load() {
		m.drainPending("worker stopped")
	} else {
		m.drainPending(ErrWorkerDead.Error())
	}
}

// drainPending closes all outstanding pending channels with an error response
// and replaces the pending map with a fresh empty one.
func (m *Manager) drainPending(errMsg string) {
	m.pendMu.Lock()
	old := m.pending
	m.pending = make(map[string]chan *Response)
	m.pendMu.Unlock()

	for id, ch := range old {
		ch <- &Response{ID: id, Status: ResponseError, Error: errMsg}
	}
}

// Call sends a typed request to the worker and returns the decoded response.
// Safe to call from multiple goroutines concurrently.
//
// Parameters:
//   - ctx: cancellation context; cancellation removes the request from the
//     pending map and returns ctx.Err() immediately.
//   - msgType: the handler routing label.
//   - payload: the handler-specific request payload (marshalled to JSON).
func (m *Manager) Call(ctx context.Context, msgType MessageType, payload any) (*Response, error) {
	m.mu.Lock()
	if m.dead {
		m.mu.Unlock()
		return nil, ErrWorkerDead
	}
	m.mu.Unlock()

	id := m.newID()
	ch := make(chan *Response, 1)

	m.pendMu.Lock()
	m.pending[id] = ch
	m.pendMu.Unlock()

	if err := m.writeRequest(id, msgType, payload); err != nil {
		m.pendMu.Lock()
		delete(m.pending, id)
		m.pendMu.Unlock()
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		m.pendMu.Lock()
		delete(m.pending, id)
		m.pendMu.Unlock()
		return nil, ctx.Err()
	}
}

// writeRequest serialises a Request to NDJSON and writes it to stdin.
// Holds writeMu for the entire write so concurrent callers cannot interleave bytes.
func (m *Manager) writeRequest(id string, msgType MessageType, payload any) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("worker: marshal payload: %w", err)
		}
		raw = b
	}
	req := Request{ID: id, Type: msgType, Payload: raw}
	line, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("worker: marshal request: %w", err)
	}
	line = append(line, '\n')

	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if m.stdin == nil {
		return ErrWorkerDead
	}
	_, err = m.stdin.Write(line)
	return err
}

// Ping sends a health-check request and returns nil if the worker is alive.
//
// Parameters:
//   - ctx: cancellation context.
func (m *Manager) Ping(ctx context.Context) error {
	resp, err := m.Call(ctx, MsgPing, nil)
	if err != nil {
		return err
	}
	if resp.Status != ResponseOK {
		return fmt.Errorf("worker: ping: %s", resp.Error)
	}
	return nil
}

// Stop sends a shutdown message to the worker and waits up to 3 seconds for
// the process to exit gracefully, then closes stdin.
// It is safe to call Stop even if the worker is already dead.
func (m *Manager) Stop() error {
	m.logger.Info("stopping python worker")
	m.stopping.Store(true)

	// Best-effort graceful shutdown; ignore errors (process may already be dead).
	shutCtx, cancel := context.WithTimeout(context.Background(), tuning.WorkerShutdownTimeout)
	defer cancel()
	_, _ = m.Call(shutCtx, MsgShutdown, nil)

	// Close stdin — signals EOF to the Python process's stdin loop.
	m.writeMu.Lock()
	stdin := m.stdin
	m.stdin = nil
	m.writeMu.Unlock()
	if stdin != nil {
		_ = stdin.Close()
	}

	m.mu.Lock()
	m.dead = true
	m.mu.Unlock()
	return nil
}

// Classify sends one classify request to the Python worker and returns the
// parsed result. It is a thin convenience wrapper around Call that handles
// payload construction and response unmarshalling.
//
// Parameters:
//   - ctx: cancellation context.
//   - surfaces: one or more surfaces to classify; must be non-empty.
func (m *Manager) Classify(ctx context.Context, surfaces []ClassifySurface) (ClassifyResult, error) {
	if len(surfaces) == 0 {
		return ClassifyResult{}, nil
	}
	resp, err := m.Call(ctx, MsgClassify, ClassifyPayload{Surfaces: surfaces})
	if err != nil {
		return ClassifyResult{}, fmt.Errorf("worker: classify: %w", err)
	}
	if resp.Status == ResponseError {
		return ClassifyResult{}, fmt.Errorf("worker: classify: %s", resp.Error)
	}
	var cr ClassifyResult
	if err := json.Unmarshal(resp.Result, &cr); err != nil {
		return ClassifyResult{}, fmt.Errorf("worker: classify: unmarshal result: %w", err)
	}
	return cr, nil
}

// Embed sends code snippets to the Python worker for MiniLM-L6-v2 embedding.
// Returns one float64 vector per input snippet. Returns nil when codes is empty.
func (m *Manager) Embed(ctx context.Context, codes []string) ([][]float64, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	resp, err := m.Call(ctx, MsgEmbed, EmbedPayload{Codes: codes})
	if err != nil {
		return nil, fmt.Errorf("worker: embed: %w", err)
	}
	if resp.Status == ResponseError {
		return nil, fmt.Errorf("worker: embed: %s", resp.Error)
	}
	var er EmbedResult
	if err := json.Unmarshal(resp.Result, &er); err != nil {
		return nil, fmt.Errorf("worker: embed: unmarshal: %w", err)
	}
	return er.Embeddings, nil
}

// ASTEditSimilarity returns a similarity score in [0, 1] between two code snippets
// using token-sequence Levenshtein distance on tree-sitter AST leaves.
func (m *Manager) ASTEditSimilarity(ctx context.Context, code1, code2, language string) (float64, error) {
	resp, err := m.Call(ctx, MsgASTEdit, ASTEditPayload{Code1: code1, Code2: code2, Language: language})
	if err != nil {
		return 0, fmt.Errorf("worker: ast_edit: %w", err)
	}
	if resp.Status == ResponseError {
		return 0, fmt.Errorf("worker: ast_edit: %s", resp.Error)
	}
	var ar ASTEditResult
	if err := json.Unmarshal(resp.Result, &ar); err != nil {
		return 0, fmt.Errorf("worker: ast_edit: unmarshal: %w", err)
	}
	return ar.Similarity, nil
}

func (m *Manager) newID() string {
	return fmt.Sprintf("%d", m.seq.Add(1))
}
