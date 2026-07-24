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
	"errors"
	"log/slog"
	"math/rand"
	"time"
)

// RetryConfig controls retry/backoff behavior for transient Generate/Chat
// failures (a dropped connection, a momentary 5xx from Ollama/OpenAI, a slow
// cold-start). Without this, a single transient hiccup fails whatever
// finding/surface triggered it outright — there was no resilience layer
// around pkg/llm.Provider at all before this.
type RetryConfig struct {
	MaxAttempts int // total attempts including the first; <=0 means DefaultRetryConfig
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// DefaultRetryConfig is applied by every Provider returned from New.
var DefaultRetryConfig = RetryConfig{
	MaxAttempts: 3,
	BaseDelay:   500 * time.Millisecond,
	MaxDelay:    5 * time.Second,
}

// WithRetry wraps p so Generate and Chat transparently retry on transient
// errors with exponential backoff and jitter. Ping and ModelName pass
// through unwrapped: Ping is a one-shot startup reachability check where the
// caller wants an immediate fail-fast signal, not a delayed one, and
// ModelName has no failure mode to retry.
//
// ErrModelBlocked and context cancellation/deadline-exceeded are never
// retried — a deliberate MIV block must never be silently retried past, and
// a caller's own cancellation must be honored immediately, not delayed
// behind a backoff sleep.
//
// Deliberately no circuit breaker here: a circuit breaker earns its keep
// protecting a long-lived server from a persistently failing dependency: no
// requests, an open circuit, error responses. A ZeroTrust.sh scan is a
// single short-lived process — if the LLM backend is down for the whole
// scan, every retry budget gets exhausted and every caller correctly sees
// the same error; there's no "next request" for a breaker to protect.
func WithRetry(p Provider, cfg RetryConfig) Provider {
	if cfg.MaxAttempts <= 0 {
		cfg = DefaultRetryConfig
	}
	return &retryProvider{next: p, cfg: cfg}
}

type retryProvider struct {
	next Provider
	cfg  RetryConfig
}

func (r *retryProvider) ModelName() string { return r.next.ModelName() }

func (r *retryProvider) Ping(ctx context.Context) error { return r.next.Ping(ctx) }

func (r *retryProvider) Generate(ctx context.Context, prompt string, opts *Options) (string, error) {
	var lastErr error
	for attempt := 0; attempt < r.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err := r.wait(ctx, attempt); err != nil {
				return "", lastErr
			}
		}
		resp, err := r.next.Generate(ctx, prompt, opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(err) {
			return "", err
		}
		slog.Warn("llm: transient error, retrying", "call", "Generate",
			"attempt", attempt+1, "max_attempts", r.cfg.MaxAttempts, "err", err)
	}
	return "", lastErr
}

func (r *retryProvider) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
	var lastErr error
	for attempt := 0; attempt < r.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err := r.wait(ctx, attempt); err != nil {
				return Message{}, lastErr
			}
		}
		resp, err := r.next.Chat(ctx, messages, opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(err) {
			return Message{}, err
		}
		slog.Warn("llm: transient error, retrying", "call", "Chat",
			"attempt", attempt+1, "max_attempts", r.cfg.MaxAttempts, "err", err)
	}
	return Message{}, lastErr
}

// retryable reports whether err is worth retrying. Everything except an
// explicit MIV block or the caller's own context cancellation/deadline is
// treated as transient — the two backends' errors are shaped too
// differently (raw HTTP status text vs. SDK error types) to reliably
// classify "permanent" vs "transient" beyond those two known cases, and a
// wasted retry on a genuinely permanent error (e.g. a malformed request)
// costs a few hundred ms, not correctness.
func retryable(err error) bool {
	if errors.Is(err, ErrModelBlocked) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func (r *retryProvider) wait(ctx context.Context, attempt int) error {
	delay := r.cfg.BaseDelay * time.Duration(uint(1)<<uint(attempt-1))
	if delay > r.cfg.MaxDelay || delay <= 0 {
		delay = r.cfg.MaxDelay
	}
	delay += time.Duration(rand.Int63n(int64(delay)/2 + 1)) // up to 50% jitter
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}
