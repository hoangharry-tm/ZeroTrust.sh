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
	"testing"
	"time"
)

// scriptedProvider fails failures times, then returns a fixed success.
type scriptedProvider struct {
	failures  int
	failErr   error
	callCount int
}

func (s *scriptedProvider) ModelName() string          { return "scripted" }
func (s *scriptedProvider) Ping(context.Context) error { return nil }

func (s *scriptedProvider) Generate(ctx context.Context, prompt string, opts *Options) (string, error) {
	s.callCount++
	if s.callCount <= s.failures {
		return "", s.failErr
	}
	return "ok", nil
}

func (s *scriptedProvider) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
	s.callCount++
	if s.callCount <= s.failures {
		return Message{}, s.failErr
	}
	return Message{Role: RoleAssistant, Content: "ok"}, nil
}

var errTransient = errors.New("connection reset")

func fastRetryConfig() RetryConfig {
	return RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
}

func TestWithRetry_Generate_SucceedsAfterTransientFailures(t *testing.T) {
	sp := &scriptedProvider{failures: 2, failErr: errTransient}
	p := WithRetry(sp, fastRetryConfig())

	resp, err := p.Generate(context.Background(), "prompt", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %q, want %q", resp, "ok")
	}
	if sp.callCount != 3 {
		t.Errorf("callCount = %d, want 3 (2 failures + 1 success)", sp.callCount)
	}
}

func TestWithRetry_Generate_ExhaustsAttemptsAndReturnsLastError(t *testing.T) {
	sp := &scriptedProvider{failures: 10, failErr: errTransient}
	p := WithRetry(sp, fastRetryConfig())

	_, err := p.Generate(context.Background(), "prompt", nil)
	if !errors.Is(err, errTransient) {
		t.Fatalf("err = %v, want errTransient", err)
	}
	if sp.callCount != 3 {
		t.Errorf("callCount = %d, want 3 (MaxAttempts)", sp.callCount)
	}
}

func TestWithRetry_Generate_NeverRetriesModelBlocked(t *testing.T) {
	sp := &scriptedProvider{failures: 10, failErr: ErrModelBlocked}
	p := WithRetry(sp, fastRetryConfig())

	_, err := p.Generate(context.Background(), "prompt", nil)
	if !errors.Is(err, ErrModelBlocked) {
		t.Fatalf("err = %v, want ErrModelBlocked", err)
	}
	if sp.callCount != 1 {
		t.Errorf("callCount = %d, want 1 — a MIV block must never be retried", sp.callCount)
	}
}

func TestWithRetry_Generate_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sp := &scriptedProvider{failures: 10, failErr: errTransient}
	p := WithRetry(sp, RetryConfig{MaxAttempts: 5, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second})

	cancel() // cancel up front so the first backoff wait returns immediately
	_, err := p.Generate(ctx, "prompt", nil)
	if err == nil {
		t.Fatal("expected an error when context is already cancelled")
	}
	if sp.callCount > 2 {
		t.Errorf("callCount = %d, want at most 2 — cancellation should stop further retries quickly", sp.callCount)
	}
}

func TestWithRetry_Chat_SucceedsAfterTransientFailures(t *testing.T) {
	sp := &scriptedProvider{failures: 1, failErr: errTransient}
	p := WithRetry(sp, fastRetryConfig())

	msg, err := p.Chat(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil)
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Content != "ok" {
		t.Errorf("Content = %q, want %q", msg.Content, "ok")
	}
}

func TestWithRetry_Ping_PassesThroughWithoutRetry(t *testing.T) {
	sp := &scriptedProvider{}
	p := WithRetry(sp, fastRetryConfig())
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestWithRetry_ZeroMaxAttempts_FallsBackToDefault(t *testing.T) {
	sp := &scriptedProvider{failures: 1, failErr: errTransient}
	p := WithRetry(sp, RetryConfig{}) // no MaxAttempts set

	if _, err := p.Generate(context.Background(), "prompt", nil); err != nil {
		t.Fatalf("Generate: %v (DefaultRetryConfig should have covered 1 failure)", err)
	}
}
