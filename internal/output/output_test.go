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

package output_test

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

// sendAndClose sends events on ch then closes it, driving the renderer to completion.
func sendAndClose(ch chan output.Event, events ...output.Event) {
	for _, e := range events {
		ch <- e
	}
	close(ch)
}

func runRenderer(t *testing.T, events ...output.Event) *output.MinimalRenderer {
	t.Helper()
	r := output.NewMinimalRenderer()
	ch := make(chan output.Event, len(events)+1)
	go sendAndClose(ch, events...)
	if err := r.Render(context.Background(), ch); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return r
}

// ─── ExitCode ─────────────────────────────────────────────────────────────────

func TestExitCode_NoFindings_Zero(t *testing.T) {
	r := runRenderer(t) // no events
	if r.ExitCode() != 0 {
		t.Errorf("expected exit 0 for no findings, got %d", r.ExitCode())
	}
}

func TestExitCode_BlockFinding_One(t *testing.T) {
	f := &finding.Finding{
		ID:            "f1",
		SeverityLabel: finding.SeverityBlock,
		CWE:           "CWE-89",
		RuleID:        "sql-injection",
		Path:          "api/user.go",
		LineRange:     finding.LineRange{Start: 42},
	}
	r := runRenderer(t, output.Event{Kind: output.EventFinding, Finding: f})
	if r.ExitCode() != 1 {
		t.Errorf("expected exit 1 for BLOCK finding, got %d", r.ExitCode())
	}
}

func TestExitCode_HighFinding_One(t *testing.T) {
	f := &finding.Finding{
		ID:            "f2",
		SeverityLabel: finding.SeverityHigh,
		CWE:           "CWE-22",
		RuleID:        "path-traversal",
		Path:          "upload.go",
		LineRange:     finding.LineRange{Start: 10},
	}
	r := runRenderer(t, output.Event{Kind: output.EventFinding, Finding: f})
	if r.ExitCode() != 1 {
		t.Errorf("expected exit 1 for HIGH finding, got %d", r.ExitCode())
	}
}

func TestExitCode_MediumOnly_Zero(t *testing.T) {
	f := &finding.Finding{
		ID:            "f3",
		SeverityLabel: finding.SeverityMedium,
		CWE:           "CWE-200",
		RuleID:        "info-exposure",
		Path:          "logger.go",
		LineRange:     finding.LineRange{Start: 5},
	}
	r := runRenderer(t, output.Event{Kind: output.EventFinding, Finding: f})
	if r.ExitCode() != 0 {
		t.Errorf("expected exit 0 for MEDIUM-only findings, got %d", r.ExitCode())
	}
}

func TestExitCode_ErrorEvent_Two(t *testing.T) {
	r := runRenderer(t, output.Event{
		Kind: output.EventError,
		Err:  context.DeadlineExceeded,
	})
	if r.ExitCode() != 2 {
		t.Errorf("expected exit 2 for error event, got %d", r.ExitCode())
	}
}

func TestExitCode_ErrorThenBlockFinding_Two(t *testing.T) {
	// Error takes precedence; exit code must stay 2, not be overwritten by BLOCK → 1.
	f := &finding.Finding{
		ID:            "f4",
		SeverityLabel: finding.SeverityBlock,
		CWE:           "CWE-89",
		RuleID:        "sqli",
		Path:          "db.go",
		LineRange:     finding.LineRange{Start: 1},
	}
	r := runRenderer(t,
		output.Event{Kind: output.EventError, Err: context.DeadlineExceeded},
		output.Event{Kind: output.EventFinding, Finding: f},
	)
	if r.ExitCode() != 2 {
		t.Errorf("expected exit 2 (error takes precedence), got %d", r.ExitCode())
	}
}

// ─── Render — EventFinding nil guard ─────────────────────────────────────────

func TestRender_NilFindingEvent_DoesNotPanic(t *testing.T) {
	// EventFinding with nil Finding pointer must not panic.
	runRenderer(t, output.Event{Kind: output.EventFinding, Finding: nil})
}

// ─── Render — stage events ────────────────────────────────────────────────────

func TestRender_StageStartEnd_DoesNotPanic(t *testing.T) {
	runRenderer(t,
		output.Event{Kind: output.EventStageStart, Stage: "ingestion"},
		output.Event{Kind: output.EventStageEnd, Stage: "ingestion", Summary: &output.StageSummary{
			Stage:  "ingestion",
			Detail: "4 files changed",
		}},
	)
}

// ─── Render — context cancellation ───────────────────────────────────────────

func TestRender_CancelledContext_ReturnsContextError(t *testing.T) {
	r := output.NewMinimalRenderer()
	ch := make(chan output.Event) // unbuffered, never closed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Render(ctx, ch)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}

// ─── Emit ─────────────────────────────────────────────────────────────────────

func TestEmit_FullChannel_DoesNotBlock(t *testing.T) {
	ch := make(chan output.Event, 1)
	ch <- output.Event{Kind: output.EventLog, Log: "first"} // fill it
	// This must not block even though ch is full.
	output.Emit(ch, output.Event{Kind: output.EventLog, Log: "dropped"})
}

func TestEmit_SetsTimestamp(t *testing.T) {
	ch := make(chan output.Event, 1)
	output.Emit(ch, output.Event{Kind: output.EventLog, Log: "hello"})
	e := <-ch
	if e.Time.IsZero() {
		t.Error("Emit did not set Time")
	}
}
