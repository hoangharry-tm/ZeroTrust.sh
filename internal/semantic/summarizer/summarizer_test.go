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

package summarizer_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

func python3Available() bool {
	_, err := exec.LookPath("python3")
	return err == nil
}

// spawnWorker creates a Manager from an inline Python script and registers cleanup.
func spawnWorker(t *testing.T, script string) *worker.Manager {
	t.Helper()
	if !python3Available() {
		t.Skip("python3 not in PATH")
	}
	m, err := worker.NewFromArgs([]string{"python3", "-c", script}, nil)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	return m
}

// echoSummarizeWorker spawns a Python worker that returns one Summary stub per chain.
func echoSummarizeWorker(t *testing.T) *worker.Manager {
	t.Helper()
	return spawnWorker(t, `
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mtype = msg.get("type", "")
    if mtype in ("ping", "shutdown"):
        print(json.dumps({"id": msg["id"], "status": "ok", "result": {}}), flush=True)
        if mtype == "shutdown":
            break
        continue
    payload = msg.get("payload", {})
    chains = payload.get("chains", [])
    summaries = [
        {
            "FunctionID": "node-" + str(i),
            "SurfaceID": c.get("SurfaceID", ""),
            "TaintFlow": {"UntrustedSources": [], "SanitizerNodes": [], "SinkType": "", "TaintPropagates": False},
            "AuthGuard": {"CheckPresent": False, "CheckLocation": "unknown"},
            "LogicFlaw": {"ResourceIDSource": "", "DBSink": "", "CheckLocation": "unknown"},
        }
        for i, c in enumerate(chains)
    ]
    print(json.dumps({"id": msg["id"], "status": "ok", "result": summaries}), flush=True)
`)
}

// errorWorker returns ok for ping/shutdown but error for all other requests.
func errorWorker(t *testing.T) *worker.Manager {
	t.Helper()
	return spawnWorker(t, `
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mtype = msg.get("type", "")
    if mtype in ("ping", "shutdown"):
        print(json.dumps({"id": msg["id"], "status": "ok", "result": {}}), flush=True)
        if mtype == "shutdown":
            break
        continue
    print(json.dumps({"id": msg["id"], "status": "error", "error": "handler failed"}), flush=True)
`)
}

// malformedWorker returns invalid JSON in the result field for non-ping requests.
func malformedWorker(t *testing.T) *worker.Manager {
	t.Helper()
	return spawnWorker(t, `
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mtype = msg.get("type", "")
    if mtype in ("ping", "shutdown"):
        print(json.dumps({"id": msg["id"], "status": "ok", "result": {}}), flush=True)
        if mtype == "shutdown":
            break
        continue
    print(json.dumps({"id": msg["id"], "status": "ok", "result": "not-valid-json"}), flush=True)
`)
}

func makeChain(surfaceID string) assembler.CallChain {
	return assembler.CallChain{
		SurfaceID: surfaceID,
		Functions: []assembler.FunctionContext{
			{NodeID: "n1"},
		},
	}
}

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_ReturnsNonNil(t *testing.T) {
	if summarizer.New(nil) == nil {
		t.Fatal("New returned nil")
	}
}

// ─── Summarize — empty input ──────────────────────────────────────────────────

func TestSummarize_NilChains_ReturnsEmpty(t *testing.T) {
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)
	ctx := context.Background()
	out, err := s.Summarize(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 summaries for nil input, got %d", len(out))
	}
}

func TestSummarize_EmptyChains_ReturnsEmpty(t *testing.T) {
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)
	out, err := s.Summarize(context.Background(), []assembler.CallChain{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 summaries for empty input, got %d", len(out))
	}
}

// ─── Summarize — happy path ───────────────────────────────────────────────────

func TestSummarize_SingleChain_ReturnsSummary(t *testing.T) {
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)
	chains := []assembler.CallChain{makeChain("surf-1")}

	out, err := s.Summarize(context.Background(), chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(out))
	}
	if out[0].SurfaceID != "surf-1" {
		t.Errorf("SurfaceID mismatch: got %q", out[0].SurfaceID)
	}
}

func TestSummarize_MultipleChainsPreservesOrder(t *testing.T) {
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)
	chains := []assembler.CallChain{
		makeChain("surf-A"),
		makeChain("surf-B"),
		makeChain("surf-C"),
	}

	out, err := s.Summarize(context.Background(), chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 summaries, got %d", len(out))
	}
	wantIDs := []string{"surf-A", "surf-B", "surf-C"}
	for i, want := range wantIDs {
		if out[i].SurfaceID != want {
			t.Errorf("summary[%d].SurfaceID = %q, want %q", i, out[i].SurfaceID, want)
		}
	}
}

// ─── Summarize — batching ─────────────────────────────────────────────────────

func TestSummarize_MoreThanBatchSize_AllSummarized(t *testing.T) {
	// Default batch size is 5; send 7 to exercise the second batch.
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)
	chains := make([]assembler.CallChain, 7)
	for i := range chains {
		chains[i] = makeChain("s" + string(rune('A'+i)))
	}

	out, err := s.Summarize(context.Background(), chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 7 {
		t.Errorf("expected 7 summaries, got %d", len(out))
	}
}

// ─── Summarize — error paths ──────────────────────────────────────────────────

func TestSummarize_WorkerReturnsError_PropagatesError(t *testing.T) {
	m := errorWorker(t)
	s := summarizer.New(m)
	chains := []assembler.CallChain{makeChain("surf-err")}

	_, err := s.Summarize(context.Background(), chains)
	if err == nil {
		t.Fatal("expected error from worker error response, got nil")
	}
}

func TestSummarize_MalformedJSON_PropagatesError(t *testing.T) {
	m := malformedWorker(t)
	s := summarizer.New(m)
	chains := []assembler.CallChain{makeChain("surf-bad")}

	_, err := s.Summarize(context.Background(), chains)
	if err == nil {
		t.Fatal("expected decode error for malformed JSON, got nil")
	}
}

func TestSummarize_CancelledContext_ReturnsError(t *testing.T) {
	m := echoSummarizeWorker(t)
	s := summarizer.New(m)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	chains := []assembler.CallChain{makeChain("surf-cancel")}
	_, err := s.Summarize(ctx, chains)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}

// ─── Summary struct — JSON round-trip ────────────────────────────────────────

func TestSummary_JSONRoundTrip(t *testing.T) {
	orig := summarizer.Summary{
		FunctionID: "fn-1",
		SurfaceID:  "surf-1",
		TaintFlow: assembler.TaintFlowSchema{
			UntrustedSources: []string{"req.body"},
			SanitizerNodes:   []string{},
			SinkType:         "sql",
			TaintPropagates:  true,
		},
		AuthGuard: assembler.AuthGuardSchema{
			CheckPresent:  false,
			CheckLocation: "unknown",
		},
		LogicFlaw: assembler.LogicFlawSchema{
			ResourceIDSource: "path_param",
			DBSink:           "repo.FindByID",
			CheckLocation:    "missing",
		},
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got summarizer.Summary
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.FunctionID != orig.FunctionID || got.SurfaceID != orig.SurfaceID {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if got.TaintFlow.SinkType != "sql" || !got.TaintFlow.TaintPropagates {
		t.Errorf("TaintFlow round-trip mismatch: got %+v", got.TaintFlow)
	}
}
