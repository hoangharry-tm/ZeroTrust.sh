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

package llmscan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
)

// stubCaller returns responses from a pre-loaded queue, one per Call invocation.
// This keeps tests independent of IPC ordering assumptions.
type stubCaller struct {
	queue []worker.Response
	idx   int
	err   error // if non-nil, returned on every Call
}

func (s *stubCaller) Call(_ context.Context, _ worker.MessageType, _ any) (*worker.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.idx >= len(s.queue) {
		return &worker.Response{Status: worker.ResponseError, Error: "stub: no more responses"}, nil
	}
	resp := s.queue[s.idx]
	s.idx++
	return &resp, nil
}

// helpers

func okResponse(v any) worker.Response {
	b, _ := json.Marshal(v)
	return worker.Response{Status: worker.ResponseOK, Result: b}
}

func probeOK() worker.Response {
	return okResponse(map[string]string{"status": "ok"})
}

func stepResp(verdict string, conf float64, earlyExit bool) worker.Response {
	return okResponse(scanStepResponse{
		Thought:     "analyzing",
		Action:      "check taint",
		Observation: "taint found",
		Verdict:     verdict,
		Confidence:  conf,
		CWE:         "CWE-89",
		EarlyExit:   earlyExit,
	})
}

func makeSurface(id string) budget.RankedSurface {
	return budget.RankedSurface{
		Summary:              summarizer.Summary{SurfaceID: id, FunctionID: id + "_fn"},
		Priority:             0.7,
		EstimatedTokens:      100,
		ClassifierConfidence: 0.5,
	}
}

// BackboneCheck tests

func TestBackboneCheck_ReAct(t *testing.T) {
	s := &Scanner{w: &stubCaller{queue: []worker.Response{probeOK()}}}
	mode, err := s.BackboneCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mode != ScanModeReAct {
		t.Errorf("want ScanModeReAct, got %q", mode)
	}
}

func TestBackboneCheck_WorkerError_SinglePass(t *testing.T) {
	s := &Scanner{w: &stubCaller{err: errors.New("connection refused")}}
	mode, err := s.BackboneCheck(context.Background())
	if err != nil {
		t.Fatal("BackboneCheck should degrade gracefully, not propagate error")
	}
	if mode != ScanModeSinglePass {
		t.Errorf("want ScanModeSinglePass on worker error, got %q", mode)
	}
}

func TestBackboneCheck_WorkerResponseError_SinglePass(t *testing.T) {
	s := &Scanner{w: &stubCaller{queue: []worker.Response{
		{Status: worker.ResponseError, Error: "model not loaded"},
	}}}
	mode, _ := s.BackboneCheck(context.Background())
	if mode != ScanModeSinglePass {
		t.Errorf("want ScanModeSinglePass on worker ResponseError, got %q", mode)
	}
}

func TestBackboneCheck_InvalidJSON_SinglePass(t *testing.T) {
	s := &Scanner{w: &stubCaller{queue: []worker.Response{
		{Status: worker.ResponseOK, Result: json.RawMessage(`not valid json`)},
	}}}
	mode, _ := s.BackboneCheck(context.Background())
	if mode != ScanModeSinglePass {
		t.Errorf("want ScanModeSinglePass on invalid JSON response, got %q", mode)
	}
}

// Scan tests (T3 + T4)

func TestScan_UncertainVerdict_Suppressed(t *testing.T) {
	// Probe + 3 step responses (uncertain on step 3).
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("", 0.3, false),      // step 1: no verdict yet
		stepResp("", 0.3, false),      // step 2: no verdict yet
		stepResp("uncertain", 0.2, false), // step 3: uncertain
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("getResource")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("severity: want SUPPRESSED, got %q", f.SeverityLabel)
	}
	if f.SuppressReason != finding.SuppressReasonUncertain {
		t.Errorf("suppress reason: want %q, got %q", finding.SuppressReasonUncertain, f.SuppressReason)
	}
}

func TestScan_VulnerableHighConfidence_HighSeverity(t *testing.T) {
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("", 0.0, false),
		stepResp("", 0.0, false),
		stepResp("vulnerable", 0.88, false),
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("getOrder")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SeverityLabel != finding.SeverityHigh {
		t.Errorf("severity: want HIGH (conf=0.88), got %q", f.SeverityLabel)
	}
	if f.SuppressReason != "" {
		t.Errorf("suppress reason should be empty for vulnerable finding, got %q", f.SuppressReason)
	}
	if f.SourcePath != finding.SourceSemantic {
		t.Errorf("source path: want SEMANTIC, got %q", f.SourcePath)
	}
}

func TestScan_EarlyExitOnStep1(t *testing.T) {
	// Step 1 returns EarlyExit=true — steps 2 and 3 must NOT be called.
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("vulnerable", 0.95, true), // step 1 early exits
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("injectSQL")})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].SeverityLabel != finding.SeverityBlock {
		t.Errorf("early exit with conf=0.95 should give BLOCK, got %q", findings[0].SeverityLabel)
	}
	// stub.idx should be 2 (probe + step1 only), not 4
	if stub.idx != 2 {
		t.Errorf("expected 2 worker calls (probe + step1), got %d", stub.idx)
	}
}

func TestScan_SafeVerdict_Suppressed(t *testing.T) {
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("", 0.0, false),
		stepResp("", 0.0, false),
		stepResp("safe", 0.92, false),
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("checkedRoute")})
	if err != nil {
		t.Fatal(err)
	}
	f := findings[0]
	if f.SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("safe verdict: want SUPPRESSED, got %q", f.SeverityLabel)
	}
	if f.SuppressReason != finding.SuppressReasonSafe {
		t.Errorf("suppress reason: want %q, got %q", finding.SuppressReasonSafe, f.SuppressReason)
	}
}

func TestScan_SinglePassMode(t *testing.T) {
	// Backbone probe returns invalid JSON → single-pass mode.
	stub := &stubCaller{queue: []worker.Response{
		{Status: worker.ResponseOK, Result: json.RawMessage(`not json`)}, // probe fails
		stepResp("vulnerable", 0.72, false),                               // single-pass response
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("upload")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].SeverityLabel != finding.SeverityMedium {
		t.Errorf("conf=0.72 → want MEDIUM, got %q", findings[0].SeverityLabel)
	}
}

func TestScan_MultipleSurfaces_OnePerFinding(t *testing.T) {
	surfaces := []budget.RankedSurface{makeSurface("s1"), makeSurface("s2")}
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		// s1: 3 steps
		stepResp("", 0.0, false), stepResp("", 0.0, false), stepResp("uncertain", 0.1, false),
		// s2: 3 steps
		stepResp("", 0.0, false), stepResp("", 0.0, false), stepResp("vulnerable", 0.80, false),
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), surfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (one per surface), got %d", len(findings))
	}
	if findings[0].SeverityLabel != finding.SeveritySuppressed {
		t.Errorf("s1: want SUPPRESSED, got %q", findings[0].SeverityLabel)
	}
	if findings[1].SeverityLabel != finding.SeverityHigh {
		t.Errorf("s2: want HIGH (conf=0.80), got %q", findings[1].SeverityLabel)
	}
}

func TestScan_EarlyExitOnStep2(t *testing.T) {
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("", 0.0, false),        // step 1: continue
		stepResp("vulnerable", 0.93, true), // step 2 early exits
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("authBypass")})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].SeverityLabel != finding.SeverityBlock {
		t.Errorf("conf=0.93 → want BLOCK, got %q", findings[0].SeverityLabel)
	}
	// probe + step1 + step2 = 3 calls; step3 must NOT be called
	if stub.idx != 3 {
		t.Errorf("want 3 worker calls (probe+step1+step2), got %d", stub.idx)
	}
}

func TestScan_AllThreeSteps(t *testing.T) {
	stub := &stubCaller{queue: []worker.Response{
		probeOK(),
		stepResp("", 0.0, false),          // step 1
		stepResp("", 0.0, false),          // step 2
		stepResp("vulnerable", 0.77, false), // step 3: trigger constraint at sink
	}}
	s := &Scanner{w: stub}
	findings, err := s.Scan(context.Background(), []budget.RankedSurface{makeSurface("fetchOrder")})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].SeverityLabel != finding.SeverityHigh {
		t.Errorf("conf=0.77 → want HIGH, got %q", findings[0].SeverityLabel)
	}
	// probe + 3 steps = 4 calls
	if stub.idx != 4 {
		t.Errorf("want 4 worker calls (probe+step1+step2+step3), got %d", stub.idx)
	}
}

// toFinding direct tests

func TestToFinding_IDStability(t *testing.T) {
	result := ScanResult{SurfaceID: "fn", Verdict: "vulnerable", Confidence: 0.85, CWE: "CWE-89"}
	surf := makeSurface("fn")
	f1 := toFinding(result, surf)
	f2 := toFinding(result, surf)
	if f1.ID != f2.ID {
		t.Errorf("finding ID must be stable: %q != %q", f1.ID, f2.ID)
	}
	if f1.ID == "" {
		t.Error("finding ID must not be empty")
	}
}
