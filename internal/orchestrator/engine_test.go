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

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// stubScanner is a minimal scanner.Scanner implementation for testing.
type stubScanner struct {
	name      string
	supports  bool
	findings  []finding.Finding
	err       error
	callCount atomic.Int32
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Supports(_ detector.StackProfile) bool { return s.supports }
func (s *stubScanner) Scan(_ context.Context, _ string) ([]finding.Finding, error) {
	s.callCount.Add(1)
	return s.findings, s.err
}

// tmpTarget creates a temp dir with a single Go file so Detect returns a
// non-empty StackProfile.
func tmpTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEngine_RunDispatchesOnlySupportedScanners(t *testing.T) {
	enabled := &stubScanner{name: "enabled", supports: true}
	disabled := &stubScanner{name: "disabled", supports: false}

	e := New(enabled, disabled)
	_, err := e.Run(context.Background(), tmpTarget(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := enabled.callCount.Load(); got != 1 {
		t.Errorf("enabled scanner called %d times, want 1", got)
	}
	if got := disabled.callCount.Load(); got != 0 {
		t.Errorf("disabled scanner called %d times, want 0", got)
	}
}

func TestEngine_RunMergesFindingsFromAllSupportedScanners(t *testing.T) {
	f1 := finding.New("a.go", finding.LineRange{Start: 1, End: 1}, "CWE-89", "sql injection", finding.WithRuleID("r1"))
	f2 := finding.New("b.go", finding.LineRange{Start: 2, End: 2}, "CWE-79", "xss", finding.WithRuleID("r2"))

	a := &stubScanner{name: "a", supports: true, findings: []finding.Finding{f1}}
	b := &stubScanner{name: "b", supports: true, findings: []finding.Finding{f2}}

	e := New(a, b)
	got, err := e.Run(context.Background(), tmpTarget(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2", len(got))
	}
}

func TestEngine_RunEmptyFindings(t *testing.T) {
	s := &stubScanner{name: "clean", supports: true}
	e := New(s)
	got, err := e.Run(context.Background(), tmpTarget(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestEngine_RunNoScanners(t *testing.T) {
	e := New()
	got, err := e.Run(context.Background(), tmpTarget(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

// TestEngine_RunScannerErrorIsLoggedNotPropagated verifies the engine's
// log-and-skip policy: a failing scanner does not abort the run; findings
// from healthy scanners are still returned.
func TestEngine_RunScannerErrorIsLoggedNotPropagated(t *testing.T) {
	sentinel := errors.New("scanner exploded")
	bad := &stubScanner{name: "bad", supports: true, err: sentinel}
	good := &stubScanner{
		name:     "good",
		supports: true,
		findings: []finding.Finding{
			finding.New("x.go", finding.LineRange{Start: 1, End: 1}, "CWE-89", "sql injection", finding.WithRuleID("r1")),
		},
	}
	e := New(bad, good)
	got, err := e.Run(context.Background(), tmpTarget(t))
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d findings, want 1 (from healthy scanner)", len(got))
	}
}

// TestEngine_RunStackDetectionErrorPropagates verifies that an error from
// detector.Detect (not a scanner error) does abort the run.
// We cannot easily inject a Detect error without mocking, so this test
// documents the boundary: a non-existent target that causes os.IsNotExist
// is currently tolerated by Detect (returns empty profile, nil error).
func TestEngine_RunNonExistentTargetIsToleratedByDetect(t *testing.T) {
	s := &stubScanner{name: "s", supports: true}
	e := New(s)
	// Detect silently returns an empty profile for missing dirs; the scanner
	// is still called because Supports() returns true for any profile.
	_, err := e.Run(context.Background(), "/nonexistent/path/zerotrust-test")
	if err != nil {
		t.Errorf("Run on non-existent target: got error %v, want nil (Detect tolerates missing dirs)", err)
	}
}
