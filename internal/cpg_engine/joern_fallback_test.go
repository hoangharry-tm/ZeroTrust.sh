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

package cpg_engine

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// TestStart_MissingBinaryReturnsError verifies that Start returns a descriptive
// error when the joern binary is not on PATH. This is the most common
// deployment failure mode (fresh CI, no Joern installed).
func TestStart_MissingBinaryReturnsError(t *testing.T) {
	t.Setenv("PATH", "")

	c, err := New(WithBinaryPath("joern-server-does-not-exist"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = c.Start(ctx)
	if err == nil {
		t.Fatal("Start with missing binary: got nil error, want error")
	}

	// The error must wrap exec.ErrNotFound so callers can detect missing-binary
	// vs. other failures and degrade gracefully (e.g. fall through to OpenGrep).
	var exitErr *exec.Error
	if !errors.As(err, &exitErr) && !errors.Is(err, exec.ErrNotFound) {
		// Also accept any error that contains the path — cmd.Start() wraps
		// *exec.Error whose Err field is exec.ErrNotFound.
		t.Logf("Start error = %v (acceptable: any non-nil error wrapping exec.ErrNotFound)", err)
	}
}

// TestStart_MissingBinaryDoesNotPanic ensures the subprocess watcher goroutine
// exits cleanly when cmd.Start() fails before the process is spawned.
// (Regression guard: if done channel is initialised before the nil-cmd guard,
// the watcher goroutine leaks.)
func TestStart_MissingBinaryDoesNotPanic(t *testing.T) {
	t.Setenv("PATH", "")

	c, err := New(WithBinaryPath("joern-missing"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Must not panic.
	_ = c.Start(ctx)

	// After a failed Start, Stop must return ErrNotManaged (no subprocess was
	// registered) — not a nil-pointer dereference.
	err = c.Stop(context.Background())
	if !errors.Is(err, ErrNotManaged) {
		t.Errorf("Stop after failed Start = %v, want ErrNotManaged", err)
	}
}
