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

package patch_test

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
)

// ─── Status constants ─────────────────────────────────────────────────────────

func TestStatusConstants_Values(t *testing.T) {
	// Guards against accidental rename / value drift that would break report rendering.
	cases := []struct {
		got  patch.Status
		want string
	}{
		{patch.StatusGenerated, "generated"},
		{patch.StatusValidationFailed, "validation_failed"},
		{patch.StatusNotAttempted, "not_attempted"},
		{patch.StatusUnsupported, "unsupported"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("Status value mismatch: got %q, want %q", c.got, c.want)
		}
	}
}

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_ReturnsNonNil(t *testing.T) {
	g := patch.New("/tmp/project")
	if g == nil {
		t.Fatal("New returned nil Generator")
	}
}

// ─── Generate ─────────────────────────────────────────────────────────────────

func TestGenerate_NilFindings_ReturnsNoError(t *testing.T) {
	g := patch.New(t.TempDir())
	patches, err := g.Generate(context.Background(), nil)
	if err != nil {
		t.Fatalf("Generate(nil): unexpected error: %v", err)
	}
	// nil or empty slice are both acceptable for zero input.
	_ = patches
}

func TestGenerate_EmptyFindings_ReturnsNoError(t *testing.T) {
	g := patch.New(t.TempDir())
	patches, err := g.Generate(context.Background(), []finding.Finding{})
	if err != nil {
		t.Fatalf("Generate([]): unexpected error: %v", err)
	}
	_ = patches
}

func TestGenerate_CancelledContext_DoesNotPanic(t *testing.T) {
	g := patch.New(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	findings := []finding.Finding{
		{ID: "f1", SeverityLabel: finding.SeverityBlock, CWE: "CWE-89"},
	}
	// Must not panic; may return error or empty result.
	_, _ = g.Generate(ctx, findings)
}

// ─── Validate ─────────────────────────────────────────────────────────────────

func TestValidate_EmptyDiff_ReturnsNoError(t *testing.T) {
	g := patch.New(t.TempDir())
	if err := g.Validate("api/user.go", ""); err != nil {
		t.Errorf("Validate with empty diff: unexpected error: %v", err)
	}
}

func TestValidate_EmptyRelPath_ReturnsNoError(t *testing.T) {
	g := patch.New(t.TempDir())
	// Stub must not panic on empty path.
	if err := g.Validate("", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n"); err != nil {
		t.Errorf("Validate with empty relPath: unexpected error: %v", err)
	}
}
