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

//go:build integration

package diffindex

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDiff_PermissionBlockedSubdirReturnsError ensures that Diff returns an
// error rather than a silent partial ChangeSet when a subdirectory is
// unreadable. A security scanner that silently skips directories gives a
// false-clean result — the worst possible failure mode.
func TestDiff_PermissionBlockedSubdirReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 is a no-op for the owner on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}

	ix, root := tempIndexer(t)

	// Create a readable file at the top level.
	writeFile(t, root, "visible.go", "package main")

	// Create a subdirectory that will become unreadable.
	blocked := filepath.Join(root, "secret")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, filepath.Join("secret", "sensitive.go"), "package secret")

	// Remove all permissions — WalkDir cannot descend into this directory.
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) }) // restore so TempDir cleanup works

	pid := DeriveProjectID(root)
	_, err := ix.Diff(context.Background(), pid, root)
	if err == nil {
		t.Fatal("Diff with permission-blocked subdir: got nil error, want error")
	}
}
