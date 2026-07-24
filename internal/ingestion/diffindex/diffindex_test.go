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
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func tempIndexer(t *testing.T) (*Indexer, string) {
	t.Helper()
	dir := t.TempDir()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres-backed integration test")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, nil), dir
}

// writeFile writes content to relPath inside root, creating subdirs as needed.
func writeFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	abs := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(abs), err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
}

func toSet(paths []string) map[string]bool {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		m[p] = true
	}
	return m
}

// ─── DeriveProjectID ─────────────────────────────────────────────────────────

func TestDeriveProjectIDDeterministic(t *testing.T) {
	id1 := DeriveProjectID("/some/project")
	id2 := DeriveProjectID("/some/project")
	if id1 != id2 {
		t.Errorf("not deterministic: %q vs %q", id1, id2)
	}
}

func TestDeriveProjectIDLength(t *testing.T) {
	id := DeriveProjectID("/any/path")
	if len(id) != 16 {
		t.Errorf("expected 16 chars, got %d: %q", len(id), id)
	}
}

func TestDeriveProjectIDDistinct(t *testing.T) {
	a := DeriveProjectID("/project/a")
	b := DeriveProjectID("/project/b")
	if a == b {
		t.Error("different paths must produce different IDs")
	}
}

// ─── shouldSkip ──────────────────────────────────────────────────────────────

func TestShouldSkipVendor(t *testing.T) {
	if !shouldSkip("vendor/pkg/util.go") {
		t.Error("vendor/ should be skipped")
	}
}

func TestShouldSkipNodeModules(t *testing.T) {
	if !shouldSkip("node_modules/lodash/index.js") {
		t.Error("node_modules/ should be skipped")
	}
}

func TestShouldSkipBinaryExt(t *testing.T) {
	for _, p := range []string{"build/app.exe", "lib.so", "image.png", "data.db"} {
		if !shouldSkip(p) {
			t.Errorf("expected %q to be skipped", p)
		}
	}
}

func TestShouldSkipGoSourceNotSkipped(t *testing.T) {
	if shouldSkip("internal/auth/handler.go") {
		t.Error("Go source files must not be skipped")
	}
}

func TestShouldSkipPyNotSkipped(t *testing.T) {
	if shouldSkip("worker/handlers/llm_verify.py") {
		t.Error("Python source files must not be skipped")
	}
}

// ─── Diff — first scan ───────────────────────────────────────────────────────

func TestDiffFirstScanAllChanged(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, "api/auth.go", "package api")

	ctx := t.Context()
	cs, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(cs.Removed) != 0 {
		t.Errorf("first scan: unexpected removals: %v", cs.Removed)
	}
	changed := toSet(cs.Changed)
	if !changed["main.go"] || !changed[filepath.Join("api", "auth.go")] {
		t.Errorf("expected both files in Changed; got %v", cs.Changed)
	}
}

// ─── Diff — repeat scan ──────────────────────────────────────────────────────

func TestDiffRepeatScanUnchangedFilesNotInChanged(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, "api/auth.go", "package api")

	ctx := t.Context()
	cs1, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("first Diff: %v", err)
	}
	if err := ix.Commit(ctx, "proj", cs1); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// No changes — second diff should return empty Changed.
	cs2, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("second Diff: %v", err)
	}
	if len(cs2.Changed) != 0 {
		t.Errorf("expected no changes on repeat scan, got %v", cs2.Changed)
	}
	if len(cs2.Removed) != 0 {
		t.Errorf("expected no removals on repeat scan, got %v", cs2.Removed)
	}
}

func TestDiffRepeatScanModifiedFileInChanged(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, "api/auth.go", "package api")

	ctx := t.Context()
	cs1, _ := ix.Diff(ctx, "proj", root)
	ix.Commit(ctx, "proj", cs1) //nolint:errcheck

	// Modify one file.
	writeFile(t, root, "main.go", "package main // updated")

	cs2, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("second Diff: %v", err)
	}
	if len(cs2.Changed) != 1 || cs2.Changed[0] != "main.go" {
		t.Errorf("expected only main.go changed, got %v", cs2.Changed)
	}
}

func TestDiffRepeatScanNewFileInChanged(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")

	ctx := t.Context()
	cs1, _ := ix.Diff(ctx, "proj", root)
	ix.Commit(ctx, "proj", cs1) //nolint:errcheck

	// Add a new file.
	writeFile(t, root, "util.go", "package main // new")

	cs2, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("second Diff: %v", err)
	}
	if len(cs2.Changed) != 1 || cs2.Changed[0] != "util.go" {
		t.Errorf("expected only util.go changed, got %v", cs2.Changed)
	}
}

// ─── Diff — removed files ────────────────────────────────────────────────────

func TestDiffRemovedFileInRemoved(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, "old.go", "package main // old")

	ctx := t.Context()
	cs1, _ := ix.Diff(ctx, "proj", root)
	ix.Commit(ctx, "proj", cs1) //nolint:errcheck

	// Delete old.go.
	os.Remove(filepath.Join(root, "old.go")) //nolint:errcheck

	cs2, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("second Diff: %v", err)
	}
	removed := toSet(cs2.Removed)
	if !removed["old.go"] {
		t.Errorf("expected old.go in Removed, got %v", cs2.Removed)
	}
	if len(cs2.Changed) != 0 {
		t.Errorf("unexpected changes: %v", cs2.Changed)
	}
}

// ─── Commit ──────────────────────────────────────────────────────────────────

func TestCommitPersistsAllStates(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "a.go", "a")
	writeFile(t, root, "b.go", "b")

	ctx := t.Context()
	cs, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if err := ix.Commit(ctx, "proj", cs); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Verify round-trip: both files now have cache rows.
	cs2, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("second Diff: %v", err)
	}
	if len(cs2.Changed) != 0 {
		t.Errorf("after Commit, no files should be changed; got %v", cs2.Changed)
	}
}

func TestCommitEvictsRemoved(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "keep.go", "keep")
	writeFile(t, root, "evict.go", "evict")

	ctx := t.Context()
	cs1, _ := ix.Diff(ctx, "proj", root)
	ix.Commit(ctx, "proj", cs1) //nolint:errcheck

	// Remove evict.go and commit the new state.
	os.Remove(filepath.Join(root, "evict.go")) //nolint:errcheck
	cs2, _ := ix.Diff(ctx, "proj", root)
	if err := ix.Commit(ctx, "proj", cs2); err != nil {
		t.Fatalf("Commit with removal: %v", err)
	}

	// Third diff: evict.go must not reappear in Removed.
	cs3, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("third Diff: %v", err)
	}
	if len(cs3.Removed) != 0 {
		t.Errorf("evict.go should be gone from cache; Removed=%v", cs3.Removed)
	}
}

func TestCommitNilChangeSetIsNoop(t *testing.T) {
	// CommitScan in ingestion.go guards nil; test the underlying Commit directly.
	ix, _ := tempIndexer(t)
	ctx := t.Context()
	// nil Removed — should not panic or error.
	if err := ix.Commit(ctx, "proj", &ChangeSet{}); err != nil {
		t.Errorf("Commit with empty ChangeSet: %v", err)
	}
}

// ─── Diff — skip rules apply ─────────────────────────────────────────────────

func TestDiffSkipsGitDir(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main")

	ctx := t.Context()
	cs, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	gitPrefix := ".git" + string(filepath.Separator)
	for _, p := range cs.Changed {
		if p == ".git" || strings.HasPrefix(p, gitPrefix) {
			t.Errorf(".git entries must not appear in Changed: %v", p)
		}
	}
}

func TestDiffSkipsBinaryExts(t *testing.T) {
	ix, root := tempIndexer(t)
	writeFile(t, root, "app.exe", "\x00\x01\x02")
	writeFile(t, root, "main.go", "package main")

	ctx := t.Context()
	cs, err := ix.Diff(ctx, "proj", root)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, p := range cs.Changed {
		if p == "app.exe" {
			t.Error("binary .exe file must be skipped")
		}
	}
	if len(cs.Changed) != 1 || cs.Changed[0] != "main.go" {
		t.Errorf("expected only main.go in Changed, got %v", cs.Changed)
	}
}
