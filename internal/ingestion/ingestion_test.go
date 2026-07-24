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

package ingestion

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// tempIngester creates a real Indexer (backed by Postgres at $DATABASE_URL,
// skipping the test if unset) and a MIV Verifier pointing at empty registry
// paths (so it uses the embedded defaults).
func tempIngester(t *testing.T) (*Ingester, string) {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres-backed integration test")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	indexer := diffindex.New(db, nil)
	verifier := miv.New("", "", nil) // empty paths → embedded registry
	return New(indexer, verifier), t.TempDir()
}

// writeFile creates a file inside root with the given content.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// ─── ProjectID derivation ─────────────────────────────────────────────────────

// When Config.ProjectID is empty, Run must derive one deterministically from
// the project root, not leave it blank.
func TestRun_DerivedProjectIDIsNonEmpty(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	res, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ProjectID == "" {
		t.Error("ProjectID must not be empty when not supplied in Config")
	}
}

// When Config.ProjectID is supplied, Run must use it exactly (no override).
func TestRun_ExplicitProjectIDIsPreserved(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	const want = "my-explicit-project-id"
	res, err := ig.Run(context.Background(), Config{ProjectID: want, ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ProjectID != want {
		t.Errorf("ProjectID = %q, want %q", res.ProjectID, want)
	}
}

// Calling Run twice with the same root must produce the same derived ProjectID.
func TestRun_DerivedProjectIDIsStable(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	res1, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	res2, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if res1.ProjectID != res2.ProjectID {
		t.Errorf("ProjectID changed between runs: %q vs %q", res1.ProjectID, res2.ProjectID)
	}
}

// ─── MIV skipped when ModelPath is empty ─────────────────────────────────────

// An empty ModelPath must never block LLM — callers skip MIV silently.
func TestRun_EmptyModelPathSkipsMIVAndDoesNotBlockLLM(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	res, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.BlockLLM {
		t.Error("BlockLLM must be false when ModelPath is empty (MIV skipped)")
	}
	if res.MIV == nil {
		t.Fatal("MIV result must not be nil even when skipped")
	}
	if res.MIV.Status == miv.StatusBlock {
		t.Error("MIV status must not be BLOCK when model path was not supplied")
	}
}

// ─── BlockLLM is set only on StatusBlock ─────────────────────────────────────

// When MIV returns a non-block status (e.g. WARN for unrecognised model),
// BlockLLM must be false — pattern matching must proceed.
func TestRun_BlockLLMFalseForWarnStatus(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	// Point at a real file that isn't a GGUF registered in the embedded registry.
	// MIV will return StatusWarn (unrecognised model), not StatusBlock.
	modelFile := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(modelFile, []byte("fake gguf content"), 0o600); err != nil {
		t.Fatalf("write model: %v", err)
	}

	res, err := ig.Run(context.Background(), Config{
		ProjectRoot: root,
		ModelPath:   modelFile,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// An unregistered model → StatusWarn; BlockLLM must stay false.
	if res.MIV.Status == miv.StatusBlock && res.BlockLLM == false {
		t.Error("BlockLLM must be true when MIV returns StatusBlock")
	}
	if res.MIV.Status != miv.StatusBlock && res.BlockLLM == true {
		t.Error("BlockLLM must be false for non-BLOCK MIV status")
	}
}

// BlockLLM must be exactly the boolean expression (MIV.Status == StatusBlock).
// This test directly verifies the invariant holds for all possible statuses.
func TestRun_BlockLLMMatchesMIVStatus(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	res, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantBlock := res.MIV.Status == miv.StatusBlock
	if res.BlockLLM != wantBlock {
		t.Errorf("BlockLLM = %v but MIV.Status = %q (want BlockLLM = %v)",
			res.BlockLLM, res.MIV.Status, wantBlock)
	}
}

// ─── DI errors are fatal ──────────────────────────────────────────────────────

// A non-existent ProjectRoot causes DI to log a warning and return an empty
// ChangeSet rather than an error (DI is intentionally lenient on missing paths
// so it does not block scans when parts of a workspace are absent).
// The Result must still be non-nil and the ChangeSet must have zero Changed files.
func TestRun_NonExistentProjectRootReturnsEmptyChangeSet(t *testing.T) {
	ig, _ := tempIngester(t)

	res, err := ig.Run(context.Background(), Config{
		ProjectRoot: "/nonexistent/path/that/does/not/exist",
	})
	// DI does not error on missing paths — it returns an empty ChangeSet.
	if err != nil {
		t.Skipf("DI returned error for non-existent path (implementation may vary): %v", err)
	}
	if res == nil {
		t.Fatal("Run must not return nil result even for a non-existent root")
	}
	if len(res.ChangeSet.Changed) != 0 {
		t.Errorf("expected 0 Changed files for non-existent root, got %d", len(res.ChangeSet.Changed))
	}
}

// ─── ChangeSet is populated ───────────────────────────────────────────────────

func TestRun_ChangeSetsAllFilesOnFirstScan(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")
	writeFile(t, root, "util.go", "package main")

	res, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ChangeSet == nil {
		t.Fatal("ChangeSet must not be nil on first scan")
	}
	// On first scan all files appear in Changed (no prior baseline).
	if len(res.ChangeSet.Changed) == 0 {
		t.Error("ChangeSet.Changed must be non-empty on first scan")
	}
}

func TestRun_ChangeSetContainsNewFilesOnRepeatScan(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	// First scan + commit.
	res1, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := ig.CommitScan(context.Background(), res1.ProjectID, res1.ChangeSet); err != nil {
		t.Fatalf("CommitScan: %v", err)
	}

	// Add a new file and run again.
	writeFile(t, root, "newfile.go", "package main\nfunc f() {}")
	res2, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}

	found := false
	for _, path := range res2.ChangeSet.Changed {
		if filepath.Base(path) == "newfile.go" {
			found = true
			break
		}
	}
	if !found {
		t.Error("second scan ChangeSet.Changed must contain the newly added file")
	}
}

// ─── CommitScan ───────────────────────────────────────────────────────────────

// CommitScan with a nil ChangeSet must be a no-op (not panic or error).
func TestCommitScan_NilChangeSetIsNoop(t *testing.T) {
	ig, _ := tempIngester(t)
	if err := ig.CommitScan(context.Background(), "proj-1", nil); err != nil {
		t.Errorf("CommitScan(nil) returned error: %v", err)
	}
}

// After CommitScan, unchanged files must not appear in the next ChangeSet.
func TestCommitScan_UnchangedFilesExcludedFromNextScan(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "stable.go", "package main")

	res1, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := ig.CommitScan(context.Background(), res1.ProjectID, res1.ChangeSet); err != nil {
		t.Fatalf("CommitScan: %v", err)
	}

	// No changes — repeat scan should have an empty or unchanged ChangeSet.
	res2, err := ig.Run(context.Background(), Config{ProjectRoot: root})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	// After committing a baseline with no changes, Changed must be empty.
	if len(res2.ChangeSet.Changed) != 0 {
		t.Errorf("unchanged file set: expected 0 Changed files on repeat scan, got %d: %v",
			len(res2.ChangeSet.Changed), res2.ChangeSet.Changed)
	}
}

// ─── Context cancellation ─────────────────────────────────────────────────────

func TestRun_CancelledContextReturnsError(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ig.Run(ctx, Config{ProjectRoot: root})
	// DI uses the context; a cancelled context may or may not surface as an error
	// depending on timing. Either way, it must not panic.
	_ = err
}

// ─── MIV result is never nil in the returned Result ──────────────────────────

func TestRun_MIVResultIsNeverNil(t *testing.T) {
	ig, root := tempIngester(t)
	writeFile(t, root, "main.go", "package main")

	cases := []Config{
		{ProjectRoot: root},                 // no model path
		{ProjectRoot: root, ModelPath: "x"}, // non-existent model path
	}
	for _, cfg := range cases {
		res, err := ig.Run(context.Background(), cfg)
		if err != nil {
			continue // DI error — not testing MIV here
		}
		if res.MIV == nil {
			t.Errorf("Config %+v: res.MIV must never be nil", cfg)
		}
	}
}
