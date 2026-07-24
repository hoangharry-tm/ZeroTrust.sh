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

// Package diffindex implements the Differential Indexer.
//
// The Indexer compares the current file set against a SQLite state cache and
// returns only files that are new or changed since the last scan, reducing
// per-scan cost of OpenGrep, Joern CPG build, and Reasoning by ~80–95%.
//
// Content hashing: each file is hashed with SHA-256; only files whose hash
// differs from the cached value are considered changed. Deleted files appear
// in ChangeSet.Removed so downstream stages can evict their CPG nodes.
//
// First scan: no rows exist in the cache, so all files are returned as Changed.
// Repeat scan: only new / modified / deleted files appear in the ChangeSet.
package diffindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// ChangeSet is the output of a differential comparison.
type ChangeSet struct {
	// Changed holds the relative paths of files that are new or modified.
	// Both detection paths consume this list as their input file set.
	Changed []string
	// Removed holds the relative paths of files present in the prior scan
	// but absent from the current file set. The Joern incremental CPG patch
	// must evict their nodes before running taint queries.
	Removed []string
}

// Indexer computes the differential file set for each scan.
type Indexer struct {
	db     *postgres.DB
	logger *slog.Logger
}

// New returns an Indexer backed by db.
// If logger is nil, slog.Default() is used.
func New(db *postgres.DB, logger *slog.Logger) *Indexer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Indexer{db: db, logger: logger}
}

// Diff walks projectRoot, hashes every file, and compares against the cached
// state for projectID in SQLite. Returns the ChangeSet for this scan.
//
// On first scan (no cache rows) all files are returned as Changed.
//
// Parameters:
//   - ctx: cancellation context; long directory walks honour it between files.
//   - projectID: primary-key prefix for the SQLite scan_state table.
//   - projectRoot: absolute path to the codebase root to walk.
//
// Returns:
//   - *ChangeSet: Changed (new/modified) and Removed (deleted).
//   - error: non-nil if projectRoot cannot be walked or SQLite access fails.
func (ix *Indexer) Diff(ctx context.Context, projectID, projectRoot string) (*ChangeSet, error) {
	ix.logger.Debug("diffindex: computing file diff",
		"component", "diffindex",
		"project_id", projectID,
		"root", projectRoot,
	)
	prior, err := ix.db.ListScanState(ctx, projectID)
	if err != nil {
		ix.logger.Error("diffindex: failed to load prior scan state", "component", "diffindex", "err", err)
		return nil, fmt.Errorf("list scan state: %w", err)
	}
	priorMap := make(map[string]string, len(prior))
	for _, row := range prior {
		priorMap[row.FilePath] = row.ContentHash
	}

	now := time.Now().Unix()
	var changed []string
	seen := make(map[string]bool)
	totalFiles := 0

	err = filepath.WalkDir(projectRoot, func(absPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			ix.logger.Error("diffindex: unreadable path, aborting diff",
				"component", "diffindex",
				"path", absPath,
				"err", walkErr,
			)
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		relPath, err := filepath.Rel(projectRoot, absPath)
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if relPath != "." && shouldSkip(relPath) {
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkip(relPath) {
			return nil
		}

		hash, err := hashFile(absPath)
		if err != nil {
			ix.logger.Warn("diffindex: file hash failed, excluded from changeset",
				"component", "diffindex",
				"path", absPath,
				"err", err,
			)
			return nil
		}

		seen[relPath] = true
		totalFiles++

		if priorMap[relPath] != hash {
			changed = append(changed, relPath)
		}

		// Stream state directly to SQLite — no slice accumulation.
		if err := ix.db.UpsertScanState(ctx, postgres.ScanStateRow{
			ProjectID:     projectID,
			FilePath:      relPath,
			ContentHash:   hash,
			LastScannedAt: now,
		}); err != nil {
			return fmt.Errorf("upsert scan state %s: %w", relPath, err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", projectRoot, err)
	}

	var removed []string
	for relPath := range priorMap {
		if !seen[relPath] {
			removed = append(removed, relPath)
		}
	}

	ix.logger.Info("diffindex: diff complete",
		"component", "diffindex",
		"changed", len(changed),
		"removed", len(removed),
		"total_files", totalFiles,
	)
	return &ChangeSet{Changed: changed, Removed: removed}, nil
}

// Commit evicts Removed entries from the cache. State rows are already persisted
// during Diff — no slice accumulation needed.
// Call this after a successful scan to remove entries for deleted files.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: primary-key prefix for the SQLite scan_state table.
//   - cs: the ChangeSet returned by Diff for this scan.
func (ix *Indexer) Commit(ctx context.Context, projectID string, cs *ChangeSet) error {
	ix.logger.Debug("diffindex: committing scan state",
		"component", "diffindex",
		"project_id", projectID,
		"removed", len(cs.Removed),
	)
	for _, r := range cs.Removed {
		if err := ix.db.DeleteScanState(ctx, projectID, r); err != nil {
			ix.logger.Error("diffindex: failed to delete removed file state",
				"component", "diffindex",
				"file", r,
				"err", err,
			)
			return fmt.Errorf("delete removed %s: %w", r, err)
		}
	}
	ix.logger.Debug("diffindex: commit complete", "component", "diffindex")
	return nil
}

// DeriveProjectID returns a deterministic project identifier from the absolute
// project root path. Used when the caller does not supply an explicit --project-id flag.
//
// The returned value is the first 16 hex characters of SHA-256(projectRoot),
// giving a compact and collision-resistant key suitable for SQLite primary keys.
//
// Parameters:
//   - projectRoot: absolute path to the codebase root.
func DeriveProjectID(projectRoot string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, projectRoot)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// hashFile computes the SHA-256 hex digest of the file at absPath.
func hashFile(absPath string) (string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", absPath, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// skipDirs are directory names always excluded from the diff walk.
var skipDirs = map[string]bool{
	".git":          true,
	"vendor":        true,
	"node_modules":  true,
	".cache":        true,
	"__pycache__":   true,
	".pytest_cache": true,
	".venv":         true,
	"venv":          true,
}

// binaryExts are file extensions treated as binary — hashing them is wasteful.
var binaryExts = map[string]bool{
	".exe": true, ".bin": true, ".so": true, ".dylib": true, ".dll": true,
	".o": true, ".a": true, ".lib": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
	".wasm": true, ".db": true, ".sqlite": true,
	// SQLite WAL-mode sidecar files have compound extensions: filepath.Ext()
	// returns ".db-shm" and ".db-wal" (the suffix after the last dot in the
	// full filename, e.g. "test.db-shm" → ".db-shm"). Kept for target codebases
	// that embed their own SQLite database — the state cache (pkg/postgres) is
	// a separate Postgres instance and no longer lives inside the scanned tree.
	".db-shm": true, ".db-wal": true,
}

// shouldSkip reports whether a file or directory at relPath should be excluded.
// Called for both directory entries (to skip entire subtrees) and file entries.
func shouldSkip(relPath string) bool {
	for part := range strings.SplitSeq(relPath, string(filepath.Separator)) {
		if skipDirs[part] {
			return true
		}
	}
	ext := strings.ToLower(filepath.Ext(relPath))
	return binaryExts[ext]
}
