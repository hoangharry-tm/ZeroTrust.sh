// Package diffindex implements the Differential Indexer.
//
// The Indexer compares the current file set against a SQLite state cache and
// returns only files that are new or changed since the last scan, reducing
// per-scan cost of OpenGrep, Joern CPG build, and Path B by ~80–95%.
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
	"io"

	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// FileState records the cached state of one file from a prior scan.
type FileState struct {
	// ProjectID identifies the owning project (matches sqlite.ScanStateRow.ProjectID).
	ProjectID string
	// FilePath is the path relative to the project root.
	FilePath string
	// ContentHash is the SHA-256 hex digest of the file's contents.
	ContentHash string
	// LastScannedAt is the Unix timestamp (seconds) of the scan that last wrote this row.
	LastScannedAt int64
}

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
	db *sqlite.DB
}

// New returns an Indexer backed by db.
func New(db *sqlite.DB) *Indexer {
	return &Indexer{db: db}
}

// Diff walks projectRoot, hashes every file, and compares against the cached
// state for projectID in SQLite. Returns the ChangeSet for this scan.
//
// On first scan (no cache rows) all files are returned as Changed.
//
// Parameters:
//   - ctx: cancellation context; long directory walks honour it between subdirectories.
//   - projectID: primary-key prefix for the SQLite scan_state table.
//   - projectRoot: absolute path to the codebase root to walk.
//
// Returns:
//   - *ChangeSet: Changed (new/modified) and Removed (deleted) file sets.
//   - error: non-nil if projectRoot cannot be walked or SQLite access fails.
func (i *Indexer) Diff(ctx context.Context, projectID, projectRoot string) (*ChangeSet, error) {
	// implemented in G2.M2.2
	return &ChangeSet{}, nil
}

// Commit persists the current file states for projectID, replacing any prior state.
// Call this after a successful scan to advance the cache baseline for the next run.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: primary-key prefix for the SQLite scan_state table.
//   - states: the complete current file-state list (one entry per file in scope).
func (i *Indexer) Commit(ctx context.Context, projectID string, states []FileState) error {
	// implemented in G2.M2.2
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
//
// Parameters:
//   - absPath: the absolute path of the file to hash.
//
// Returns:
//   - string: lowercase hex-encoded SHA-256 digest.
//   - error: non-nil if the file cannot be opened or read.
func hashFile(absPath string) (string, error) {
	// implemented in G2.M2.2
	return "", nil
}

// shouldSkip reports whether a file at relPath should be excluded from the diff.
// Skipped paths include: .git/, vendor/, node_modules/, and binary file extensions.
//
// Parameters:
//   - relPath: the file path relative to projectRoot.
func shouldSkip(relPath string) bool {
	// implemented in G2.M2.2
	return false
}
