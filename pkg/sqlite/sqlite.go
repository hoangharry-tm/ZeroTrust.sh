// Package sqlite wraps a SQLite database connection for the ZeroTrust.sh state cache.
// Uses modernc.org/sqlite (pure-Go, no CGo dependency).
//
// Two tables are managed:
//   - scan_state: one row per (project, file), keyed on content hash for diff detection.
//   - suppressions: user-acknowledged suppression decisions persisted across scans.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// DB wraps a SQLite connection and owns the schema migration.
type DB struct {
	conn *sql.DB
}

// ScanStateRow is one row from the scan_state table.
type ScanStateRow struct {
	// ProjectID identifies the scanned project (derived from project root path).
	ProjectID string
	// FilePath is the file path relative to the project root.
	FilePath string
	// ContentHash is the SHA-256 hex digest of the file's contents.
	ContentHash string
	// LastScannedAt is a Unix timestamp (seconds) of the scan that last touched this row.
	LastScannedAt int64
}

// SuppressionRow is one row from the suppressions table.
type SuppressionRow struct {
	// ProjectID identifies the scanned project.
	ProjectID string
	// FindingID is the stable dedup hash of the suppressed finding.
	FindingID string
	// Reason is a human-readable justification supplied at suppression time.
	Reason string
	// SuppressedAt is a Unix timestamp of when the suppression was recorded.
	SuppressedAt int64
}

// Open opens or creates the SQLite database at path, running schema migrations if needed.
//
// Parameters:
//   - path: absolute path to the .db file; created if it does not exist.
//
// Returns a ready-to-use *DB, or an error if the file cannot be opened or migration fails.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", path, err)
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}
	return db, nil
}

// Conn exposes the underlying *sql.DB for callers that need raw query access.
// Prefer the typed helpers (GetScanState, UpsertScanState, etc.) where possible.
func (db *DB) Conn() *sql.DB { return db.conn }

// Close releases the database connection.
func (db *DB) Close() error { return db.conn.Close() }

// ─── scan_state helpers ──────────────────────────────────────────────────────

// GetScanState returns the cached state row for (projectID, filePath).
// Returns sql.ErrNoRows if no prior scan entry exists for the file.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: project identifier.
//   - filePath: file path relative to project root.
func (db *DB) GetScanState(ctx context.Context, projectID, filePath string) (*ScanStateRow, error) {
	row := &ScanStateRow{}
	err := db.conn.QueryRowContext(ctx,
		`SELECT project_id, file_path, content_hash, last_scanned_at
		 FROM scan_state WHERE project_id = ? AND file_path = ?`,
		projectID, filePath,
	).Scan(&row.ProjectID, &row.FilePath, &row.ContentHash, &row.LastScannedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// UpsertScanState inserts or replaces the scan state row for one file.
// Called by diffindex.Indexer.Commit after a successful scan.
//
// Parameters:
//   - ctx: cancellation context.
//   - row: the state row to persist.
func (db *DB) UpsertScanState(ctx context.Context, row ScanStateRow) error {
	_, err := db.conn.ExecContext(ctx,
		`INSERT OR REPLACE INTO scan_state (project_id, file_path, content_hash, last_scanned_at)
		 VALUES (?, ?, ?, ?)`,
		row.ProjectID, row.FilePath, row.ContentHash, row.LastScannedAt,
	)
	return err
}

// ListScanState returns all cached state rows for the given projectID.
// Used by diffindex.Indexer.Diff to build the prior-state map.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: project identifier.
func (db *DB) ListScanState(ctx context.Context, projectID string) ([]ScanStateRow, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT project_id, file_path, content_hash, last_scanned_at
		 FROM scan_state WHERE project_id = ?`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var result []ScanStateRow
	for rows.Next() {
		var r ScanStateRow
		if err := rows.Scan(&r.ProjectID, &r.FilePath, &r.ContentHash, &r.LastScannedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// DeleteScanState removes the state row for (projectID, filePath).
// Called when a file is detected as removed from the project.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: project identifier.
//   - filePath: file path to remove.
func (db *DB) DeleteScanState(ctx context.Context, projectID, filePath string) error {
	_, err := db.conn.ExecContext(ctx,
		`DELETE FROM scan_state WHERE project_id = ? AND file_path = ?`,
		projectID, filePath,
	)
	return err
}

// ─── suppressions helpers ────────────────────────────────────────────────────

// IsSuppressed reports whether findingID is in the suppressions table for projectID.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: project identifier.
//   - findingID: the stable dedup hash of the finding.
func (db *DB) IsSuppressed(ctx context.Context, projectID, findingID string) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM suppressions WHERE project_id = ? AND finding_id = ?`,
		projectID, findingID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("sqlite: IsSuppressed: %w", err)
	}
	return count > 0, nil
}

// AddSuppression records a new suppression decision.
// Idempotent: re-inserting the same (projectID, findingID) updates the reason.
//
// Parameters:
//   - ctx: cancellation context.
//   - row: the suppression to persist.
func (db *DB) AddSuppression(ctx context.Context, row SuppressionRow) error {
	if row.SuppressedAt == 0 {
		row.SuppressedAt = time.Now().Unix()
	}
	_, err := db.conn.ExecContext(ctx,
		`INSERT OR REPLACE INTO suppressions (project_id, finding_id, reason, suppressed_at)
		 VALUES (?, ?, ?, ?)`,
		row.ProjectID, row.FindingID, row.Reason, row.SuppressedAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: AddSuppression: %w", err)
	}
	return nil
}

// ListSuppressions returns all suppression rows for the given projectID.
// Used by the report generator to annotate suppressed findings.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: project identifier.
func (db *DB) ListSuppressions(ctx context.Context, projectID string) ([]SuppressionRow, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT project_id, finding_id, reason, suppressed_at
		 FROM suppressions WHERE project_id = ?`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListSuppressions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var result []SuppressionRow
	for rows.Next() {
		var r SuppressionRow
		if err := rows.Scan(&r.ProjectID, &r.FindingID, &r.Reason, &r.SuppressedAt); err != nil {
			return nil, fmt.Errorf("sqlite: ListSuppressions scan: %w", err)
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: ListSuppressions: %w", err)
	}
	return result, nil
}

// ─── schema ──────────────────────────────────────────────────────────────────

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS scan_state (
			project_id      TEXT    NOT NULL,
			file_path       TEXT    NOT NULL,
			content_hash    TEXT    NOT NULL,
			last_scanned_at INTEGER NOT NULL,
			PRIMARY KEY (project_id, file_path)
		);
		CREATE INDEX IF NOT EXISTS idx_scan_state_hash
			ON scan_state (project_id, content_hash);

		CREATE TABLE IF NOT EXISTS suppressions (
			project_id    TEXT    NOT NULL,
			finding_id    TEXT    NOT NULL,
			reason        TEXT    NOT NULL,
			suppressed_at INTEGER NOT NULL,
			PRIMARY KEY (project_id, finding_id)
		);
	`)
	return err
}
