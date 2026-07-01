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

// Package sqlite wraps a SQLite database connection for the ZeroTrust.sh state cache.
// Uses modernc.org/sqlite (pure-Go, no CGo dependency).
//
// Eight tables across two versioned migrations:
//
//	Migration 1: scan_state, suppressions
//	Migration 2: projects, scan_runs, findings, ssvc_scores, poe_results, cpg_cache
//
// The database file is created with mode 0600. WAL journal mode and foreign-key
// enforcement are applied on every Open so callers never need to set them manually.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

const currentSchemaVersion = 3

// DB wraps a SQLite connection and owns schema migrations.
type DB struct {
	conn *sql.DB
}

// ScanStateRow is one row from the scan_state table.
type ScanStateRow struct {
	ProjectID     string
	FilePath      string
	ContentHash   string
	LastScannedAt int64
}

// SuppressionRow is one row from the suppressions table.
type SuppressionRow struct {
	ProjectID    string
	FindingID    string
	Reason       string
	SuppressedAt int64
}

// Open opens or creates the SQLite database at path, enforces 0600 permissions,
// applies connection-level PRAGMAs for safety and performance, and runs any
// pending schema migrations.
func Open(path string) (*DB, error) {
	if err := ensureFile(path); err != nil {
		return nil, err
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", path, err)
	}

	// Single writer; multiple readers via WAL — set max open connections to 1
	// for the write connection so we never get SQLITE_BUSY on WAL checkpoint.
	conn.SetMaxOpenConns(1)

	db := &DB{conn: conn}
	if err := db.applyPragmas(); err != nil {
		conn.Close() //nolint:errcheck
		return nil, err
	}
	if err := db.migrate(); err != nil {
		conn.Close() //nolint:errcheck
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}
	return db, nil
}

// Conn exposes the underlying *sql.DB for callers that need raw query access.
// Prefer the typed helpers where possible.
func (db *DB) Conn() *sql.DB { return db.conn }

// Close releases the database connection. WAL checkpoint runs on close.
func (db *DB) Close() error { return db.conn.Close() }

// ─── scan_state helpers ──────────────────────────────────────────────────────

// GetScanState returns the cached state row for (projectID, filePath).
// Returns sql.ErrNoRows if no prior scan entry exists for the file.
func (db *DB) GetScanState(ctx context.Context, projectID, filePath string) (*ScanStateRow, error) {
	row := &ScanStateRow{}
	err := db.conn.QueryRowContext(
		ctx,
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
func (db *DB) UpsertScanState(ctx context.Context, row ScanStateRow) error {
	_, err := db.conn.ExecContext(
		ctx,
		`INSERT OR REPLACE INTO scan_state (project_id, file_path, content_hash, last_scanned_at)
		 VALUES (?, ?, ?, ?)`,
		row.ProjectID, row.FilePath, row.ContentHash, row.LastScannedAt,
	)
	return err
}

// ListScanState returns all cached state rows for the given projectID.
func (db *DB) ListScanState(ctx context.Context, projectID string) ([]ScanStateRow, error) {
	rows, err := db.conn.QueryContext(
		ctx,
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
func (db *DB) DeleteScanState(ctx context.Context, projectID, filePath string) error {
	_, err := db.conn.ExecContext(
		ctx,
		`DELETE FROM scan_state WHERE project_id = ? AND file_path = ?`,
		projectID, filePath,
	)
	return err
}

// ─── suppressions helpers ────────────────────────────────────────────────────

// IsSuppressed reports whether findingID is in the suppressions table for projectID.
func (db *DB) IsSuppressed(ctx context.Context, projectID, findingID string) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM suppressions WHERE project_id = ? AND finding_id = ?`,
		projectID, findingID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("sqlite: IsSuppressed: %w", err)
	}
	return count > 0, nil
}

// AddSuppression records a new suppression decision. Idempotent.
func (db *DB) AddSuppression(ctx context.Context, row SuppressionRow) error {
	if row.SuppressedAt == 0 {
		row.SuppressedAt = time.Now().Unix()
	}
	_, err := db.conn.ExecContext(
		ctx,
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
func (db *DB) ListSuppressions(ctx context.Context, projectID string) ([]SuppressionRow, error) {
	rows, err := db.conn.QueryContext(
		ctx,
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

// ─── internal ────────────────────────────────────────────────────────────────

// ensureFile creates the database file with mode 0600 if it does not exist,
// then enforces 0600 on any existing file. This must be called before sql.Open
// so the driver does not create the file with the process umask.
func ensureFile(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("sqlite: create db file: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("sqlite: close db file: %w", err)
		}
	}
	// Enforce 0600 on existing files too — catches files created by older versions.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("sqlite: chmod db file: %w", err)
	}
	return nil
}

// applyPragmas sets per-connection SQLite settings for performance and safety.
func (db *DB) applyPragmas() error {
	ctx := context.Background()
	pragmas := []string{
		"PRAGMA journal_mode=WAL",   // concurrent reads during writes
		"PRAGMA foreign_keys=ON",    // referential integrity
		"PRAGMA busy_timeout=5000",  // 5 s retry on lock instead of SQLITE_BUSY
		"PRAGMA synchronous=NORMAL", // safe with WAL; faster than FULL
		"PRAGMA temp_store=MEMORY",  // temp tables in RAM
	}
	for _, p := range pragmas {
		if _, err := db.conn.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("sqlite pragma %q: %w", p, err)
		}
	}
	return nil
}

// migrate runs any schema migrations that have not yet been applied.
// Each migration is wrapped in a transaction. The schema version is tracked
// via SQLite's built-in user_version PRAGMA.
func (db *DB) migrate() error {
	var ver int
	if err := db.conn.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for ver < currentSchemaVersion {
		ver++
		if err := db.runMigration(ver); err != nil {
			return fmt.Errorf("migration %d: %w", ver, err)
		}
	}
	return nil
}

func (db *DB) runMigration(ver int) error {
	ctx := context.Background()
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	switch ver {
	case 1:
		err = migration1(ctx, tx)
	case 2:
		err = migration2(ctx, tx)
	case 3:
		err = migration3(ctx, tx)
	default:
		return fmt.Errorf("unknown migration version %d", ver)
	}
	if err != nil {
		return err
	}

	// user_version must be set outside the transaction in some SQLite builds;
	// set it inside and then commit — this is safe with modernc.org/sqlite.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", ver)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}

func migration1(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
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

func migration2(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS projects (
			project_id       TEXT    PRIMARY KEY,
			root_path        TEXT    NOT NULL UNIQUE,
			primary_language TEXT,
			first_seen_at    INTEGER NOT NULL,
			last_scanned_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS scan_runs (
			run_id          TEXT    PRIMARY KEY,
			project_id      TEXT    NOT NULL REFERENCES projects(project_id),
			started_at      INTEGER NOT NULL,
			finished_at     INTEGER,
			scan_mode       TEXT    NOT NULL DEFAULT 'default',
			files_scanned   INTEGER NOT NULL DEFAULT 0,
			findings_total  INTEGER NOT NULL DEFAULT 0,
			status          TEXT    NOT NULL DEFAULT 'running'
		);
		CREATE INDEX IF NOT EXISTS idx_scan_runs_project
			ON scan_runs (project_id, started_at DESC);

		CREATE TABLE IF NOT EXISTS findings (
			finding_id      TEXT    PRIMARY KEY,
			project_id      TEXT    NOT NULL REFERENCES projects(project_id),
			run_id          TEXT    NOT NULL REFERENCES scan_runs(run_id),
			file_path       TEXT    NOT NULL,
			line_start      INTEGER NOT NULL,
			line_end        INTEGER NOT NULL,
			cwe             TEXT,
			severity        TEXT    NOT NULL,
			confidence      REAL    NOT NULL,
			source_path     TEXT    NOT NULL,
			rule_id         TEXT,
			matched_code    TEXT,
			justification   TEXT,
			suppress_reason TEXT,
			first_seen_at   INTEGER NOT NULL,
			last_seen_at    INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_findings_project_sev
			ON findings (project_id, severity);
		CREATE INDEX IF NOT EXISTS idx_findings_first_seen
			ON findings (project_id, first_seen_at DESC);

		CREATE TABLE IF NOT EXISTS ssvc_scores (
			finding_id       TEXT PRIMARY KEY REFERENCES findings(finding_id),
			exploitation     TEXT,
			automatable      TEXT,
			technical_impact TEXT
		);

		CREATE TABLE IF NOT EXISTS poe_results (
			finding_id           TEXT PRIMARY KEY REFERENCES findings(finding_id),
			status               TEXT,
			confidence           REAL,
			business_impact_tier TEXT,
			exec_summary         TEXT
		);

		CREATE TABLE IF NOT EXISTS cpg_cache (
			project_id        TEXT    PRIMARY KEY REFERENCES projects(project_id),
			cpg_path          TEXT    NOT NULL,
			scope_mode        TEXT    NOT NULL,
			built_at          INTEGER NOT NULL,
			changed_functions INTEGER NOT NULL DEFAULT 0
		);
	`)
	return err
}

func migration3(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range []string{
		`ALTER TABLE findings ADD COLUMN patch TEXT`,
		`ALTER TABLE findings ADD COLUMN patch_status TEXT`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			// SQLite returns "duplicate column name" when the column already exists;
			// treat that as a no-op so re-running the migration is safe.
			if !isDuplicateColumn(err) {
				return err
			}
		}
	}
	return nil
}

// isDuplicateColumn reports whether err is a SQLite "duplicate column name" error.
func isDuplicateColumn(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "duplicate column name") ||
		strings.Contains(err.Error(), "already exists"))
}
