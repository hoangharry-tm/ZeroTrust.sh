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

// Package sqlite provides the ZeroTrust.sh scan database.
//
// The database is ephemeral — created fresh per scan, not persisted between runs.
// All tables are created in a single applySchema call on Open. No version tracking.
//
// Files:
//
//	sqlite.go          — DB struct, Open, pragmas, schema DDL
//	sqlite_state.go    — scan_state, suppressions
//	sqlite_findings.go — projects, scan_runs, findings, ssvc_scores, poe_results, cpg_cache
//	sqlite_pipeline.go — work_items, pending_findings (sequential pipeline queue)
//	sqlite_cpg.go      — cpg_nodes, cpg_edges, cpg_builds, NodeCursor, EdgeCursor
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// DB holds a writer (single connection) and a reader pool (8 connections).
// WAL mode allows concurrent reads alongside the single writer.
type DB struct {
	writer *sql.DB
	reader *sql.DB
}

// queryRows executes q on db, scans each row with scan, and returns the results.
// It is a generic helper that eliminates the rows.Next/Scan/Close boilerplate.
func queryRows[T any](ctx context.Context, db *sql.DB, q string, args []any, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Open creates or opens the SQLite database at path with 0600 permissions,
// applies performance PRAGMAs, and creates all tables in one shot.
func Open(path string) (*DB, error) {
	if err := ensureFile(path); err != nil {
		return nil, err
	}

	writer, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open writer %s: %w", path, err)
	}
	writer.SetMaxOpenConns(1) // single writer; WAL allows concurrent readers

	reader, err := sql.Open("sqlite", path)
	if err != nil {
		writer.Close() //nolint:errcheck
		return nil, fmt.Errorf("sqlite open reader %s: %w", path, err)
	}
	reader.SetMaxOpenConns(8) // concurrent reads; WAL handles isolation

	db := &DB{writer: writer, reader: reader}
	if err := db.applyPragmas(); err != nil {
		writer.Close() //nolint:errcheck
		reader.Close() //nolint:errcheck
		return nil, err
	}
	if err := db.applySchema(); err != nil {
		writer.Close() //nolint:errcheck
		reader.Close() //nolint:errcheck
		return nil, fmt.Errorf("sqlite schema: %w", err)
	}
	return db, nil
}

// Reader returns the shared read pool (MaxOpenConns=8, WAL concurrent reads).
func (db *DB) Reader() *sql.DB { return db.reader }

// Writer returns the single-writer connection (MaxOpenConns=1).
func (db *DB) Writer() *sql.DB { return db.writer }

// Close releases both connections. WAL checkpoint runs on writer close.
func (db *DB) Close() error {
	rerr := db.reader.Close()
	werr := db.writer.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

// ─── internal ────────────────────────────────────────────────────────────────

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
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("sqlite: chmod db file: %w", err)
	}
	return nil
}

func (db *DB) applyPragmas() error {
	ctx := context.Background()
	shared := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=30000",  // 30 s — enough for bulk CPG ingestion
		"PRAGMA synchronous=NORMAL",  // safe with WAL
		"PRAGMA temp_store=MEMORY",
		"PRAGMA cache_size=-131072",  // 128 MB page cache per connection
		"PRAGMA page_size=16384",     // 16 KB pages; no-op after first write
	}
	readerOnly := []string{
		"PRAGMA mmap_size=1073741824", // 1 GB mmap on reader pool only
	}
	for _, p := range shared {
		if _, err := db.writer.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("sqlite writer pragma %q: %w", p, err)
		}
		if _, err := db.reader.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("sqlite reader pragma %q: %w", p, err)
		}
	}
	for _, p := range readerOnly {
		if _, err := db.reader.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("sqlite reader pragma %q: %w", p, err)
		}
	}
	return nil
}

// applySchema creates all tables in a single transaction.
// Safe to call on an existing file — all statements use CREATE TABLE IF NOT EXISTS.
func (db *DB) applySchema() error {
	ctx := context.Background()
	tx, err := db.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	return tx.Commit()
}

// schema is the complete DDL for all tables, applied once on Open.
const schema = `
-- ── scan state ───────────────────────────────────────────────────────────────
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

-- ── findings ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
	project_id       TEXT PRIMARY KEY,
	root_path        TEXT    NOT NULL UNIQUE,
	primary_language TEXT,
	first_seen_at    INTEGER NOT NULL,
	last_scanned_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
	run_id         TEXT PRIMARY KEY,
	project_id     TEXT    NOT NULL REFERENCES projects(project_id),
	started_at     INTEGER NOT NULL,
	finished_at    INTEGER,
	scan_mode      TEXT    NOT NULL DEFAULT 'default',
	files_scanned  INTEGER NOT NULL DEFAULT 0,
	findings_total INTEGER NOT NULL DEFAULT 0,
	status         TEXT    NOT NULL DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_project
	ON scan_runs (project_id, started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
	finding_id      TEXT PRIMARY KEY,
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
	patch           TEXT,
	patch_status    TEXT,
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
	project_id        TEXT PRIMARY KEY REFERENCES projects(project_id),
	cpg_path          TEXT    NOT NULL,
	scope_mode        TEXT    NOT NULL,
	built_at          INTEGER NOT NULL,
	changed_functions INTEGER NOT NULL DEFAULT 0
);

-- ── CPG graph store ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cpg_nodes (
	project_id  TEXT    NOT NULL,
	cpg_version TEXT    NOT NULL,
	node_id     TEXT    NOT NULL,
	node_type   TEXT    NOT NULL,
	name        TEXT    NOT NULL DEFAULT '',
	file        TEXT    NOT NULL DEFAULT '',
	line        INTEGER NOT NULL DEFAULT 0,
	code        TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY (project_id, cpg_version, node_id)
);
CREATE INDEX IF NOT EXISTS idx_cpn_type ON cpg_nodes (project_id, cpg_version, node_type);
CREATE INDEX IF NOT EXISTS idx_cpn_file ON cpg_nodes (project_id, cpg_version, file);

CREATE TABLE IF NOT EXISTS cpg_edges (
	project_id  TEXT NOT NULL,
	cpg_version TEXT NOT NULL,
	from_id     TEXT NOT NULL,
	to_id       TEXT NOT NULL,
	edge_type   TEXT NOT NULL DEFAULT 'CALL',
	PRIMARY KEY (project_id, cpg_version, from_id, to_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_cpe_from ON cpg_edges (project_id, cpg_version, from_id);
CREATE INDEX IF NOT EXISTS idx_cpe_to   ON cpg_edges (project_id, cpg_version, to_id);

CREATE TABLE IF NOT EXISTS cpg_builds (
	project_id   TEXT PRIMARY KEY,
	cpg_version  TEXT    NOT NULL,
	changed_hash TEXT    NOT NULL,
	node_count   INTEGER NOT NULL DEFAULT 0,
	edge_count   INTEGER NOT NULL DEFAULT 0,
	built_at     INTEGER NOT NULL
);

-- ── pipeline work queue ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS work_items (
	scan_id    TEXT    NOT NULL,
	component  TEXT    NOT NULL,
	surface_id TEXT    NOT NULL,
	status     TEXT    NOT NULL DEFAULT 'pending',
	payload    TEXT,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (scan_id, component, surface_id)
);
CREATE INDEX IF NOT EXISTS idx_work_pending
	ON work_items (scan_id, component, status);

CREATE TABLE IF NOT EXISTS pending_findings (
	scan_id    TEXT    NOT NULL,
	finding_id TEXT    NOT NULL,
	data       TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (scan_id, finding_id)
);
`
