// Package sqlite wraps a SQLite database connection for the ZeroTrust.sh state cache.
// Uses modernc.org/sqlite (pure-Go, no CGo dependency).
package sqlite

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// DB wraps a SQLite connection and owns the schema migration.
type DB struct {
	conn *sql.DB
}

// Open opens or creates the SQLite database at path, running migrations if needed.
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
func (db *DB) Conn() *sql.DB { return db.conn }

// Close releases the database connection.
func (db *DB) Close() error { return db.conn.Close() }

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
			project_id  TEXT NOT NULL,
			finding_id  TEXT NOT NULL,
			reason      TEXT NOT NULL,
			suppressed_at INTEGER NOT NULL,
			PRIMARY KEY (project_id, finding_id)
		);
	`)
	return err
}
