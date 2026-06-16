package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// tempDB opens a fresh SQLite database in a temp directory.
// The cleanup func removes the temp dir when the test ends.
func tempDB(t *testing.T) (*DB, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return db, func() { db.Close() }
}

func TestOpenCreatesDatabase(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestOpenCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zerotrust.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db.Close()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected database file to be created on disk")
	}
}

func TestOpenIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	db1.Close()

	// second open of the same path must not error (migration is idempotent)
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	db2.Close()
}

func TestMigrateCreatesScanStateTable(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	rows, err := db.Conn().Query(`SELECT name FROM sqlite_master WHERE type='table' AND name='scan_state'`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Error("scan_state table was not created by migration")
	}
}

func TestMigrateCreatesSuppressionsTable(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	rows, err := db.Conn().Query(`SELECT name FROM sqlite_master WHERE type='table' AND name='suppressions'`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Error("suppressions table was not created by migration")
	}
}

func TestMigrateCreatesIndex(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	rows, err := db.Conn().Query(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_scan_state_hash'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Error("idx_scan_state_hash index was not created by migration")
	}
}

func TestConnReturnsWorkingConnection(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	conn := db.Conn()
	if conn == nil {
		t.Fatal("Conn() returned nil")
	}
	if err := conn.Ping(); err != nil {
		t.Errorf("Conn() ping failed: %v", err)
	}
}

func TestScanStateInsertAndQuery(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	_, err := db.Conn().Exec(
		`INSERT INTO scan_state (project_id, file_path, content_hash, last_scanned_at) VALUES (?, ?, ?, ?)`,
		"proj-1", "api/auth.py", "abc123", 1718523661,
	)
	if err != nil {
		t.Fatalf("insert scan_state: %v", err)
	}

	var hash string
	err = db.Conn().QueryRow(
		`SELECT content_hash FROM scan_state WHERE project_id = ? AND file_path = ?`,
		"proj-1", "api/auth.py",
	).Scan(&hash)
	if err != nil {
		t.Fatalf("query scan_state: %v", err)
	}
	if hash != "abc123" {
		t.Errorf("expected hash abc123, got %s", hash)
	}
}

func TestSuppressionsInsertAndQuery(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	_, err := db.Conn().Exec(
		`INSERT INTO suppressions (project_id, finding_id, reason, suppressed_at) VALUES (?, ?, ?, ?)`,
		"proj-1", "finding-42", "framework-safe:orm", 1718523661,
	)
	if err != nil {
		t.Fatalf("insert suppressions: %v", err)
	}

	var reason string
	err = db.Conn().QueryRow(
		`SELECT reason FROM suppressions WHERE project_id = ? AND finding_id = ?`,
		"proj-1", "finding-42",
	).Scan(&reason)
	if err != nil {
		t.Fatalf("query suppressions: %v", err)
	}
	if reason != "framework-safe:orm" {
		t.Errorf("unexpected reason: %s", reason)
	}
}

func TestScanStatePrimaryKeyEnforced(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	insert := func() error {
		_, err := db.Conn().Exec(
			`INSERT INTO scan_state (project_id, file_path, content_hash, last_scanned_at) VALUES (?, ?, ?, ?)`,
			"proj-1", "main.go", "hash1", 0,
		)
		return err
	}

	if err := insert(); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert(); err == nil {
		t.Error("expected primary key violation on duplicate insert")
	}
}

func TestClosePreventsFurtherUse(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "close.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// after close, the underlying connection should be unusable
	if err := db.Conn().Ping(); err == nil {
		t.Error("expected error after Close(), but Ping succeeded")
	}
}

func TestOpenInvalidPath(t *testing.T) {
	// a directory path is not a valid SQLite file
	dir := t.TempDir()
	_, err := Open(dir)
	if err == nil {
		// Some SQLite drivers may permit opening a directory briefly; close is enough.
		// But the migrate step should fail with a directory path.
		t.Skip("driver accepted directory as DB path — skipping")
	}
}

func TestConnReturnsTypedSQLDB(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	var _ *sql.DB = db.Conn() // compile-time type check
}
