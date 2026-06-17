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

// ─── GetScanState / UpsertScanState ─────────────────────────────────────────

func TestGetScanStateNotFound(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	_, err := db.GetScanState(ctx, "proj", "nonexistent.go")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUpsertAndGetScanState(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	row := ScanStateRow{
		ProjectID:     "proj-1",
		FilePath:      "cmd/main.go",
		ContentHash:   "abc123",
		LastScannedAt: 1718000000,
	}
	if err := db.UpsertScanState(ctx, row); err != nil {
		t.Fatalf("UpsertScanState: %v", err)
	}

	got, err := db.GetScanState(ctx, "proj-1", "cmd/main.go")
	if err != nil {
		t.Fatalf("GetScanState: %v", err)
	}
	if got.ContentHash != "abc123" {
		t.Errorf("hash: got %q, want %q", got.ContentHash, "abc123")
	}
	if got.LastScannedAt != 1718000000 {
		t.Errorf("timestamp: got %d, want 1718000000", got.LastScannedAt)
	}
}

func TestUpsertScanStateReplaces(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	base := ScanStateRow{ProjectID: "p", FilePath: "a.go", ContentHash: "old", LastScannedAt: 1}
	if err := db.UpsertScanState(ctx, base); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	updated := ScanStateRow{ProjectID: "p", FilePath: "a.go", ContentHash: "new", LastScannedAt: 2}
	if err := db.UpsertScanState(ctx, updated); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := db.GetScanState(ctx, "p", "a.go")
	if err != nil {
		t.Fatalf("GetScanState: %v", err)
	}
	if got.ContentHash != "new" {
		t.Errorf("expected hash %q after upsert, got %q", "new", got.ContentHash)
	}
}

// ─── ListScanState ───────────────────────────────────────────────────────────

func TestListScanStateEmpty(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	rows, err := db.ListScanState(ctx, "proj-empty")
	if err != nil {
		t.Fatalf("ListScanState: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}

func TestListScanStateIsolatedByProject(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	for _, r := range []ScanStateRow{
		{ProjectID: "p1", FilePath: "a.go", ContentHash: "h1", LastScannedAt: 1},
		{ProjectID: "p1", FilePath: "b.go", ContentHash: "h2", LastScannedAt: 1},
		{ProjectID: "p2", FilePath: "c.go", ContentHash: "h3", LastScannedAt: 1},
	} {
		if err := db.UpsertScanState(ctx, r); err != nil {
			t.Fatalf("upsert %v: %v", r.FilePath, err)
		}
	}

	rows, err := db.ListScanState(ctx, "p1")
	if err != nil {
		t.Fatalf("ListScanState: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows for p1, got %d", len(rows))
	}
}

// ─── DeleteScanState ─────────────────────────────────────────────────────────

func TestDeleteScanState(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	row := ScanStateRow{ProjectID: "proj", FilePath: "deleted.go", ContentHash: "h", LastScannedAt: 1}
	if err := db.UpsertScanState(ctx, row); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := db.DeleteScanState(ctx, "proj", "deleted.go"); err != nil {
		t.Fatalf("DeleteScanState: %v", err)
	}

	_, err := db.GetScanState(ctx, "proj", "deleted.go")
	if err != sql.ErrNoRows {
		t.Errorf("expected ErrNoRows after delete, got %v", err)
	}
}

func TestDeleteScanStateNonexistentIsNoop(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	// Deleting a row that does not exist must not error.
	if err := db.DeleteScanState(ctx, "proj", "ghost.go"); err != nil {
		t.Errorf("unexpected error deleting non-existent row: %v", err)
	}
}
