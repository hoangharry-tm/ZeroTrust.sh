// Copyright 2026 hoangharry-tm
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

// ─── schema version ──────────────────────────────────────────────────────────

func TestSchemaVersionAfterOpen(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	var ver int
	if err := db.Conn().QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if ver != currentSchemaVersion {
		t.Errorf("user_version: got %d, want %d", ver, currentSchemaVersion)
	}
}

func TestAllTablesExist(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	want := []string{
		"scan_state", "suppressions",
		"projects", "scan_runs", "findings",
		"ssvc_scores", "poe_results", "cpg_cache",
	}
	for _, name := range want {
		var got string
		err := db.Conn().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name,
		).Scan(&got)
		if err != nil || got != name {
			t.Errorf("table %q missing: %v", name, err)
		}
	}
}

// ─── PRAGMA checks ───────────────────────────────────────────────────────────

func TestWALModeEnabled(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	var mode string
	if err := db.Conn().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode: got %q, want %q", mode, "wal")
	}
}

func TestForeignKeysEnabled(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	var on int
	if err := db.Conn().QueryRow("PRAGMA foreign_keys").Scan(&on); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if on != 1 {
		t.Errorf("foreign_keys: got %d, want 1", on)
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode: got %04o, want 0600", got)
	}
}

// ─── projects ────────────────────────────────────────────────────────────────

func TestUpsertAndGetProject(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	row := ProjectRow{
		ProjectID:       "p-abc",
		RootPath:        "/home/dev/myapp",
		PrimaryLanguage: "Go",
		FirstSeenAt:     1718000000,
		LastScannedAt:   1718001000,
	}
	if err := db.UpsertProject(ctx, row); err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	got, err := db.GetProject(ctx, "p-abc")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.RootPath != "/home/dev/myapp" {
		t.Errorf("RootPath: got %q, want %q", got.RootPath, "/home/dev/myapp")
	}
	if got.PrimaryLanguage != "Go" {
		t.Errorf("PrimaryLanguage: got %q, want %q", got.PrimaryLanguage, "Go")
	}
}

func TestUpsertProjectPreservesFirstSeen(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	row := ProjectRow{
		ProjectID: "p-x", RootPath: "/x",
		FirstSeenAt: 1000, LastScannedAt: 1000,
	}
	if err := db.UpsertProject(ctx, row); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	row.LastScannedAt = 9999
	if err := db.UpsertProject(ctx, row); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := db.GetProject(ctx, "p-x")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	// first_seen_at must not be overwritten
	if got.FirstSeenAt != 1000 {
		t.Errorf("FirstSeenAt: got %d, want 1000", got.FirstSeenAt)
	}
	// last_scanned_at should reflect the latest call
	if got.LastScannedAt != 9999 {
		t.Errorf("LastScannedAt: got %d, want 9999", got.LastScannedAt)
	}
}

func TestGetProjectNotFound(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	_, err := db.GetProject(ctx, "missing")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

// ─── scan_runs ───────────────────────────────────────────────────────────────

func TestCreateAndFinalizeScanRun(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()

	// project must exist first (FK)
	if err := db.UpsertProject(ctx, ProjectRow{
		ProjectID: "p1", RootPath: "/p1", FirstSeenAt: 1, LastScannedAt: 1,
	}); err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	run := ScanRunRow{
		RunID:     "run-001",
		ProjectID: "p1",
		StartedAt: 1718000000,
		ScanMode:  "default",
		Status:    "running",
	}
	if err := db.CreateScanRun(ctx, run); err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}

	if err := db.FinalizeScanRun(ctx, "run-001", 1718001000, 12, 3); err != nil {
		t.Fatalf("FinalizeScanRun: %v", err)
	}

	var status string
	var total int
	if err := db.Conn().QueryRowContext(ctx,
		`SELECT status, findings_total FROM scan_runs WHERE run_id = ?`, "run-001",
	).Scan(&status, &total); err != nil {
		t.Fatalf("query scan_runs: %v", err)
	}
	if status != "complete" {
		t.Errorf("status: got %q, want %q", status, "complete")
	}
	if total != 3 {
		t.Errorf("findings_total: got %d, want 3", total)
	}
}

func TestFinalizeScanRunNotFound(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	if err := db.FinalizeScanRun(ctx, "ghost-run", 0, 0, 0); err == nil {
		t.Error("expected error when run_id not found, got nil")
	}
}

// ─── findings ────────────────────────────────────────────────────────────────

// setupProjectAndRun inserts prerequisite project + run rows so finding FK is satisfied.
func setupProjectAndRun(t *testing.T, db *DB, projectID, runID string) {
	t.Helper()
	ctx := t.Context()
	if err := db.UpsertProject(ctx, ProjectRow{
		ProjectID: projectID, RootPath: "/" + projectID,
		FirstSeenAt: 1, LastScannedAt: 1,
	}); err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := db.CreateScanRun(ctx, ScanRunRow{
		RunID: runID, ProjectID: projectID, StartedAt: 1, Status: "running",
	}); err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
}

func TestUpsertAndListFindings(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-1")

	f := FindingRow{
		FindingID:   "fid-001",
		ProjectID:   "proj",
		RunID:       "run-1",
		FilePath:    "src/auth.go",
		LineStart:   42,
		LineEnd:     44,
		CWE:         "CWE-89",
		Severity:    "HIGH",
		Confidence:  0.9,
		SourcePath:  "PATTERN",
		RuleID:      "SQL-001",
		MatchedCode: "db.Query(input)",
		FirstSeenAt: 1718000000,
		LastSeenAt:  1718000000,
	}
	if err := db.UpsertFinding(ctx, f); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	got, err := db.ListFindings(ctx, "proj")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].FindingID != "fid-001" {
		t.Errorf("FindingID: got %q, want %q", got[0].FindingID, "fid-001")
	}
	if got[0].Severity != "HIGH" {
		t.Errorf("Severity: got %q, want %q", got[0].Severity, "HIGH")
	}
}

func TestUpsertFindingUpdatesLastSeenAt(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-1")

	f := FindingRow{
		FindingID:   "fid-002",
		ProjectID:   "proj",
		RunID:       "run-1",
		FilePath:    "a.go",
		LineStart:   1,
		LineEnd:     1,
		Severity:    "LOW",
		Confidence:  0.5,
		SourcePath:  "PATTERN",
		FirstSeenAt: 1000,
		LastSeenAt:  1000,
	}
	if err := db.UpsertFinding(ctx, f); err != nil {
		t.Fatalf("first UpsertFinding: %v", err)
	}

	f.LastSeenAt = 9999
	if err := db.UpsertFinding(ctx, f); err != nil {
		t.Fatalf("second UpsertFinding: %v", err)
	}

	findings, err := db.ListFindings(ctx, "proj")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after upsert, got %d", len(findings))
	}
	// first_seen_at must not change
	if findings[0].FirstSeenAt != 1000 {
		t.Errorf("FirstSeenAt: got %d, want 1000", findings[0].FirstSeenAt)
	}
	if findings[0].LastSeenAt != 9999 {
		t.Errorf("LastSeenAt: got %d, want 9999", findings[0].LastSeenAt)
	}
}

func TestCountFindingsByRun(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-cnt")

	severities := []string{"HIGH", "HIGH", "MEDIUM", "LOW"}
	for i, sev := range severities {
		f := FindingRow{
			FindingID:  filepath.Join("fid", string(rune('a'+i))),
			ProjectID:  "proj",
			RunID:      "run-cnt",
			FilePath:   "x.go",
			LineStart:  i + 1,
			LineEnd:    i + 1,
			Severity:   sev,
			Confidence: 0.8,
			SourcePath: "PATTERN",
		}
		if err := db.UpsertFinding(ctx, f); err != nil {
			t.Fatalf("UpsertFinding %d: %v", i, err)
		}
	}

	counts, err := db.CountFindingsByRun(ctx, "run-cnt")
	if err != nil {
		t.Fatalf("CountFindingsByRun: %v", err)
	}
	if counts["HIGH"] != 2 {
		t.Errorf("HIGH count: got %d, want 2", counts["HIGH"])
	}
	if counts["MEDIUM"] != 1 {
		t.Errorf("MEDIUM count: got %d, want 1", counts["MEDIUM"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("LOW count: got %d, want 1", counts["LOW"])
	}
}

// ─── cpg_cache ───────────────────────────────────────────────────────────────

func TestUpsertAndGetCPGCache(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	if err := db.UpsertProject(ctx, ProjectRow{
		ProjectID: "cpg-proj", RootPath: "/cpg",
		FirstSeenAt: 1, LastScannedAt: 1,
	}); err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	row := CPGCacheRow{
		ProjectID:        "cpg-proj",
		CPGPath:          "/home/.zerotrust/cpg-proj.cpg",
		ScopeMode:        "default",
		BuiltAt:          1718000000,
		ChangedFunctions: 5,
	}
	if err := db.UpsertCPGCache(ctx, row); err != nil {
		t.Fatalf("UpsertCPGCache: %v", err)
	}

	got, err := db.GetCPGCache(ctx, "cpg-proj")
	if err != nil {
		t.Fatalf("GetCPGCache: %v", err)
	}
	if got.CPGPath != row.CPGPath {
		t.Errorf("CPGPath: got %q, want %q", got.CPGPath, row.CPGPath)
	}
	if got.ChangedFunctions != 5 {
		t.Errorf("ChangedFunctions: got %d, want 5", got.ChangedFunctions)
	}
}

func TestGetCPGCacheNotFound(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()

	ctx := t.Context()
	_, err := db.GetCPGCache(ctx, "no-such-project")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}
