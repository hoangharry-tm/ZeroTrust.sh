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

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ProjectRow is one row from the projects table.
type ProjectRow struct {
	ProjectID       string
	RootPath        string
	PrimaryLanguage string
	FirstSeenAt     int64
	LastScannedAt   int64
}

// ScanRunRow is one row from the scan_runs table.
type ScanRunRow struct {
	RunID         string
	ProjectID     string
	StartedAt     int64
	FinishedAt    int64 // 0 = still running
	ScanMode      string
	FilesScanned  int
	FindingsTotal int
	Status        string // "running" | "complete" | "error"
}

// FindingRow is one row from the findings table.
type FindingRow struct {
	FindingID      string
	ProjectID      string
	RunID          string
	FilePath       string
	LineStart      int
	LineEnd        int
	CWE            string
	Severity       string
	Confidence     float64
	SourcePath     string
	RuleID         string
	MatchedCode    string
	Justification  string
	SuppressReason string
	Patch          string
	PatchStatus    string
	FirstSeenAt    int64
	LastSeenAt     int64
}

// CPGCacheRow is one row from the cpg_cache table.
type CPGCacheRow struct {
	ProjectID        string
	CPGPath          string
	ScopeMode        string
	BuiltAt          int64
	ChangedFunctions int
}

// ─── projects ────────────────────────────────────────────────────────────────

// UpsertProject inserts or updates a project row.
// If the project already exists, only last_scanned_at and primary_language are updated.
// If the root_path is already registered under a different project_id (e.g. after a
// state-database reset changed the derived hash), the existing project_id is adopted
// so callers can create scan_runs with a consistent FK reference.
// Returns the effective project_id (possibly reconciled from an existing row).
func (db *DB) UpsertProject(ctx context.Context, row ProjectRow) (string, error) {
	now := time.Now().Unix()
	if row.FirstSeenAt == 0 {
		row.FirstSeenAt = now
	}
	if row.LastScannedAt == 0 {
		row.LastScannedAt = now
	}

	// Reconcile project_id when the root_path is already known. This avoids
	// UNIQUE constraint violations on root_path when DeriveProjectID produces a
	// different hash than the one stored from a prior scan.
	existing, err := db.getProjectByRootPath(ctx, row.RootPath)
	if err == nil && existing != nil {
		row.ProjectID = existing.ProjectID
		row.FirstSeenAt = existing.FirstSeenAt
	}

	_, err = db.writer.ExecContext(ctx, `
		INSERT INTO projects (project_id, root_path, primary_language, first_seen_at, last_scanned_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(project_id) DO UPDATE SET
			primary_language = excluded.primary_language,
			last_scanned_at  = excluded.last_scanned_at`,
		row.ProjectID, row.RootPath, row.PrimaryLanguage, row.FirstSeenAt, row.LastScannedAt,
	)
	if err != nil {
		return "", fmt.Errorf("sqlite: UpsertProject: %w", err)
	}
	return row.ProjectID, nil
}

// getProjectByRootPath returns the project row for the given root path, or nil
// if no project has been registered for that path.
func (db *DB) getProjectByRootPath(ctx context.Context, rootPath string) (*ProjectRow, error) {
	row := &ProjectRow{}
	err := db.reader.QueryRowContext(ctx, `
		SELECT project_id, root_path, primary_language, first_seen_at, last_scanned_at
		FROM projects WHERE root_path = ?`, rootPath,
	).Scan(&row.ProjectID, &row.RootPath, &row.PrimaryLanguage, &row.FirstSeenAt, &row.LastScannedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetProject returns the project row for projectID, or sql.ErrNoRows if absent.
func (db *DB) GetProject(ctx context.Context, projectID string) (*ProjectRow, error) {
	row := &ProjectRow{}
	err := db.reader.QueryRowContext(ctx, `
		SELECT project_id, root_path, primary_language, first_seen_at, last_scanned_at
		FROM projects WHERE project_id = ?`, projectID,
	).Scan(&row.ProjectID, &row.RootPath, &row.PrimaryLanguage, &row.FirstSeenAt, &row.LastScannedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// ─── scan_runs ───────────────────────────────────────────────────────────────

// CreateScanRun inserts a new scan_run row with status="running".
func (db *DB) CreateScanRun(ctx context.Context, row ScanRunRow) error {
	if row.StartedAt == 0 {
		row.StartedAt = time.Now().Unix()
	}
	if row.Status == "" {
		row.Status = "running"
	}
	if row.ScanMode == "" {
		row.ScanMode = "default"
	}
	_, err := db.writer.ExecContext(ctx, `
		INSERT INTO scan_runs (run_id, project_id, started_at, finished_at, scan_mode, files_scanned, findings_total, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.RunID, row.ProjectID, row.StartedAt, nullableInt64(row.FinishedAt),
		row.ScanMode, row.FilesScanned, row.FindingsTotal, row.Status,
	)
	if err != nil {
		return fmt.Errorf("sqlite: CreateScanRun: %w", err)
	}
	return nil
}

// FinalizeScanRun marks a scan run complete and records the final counts.
func (db *DB) FinalizeScanRun(ctx context.Context, runID string, finishedAt int64, filesScanned, findingsTotal int) error {
	if finishedAt == 0 {
		finishedAt = time.Now().Unix()
	}
	res, err := db.writer.ExecContext(ctx, `
		UPDATE scan_runs
		SET finished_at = ?, files_scanned = ?, findings_total = ?, status = 'complete'
		WHERE run_id = ?`,
		finishedAt, filesScanned, findingsTotal, runID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: FinalizeScanRun: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("sqlite: FinalizeScanRun: run %q not found", runID)
	}
	return nil
}

// ─── findings ────────────────────────────────────────────────────────────────

// ListFindingIDs returns all finding_id values for a project.
// This is a lightweight query that only fetches the primary key column,
// suitable for cross-scan dedup where only existence checks are needed.
// Deprecated: prefer WalkFindingIDs to avoid unbounded slice accumulation.
func (db *DB) ListFindingIDs(ctx context.Context, projectID string) ([]string, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT finding_id FROM findings WHERE project_id = ?`, projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListFindingIDs: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("sqlite: ListFindingIDs scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: ListFindingIDs: %w", err)
	}
	return ids, nil
}

// WalkFindingIDs streams every finding_id for projectID through fn, one at a time.
// Returns the first error from fn or a query error. Use in dedup to avoid loading
// all IDs into a single slice.
func (db *DB) WalkFindingIDs(ctx context.Context, projectID string, fn func(id string) error) error {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT finding_id FROM findings WHERE project_id = ?`, projectID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: WalkFindingIDs: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("sqlite: WalkFindingIDs scan: %w", err)
		}
		if err := fn(id); err != nil {
			return err
		}
	}
	return rows.Err()
}

// UpsertFinding inserts a new finding or updates an existing one.
// On conflict (same finding_id), run_id, severity, confidence, justification, suppress_reason,
// and last_seen_at are updated; first_seen_at is preserved.
func (db *DB) UpsertFinding(ctx context.Context, row FindingRow) error {
	now := time.Now().Unix()
	if row.FirstSeenAt == 0 {
		row.FirstSeenAt = now
	}
	if row.LastSeenAt == 0 {
		row.LastSeenAt = now
	}
	_, err := db.writer.ExecContext(ctx, `
		INSERT INTO findings
			(finding_id, project_id, run_id, file_path, line_start, line_end,
			 cwe, severity, confidence, source_path, rule_id, matched_code,
			 justification, suppress_reason, patch, patch_status, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(finding_id) DO UPDATE SET
			run_id          = excluded.run_id,
			severity        = excluded.severity,
			confidence      = excluded.confidence,
			justification   = excluded.justification,
			suppress_reason = excluded.suppress_reason,
			patch           = COALESCE(excluded.patch, findings.patch),
			patch_status    = COALESCE(excluded.patch_status, findings.patch_status),
			last_seen_at    = excluded.last_seen_at`,
		row.FindingID, row.ProjectID, row.RunID,
		row.FilePath, row.LineStart, row.LineEnd,
		nullableStr(row.CWE), row.Severity, row.Confidence,
		row.SourcePath, nullableStr(row.RuleID), nullableStr(row.MatchedCode),
		nullableStr(row.Justification), nullableStr(row.SuppressReason),
		nullableStr(row.Patch), nullableStr(row.PatchStatus),
		row.FirstSeenAt, row.LastSeenAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertFinding %s: %w", row.FindingID, err)
	}
	return nil
}

// scanFindingRow scans one FindingRow from rows.
func scanFindingRow(rows *sql.Rows) (FindingRow, error) {
	var r FindingRow
	return r, rows.Scan(
		&r.FindingID, &r.ProjectID, &r.RunID,
		&r.FilePath, &r.LineStart, &r.LineEnd,
		&r.CWE, &r.Severity, &r.Confidence, &r.SourcePath,
		&r.RuleID, &r.MatchedCode, &r.Justification, &r.SuppressReason,
		&r.Patch, &r.PatchStatus,
		&r.FirstSeenAt, &r.LastSeenAt,
	)
}

const findingCols = `finding_id, project_id, run_id, file_path, line_start, line_end,
		       COALESCE(cwe,''), severity, confidence, source_path,
		       COALESCE(rule_id,''), COALESCE(matched_code,''),
		       COALESCE(justification,''), COALESCE(suppress_reason,''),
		       COALESCE(patch,''), COALESCE(patch_status,''),
		       first_seen_at, last_seen_at`

// ListFindings returns all findings for projectID, newest first.
func (db *DB) ListFindings(ctx context.Context, projectID string) ([]FindingRow, error) {
	return queryRows(ctx, db.reader,
		"SELECT "+findingCols+" FROM findings WHERE project_id = ? ORDER BY first_seen_at DESC",
		[]any{projectID}, scanFindingRow,
	)
}

// GetFindingByID returns a single finding row for the given project_id and finding_id.
// Returns sql.ErrNoRows if no finding matches.
func (db *DB) GetFindingByID(ctx context.Context, projectID, findingID string) (*FindingRow, error) {
	row := &FindingRow{}
	err := db.reader.QueryRowContext(ctx, `
		SELECT finding_id, project_id, run_id, file_path, line_start, line_end,
		       COALESCE(cwe,''), severity, confidence, source_path,
		       COALESCE(rule_id,''), COALESCE(matched_code,''),
		       COALESCE(justification,''), COALESCE(suppress_reason,''),
		       COALESCE(patch,''), COALESCE(patch_status,''),
		       first_seen_at, last_seen_at
		FROM findings WHERE project_id = ? AND finding_id = ?`,
		projectID, findingID,
	).Scan(
		&row.FindingID, &row.ProjectID, &row.RunID,
		&row.FilePath, &row.LineStart, &row.LineEnd,
		&row.CWE, &row.Severity, &row.Confidence, &row.SourcePath,
		&row.RuleID, &row.MatchedCode, &row.Justification, &row.SuppressReason,
		&row.Patch, &row.PatchStatus,
		&row.FirstSeenAt, &row.LastSeenAt,
	)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetFindingsByProjectAndSeverity returns findings for a project filtered by severity.
// Uses the idx_findings_project_sev index for efficient lookups.
// This is the preferred method for cross-scan dedup — it avoids loading the
// entire findings table into memory.
func (db *DB) GetFindingsByProjectAndSeverity(ctx context.Context, projectID, severity string) ([]FindingRow, error) {
	return queryRows(ctx, db.reader,
		"SELECT "+findingCols+" FROM findings WHERE project_id = ? AND severity = ? ORDER BY first_seen_at DESC",
		[]any{projectID, severity}, scanFindingRow,
	)
}

// CountFindingsByRun returns a severity → count map for all findings in runID.
func (db *DB) CountFindingsByRun(ctx context.Context, runID string) (map[string]int, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE run_id = ? GROUP BY severity`,
		runID,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: CountFindingsByRun: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	counts := make(map[string]int)
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, fmt.Errorf("sqlite: CountFindingsByRun scan: %w", err)
		}
		counts[sev] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: CountFindingsByRun: %w", err)
	}
	return counts, nil
}

// ─── cpg_cache ───────────────────────────────────────────────────────────────

// UpsertCPGCache inserts or replaces the CPG cache row for a project.
func (db *DB) UpsertCPGCache(ctx context.Context, row CPGCacheRow) error {
	if row.BuiltAt == 0 {
		row.BuiltAt = time.Now().Unix()
	}
	_, err := db.writer.ExecContext(ctx, `
		INSERT INTO cpg_cache (project_id, cpg_path, scope_mode, built_at, changed_functions)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(project_id) DO UPDATE SET
			cpg_path          = excluded.cpg_path,
			scope_mode        = excluded.scope_mode,
			built_at          = excluded.built_at,
			changed_functions = excluded.changed_functions`,
		row.ProjectID, row.CPGPath, row.ScopeMode, row.BuiltAt, row.ChangedFunctions,
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpsertCPGCache: %w", err)
	}
	return nil
}

// GetCPGCache returns the CPG cache row for projectID, or sql.ErrNoRows if absent.
func (db *DB) GetCPGCache(ctx context.Context, projectID string) (*CPGCacheRow, error) {
	row := &CPGCacheRow{}
	err := db.reader.QueryRowContext(ctx, `
		SELECT project_id, cpg_path, scope_mode, built_at, changed_functions
		FROM cpg_cache WHERE project_id = ?`, projectID,
	).Scan(&row.ProjectID, &row.CPGPath, &row.ScopeMode, &row.BuiltAt, &row.ChangedFunctions)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCPGCache: %w", err)
	}
	return row, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// nullableStr converts an empty string to nil for optional TEXT columns.
func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableInt64 converts a zero int64 to nil for optional INTEGER columns.
func nullableInt64(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// UpdateFindingPatch stores the generated patch and its status for a finding.
// Called after patch generation so the result is cached for future curate runs.
func (db *DB) UpdateFindingPatch(ctx context.Context, findingID, patch, patchStatus string) error {
	_, err := db.writer.ExecContext(ctx,
		`UPDATE findings SET patch = ?, patch_status = ? WHERE finding_id = ?`,
		nullableStr(patch), nullableStr(patchStatus), findingID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateFindingPatch %s: %w", findingID, err)
	}
	return nil
}
