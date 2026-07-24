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

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
// If the root_path is already registered under a different project_id (e.g.
// after a state reset changed the derived hash), the existing project_id is
// adopted so callers can create scan_runs with a consistent FK reference.
// Returns the effective project_id (possibly reconciled from an existing row).
func (db *DB) UpsertProject(ctx context.Context, row ProjectRow) (string, error) {
	now := time.Now().Unix()
	if row.FirstSeenAt == 0 {
		row.FirstSeenAt = now
	}
	if row.LastScannedAt == 0 {
		row.LastScannedAt = now
	}

	existing, err := db.getProjectByRootPath(ctx, row.RootPath)
	if err == nil && existing != nil {
		row.ProjectID = existing.ProjectID
		row.FirstSeenAt = existing.FirstSeenAt
	}

	m := projectModel{
		ProjectID: row.ProjectID, RootPath: row.RootPath, PrimaryLanguage: row.PrimaryLanguage,
		FirstSeenAt: row.FirstSeenAt, LastScannedAt: row.LastScannedAt,
	}
	err = db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"primary_language", "last_scanned_at"}),
	}).Create(&m).Error
	if err != nil {
		return "", fmt.Errorf("postgres: UpsertProject: %w", err)
	}
	return row.ProjectID, nil
}

// getProjectByRootPath returns the project row for the given root path, or
// nil if no project has been registered for that path.
func (db *DB) getProjectByRootPath(ctx context.Context, rootPath string) (*ProjectRow, error) {
	var m projectModel
	err := db.gorm.WithContext(ctx).Where("root_path = ?", rootPath).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return projectRowFromModel(m), nil
}

// GetProject returns the project row for projectID, or gorm.ErrRecordNotFound if absent.
func (db *DB) GetProject(ctx context.Context, projectID string) (*ProjectRow, error) {
	var m projectModel
	if err := db.gorm.WithContext(ctx).Where("project_id = ?", projectID).First(&m).Error; err != nil {
		return nil, err
	}
	return projectRowFromModel(m), nil
}

func projectRowFromModel(m projectModel) *ProjectRow {
	return &ProjectRow{
		ProjectID: m.ProjectID, RootPath: m.RootPath, PrimaryLanguage: m.PrimaryLanguage,
		FirstSeenAt: m.FirstSeenAt, LastScannedAt: m.LastScannedAt,
	}
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
	m := scanRunModel{
		RunID: row.RunID, ProjectID: row.ProjectID, StartedAt: row.StartedAt, FinishedAt: row.FinishedAt,
		ScanMode: row.ScanMode, FilesScanned: row.FilesScanned, FindingsTotal: row.FindingsTotal, Status: row.Status,
	}
	if err := db.gorm.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("postgres: CreateScanRun: %w", err)
	}
	return nil
}

// FinalizeScanRun marks a scan run complete and records the final counts.
func (db *DB) FinalizeScanRun(ctx context.Context, runID string, finishedAt int64, filesScanned, findingsTotal int) error {
	if finishedAt == 0 {
		finishedAt = time.Now().Unix()
	}
	res := db.gorm.WithContext(ctx).Model(&scanRunModel{}).Where("run_id = ?", runID).Updates(map[string]any{
		"finished_at":    finishedAt,
		"files_scanned":  filesScanned,
		"findings_total": findingsTotal,
		"status":         "complete",
	})
	if res.Error != nil {
		return fmt.Errorf("postgres: FinalizeScanRun: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("postgres: FinalizeScanRun: run %q not found", runID)
	}
	return nil
}

// ─── findings ────────────────────────────────────────────────────────────────

// ListFindingIDs returns all finding_id values for a project.
//
// Deprecated: prefer WalkFindingIDs to avoid unbounded slice accumulation.
func (db *DB) ListFindingIDs(ctx context.Context, projectID string) ([]string, error) {
	var ids []string
	err := db.gorm.WithContext(ctx).Model(&findingModel{}).
		Where("project_id = ?", projectID).Pluck("finding_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: ListFindingIDs: %w", err)
	}
	return ids, nil
}

// WalkFindingIDs streams every finding_id for projectID through fn, one at a
// time. Returns the first error from fn or a query error.
func (db *DB) WalkFindingIDs(ctx context.Context, projectID string, fn func(id string) error) error {
	rows, err := db.gorm.WithContext(ctx).Model(&findingModel{}).
		Where("project_id = ?", projectID).Select("finding_id").Rows()
	if err != nil {
		return fmt.Errorf("postgres: WalkFindingIDs: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("postgres: WalkFindingIDs scan: %w", err)
		}
		if err := fn(id); err != nil {
			return err
		}
	}
	return rows.Err()
}

// FindingSnapshot is the subset of a persisted finding's fields that matter
// for deciding whether a re-scan's result for the same finding_id carries
// new information worth persisting.
type FindingSnapshot struct {
	Severity       string
	Confidence     float64
	SuppressReason string
}

// WalkFindingSnapshots streams every (finding_id, FindingSnapshot) pair for
// projectID through fn, one at a time. Returns the first error from fn or a
// query error.
func (db *DB) WalkFindingSnapshots(ctx context.Context, projectID string, fn func(id string, snap FindingSnapshot) error) error {
	rows, err := db.gorm.WithContext(ctx).Model(&findingModel{}).
		Where("project_id = ?", projectID).
		Select("finding_id", "severity", "confidence", "suppress_reason").Rows()
	if err != nil {
		return fmt.Errorf("postgres: WalkFindingSnapshots: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var id, severity, suppressReason string
		var confidence float64
		if err := rows.Scan(&id, &severity, &confidence, &suppressReason); err != nil {
			return fmt.Errorf("postgres: WalkFindingSnapshots scan: %w", err)
		}
		if err := fn(id, FindingSnapshot{Severity: severity, Confidence: confidence, SuppressReason: suppressReason}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// UpsertFinding inserts a new finding or updates an existing one. On conflict
// (same finding_id), run_id/severity/confidence/justification/suppress_reason
// and last_seen_at are updated; first_seen_at and non-empty patch fields are
// preserved (COALESCE semantics, matching the SQLite-era behavior).
func (db *DB) UpsertFinding(ctx context.Context, row FindingRow) error {
	now := time.Now().Unix()
	if row.FirstSeenAt == 0 {
		row.FirstSeenAt = now
	}
	if row.LastSeenAt == 0 {
		row.LastSeenAt = now
	}
	m := findingModel{
		FindingID: row.FindingID, ProjectID: row.ProjectID, RunID: row.RunID,
		FilePath: row.FilePath, LineStart: row.LineStart, LineEnd: row.LineEnd,
		CWE: row.CWE, Severity: row.Severity, Confidence: row.Confidence, SourcePath: row.SourcePath,
		RuleID: row.RuleID, MatchedCode: row.MatchedCode, Justification: row.Justification,
		SuppressReason: row.SuppressReason, Patch: row.Patch, PatchStatus: row.PatchStatus,
		FirstSeenAt: row.FirstSeenAt, LastSeenAt: row.LastSeenAt,
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "finding_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"run_id":          gorm.Expr("excluded.run_id"),
			"severity":        gorm.Expr("excluded.severity"),
			"confidence":      gorm.Expr("excluded.confidence"),
			"justification":   gorm.Expr("excluded.justification"),
			"suppress_reason": gorm.Expr("excluded.suppress_reason"),
			"patch":           gorm.Expr("COALESCE(excluded.patch, findings.patch)"),
			"patch_status":    gorm.Expr("COALESCE(excluded.patch_status, findings.patch_status)"),
			"last_seen_at":    gorm.Expr("excluded.last_seen_at"),
		}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: UpsertFinding %s: %w", row.FindingID, err)
	}
	return nil
}

func findingRowFromModel(m findingModel) FindingRow {
	return FindingRow{
		FindingID: m.FindingID, ProjectID: m.ProjectID, RunID: m.RunID,
		FilePath: m.FilePath, LineStart: m.LineStart, LineEnd: m.LineEnd,
		CWE: m.CWE, Severity: m.Severity, Confidence: m.Confidence, SourcePath: m.SourcePath,
		RuleID: m.RuleID, MatchedCode: m.MatchedCode, Justification: m.Justification,
		SuppressReason: m.SuppressReason, Patch: m.Patch, PatchStatus: m.PatchStatus,
		FirstSeenAt: m.FirstSeenAt, LastSeenAt: m.LastSeenAt,
	}
}

// ListFindings returns all findings for projectID, newest first.
func (db *DB) ListFindings(ctx context.Context, projectID string) ([]FindingRow, error) {
	var ms []findingModel
	err := db.gorm.WithContext(ctx).Where("project_id = ?", projectID).
		Order("first_seen_at DESC").Find(&ms).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: ListFindings: %w", err)
	}
	rows := make([]FindingRow, len(ms))
	for i, m := range ms {
		rows[i] = findingRowFromModel(m)
	}
	return rows, nil
}

// GetFindingByID returns a single finding row for the given project_id and
// finding_id. Returns gorm.ErrRecordNotFound if no finding matches.
func (db *DB) GetFindingByID(ctx context.Context, projectID, findingID string) (*FindingRow, error) {
	var m findingModel
	err := db.gorm.WithContext(ctx).
		Where("project_id = ? AND finding_id = ?", projectID, findingID).First(&m).Error
	if err != nil {
		return nil, err
	}
	row := findingRowFromModel(m)
	return &row, nil
}

// GetFindingsByProjectAndSeverity returns findings for a project filtered by
// severity, using the idx_findings_project_sev index.
func (db *DB) GetFindingsByProjectAndSeverity(ctx context.Context, projectID, severity string) ([]FindingRow, error) {
	var ms []findingModel
	err := db.gorm.WithContext(ctx).
		Where("project_id = ? AND severity = ?", projectID, severity).
		Order("first_seen_at DESC").Find(&ms).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: GetFindingsByProjectAndSeverity: %w", err)
	}
	rows := make([]FindingRow, len(ms))
	for i, m := range ms {
		rows[i] = findingRowFromModel(m)
	}
	return rows, nil
}

// CountFindingsByRun returns a severity → count map for all findings in runID.
func (db *DB) CountFindingsByRun(ctx context.Context, runID string) (map[string]int, error) {
	var results []struct {
		Severity string
		Count    int
	}
	err := db.gorm.WithContext(ctx).Model(&findingModel{}).
		Select("severity, COUNT(*) as count").
		Where("run_id = ?", runID).Group("severity").Scan(&results).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: CountFindingsByRun: %w", err)
	}
	counts := make(map[string]int, len(results))
	for _, r := range results {
		counts[r.Severity] = r.Count
	}
	return counts, nil
}

// UpdateFindingPatch stores the generated patch and its status for a finding.
func (db *DB) UpdateFindingPatch(ctx context.Context, findingID, patch, patchStatus string) error {
	err := db.gorm.WithContext(ctx).Model(&findingModel{}).Where("finding_id = ?", findingID).
		Updates(map[string]any{"patch": patch, "patch_status": patchStatus}).Error
	if err != nil {
		return fmt.Errorf("postgres: UpdateFindingPatch %s: %w", findingID, err)
	}
	return nil
}

// ─── cpg_cache ───────────────────────────────────────────────────────────────

// UpsertCPGCache inserts or replaces the CPG cache row for a project.
func (db *DB) UpsertCPGCache(ctx context.Context, row CPGCacheRow) error {
	if row.BuiltAt == 0 {
		row.BuiltAt = time.Now().Unix()
	}
	m := cpgCacheModel{
		ProjectID: row.ProjectID, CPGPath: row.CPGPath, ScopeMode: row.ScopeMode,
		BuiltAt: row.BuiltAt, ChangedFunctions: row.ChangedFunctions,
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"cpg_path", "scope_mode", "built_at", "changed_functions"}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: UpsertCPGCache: %w", err)
	}
	return nil
}

// GetCPGCache returns the CPG cache row for projectID, or gorm.ErrRecordNotFound if absent.
func (db *DB) GetCPGCache(ctx context.Context, projectID string) (*CPGCacheRow, error) {
	var m cpgCacheModel
	if err := db.gorm.WithContext(ctx).Where("project_id = ?", projectID).First(&m).Error; err != nil {
		return nil, err
	}
	return &CPGCacheRow{
		ProjectID: m.ProjectID, CPGPath: m.CPGPath, ScopeMode: m.ScopeMode,
		BuiltAt: m.BuiltAt, ChangedFunctions: m.ChangedFunctions,
	}, nil
}

// ─── ssvc_scores ─────────────────────────────────────────────────────────────

// SSVCScoreRow is one row from the ssvc_scores table.
type SSVCScoreRow struct {
	FindingID       string
	Exploitation    string // "Active" | "PoC" | "None"
	Automatable     string // "Yes" | "No"
	TechnicalImpact string // "Total" | "Partial"
}

// UpsertSSVCScore inserts or replaces the SSVC scoring dimensions for a finding.
func (db *DB) UpsertSSVCScore(ctx context.Context, row SSVCScoreRow) error {
	m := ssvcScoreModel{
		FindingID: row.FindingID, Exploitation: row.Exploitation,
		Automatable: row.Automatable, TechnicalImpact: row.TechnicalImpact,
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "finding_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"exploitation", "automatable", "technical_impact"}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: UpsertSSVCScore %s: %w", row.FindingID, err)
	}
	return nil
}

// ─── poe_results ─────────────────────────────────────────────────────────────

// PoEResultRow is one row from the poe_results table. Only the columns the
// original schema defined are persisted here — finding.PoEResult's more
// verbose ExploitInput/DevTrace fields stay in-memory/logs only.
type PoEResultRow struct {
	FindingID          string
	Status             string
	Confidence         float64
	BusinessImpactTier string
	ExecSummary        string
}

// UpsertPoEResult inserts or replaces the sandboxed PoC verification result for a finding.
func (db *DB) UpsertPoEResult(ctx context.Context, row PoEResultRow) error {
	m := poeResultModel{
		FindingID: row.FindingID, Status: row.Status,
		Confidence: row.Confidence, BusinessImpactTier: row.BusinessImpactTier, ExecSummary: row.ExecSummary,
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "finding_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "confidence", "business_impact_tier", "exec_summary"}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: UpsertPoEResult %s: %w", row.FindingID, err)
	}
	return nil
}
