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
	"fmt"
	"time"

	"gorm.io/gorm/clause"
)

// ─── scan_state ──────────────────────────────────────────────────────────────

// ScanStateRow is one row from the scan_state table.
type ScanStateRow struct {
	ProjectID     string
	FilePath      string
	ContentHash   string
	LastScannedAt int64
}

// GetScanState returns the cached state for (projectID, filePath).
// Returns gorm.ErrRecordNotFound if no entry exists.
func (db *DB) GetScanState(ctx context.Context, projectID, filePath string) (*ScanStateRow, error) {
	var m scanStateModel
	err := db.gorm.WithContext(ctx).
		Where("project_id = ? AND file_path = ?", projectID, filePath).First(&m).Error
	if err != nil {
		return nil, err
	}
	return &ScanStateRow{
		ProjectID: m.ProjectID, FilePath: m.FilePath,
		ContentHash: m.ContentHash, LastScannedAt: m.LastScannedAt,
	}, nil
}

// UpsertScanState inserts or replaces the scan state row for one file.
// Call per-file during the ingestion walk — do not accumulate slices.
func (db *DB) UpsertScanState(ctx context.Context, row ScanStateRow) error {
	m := scanStateModel{
		ProjectID: row.ProjectID, FilePath: row.FilePath,
		ContentHash: row.ContentHash, LastScannedAt: row.LastScannedAt,
	}
	return db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "file_path"}},
		DoUpdates: clause.AssignmentColumns([]string{"content_hash", "last_scanned_at"}),
	}).Create(&m).Error
}

// ListScanState returns all cached state rows for the given projectID.
func (db *DB) ListScanState(ctx context.Context, projectID string) ([]ScanStateRow, error) {
	var ms []scanStateModel
	if err := db.gorm.WithContext(ctx).Where("project_id = ?", projectID).Find(&ms).Error; err != nil {
		return nil, fmt.Errorf("postgres: ListScanState: %w", err)
	}
	rows := make([]ScanStateRow, len(ms))
	for i, m := range ms {
		rows[i] = ScanStateRow{
			ProjectID: m.ProjectID, FilePath: m.FilePath,
			ContentHash: m.ContentHash, LastScannedAt: m.LastScannedAt,
		}
	}
	return rows, nil
}

// DeleteScanState removes the state row for (projectID, filePath).
func (db *DB) DeleteScanState(ctx context.Context, projectID, filePath string) error {
	return db.gorm.WithContext(ctx).
		Where("project_id = ? AND file_path = ?", projectID, filePath).
		Delete(&scanStateModel{}).Error
}

// ─── suppressions ────────────────────────────────────────────────────────────

// SuppressionRow is one row from the suppressions table.
type SuppressionRow struct {
	ProjectID    string
	FindingID    string
	Reason       string
	SuppressedAt int64
}

// IsSuppressed reports whether findingID is suppressed for projectID.
func (db *DB) IsSuppressed(ctx context.Context, projectID, findingID string) (bool, error) {
	var count int64
	err := db.gorm.WithContext(ctx).Model(&suppressionModel{}).
		Where("project_id = ? AND finding_id = ?", projectID, findingID).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("postgres: IsSuppressed: %w", err)
	}
	return count > 0, nil
}

// AddSuppression records a suppression decision. Idempotent.
func (db *DB) AddSuppression(ctx context.Context, row SuppressionRow) error {
	if row.SuppressedAt == 0 {
		row.SuppressedAt = time.Now().Unix()
	}
	m := suppressionModel{
		ProjectID: row.ProjectID, FindingID: row.FindingID,
		Reason: row.Reason, SuppressedAt: row.SuppressedAt,
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "finding_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"reason", "suppressed_at"}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: AddSuppression: %w", err)
	}
	return nil
}

// ListSuppressions returns all suppression rows for the given projectID.
func (db *DB) ListSuppressions(ctx context.Context, projectID string) ([]SuppressionRow, error) {
	var ms []suppressionModel
	if err := db.gorm.WithContext(ctx).Where("project_id = ?", projectID).Find(&ms).Error; err != nil {
		return nil, fmt.Errorf("postgres: ListSuppressions: %w", err)
	}
	rows := make([]SuppressionRow, len(ms))
	for i, m := range ms {
		rows[i] = SuppressionRow{
			ProjectID: m.ProjectID, FindingID: m.FindingID,
			Reason: m.Reason, SuppressedAt: m.SuppressedAt,
		}
	}
	return rows, nil
}
