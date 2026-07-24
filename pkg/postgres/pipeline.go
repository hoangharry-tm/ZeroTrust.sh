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
	"database/sql"
	"fmt"
	"time"

	"gorm.io/gorm/clause"
)

// ─── work_items ───────────────────────────────────────────────────────────────
//
// work_items is the sequential pipeline queue. Each stage reads pending rows
// for its component, processes them, and writes the next stage's rows.
// status: 'pending' → 'done' | 'error'
//
// Dead code path today (ported for parity from the SQLite era; not newly
// wired by this migration — see the pkg/postgres package doc).

// WorkItem is one row from the work_items table.
type WorkItem struct {
	ScanID    string
	Component string // 'enricher','classifier','assembler','llm_scan','dedup'
	SurfaceID string
	Status    string
	Payload   string // JSON metadata; may be empty
	CreatedAt int64
	UpdatedAt int64
}

// InsertWorkItems writes a batch of work items in a single transaction.
func (db *DB) InsertWorkItems(ctx context.Context, items []WorkItem) error {
	if len(items) == 0 {
		return nil
	}
	now := time.Now().Unix()
	ms := make([]workItemModel, len(items))
	for i, it := range items {
		ms[i] = workItemModel{
			ScanID: it.ScanID, Component: it.Component, SurfaceID: it.SurfaceID,
			Status: "pending", Payload: it.Payload, CreatedAt: now, UpdatedAt: now,
		}
	}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ms).Error
	if err != nil {
		return fmt.Errorf("postgres: InsertWorkItems: %w", err)
	}
	return nil
}

// PollWorkItems returns a *sql.Rows cursor over pending items for (scanID, component).
// The caller must close the rows and call MarkWorkItemDone for each processed row.
func (db *DB) PollWorkItems(ctx context.Context, scanID, component string) (*sql.Rows, error) {
	rows, err := db.gorm.WithContext(ctx).Model(&workItemModel{}).
		Where("scan_id = ? AND component = ? AND status = 'pending'", scanID, component).
		Order("surface_id").Select("surface_id, payload").Rows()
	if err != nil {
		return nil, fmt.Errorf("postgres: PollWorkItems: %w", err)
	}
	return rows, nil
}

// MarkWorkItemDone sets status='done' for one work item.
func (db *DB) MarkWorkItemDone(ctx context.Context, scanID, component, surfaceID string) error {
	return db.gorm.WithContext(ctx).Model(&workItemModel{}).
		Where("scan_id = ? AND component = ? AND surface_id = ?", scanID, component, surfaceID).
		Updates(map[string]any{"status": "done", "updated_at": time.Now().Unix()}).Error
}

// MarkWorkItemError sets status='error' and stores a reason in payload.
func (db *DB) MarkWorkItemError(ctx context.Context, scanID, component, surfaceID, reason string) error {
	return db.gorm.WithContext(ctx).Model(&workItemModel{}).
		Where("scan_id = ? AND component = ? AND surface_id = ?", scanID, component, surfaceID).
		Updates(map[string]any{"status": "error", "payload": reason, "updated_at": time.Now().Unix()}).Error
}

// CountWorkItems returns (pending, done, error) counts for a scan+component.
func (db *DB) CountWorkItems(ctx context.Context, scanID, component string) (pending, done, errCount int, err error) {
	var results []struct {
		Status string
		Count  int
	}
	err = db.gorm.WithContext(ctx).Model(&workItemModel{}).
		Select("status, COUNT(*) as count").
		Where("scan_id = ? AND component = ?", scanID, component).
		Group("status").Scan(&results).Error
	if err != nil {
		return 0, 0, 0, err
	}
	for _, r := range results {
		switch r.Status {
		case "pending":
			pending = r.Count
		case "done":
			done = r.Count
		case "error":
			errCount = r.Count
		}
	}
	return pending, done, errCount, nil
}

// ─── pending_findings ────────────────────────────────────────────────────────
//
// LLM scanner writes findings here BEFORE marking the work_item done.
// Dedup reads from here. If the process dies, findings survive and can be
// recovered on restart.

// WritePendingFinding persists a JSON-encoded finding before it is deduplicated.
func (db *DB) WritePendingFinding(ctx context.Context, scanID, findingID, data string) error {
	m := pendingFindingModel{ScanID: scanID, FindingID: findingID, Data: data, CreatedAt: time.Now().Unix()}
	err := db.gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_id"}, {Name: "finding_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"data", "created_at"}),
	}).Create(&m).Error
	if err != nil {
		return fmt.Errorf("postgres: WritePendingFinding: %w", err)
	}
	return nil
}

// ReadPendingFinding returns the JSON data for one finding.
func (db *DB) ReadPendingFinding(ctx context.Context, scanID, findingID string) (string, error) {
	var m pendingFindingModel
	err := db.gorm.WithContext(ctx).
		Where("scan_id = ? AND finding_id = ?", scanID, findingID).First(&m).Error
	if err != nil {
		return "", fmt.Errorf("postgres: ReadPendingFinding: %w", err)
	}
	return m.Data, nil
}

// DeletePendingFindings removes all pending findings for a scan after dedup completes.
func (db *DB) DeletePendingFindings(ctx context.Context, scanID string) error {
	return db.gorm.WithContext(ctx).Where("scan_id = ?", scanID).Delete(&pendingFindingModel{}).Error
}
