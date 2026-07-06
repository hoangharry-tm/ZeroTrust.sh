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
	"fmt"
	"time"
)

// ─── work_items ───────────────────────────────────────────────────────────────
//
// work_items is the sequential pipeline queue. Each stage reads pending rows
// for its component, processes them, and writes the next stage's rows.
// status: 'pending' → 'done' | 'error'

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
	tx, err := db.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: InsertWorkItems begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO work_items (scan_id, component, surface_id, status, payload, created_at, updated_at)
		 VALUES (?, ?, ?, 'pending', ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: InsertWorkItems prepare: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	now := time.Now().Unix()
	for _, it := range items {
		if _, err := stmt.ExecContext(ctx, it.ScanID, it.Component, it.SurfaceID, it.Payload, now, now); err != nil {
			return fmt.Errorf("sqlite: InsertWorkItems exec: %w", err)
		}
	}
	return tx.Commit()
}

// PollWorkItems returns a *sql.Rows cursor over pending items for (scanID, component).
// The caller must close the rows and call MarkWorkItemDone for each processed row.
func (db *DB) PollWorkItems(ctx context.Context, scanID, component string) (*sql.Rows, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT surface_id, payload FROM work_items
		 WHERE scan_id = ? AND component = ? AND status = 'pending'
		 ORDER BY surface_id`,
		scanID, component)
	if err != nil {
		return nil, fmt.Errorf("sqlite: PollWorkItems: %w", err)
	}
	return rows, nil
}

// MarkWorkItemDone sets status='done' for one work item.
func (db *DB) MarkWorkItemDone(ctx context.Context, scanID, component, surfaceID string) error {
	_, err := db.writer.ExecContext(ctx,
		`UPDATE work_items SET status='done', updated_at=?
		 WHERE scan_id=? AND component=? AND surface_id=?`,
		time.Now().Unix(), scanID, component, surfaceID)
	return err
}

// MarkWorkItemError sets status='error' and stores a reason in payload.
func (db *DB) MarkWorkItemError(ctx context.Context, scanID, component, surfaceID, reason string) error {
	_, err := db.writer.ExecContext(ctx,
		`UPDATE work_items SET status='error', payload=?, updated_at=?
		 WHERE scan_id=? AND component=? AND surface_id=?`,
		reason, time.Now().Unix(), scanID, component, surfaceID)
	return err
}

// CountWorkItems returns (pending, done, error) counts for a scan+component.
func (db *DB) CountWorkItems(ctx context.Context, scanID, component string) (pending, done, errCount int, err error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM work_items
		 WHERE scan_id=? AND component=? GROUP BY status`,
		scanID, component)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var status string
		var count int
		rows.Scan(&status, &count) //nolint:errcheck
		switch status {
		case "pending":
			pending = count
		case "done":
			done = count
		case "error":
			errCount = count
		}
	}
	return pending, done, errCount, rows.Err()
}

// ─── pending_findings ────────────────────────────────────────────────────────
//
// LLM scanner writes findings here BEFORE marking the work_item done.
// Dedup reads from here. If the process dies, findings survive and can be
// recovered on restart.

// WritePendingFinding persists a JSON-encoded finding before it is deduplicated.
func (db *DB) WritePendingFinding(ctx context.Context, scanID, findingID, data string) error {
	_, err := db.writer.ExecContext(ctx,
		`INSERT OR REPLACE INTO pending_findings (scan_id, finding_id, data, created_at)
		 VALUES (?, ?, ?, ?)`,
		scanID, findingID, data, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("sqlite: WritePendingFinding: %w", err)
	}
	return nil
}

// ReadPendingFinding returns the JSON data for one finding.
func (db *DB) ReadPendingFinding(ctx context.Context, scanID, findingID string) (string, error) {
	var data string
	err := db.reader.QueryRowContext(ctx,
		`SELECT data FROM pending_findings WHERE scan_id=? AND finding_id=?`,
		scanID, findingID).Scan(&data)
	if err != nil {
		return "", fmt.Errorf("sqlite: ReadPendingFinding: %w", err)
	}
	return data, nil
}

// DeletePendingFindings removes all pending findings for a scan after dedup completes.
func (db *DB) DeletePendingFindings(ctx context.Context, scanID string) error {
	_, err := db.writer.ExecContext(ctx,
		`DELETE FROM pending_findings WHERE scan_id=?`, scanID)
	return err
}
