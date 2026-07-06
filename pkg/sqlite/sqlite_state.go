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

// ─── scan_state ──────────────────────────────────────────────────────────────

// ScanStateRow is one row from the scan_state table.
type ScanStateRow struct {
	ProjectID     string
	FilePath      string
	ContentHash   string
	LastScannedAt int64
}

// GetScanState returns the cached state for (projectID, filePath).
// Returns sql.ErrNoRows if no entry exists.
func (db *DB) GetScanState(ctx context.Context, projectID, filePath string) (*ScanStateRow, error) {
	row := &ScanStateRow{}
	err := db.reader.QueryRowContext(ctx,
		`SELECT project_id, file_path, content_hash, last_scanned_at
		 FROM scan_state WHERE project_id = ? AND file_path = ?`,
		projectID, filePath,
	).Scan(&row.ProjectID, &row.FilePath, &row.ContentHash, &row.LastScannedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// UpsertScanState inserts or replaces the scan state row for one file.
// Call per-file during the ingestion walk — do not accumulate slices.
func (db *DB) UpsertScanState(ctx context.Context, row ScanStateRow) error {
	_, err := db.writer.ExecContext(ctx,
		`INSERT OR REPLACE INTO scan_state (project_id, file_path, content_hash, last_scanned_at)
		 VALUES (?, ?, ?, ?)`,
		row.ProjectID, row.FilePath, row.ContentHash, row.LastScannedAt,
	)
	return err
}

// ListScanState returns all cached state rows for the given projectID.
func (db *DB) ListScanState(ctx context.Context, projectID string) ([]ScanStateRow, error) {
	return queryRows(ctx, db.reader,
		`SELECT project_id, file_path, content_hash, last_scanned_at
		 FROM scan_state WHERE project_id = ?`,
		[]any{projectID},
		func(rows *sql.Rows) (ScanStateRow, error) {
			var r ScanStateRow
			return r, rows.Scan(&r.ProjectID, &r.FilePath, &r.ContentHash, &r.LastScannedAt)
		},
	)
}

// DeleteScanState removes the state row for (projectID, filePath).
func (db *DB) DeleteScanState(ctx context.Context, projectID, filePath string) error {
	_, err := db.writer.ExecContext(ctx,
		`DELETE FROM scan_state WHERE project_id = ? AND file_path = ?`,
		projectID, filePath,
	)
	return err
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
	var count int
	err := db.reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM suppressions WHERE project_id = ? AND finding_id = ?`,
		projectID, findingID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("sqlite: IsSuppressed: %w", err)
	}
	return count > 0, nil
}

// AddSuppression records a suppression decision. Idempotent.
func (db *DB) AddSuppression(ctx context.Context, row SuppressionRow) error {
	if row.SuppressedAt == 0 {
		row.SuppressedAt = time.Now().Unix()
	}
	_, err := db.writer.ExecContext(ctx,
		`INSERT OR REPLACE INTO suppressions (project_id, finding_id, reason, suppressed_at)
		 VALUES (?, ?, ?, ?)`,
		row.ProjectID, row.FindingID, row.Reason, row.SuppressedAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: AddSuppression: %w", err)
	}
	return nil
}

// ListSuppressions returns all suppression rows for the given projectID.
func (db *DB) ListSuppressions(ctx context.Context, projectID string) ([]SuppressionRow, error) {
	return queryRows(ctx, db.reader,
		`SELECT project_id, finding_id, reason, suppressed_at
		 FROM suppressions WHERE project_id = ?`,
		[]any{projectID},
		func(rows *sql.Rows) (SuppressionRow, error) {
			var r SuppressionRow
			return r, rows.Scan(&r.ProjectID, &r.FindingID, &r.Reason, &r.SuppressedAt)
		},
	)
}
