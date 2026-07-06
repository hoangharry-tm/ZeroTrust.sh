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

// ─── row types ───────────────────────────────────────────────────────────────

// CPGNode is one row from cpg_nodes.
type CPGNode struct {
	ID   string
	Type string
	Name string
	File string
	Line int
	Code string
}

// CPGEdge is one row from cpg_edges.
type CPGEdge struct {
	FromID   string
	ToID     string
	EdgeType string
}

// ─── cursors ─────────────────────────────────────────────────────────────────

// NodeCursor streams CPGNode rows one at a time — no []CPGNode is materialised.
type NodeCursor struct{ rows *sql.Rows }

func (c *NodeCursor) Next() bool { return c.rows.Next() }
func (c *NodeCursor) Scan() (CPGNode, error) {
	var n CPGNode
	return n, c.rows.Scan(&n.ID, &n.Name, &n.File, &n.Line, &n.Code)
}
func (c *NodeCursor) Close() { c.rows.Close() }

// EdgeCursor streams CPGEdge rows one at a time.
type EdgeCursor struct{ rows *sql.Rows }

func (c *EdgeCursor) Next() bool { return c.rows.Next() }
func (c *EdgeCursor) Scan() (CPGEdge, error) {
	var e CPGEdge
	return e, c.rows.Scan(&e.FromID, &e.ToID, &e.EdgeType)
}
func (c *EdgeCursor) Close() { c.rows.Close() }

// ─── ingest helpers ───────────────────────────────────────────────────────────

// IngestNodeBatch writes a batch of CPG nodes in a single transaction.
// Call once per pagination page from IngestCPGToSQLite.
func (db *DB) IngestNodeBatch(ctx context.Context, projectID, cpgVersion, nodeType string, nodes []CPGNode) error {
	if len(nodes) == 0 {
		return nil
	}
	tx, err := db.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: IngestNodeBatch begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO cpg_nodes (project_id, cpg_version, node_id, node_type, name, file, line, code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: IngestNodeBatch prepare: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	for _, n := range nodes {
		if _, err := stmt.ExecContext(ctx, projectID, cpgVersion, n.ID, nodeType, n.Name, n.File, n.Line, n.Code); err != nil {
			return fmt.Errorf("sqlite: IngestNodeBatch exec: %w", err)
		}
	}
	return tx.Commit()
}

// IngestEdgeBatch writes a batch of CPG edges in a single transaction.
func (db *DB) IngestEdgeBatch(ctx context.Context, projectID, cpgVersion string, edges []CPGEdge) error {
	if len(edges) == 0 {
		return nil
	}
	tx, err := db.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: IngestEdgeBatch begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO cpg_edges (project_id, cpg_version, from_id, to_id, edge_type)
		 VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: IngestEdgeBatch prepare: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	for _, e := range edges {
		edgeType := e.EdgeType
		if edgeType == "" {
			edgeType = "CALL"
		}
		if _, err := stmt.ExecContext(ctx, projectID, cpgVersion, e.FromID, e.ToID, edgeType); err != nil {
			return fmt.Errorf("sqlite: IngestEdgeBatch exec: %w", err)
		}
	}
	return tx.Commit()
}

// RecordBuild upserts a cpg_builds row after ingestion completes.
func (db *DB) RecordBuild(ctx context.Context, projectID, cpgVersion, changedHash string, nodeCount, edgeCount int) error {
	_, err := db.writer.ExecContext(ctx,
		`INSERT OR REPLACE INTO cpg_builds (project_id, cpg_version, changed_hash, node_count, edge_count, built_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		projectID, cpgVersion, changedHash, nodeCount, edgeCount, time.Now().Unix())
	return err
}

// GetCPGVersion returns the current cpg_version for projectID, and whether one exists.
func (db *DB) GetCPGVersion(ctx context.Context, projectID string) (version string, ok bool, err error) {
	err = db.reader.QueryRowContext(ctx,
		`SELECT cpg_version FROM cpg_builds WHERE project_id=?`, projectID).Scan(&version)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return version, err == nil, err
}

// ─── graph queries ────────────────────────────────────────────────────────────

// QueryNodesByType returns a cursor over all nodes of the given type for a CPG version.
func (db *DB) QueryNodesByType(ctx context.Context, projectID, cpgVersion, nodeType string) (*NodeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT node_id, name, file, line, code
		 FROM cpg_nodes
		 WHERE project_id=? AND cpg_version=? AND node_type=?
		 ORDER BY node_id`,
		projectID, cpgVersion, nodeType)
	if err != nil {
		return nil, fmt.Errorf("sqlite: QueryNodesByType: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// QueryNodesByFile returns a cursor over nodes of the given type in a specific file.
func (db *DB) QueryNodesByFile(ctx context.Context, projectID, cpgVersion, file, nodeType string) (*NodeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT node_id, name, file, line, code
		 FROM cpg_nodes
		 WHERE project_id=? AND cpg_version=? AND file=? AND node_type=?
		 ORDER BY node_id`,
		projectID, cpgVersion, file, nodeType)
	if err != nil {
		return nil, fmt.Errorf("sqlite: QueryNodesByFile: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetCallers returns a cursor over nodes that call functionID.
func (db *DB) GetCallers(ctx context.Context, projectID, cpgVersion, functionID string) (*NodeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT n.node_id, n.name, n.file, n.line, n.code
		 FROM cpg_edges e
		 JOIN cpg_nodes n ON n.node_id=e.from_id
		     AND n.project_id=e.project_id AND n.cpg_version=e.cpg_version
		 WHERE e.project_id=? AND e.cpg_version=?
		     AND e.to_id=? AND e.edge_type='CALL'
		 ORDER BY n.node_id`,
		projectID, cpgVersion, functionID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCallers: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetCallees returns a cursor over nodes called by functionID.
func (db *DB) GetCallees(ctx context.Context, projectID, cpgVersion, functionID string) (*NodeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT n.node_id, n.name, n.file, n.line, n.code
		 FROM cpg_edges e
		 JOIN cpg_nodes n ON n.node_id=e.to_id
		     AND n.project_id=e.project_id AND n.cpg_version=e.cpg_version
		 WHERE e.project_id=? AND e.cpg_version=?
		     AND e.from_id=? AND e.edge_type='CALL'
		 ORDER BY n.node_id`,
		projectID, cpgVersion, functionID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetCallees: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetEdgesFrom returns a cursor over all edges originating from nodeID.
func (db *DB) GetEdgesFrom(ctx context.Context, projectID, cpgVersion, nodeID string) (*EdgeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT from_id, to_id, edge_type FROM cpg_edges
		 WHERE project_id=? AND cpg_version=? AND from_id=?
		 ORDER BY to_id`,
		projectID, cpgVersion, nodeID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetEdgesFrom: %w", err)
	}
	return &EdgeCursor{rows: rows}, nil
}

// GetEdgesTo returns a cursor over all edges pointing to nodeID.
func (db *DB) GetEdgesTo(ctx context.Context, projectID, cpgVersion, nodeID string) (*EdgeCursor, error) {
	rows, err := db.reader.QueryContext(ctx,
		`SELECT from_id, to_id, edge_type FROM cpg_edges
		 WHERE project_id=? AND cpg_version=? AND to_id=?
		 ORDER BY from_id`,
		projectID, cpgVersion, nodeID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetEdgesTo: %w", err)
	}
	return &EdgeCursor{rows: rows}, nil
}

// GetNeighboursAtDepth does a BFS via recursive CTE up to maxDepth hops
// in both directions. Returns a cursor over all reachable nodes (excluding root).
func (db *DB) GetNeighboursAtDepth(ctx context.Context, projectID, cpgVersion, rootID string, maxDepth int) (*NodeCursor, error) {
	rows, err := db.reader.QueryContext(ctx, `
		WITH RECURSIVE bfs(id, d) AS (
			SELECT ?, 0
			UNION ALL
			SELECT e.to_id, bfs.d+1
			FROM cpg_edges e JOIN bfs ON e.from_id=bfs.id
			WHERE e.edge_type='CALL' AND bfs.d<?
			UNION ALL
			SELECT e.from_id, bfs.d+1
			FROM cpg_edges e JOIN bfs ON e.to_id=bfs.id
			WHERE e.edge_type='CALL' AND bfs.d<?
		)
		SELECT DISTINCT n.node_id, n.name, n.file, n.line, n.code
		FROM bfs
		JOIN cpg_nodes n ON n.node_id=bfs.id
			AND n.project_id=? AND n.cpg_version=?
		WHERE bfs.id!=?
		ORDER BY n.node_id`,
		rootID, maxDepth, maxDepth, projectID, cpgVersion, rootID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetNeighboursAtDepth: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}
