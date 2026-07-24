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

	"github.com/jackc/pgx/v5"
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
type NodeCursor struct{ rows pgx.Rows }

func (c *NodeCursor) Next() bool { return c.rows.Next() }
func (c *NodeCursor) Scan() (CPGNode, error) {
	var n CPGNode
	return n, c.rows.Scan(&n.ID, &n.Name, &n.File, &n.Line, &n.Code)
}
func (c *NodeCursor) Close() { c.rows.Close() }

// EdgeCursor streams CPGEdge rows one at a time.
type EdgeCursor struct{ rows pgx.Rows }

func (c *EdgeCursor) Next() bool { return c.rows.Next() }
func (c *EdgeCursor) Scan() (CPGEdge, error) {
	var e CPGEdge
	return e, c.rows.Scan(&e.FromID, &e.ToID, &e.EdgeType)
}
func (c *EdgeCursor) Close() { c.rows.Close() }

// ─── ingest helpers ───────────────────────────────────────────────────────────
//
// These use the raw pgx pool (not GORM): CPG node/edge ingestion is the
// actual high-volume write path (thousands of rows per scan), and pgx's
// COPY protocol is materially faster here than row-by-row/batched INSERT.

// IngestNodeBatch writes a batch of CPG nodes via COPY. Call once per
// pagination page from cpg_engine's IngestCPGToDB.
func (db *DB) IngestNodeBatch(ctx context.Context, projectID, cpgVersion, nodeType string, nodes []CPGNode) error {
	if len(nodes) == 0 {
		return nil
	}
	// Nodes may repeat across pages/re-ingests (INSERT OR REPLACE semantics in
	// the SQLite era); COPY can't upsert, so stage into a temp table and merge.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: IngestNodeBatch begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE cpg_nodes_stage
		(project_id text, cpg_version text, node_id text, node_type text, name text, file text, line int, code text)
		ON COMMIT DROP`); err != nil {
		return fmt.Errorf("postgres: IngestNodeBatch create stage: %w", err)
	}

	rowsInput := make([][]any, len(nodes))
	for i, n := range nodes {
		rowsInput[i] = []any{projectID, cpgVersion, n.ID, nodeType, n.Name, n.File, n.Line, n.Code}
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"cpg_nodes_stage"},
		[]string{"project_id", "cpg_version", "node_id", "node_type", "name", "file", "line", "code"},
		pgx.CopyFromRows(rowsInput))
	if err != nil {
		return fmt.Errorf("postgres: IngestNodeBatch copy: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO cpg_nodes (project_id, cpg_version, node_id, node_type, name, file, line, code)
		SELECT project_id, cpg_version, node_id, node_type, name, file, line, code FROM cpg_nodes_stage
		ON CONFLICT (project_id, cpg_version, node_id) DO UPDATE SET
			node_type = excluded.node_type, name = excluded.name,
			file = excluded.file, line = excluded.line, code = excluded.code`); err != nil {
		return fmt.Errorf("postgres: IngestNodeBatch merge: %w", err)
	}
	return tx.Commit(ctx)
}

// IngestEdgeBatch writes a batch of CPG edges via COPY, same stage-then-merge
// pattern as IngestNodeBatch.
func (db *DB) IngestEdgeBatch(ctx context.Context, projectID, cpgVersion string, edges []CPGEdge) error {
	if len(edges) == 0 {
		return nil
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: IngestEdgeBatch begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE cpg_edges_stage
		(project_id text, cpg_version text, from_id text, to_id text, edge_type text)
		ON COMMIT DROP`); err != nil {
		return fmt.Errorf("postgres: IngestEdgeBatch create stage: %w", err)
	}

	rowsInput := make([][]any, len(edges))
	for i, e := range edges {
		edgeType := e.EdgeType
		if edgeType == "" {
			edgeType = "CALL"
		}
		rowsInput[i] = []any{projectID, cpgVersion, e.FromID, e.ToID, edgeType}
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"cpg_edges_stage"},
		[]string{"project_id", "cpg_version", "from_id", "to_id", "edge_type"},
		pgx.CopyFromRows(rowsInput))
	if err != nil {
		return fmt.Errorf("postgres: IngestEdgeBatch copy: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO cpg_edges (project_id, cpg_version, from_id, to_id, edge_type)
		SELECT project_id, cpg_version, from_id, to_id, edge_type FROM cpg_edges_stage
		ON CONFLICT (project_id, cpg_version, from_id, to_id, edge_type) DO NOTHING`); err != nil {
		return fmt.Errorf("postgres: IngestEdgeBatch merge: %w", err)
	}
	return tx.Commit(ctx)
}

// RecordBuild upserts a cpg_builds row after ingestion completes.
func (db *DB) RecordBuild(ctx context.Context, projectID, cpgVersion, changedHash string, nodeCount, edgeCount int) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO cpg_builds (project_id, cpg_version, changed_hash, node_count, edge_count, built_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (project_id) DO UPDATE SET
			cpg_version = excluded.cpg_version, changed_hash = excluded.changed_hash,
			node_count = excluded.node_count, edge_count = excluded.edge_count, built_at = excluded.built_at`,
		projectID, cpgVersion, changedHash, nodeCount, edgeCount, time.Now().Unix())
	return err
}

// GetCPGVersion returns the current cpg_version for projectID, and whether one exists.
func (db *DB) GetCPGVersion(ctx context.Context, projectID string) (version string, ok bool, err error) {
	err = db.pool.QueryRow(ctx,
		`SELECT cpg_version FROM cpg_builds WHERE project_id=$1`, projectID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return version, err == nil, err
}

// ─── graph queries ────────────────────────────────────────────────────────────

// QueryNodesByType returns a cursor over all nodes of the given type for a CPG version.
func (db *DB) QueryNodesByType(ctx context.Context, projectID, cpgVersion, nodeType string) (*NodeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT node_id, name, file, line, code
		 FROM cpg_nodes
		 WHERE project_id=$1 AND cpg_version=$2 AND node_type=$3
		 ORDER BY node_id`,
		projectID, cpgVersion, nodeType)
	if err != nil {
		return nil, fmt.Errorf("postgres: QueryNodesByType: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// QueryNodesByFile returns a cursor over nodes of the given type in a specific file.
func (db *DB) QueryNodesByFile(ctx context.Context, projectID, cpgVersion, file, nodeType string) (*NodeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT node_id, name, file, line, code
		 FROM cpg_nodes
		 WHERE project_id=$1 AND cpg_version=$2 AND file=$3 AND node_type=$4
		 ORDER BY node_id`,
		projectID, cpgVersion, file, nodeType)
	if err != nil {
		return nil, fmt.Errorf("postgres: QueryNodesByFile: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetCallers returns a cursor over nodes that call functionID.
func (db *DB) GetCallers(ctx context.Context, projectID, cpgVersion, functionID string) (*NodeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT n.node_id, n.name, n.file, n.line, n.code
		 FROM cpg_edges e
		 JOIN cpg_nodes n ON n.node_id=e.from_id
		     AND n.project_id=e.project_id AND n.cpg_version=e.cpg_version
		 WHERE e.project_id=$1 AND e.cpg_version=$2
		     AND e.to_id=$3 AND e.edge_type='CALL'
		 ORDER BY n.node_id`,
		projectID, cpgVersion, functionID)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCallers: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetCallees returns a cursor over nodes called by functionID.
func (db *DB) GetCallees(ctx context.Context, projectID, cpgVersion, functionID string) (*NodeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT n.node_id, n.name, n.file, n.line, n.code
		 FROM cpg_edges e
		 JOIN cpg_nodes n ON n.node_id=e.to_id
		     AND n.project_id=e.project_id AND n.cpg_version=e.cpg_version
		 WHERE e.project_id=$1 AND e.cpg_version=$2
		     AND e.from_id=$3 AND e.edge_type='CALL'
		 ORDER BY n.node_id`,
		projectID, cpgVersion, functionID)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetCallees: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}

// GetAllCallEdges returns a cursor over every CALL edge for a CPG version —
// used to build the full in-memory CallGraph in one query instead of N.
func (db *DB) GetAllCallEdges(ctx context.Context, projectID, cpgVersion string) (*EdgeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT from_id, to_id, edge_type FROM cpg_edges
		 WHERE project_id=$1 AND cpg_version=$2 AND edge_type='CALL'
		 ORDER BY from_id`,
		projectID, cpgVersion)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetAllCallEdges: %w", err)
	}
	return &EdgeCursor{rows: rows}, nil
}

// GetEdgesFrom returns a cursor over all edges originating from nodeID.
func (db *DB) GetEdgesFrom(ctx context.Context, projectID, cpgVersion, nodeID string) (*EdgeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT from_id, to_id, edge_type FROM cpg_edges
		 WHERE project_id=$1 AND cpg_version=$2 AND from_id=$3
		 ORDER BY to_id`,
		projectID, cpgVersion, nodeID)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetEdgesFrom: %w", err)
	}
	return &EdgeCursor{rows: rows}, nil
}

// GetEdgesTo returns a cursor over all edges pointing to nodeID.
func (db *DB) GetEdgesTo(ctx context.Context, projectID, cpgVersion, nodeID string) (*EdgeCursor, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT from_id, to_id, edge_type FROM cpg_edges
		 WHERE project_id=$1 AND cpg_version=$2 AND to_id=$3
		 ORDER BY from_id`,
		projectID, cpgVersion, nodeID)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetEdgesTo: %w", err)
	}
	return &EdgeCursor{rows: rows}, nil
}

// GetNeighboursAtDepth does a BFS via recursive CTE up to maxDepth hops in
// both directions. Returns a cursor over all reachable nodes (excluding root).
func (db *DB) GetNeighboursAtDepth(ctx context.Context, projectID, cpgVersion, rootID string, maxDepth int) (*NodeCursor, error) {
	rows, err := db.pool.Query(ctx, `
		WITH RECURSIVE bfs(id, d) AS (
			SELECT $1::text, 0
			UNION ALL
			SELECT e.to_id, bfs.d+1
			FROM cpg_edges e JOIN bfs ON e.from_id=bfs.id
			WHERE e.edge_type='CALL' AND bfs.d<$2
			UNION ALL
			SELECT e.from_id, bfs.d+1
			FROM cpg_edges e JOIN bfs ON e.to_id=bfs.id
			WHERE e.edge_type='CALL' AND bfs.d<$2
		)
		SELECT DISTINCT n.node_id, n.name, n.file, n.line, n.code
		FROM bfs
		JOIN cpg_nodes n ON n.node_id=bfs.id
			AND n.project_id=$3 AND n.cpg_version=$4
		WHERE bfs.id!=$1
		ORDER BY n.node_id`,
		rootID, maxDepth, projectID, cpgVersion)
	if err != nil {
		return nil, fmt.Errorf("postgres: GetNeighboursAtDepth: %w", err)
	}
	return &NodeCursor{rows: rows}, nil
}
