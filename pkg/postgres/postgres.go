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

// Package postgres provides the ZeroTrust.sh scan database, backed by
// PostgreSQL. It replaces the earlier SQLite-backed pkg/sqlite: Postgres's
// MVCC handles concurrent reads+writes over one pool natively, removing the
// single-writer WAL workaround SQLite required, and gives a proper query
// engine for future RAG/analyst-query workloads.
//
// Two handles are kept open against the same DSN:
//   - gorm — CRUD tables (projects, scan_runs, findings, ssvc_scores,
//     poe_results, cpg_cache, scan_state, suppressions, work_items,
//     pending_findings), schema managed via AutoMigrate.
//   - pool — a raw pgx pool used only for the CPG node/edge bulk path
//     (IngestNodeBatch/IngestEdgeBatch, GetNeighboursAtDepth's recursive CTE),
//     since that's the actual high-volume write path and pgx's COPY protocol
//     is materially faster there than row-by-row ORM inserts.
//
// Files:
//
//	postgres.go  — DB struct, Open, Close
//	models.go    — GORM struct-tagged models for every table
//	findings.go  — projects, scan_runs, findings, ssvc_scores, poe_results, cpg_cache
//	state.go     — scan_state, suppressions
//	pipeline.go  — work_items, pending_findings (sequential pipeline queue)
//	cpg.go       — cpg_nodes, cpg_edges, cpg_builds, NodeCursor, EdgeCursor
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	gormpg "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB holds a GORM handle (CRUD tables) and a raw pgx pool (CPG bulk path).
type DB struct {
	gorm *gorm.DB
	pool *pgxpool.Pool
}

// Open connects to the Postgres instance at dsn, runs AutoMigrate for every
// CRUD model, and returns a ready-to-use DB. dsn is a standard Postgres
// connection string, e.g. "postgres://user:pass@localhost:5432/zerotrust".
func Open(ctx context.Context, dsn string) (*DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres: dsn is empty (set --db-url or $DATABASE_URL)")
	}

	gdb, err := gorm.Open(gormpg.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: gorm open: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: pgxpool open: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	if err := gdb.WithContext(ctx).AutoMigrate(allModels...); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: automigrate: %w", err)
	}

	return &DB{gorm: gdb, pool: pool}, nil
}

// Close releases both the GORM connection and the pgx pool.
func (db *DB) Close() error {
	db.pool.Close()
	sqlDB, err := db.gorm.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
