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

//go:build stress

package sqlite

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

// ─── Benchmarks ──────────────────────────────────────────────────────────────

// BenchmarkIngestNodes measures throughput of IngestNodeBatch at various scales.
func BenchmarkIngestNodes(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", count), func(b *testing.B) {
			db, cleanup := openBenchDB(b)
			defer cleanup()
			ctx := context.Background()

			nodes := make([]CPGNode, count)
			for i := range nodes {
				nodes[i] = CPGNode{
					ID:   fmt.Sprintf("n%07d", i),
					Name: fmt.Sprintf("func_%d", i),
					File: fmt.Sprintf("file_%d.go", i%100),
					Line: i,
					Code: fmt.Sprintf("def func_%d(): pass", i),
				}
			}

			b.ResetTimer()
			for range b.N {
				if err := db.IngestNodeBatch(ctx, "bench", "v1", "METHOD", nodes); err != nil {
					b.Fatalf("IngestNodeBatch: %v", err)
				}
			}
		})
	}
}

// BenchmarkIngestEdges measures throughput of IngestEdgeBatch at various scales.
func BenchmarkIngestEdges(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("edges=%d", count), func(b *testing.B) {
			db, cleanup := openBenchDB(b)
			defer cleanup()
			ctx := context.Background()

			edges := make([]CPGEdge, count)
			for i := range edges {
				edges[i] = CPGEdge{
					FromID:   fmt.Sprintf("n%07d", i%1000),
					ToID:     fmt.Sprintf("n%07d", (i+1)%1000),
					EdgeType: "CALL",
				}
			}

			b.ResetTimer()
			for range b.N {
				if err := db.IngestEdgeBatch(ctx, "bench", "v1", edges); err != nil {
					b.Fatalf("IngestEdgeBatch: %v", err)
				}
			}
		})
	}
}

// BenchmarkWalkFindingIDs compares streaming WalkFindingIDs vs ListFindingIDs.
func BenchmarkWalkFindingIDs(b *testing.B) {
	db, cleanup := openBenchDB(b)
	defer cleanup()
	ctx := context.Background()
	setupBenchProject(b, db, "bench-findings", "run-bench")

	const numFindings = 50000
	for i := range numFindings {
		if err := db.UpsertFinding(ctx, FindingRow{
			FindingID:  fmt.Sprintf("fid-%07d", i),
			ProjectID:  "bench-findings",
			RunID:      "run-bench",
			FilePath:   "x.go",
			LineStart:  1,
			LineEnd:    1,
			Severity:   "LOW",
			Confidence: 0.5,
			SourcePath: "BENCH",
		}); err != nil {
			b.Fatalf("UpsertFinding: %v", err)
		}
	}

	b.Run("WalkFindingIDs", func(b *testing.B) {
		for range b.N {
			count := 0
			if err := db.WalkFindingIDs(ctx, "bench-findings", func(id string) error {
				count++
				return nil
			}); err != nil {
				b.Fatalf("WalkFindingIDs: %v", err)
			}
			if count != numFindings {
				b.Fatalf("expected %d, got %d", numFindings, count)
			}
		}
	})

	b.Run("ListFindingIDs", func(b *testing.B) {
		for range b.N {
			ids, err := db.ListFindingIDs(ctx, "bench-findings")
			if err != nil {
				b.Fatalf("ListFindingIDs: %v", err)
			}
			if len(ids) != numFindings {
				b.Fatalf("expected %d, got %d", numFindings, len(ids))
			}
		}
	})
}

// ─── Concurrent Query Stress Tests ──────────────────────────────────────────

// TestConcurrentQueries_NoDeadlock runs concurrent readers against a
// pre-populated CPG dataset. Run with -race to detect data races.
func TestConcurrentQueries_NoDeadlock(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proj := "stress-proj"
	ver := "v1"

	db.writer.SetMaxOpenConns(4)
	db.reader.SetMaxOpenConns(4)

	// Pre-populate 100 nodes + 400 edges.
	var nodes []CPGNode
	for i := range 100 {
		nodes = append(nodes, CPGNode{
			ID:   fmt.Sprintf("n%07d", i),
			Name: fmt.Sprintf("func_%d", i),
			File: fmt.Sprintf("file_%d.go", i%10),
			Line: i,
		})
	}
	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", nodes); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}

	var edges []CPGEdge
	for i := range 200 {
		edges = append(edges, CPGEdge{
			FromID:   fmt.Sprintf("n%07d", i%100),
			ToID:     fmt.Sprintf("n%07d", (i+1)%100),
			EdgeType: "CALL",
		})
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, edges); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	trySendErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	queryTypes := []func(){
		func() { cur, err := db.QueryNodesByType(ctx, proj, ver, "METHOD"); if err != nil { trySendErr(err) } else { cur.Close() } },
		func() {
			cur, err := db.GetCallers(ctx, proj, ver, "n0000000")
			if err == nil {
				for cur.Next() {
					_, _ = cur.Scan()
				}
				cur.Close()
			} else {
				trySendErr(err)
			}
		},
		func() {
			cur, err := db.GetEdgesFrom(ctx, proj, ver, "n0000000")
			if err == nil {
				for cur.Next() {
					_, _ = cur.Scan()
				}
				cur.Close()
			} else {
				trySendErr(err)
			}
		},
		func() {
			cur, err := db.GetEdgesTo(ctx, proj, ver, "n0000000")
			if err == nil {
				for cur.Next() {
					_, _ = cur.Scan()
				}
				cur.Close()
			} else {
				trySendErr(err)
			}
		},
	}

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				fn := queryTypes[rand.IntN(len(queryTypes))]
				fn()
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent query error: %v", err)
	}
}

// TestConcurrentReads_AfterWrite verifies concurrent readers after pre-population
// do not produce data races when using -race. (modernc.org/sqlite uses a global
// mutex, so true concurrent reads+write is not possible.)
func TestConcurrentReads_AfterWrite(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proj := "rw-stress"
	ver := "v1"

	db.writer.SetMaxOpenConns(4)
	db.reader.SetMaxOpenConns(4)

	// Pre-populate 500 nodes.
	nodes := make([]CPGNode, 500)
	for i := range nodes {
		nodes[i] = CPGNode{
			ID:   fmt.Sprintf("n%07d", i),
			Name: fmt.Sprintf("func_%d", i),
		}
	}
	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", nodes); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				cur, err := db.QueryNodesByType(ctx, proj, ver, "METHOD")
				if err != nil {
					errCh <- err
					return
				}
				var count int
				for cur.Next() {
					_, _ = cur.Scan()
					count++
				}
				cur.Close()
				if count < 500 {
					errCh <- fmt.Errorf("expected >=500 nodes, got %d", count)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent read error: %v", err)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func openBenchDB(b testing.TB) (*DB, func()) {
	b.Helper()
	dir := b.TempDir()
	db, err := Open(dir + "/bench.db")
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	return db, func() { db.Close() }
}

func setupBenchProject(b testing.TB, db *DB, projectID, runID string) {
	b.Helper()
	ctx := context.Background()
	if _, err := db.UpsertProject(ctx, ProjectRow{
		ProjectID: projectID, RootPath: "/" + projectID,
		FirstSeenAt: 1, LastScannedAt: 1,
	}); err != nil {
		b.Fatalf("UpsertProject: %v", err)
	}
	if err := db.CreateScanRun(ctx, ScanRunRow{
		RunID: runID, ProjectID: projectID, StartedAt: 1, Status: "running",
	}); err != nil {
		b.Fatalf("CreateScanRun: %v", err)
	}
}
