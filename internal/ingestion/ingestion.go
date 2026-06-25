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

// Package ingestion orchestrates the two parallel startup tasks: Model Integrity
// Verification (MIV) and Differential Indexing (DI).
//
// Both tasks launch concurrently. MIV gates only LLM invocations — CPG build and
// pattern matching proceed regardless of the MIV outcome. DI produces the ChangeSet
// (new or modified files) that all downstream stages consume.
//
// On first scan, DI returns all files in the project. On repeat scans it returns
// only changed files, reducing pattern-matching and CPG cost by ~80–95%.
//
// Usage:
//
//	ig := ingestion.New(diffindexer, mivVerifier)
//	result, err := ig.Run(ctx, ingestion.Config{
//	    ProjectID:   "my-service",
//	    ProjectRoot: "/path/to/project",
//	    ModelPath:   "/path/to/model.gguf",
//	})
//	if result.MIV.Status == miv.StatusBlock {
//	    // Skip all LLM stages.
//	}
//	// After successful scan:
//	ig.CommitScan(ctx, result.ProjectID, result.ChangeSet)
package ingestion

import (
	"context"
	"log/slog"
	"sync"

	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
)

// Config holds the inputs for a single ingestion run.
type Config struct {
	// ProjectID is the unique identifier for this project's scan state in SQLite.
	// If empty, a deterministic ID is derived from the ProjectRoot path.
	ProjectID string
	// ProjectRoot is the absolute path to the codebase being scanned.
	ProjectRoot string
	// ModelPath is the absolute path to the local GGUF model file.
	// If empty, MIV is skipped and the result carries StatusWarn.
	ModelPath string
}

// Result is the combined output of a parallel MIV + DI run.
type Result struct {
	// ProjectID is the resolved project identifier (derived if not supplied in Config).
	ProjectID string
	// MIV is the outcome of model integrity verification.
	// Status == StatusBlock means all LLM invocations must be skipped.
	MIV *miv.Result
	// ChangeSet contains the files to be scanned in this run.
	// On first scan this is the full file list; on repeat scans it is the diff.
	ChangeSet *diffindex.ChangeSet
	// BlockLLM is a convenience flag derived from MIV.Status == miv.StatusBlock.
	BlockLLM bool
}

// Ingester runs MIV and DI in parallel and merges their results.
type Ingester struct {
	indexer  *diffindex.Indexer
	verifier *miv.Verifier
}

// New returns an Ingester that uses the given indexer and verifier.
func New(indexer *diffindex.Indexer, verifier *miv.Verifier) *Ingester {
	return &Ingester{indexer: indexer, verifier: verifier}
}

// Run launches MIV and DI concurrently and waits for both to complete.
// Context cancellation propagates to both subtasks.
//
// Errors from MIV are non-fatal (the scan continues with BlockLLM=true).
// Errors from DI are fatal (the scan cannot proceed without a file list).
//
// Parameters:
//   - ctx: cancellation context passed to both subtasks.
//   - cfg: scan configuration (see Config).
//
// Returns:
//   - *Result: combined MIV + DI output.
//   - error: non-nil only if DI fails (MIV errors are captured in Result.MIV).
func (ig *Ingester) Run(ctx context.Context, cfg Config) (*Result, error) {
	slog.Debug("ingestion run started", "component", "ingestion", "root", cfg.ProjectRoot)
	projectID := cfg.ProjectID
	if projectID == "" {
		projectID = diffindex.DeriveProjectID(cfg.ProjectRoot)
	}

	var (
		wg      sync.WaitGroup
		mivRes  *miv.Result
		mivErr  error
		cs      *diffindex.ChangeSet
		diffErr error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		if cfg.ModelPath == "" {
			mivRes = &miv.Result{Status: miv.StatusWarn, Message: "no model path specified; MIV skipped"}
			return
		}
		mivRes, mivErr = ig.verifier.Verify(ctx, cfg.ModelPath)
	}()

	go func() {
		defer wg.Done()
		cs, diffErr = ig.indexer.Diff(ctx, projectID, cfg.ProjectRoot)
	}()

	wg.Wait()

	if diffErr != nil {
		slog.Error("ingestion: differential indexing failed", "component", "ingestion", "err", diffErr)
		return nil, diffErr
	}

	if mivErr != nil || mivRes == nil {
		slog.Warn("ingestion: MIV failed, defaulting to WARN", "component", "ingestion", "err", mivErr)
		mivRes = &miv.Result{Status: miv.StatusWarn, Message: "MIV failed; defaulting to WARN"}
	}

	blockLLM := mivRes.Status == miv.StatusBlock
	changedCount := 0
	if cs != nil {
		changedCount = len(cs.Changed)
	}
	slog.Info("ingestion complete",
		"component", "ingestion",
		"project_id", projectID,
		"changed_files", changedCount,
		"miv_status", mivRes.Status,
		"block_llm", blockLLM,
	)
	return &Result{
		ProjectID: projectID,
		MIV:       mivRes,
		ChangeSet: cs,
		BlockLLM:  blockLLM,
	}, nil
}

// CommitScan persists the file states from cs to the SQLite cache and removes
// entries for deleted files. Call this after a successful scan to advance the
// baseline for the next incremental diff.
//
// Errors are non-fatal — the scan report is already written; a commit failure
// only means the next scan will be a full scan instead of a diff.
//
// Parameters:
//   - ctx: cancellation context.
//   - projectID: the resolved project ID from Result.ProjectID.
//   - cs: the ChangeSet from Result.ChangeSet.
func (ig *Ingester) CommitScan(ctx context.Context, projectID string, cs *diffindex.ChangeSet) error {
	slog.Debug("committing scan state", "component", "ingestion", "project_id", projectID)
	if cs == nil {
		return nil
	}
	return ig.indexer.Commit(ctx, projectID, cs)
}
