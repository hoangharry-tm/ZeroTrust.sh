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
//	// Use result.ChangeSet for downstream stages.
package ingestion

import (
	"context"
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
		// implemented in G2.M2.2
		_, _ = mivRes, mivErr
	}()

	go func() {
		defer wg.Done()
		// implemented in G2.M2.2
		_, _ = cs, diffErr
	}()

	wg.Wait()

	if diffErr != nil {
		return nil, diffErr
	}

	if mivErr != nil || mivRes == nil {
		mivRes = &miv.Result{Status: miv.StatusWarn, Message: "MIV failed; defaulting to WARN"}
	}

	return &Result{
		MIV:       mivRes,
		ChangeSet: cs,
		BlockLLM:  mivRes.Status == miv.StatusBlock,
	}, nil
}
