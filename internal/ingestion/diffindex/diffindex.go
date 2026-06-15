// Package diffindex implements the Differential Indexer.
// It compares the current file set against a SQLite state cache and returns only
// files that are new or changed, reducing repeat-scan cost by ~80–95%.
package diffindex

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// FileState records the cached state of one file from a prior scan.
type FileState struct {
	ProjectID     string
	FilePath      string
	ContentHash   string
	LastScannedAt int64
}

// ChangeSet is the output of a differential comparison.
type ChangeSet struct {
	Changed []string // new or modified file paths relative to project root
	Removed []string // files present in the prior scan but absent now
}

// Indexer computes the differential file set for each scan.
type Indexer struct {
	db *sqlite.DB
}

// New returns an Indexer backed by db.
func New(db *sqlite.DB) *Indexer {
	return &Indexer{db: db}
}

// Diff compares files under projectRoot against the cached state for projectID.
// On first scan all files are returned as Changed.
func (i *Indexer) Diff(ctx context.Context, projectID, projectRoot string) (*ChangeSet, error) {
	// implemented in G2.M2.2
	return &ChangeSet{}, nil
}

// Commit persists the current file states for projectID, replacing any prior state.
func (i *Indexer) Commit(ctx context.Context, projectID string, states []FileState) error {
	// implemented in G2.M2.2
	return nil
}
