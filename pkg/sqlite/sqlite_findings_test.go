package sqlite

import (
	"testing"
)

func TestWalkFindingIDs_StreamsAllIDs(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-walk")

	ids := []string{"fid-a", "fid-b", "fid-c", "fid-d", "fid-e"}
	for _, id := range ids {
		if err := db.UpsertFinding(ctx, FindingRow{
			FindingID: id,
			ProjectID: "proj",
			RunID:     "run-walk",
			FilePath:  "a.go",
			LineStart: 1,
			LineEnd:   1,
			Severity:  "LOW",
			Confidence: 0.5,
			SourcePath: "TEST",
		}); err != nil {
			t.Fatalf("UpsertFinding %s: %v", id, err)
		}
	}

	var walked []string
	err := db.WalkFindingIDs(ctx, "proj", func(id string) error {
		walked = append(walked, id)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFindingIDs: %v", err)
	}
	if len(walked) != 5 {
		t.Fatalf("expected 5 IDs, got %d: %v", len(walked), walked)
	}

	seen := make(map[string]bool, len(walked))
	for _, id := range walked {
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Errorf("missing ID %s", id)
		}
	}
}

func TestWalkFindingIDs_EmptyProject(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()

	called := false
	err := db.WalkFindingIDs(ctx, "empty", func(id string) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("WalkFindingIDs: %v", err)
	}
	if called {
		t.Error("callback should not be invoked for empty project")
	}
}

func TestWalkFindingIDs_CallbackErrorStops(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-err")

	for i := range 10 {
		if err := db.UpsertFinding(ctx, FindingRow{
			FindingID:  findingID(i),
			ProjectID:  "proj",
			RunID:      "run-err",
			FilePath:   "a.go",
			LineStart:  1,
			LineEnd:    1,
			Severity:   "LOW",
			Confidence: 0.5,
			SourcePath: "TEST",
		}); err != nil {
			t.Fatalf("UpsertFinding %d: %v", i, err)
		}
	}

	var walked []string
	err := db.WalkFindingIDs(ctx, "proj", func(id string) error {
		walked = append(walked, id)
		if len(walked) >= 3 {
			return errStopWalk
		}
		return nil
	})
	if err != errStopWalk {
		t.Fatalf("expected errStopWalk, got %v", err)
	}
	if len(walked) != 3 {
		t.Errorf("expected 3 walked, got %d", len(walked))
	}
}

func TestListFindingIDs_DeprecatedButWorks(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	setupProjectAndRun(t, db, "proj", "run-old")

	for i := range 3 {
		if err := db.UpsertFinding(ctx, FindingRow{
			FindingID:  findingID(i),
			ProjectID:  "proj",
			RunID:      "run-old",
			FilePath:   "a.go",
			LineStart:  1,
			LineEnd:    1,
			Severity:   "LOW",
			Confidence: 0.5,
			SourcePath: "TEST",
		}); err != nil {
			t.Fatalf("UpsertFinding %d: %v", i, err)
		}
	}

	ids, err := db.ListFindingIDs(ctx, "proj")
	if err != nil {
		t.Fatalf("ListFindingIDs: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 IDs, got %d", len(ids))
	}
}

var errStopWalk = errWalkStop()

type stopWalkErr struct{}

func (e *stopWalkErr) Error() string { return "stop walk" }

func errWalkStop() error { return &stopWalkErr{} }

func findingID(i int) string {
	return "fid-" + string(rune('0'+i%10))
}
