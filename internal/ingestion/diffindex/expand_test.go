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

package diffindex

import (
	"context"
	"errors"
	"testing"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// ─── mock Graph ──────────────────────────────────────────────────────────────

// mockGraph is a minimal cpg.Graph that returns pre-configured nodes for
// specified files, and empty results for everything else.
type mockGraph struct {
	// nodesByFile maps relPath → []cpg.Node
	nodesByFile map[string][]cpg.Node
	// callersByID maps nodeID → caller nodes
	callersByID map[string][]cpg.Node
	// calleesByID maps nodeID → callee nodes
	calleesByID map[string][]cpg.Node
	// queryNodesByFileErr, if non-nil, is returned by QueryNodesByFile.
	queryNodesByFileErr error
}

func (m *mockGraph) QueryNodesByFile(relPath string, _ cpg.NodeType) ([]cpg.Node, error) {
	if m.queryNodesByFileErr != nil {
		return nil, m.queryNodesByFileErr
	}
	return m.nodesByFile[relPath], nil
}

func (m *mockGraph) GetCallers(id string) ([]cpg.Node, error) {
	return m.callersByID[id], nil
}

func (m *mockGraph) GetCallees(id string) ([]cpg.Node, error) {
	return m.calleesByID[id], nil
}

// Unused Graph interface methods.
func (m *mockGraph) QueryNodes(_ cpg.NodeType) ([]cpg.Node, error)                   { return nil, nil }
func (m *mockGraph) QueryEdges(_, _ string) ([]cpg.Edge, error)                      { return nil, nil }
func (m *mockGraph) GetCallGraph() (cpg.CallGraph, error)                             { return nil, nil }
func (m *mockGraph) GetNeighboursAtDepth(_ string, _ int) ([]cpg.Node, error)        { return nil, nil }
func (m *mockGraph) TaintPaths(_ []cpg.TaintSource, _ []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}
func (m *mockGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return nil, nil }

// containsFile returns true if file is in the Changed slice.
func containsFile(cs *ChangeSet, file string) bool {
	for _, f := range cs.Changed {
		if f == file {
			return true
		}
	}
	return false
}

// ─── ExpandWithCPG ───────────────────────────────────────────────────────────

func TestExpandWithCPG_NilChangeSet_ReturnsNil(t *testing.T) {
	g := &mockGraph{}
	out, err := ExpandWithCPG(context.Background(), nil, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil output for nil input, got %+v", out)
	}
}

func TestExpandWithCPG_EmptyChangeSet_ReturnsSamePointer(t *testing.T) {
	cs := &ChangeSet{Changed: []string{}}
	g := &mockGraph{}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != cs {
		t.Error("expected same ChangeSet pointer for empty input")
	}
}

func TestExpandWithCPG_NoNeighbours_ReturnsSamePointer(t *testing.T) {
	cs := &ChangeSet{Changed: []string{"pkg/auth/auth.go"}}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"pkg/auth/auth.go": {{ID: "n1", File: "pkg/auth/auth.go"}},
		},
		// No callers or callees registered → no expansion.
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != cs {
		t.Error("expected same ChangeSet pointer when no expansion occurs")
	}
}

func TestExpandWithCPG_CallersExpanded(t *testing.T) {
	cs := &ChangeSet{Changed: []string{"pkg/db/query.go"}}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"pkg/db/query.go": {{ID: "n1", File: "pkg/db/query.go"}},
		},
		callersByID: map[string][]cpg.Node{
			"n1": {{ID: "n2", File: "api/handler.go"}},
		},
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsFile(out, "api/handler.go") {
		t.Error("expected caller file api/handler.go in expanded set")
	}
	if !containsFile(out, "pkg/db/query.go") {
		t.Error("original changed file must remain in expanded set")
	}
}

func TestExpandWithCPG_CalleesExpanded(t *testing.T) {
	cs := &ChangeSet{Changed: []string{"service/user.go"}}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"service/user.go": {{ID: "n1", File: "service/user.go"}},
		},
		calleesByID: map[string][]cpg.Node{
			"n1": {{ID: "n3", File: "repo/user_repo.go"}},
		},
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsFile(out, "repo/user_repo.go") {
		t.Error("expected callee file repo/user_repo.go in expanded set")
	}
}

func TestExpandWithCPG_SameFileCallerIgnored(t *testing.T) {
	// A caller in the same file as the changed function must not create a duplicate.
	cs := &ChangeSet{Changed: []string{"svc/auth.go"}}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"svc/auth.go": {{ID: "n1", File: "svc/auth.go"}},
		},
		callersByID: map[string][]cpg.Node{
			// Caller is in the same file — no new entry expected.
			"n1": {{ID: "n2", File: "svc/auth.go"}},
		},
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No expansion → same pointer.
	if out != cs {
		// Count occurrences of svc/auth.go.
		count := 0
		for _, f := range out.Changed {
			if f == "svc/auth.go" {
				count++
			}
		}
		if count > 1 {
			t.Errorf("svc/auth.go appears %d times in expanded set, want 1", count)
		}
	}
}

func TestExpandWithCPG_QueryError_BestEffortContinues(t *testing.T) {
	// QueryNodesByFile returning an error must not abort; the original set is returned.
	cs := &ChangeSet{Changed: []string{"broken.go"}}
	g := &mockGraph{
		queryNodesByFileErr: errors.New("joern unavailable"),
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// On error we continue best-effort; output should still contain original file.
	if !containsFile(out, "broken.go") {
		t.Error("original file must be preserved on query error")
	}
}

func TestExpandWithCPG_EmptyFileInNeighbour_Skipped(t *testing.T) {
	// Neighbour nodes with empty File field must not add an empty string to Changed.
	cs := &ChangeSet{Changed: []string{"core/logic.go"}}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"core/logic.go": {{ID: "n1", File: "core/logic.go"}},
		},
		callersByID: map[string][]cpg.Node{
			"n1": {
				{ID: "n2", File: ""},          // empty file — must be skipped
				{ID: "n3", File: "util/x.go"}, // valid
			},
		},
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range out.Changed {
		if f == "" {
			t.Error("empty file path must not appear in expanded ChangeSet")
		}
	}
	if !containsFile(out, "util/x.go") {
		t.Error("valid neighbour util/x.go should be included")
	}
}

func TestExpandWithCPG_PreservesRemovedAndAllStates(t *testing.T) {
	cs := &ChangeSet{
		Changed: []string{"pkg/cache/cache.go"},
		Removed: []string{"pkg/cache/old.go"},
		AllStates: []FileState{
			{FilePath: "pkg/cache/cache.go", ContentHash: "abc"},
		},
	}
	g := &mockGraph{
		nodesByFile: map[string][]cpg.Node{
			"pkg/cache/cache.go": {{ID: "n1", File: "pkg/cache/cache.go"}},
		},
		callersByID: map[string][]cpg.Node{
			"n1": {{ID: "n2", File: "cmd/server.go"}},
		},
	}
	out, err := ExpandWithCPG(context.Background(), cs, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Removed) != 1 || out.Removed[0] != "pkg/cache/old.go" {
		t.Errorf("Removed not preserved: %v", out.Removed)
	}
	if len(out.AllStates) != 1 || out.AllStates[0].FilePath != "pkg/cache/cache.go" {
		t.Errorf("AllStates not preserved in expanded ChangeSet: %v", out.AllStates)
	}
}
