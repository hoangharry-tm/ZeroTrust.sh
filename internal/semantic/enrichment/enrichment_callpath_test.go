package enrichment

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	cpg "github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
)

// callPathMockGraph implements cpg.Graph for CallPath augmentation tests.
type callPathMockGraph struct {
	cpg.Graph
	getCalleesFunc  func(id string) ([]cpg.Node, error)
	projectWideFunc func(ids []string, lang string) ([]cpg.TaintPath, error)
}

func (m *callPathMockGraph) GetCallers(id string) ([]cpg.Node, error) { return nil, nil }

func (m *callPathMockGraph) GetCallees(id string) ([]cpg.Node, error) {
	if m.getCalleesFunc != nil {
		return m.getCalleesFunc(id)
	}
	return nil, nil
}

func (m *callPathMockGraph) ProjectWideTaintPaths(ids []string, lang string) ([]cpg.TaintPath, error) {
	if m.projectWideFunc != nil {
		return m.projectWideFunc(ids, lang)
	}
	return nil, nil
}

func (m *callPathMockGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) { return nil, nil }

func (m *callPathMockGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	return nil, nil
}

func (m *callPathMockGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error) { return nil, nil }

func (m *callPathMockGraph) GetCallGraph() (cpg.CallGraph, error) { return nil, nil }

func (m *callPathMockGraph) GetNeighboursAtDepth(rootID string, depth int) ([]cpg.Node, error) {
	return nil, nil
}

func (m *callPathMockGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}

func (m *callPathMockGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return nil, nil }

func TestCalleeNamesAugmentCallPath_ContainsExecuteQuery(t *testing.T) {
	mock := &callPathMockGraph{
		projectWideFunc: func(ids []string, lang string) ([]cpg.TaintPath, error) {
			return nil, nil
		},
		getCalleesFunc: func(id string) ([]cpg.Node, error) {
			return []cpg.Node{
				{Name: "executeQuery"},
				{Name: "processResults"},
			}, nil
		},
	}

	e := New(mock, "nonexistent", true)
	surfaces := []targeting.Surface{{
		ID:           "test-surface",
		File:         "test.go",
		FunctionName: "myFunc",
	}}

	enriched, err := e.Enrich(context.Background(), surfaces, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched surface, got %d", len(enriched))
	}

	es := enriched[0]
	found := false
	for _, cp := range es.CallPath {
		if cp == "executeQuery" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CallPath to contain 'executeQuery' (from callee names), got %v", es.CallPath)
	}
}

func TestCalleeNamesAugmentCallPath_OperatorNodesExcluded(t *testing.T) {
	mock := &callPathMockGraph{
		projectWideFunc: func(ids []string, lang string) ([]cpg.TaintPath, error) {
			return nil, nil
		},
		getCalleesFunc: func(id string) ([]cpg.Node, error) {
			return []cpg.Node{
				{Name: "executeQuery"},
				{Name: "<operator>.assignment"},
				{Name: "<operator>.addition"},
			}, nil
		},
	}

	e := New(mock, "nonexistent", true)
	surfaces := []targeting.Surface{{
		ID:           "test-surface-2",
		File:         "test.go",
		FunctionName: "myFunc",
	}}

	enriched, err := e.Enrich(context.Background(), surfaces, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched surface, got %d", len(enriched))
	}

	es := enriched[0]
	for _, cp := range es.CallPath {
		if cp == "<operator>.assignment" || cp == "<operator>.addition" {
			t.Errorf("operator node %q should be excluded from CallPath, got %v", cp, es.CallPath)
		}
	}
	found := false
	for _, cp := range es.CallPath {
		if cp == "executeQuery" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CallPath to contain 'executeQuery', got %v", es.CallPath)
	}
}

func TestCalleeNamesAugmentCallPath_NoAugmentWhenCallPathLong(t *testing.T) {
	// When intermediate nodes populate CallPath to >= 3, the callee name
	// augmentation should be skipped (len(es.CallPath) < 3 guard).
	mock := &callPathMockGraph{
		projectWideFunc: func(ids []string, lang string) ([]cpg.TaintPath, error) {
			return []cpg.TaintPath{{
				Source: cpg.TaintSource{NodeID: "test-surface-3"},
				Sink:   cpg.TaintSink{Name: "db.Query"},
				IntermediateNodes: []cpg.Node{
					{Name: "node1"},
					{Name: "node2"},
					{Name: "node3"},
				},
			}}, nil
		},
		getCalleesFunc: func(id string) ([]cpg.Node, error) {
			return []cpg.Node{{Name: "shouldNotAppear"}}, nil
		},
	}

	e := New(mock, "nonexistent", true)
	surfaces := []targeting.Surface{{
		ID:           "test-surface-3",
		File:         "test.go",
		FunctionName: "myFunc",
	}}

	enriched, err := e.Enrich(context.Background(), surfaces, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched surface, got %d", len(enriched))
	}

	es := enriched[0]
	// CallPath should have 4 entries (3 intermediate + sink label from direct attribution)
	// "shouldNotAppear" from callee names should NOT be added because CallPath >= 3
	if len(es.CallPath) < 4 {
		t.Errorf("expected CallPath to have at least 4 entries (3 intermediate + sink), got %d: %v", len(es.CallPath), es.CallPath)
	}
	for _, cp := range es.CallPath {
		if cp == "shouldNotAppear" {
			t.Errorf("callee name 'shouldNotAppear' should NOT be in CallPath when >= 3 entries, got %v", es.CallPath)
		}
	}
}
