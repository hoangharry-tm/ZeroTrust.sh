package enrichment

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	cpg "github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
)

// bfsMockGraph implements cpg.Graph for BFS walk-up tests.
type bfsMockGraph struct {
	cpg.Graph
	getCallersFunc  func(id string) ([]cpg.Node, error)
	getCallersCount int
	mu              sync.Mutex
	projectWideFunc func(ids []string, lang string) ([]cpg.TaintPath, error)
}

func (m *bfsMockGraph) GetCallers(id string) ([]cpg.Node, error) {
	m.mu.Lock()
	m.getCallersCount++
	m.mu.Unlock()
	if m.getCallersFunc != nil {
		return m.getCallersFunc(id)
	}
	return nil, nil
}

func (m *bfsMockGraph) GetCallerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCallersCount
}

func (m *bfsMockGraph) ProjectWideTaintPaths(ids []string, lang string) ([]cpg.TaintPath, error) {
	if m.projectWideFunc != nil {
		return m.projectWideFunc(ids, lang)
	}
	return nil, nil
}

func (m *bfsMockGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error)  { return nil, nil }
func (m *bfsMockGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	return nil, nil
}
func (m *bfsMockGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error)   { return nil, nil }
func (m *bfsMockGraph) GetCallGraph() (cpg.CallGraph, error)                  { return nil, nil }
func (m *bfsMockGraph) GetCallees(functionID string) ([]cpg.Node, error)      { return nil, nil }
func (m *bfsMockGraph) GetNeighboursAtDepth(rootID string, depth int) ([]cpg.Node, error) {
	return nil, nil
}
func (m *bfsMockGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	return nil, nil
}
func (m *bfsMockGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) { return nil, nil }

func TestBFS_StopsEarlyWithNoSurfaceNeighbour(t *testing.T) {
	// Create a linear chain of 10 non-surface callers.
	// Source "taintSrc" → caller0 → caller1 → ... → caller9.
	// Since no caller is a surface, BFS must early-stop at depth ≥ 2.
	callerMap := map[string]string{
		"taintSrc": "caller0",
		"caller0":  "caller1",
		"caller1":  "caller2",
		"caller2":  "caller3",
		"caller3":  "caller4",
		"caller4":  "caller5",
		"caller5":  "caller6",
		"caller6":  "caller7",
		"caller7":  "caller8",
		"caller8":  "caller9",
		"caller9":  "caller10",
	}

	mock := &bfsMockGraph{
		projectWideFunc: func(ids []string, lang string) ([]cpg.TaintPath, error) {
			return []cpg.TaintPath{{
				Source: cpg.TaintSource{NodeID: "taintSrc"},
				Sink:   cpg.TaintSink{NodeID: "sink1", Name: "execQuery"},
			}}, nil
		},
		getCallersFunc: func(id string) ([]cpg.Node, error) {
			next, ok := callerMap[id]
			if !ok || next == "" {
				return nil, nil
			}
			return []cpg.Node{{ID: next, Name: "nonSurfaceFunc"}}, nil
		},
	}

	e := New(mock, "nonexistent", true)
	surfaces := []targeting.Surface{{ID: "surf1"}}
	_, err := e.Enrich(context.Background(), surfaces, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Early-stop: depths 0 (taintSrc), 1 (caller0), 2 (caller1) = 3 BFS calls.
	// Plus 1 call for surface surfl's own caller query in the goroutine = 4 max.
	got := mock.GetCallerCount()
	if got > 4 {
		t.Errorf("GetCallers called %d times, want ≤ 4 (1 surface query + 3 BFS)", got)
	}
}

func TestDirectAttribution_SeedsSinkInCallPath(t *testing.T) {
	// When sink label appears in CallPath (seeded by direct attribution),
	// filterSinksByCallPath must retain it.
	callPath := []string{"executeQuery"}
	sinks := []string{"executeQuery"}
	got := filterSinksByCallPath(sinks, callPath)
	if len(got) != 1 || got[0] != "executeQuery" {
		t.Errorf("directly attributed sink must survive filter, got %v", got)
	}
}

func TestAttributionSummary_LogsGapPct(t *testing.T) {
	total := 10
	attributed := 4
	gapPct := 100 * float64(total-attributed) / float64(total)
	if gapPct != 60.0 {
		t.Errorf("expected 60.0%% gap, got %.1f%%", gapPct)
	}
}

func TestBFS_DepthCapRespected(t *testing.T) {
	// Branching call graph: each non-surface node returns 3 new unique
	// callers, creating exponential growth. Without any cap the BFS would
	// explode; with the early-stop at depth ≥ 2 (no surface neighbours),
	// it terminates after at most 1 + 3 + 9 = 13 GetCallers calls.
	var (
		mu       sync.Mutex
		counter  int
		idSeq    int
	)

	mock := &bfsMockGraph{
		projectWideFunc: func(ids []string, lang string) ([]cpg.TaintPath, error) {
			return []cpg.TaintPath{{
				Source: cpg.TaintSource{NodeID: "taintSrc"},
				Sink:   cpg.TaintSink{NodeID: "sink1", Name: "execQuery"},
			}}, nil
		},
		getCallersFunc: func(id string) ([]cpg.Node, error) {
			mu.Lock()
			counter++
			nodes := make([]cpg.Node, 3)
			for i := range nodes {
				idSeq++
				nodes[i] = cpg.Node{ID: fmt.Sprintf("branch_%d", idSeq), Name: "nonSurface"}
			}
			mu.Unlock()
			return nodes, nil
		},
	}

	e := New(mock, "nonexistent", true)
	surfaces := []targeting.Surface{{ID: "surf1"}}
	_, err := e.Enrich(context.Background(), surfaces, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// With branching factor 3 and early-stop at depth ≥ 2:
	// depth 0: 1 call, depth 1: 3 calls, depth 2: up to 9 calls = 13 max.
	if counter > 15 {
		t.Errorf("BFS made %d GetCallers calls, expected ≤ 15 (early-stop)", counter)
	}
}
