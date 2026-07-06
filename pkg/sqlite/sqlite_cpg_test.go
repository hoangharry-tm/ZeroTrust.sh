package sqlite

import (
	"fmt"
	"testing"

	_ "modernc.org/sqlite"
)

func TestGetEdgesTo_ReturnsIncomingEdges(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	proj := "proj"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", []CPGNode{
		{ID: "n1", Name: "caller1"},
		{ID: "n2", Name: "caller2"},
		{ID: "n3", Name: "callee"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []CPGEdge{
		{FromID: "n1", ToID: "n3", EdgeType: "CALL"},
		{FromID: "n2", ToID: "n3", EdgeType: "CALL"},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	cur, err := db.GetEdgesTo(ctx, proj, ver, "n3")
	if err != nil {
		t.Fatalf("GetEdgesTo: %v", err)
	}
	defer cur.Close()

	var edges []CPGEdge
	for cur.Next() {
		e, scanErr := cur.Scan()
		if scanErr != nil {
			t.Fatalf("Scan: %v", scanErr)
		}
		edges = append(edges, e)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges to n3, got %d", len(edges))
	}
	if edges[0].FromID != "n1" && edges[0].FromID != "n2" {
		t.Errorf("unexpected from_id: %s", edges[0].FromID)
	}
}

func TestGetEdgesTo_EmptyForUnknownNode(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()

	cur, err := db.GetEdgesTo(ctx, "proj", "v1", "nonexistent")
	if err != nil {
		t.Fatalf("GetEdgesTo: %v", err)
	}
	defer cur.Close()
	if cur.Next() {
		t.Error("expected no rows for unknown node")
	}
}

func TestGetEdgesTo_IsolatedByProjectAndVersion(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()

	if err := db.IngestEdgeBatch(ctx, "proj-a", "v1", []CPGEdge{{FromID: "n1", ToID: "n3", EdgeType: "CALL"}}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, "proj-b", "v1", []CPGEdge{{FromID: "n2", ToID: "n3", EdgeType: "CALL"}}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	cur, err := db.GetEdgesTo(ctx, "proj-a", "v1", "n3")
	if err != nil {
		t.Fatalf("GetEdgesTo: %v", err)
	}
	defer cur.Close()
	count := 0
	for cur.Next() {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 edge for proj-a, got %d", count)
	}
}

func TestIngestNodeBatch_MultiPage(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	proj := "proj"
	ver := "v1"

	var nodes []CPGNode
	for i := range 1500 {
		nodes = append(nodes, CPGNode{
			ID:   intToNodeID(i),
			Name: nodeName(i),
		})
	}

	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", nodes); err != nil {
		t.Fatalf("IngestNodeBatch 1500 nodes: %v", err)
	}

	cur, err := db.QueryNodesByType(ctx, proj, ver, "METHOD")
	if err != nil {
		t.Fatalf("QueryNodesByType: %v", err)
	}
	defer cur.Close()

	count := 0
	for cur.Next() {
		_, scanErr := cur.Scan()
		if scanErr != nil {
			t.Fatalf("Scan: %v", scanErr)
		}
		count++
	}
	if count != 1500 {
		t.Errorf("expected 1500 nodes, got %d", count)
	}
}

func TestIngestEdgeBatch_CallersQueryableAfter(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	proj := "proj"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", []CPGNode{
		{ID: "caller1", Name: "CallerOne"},
		{ID: "caller2", Name: "CallerTwo"},
		{ID: "target", Name: "TargetFunc"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []CPGEdge{
		{FromID: "caller1", ToID: "target", EdgeType: "CALL"},
		{FromID: "caller2", ToID: "target", EdgeType: "CALL"},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	cur, err := db.GetCallers(ctx, proj, ver, "target")
	if err != nil {
		t.Fatalf("GetCallers: %v", err)
	}
	defer cur.Close()

	var callers []string
	for cur.Next() {
		n, scanErr := cur.Scan()
		if scanErr != nil {
			t.Fatalf("Scan: %v", scanErr)
		}
		callers = append(callers, n.Name)
	}
	if len(callers) != 2 {
		t.Fatalf("expected 2 callers, got %d", len(callers))
	}
	if (callers[0] != "CallerOne" && callers[0] != "CallerTwo") ||
		(callers[1] != "CallerOne" && callers[1] != "CallerTwo") {
		t.Errorf("unexpected callers: %v", callers)
	}
}

func TestGetNeighboursAtDepth_ReturnsNeighbours(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()
	proj := "proj"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, "METHOD", []CPGNode{
		{ID: "root", Name: "RootFunc"},
		{ID: "child1", Name: "ChildOne"},
		{ID: "child2", Name: "ChildTwo"},
		{ID: "grandchild", Name: "Grandchild"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []CPGEdge{
		{FromID: "root", ToID: "child1", EdgeType: "CALL"},
		{FromID: "root", ToID: "child2", EdgeType: "CALL"},
		{FromID: "child1", ToID: "grandchild", EdgeType: "CALL"},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	cur, err := db.GetNeighboursAtDepth(ctx, proj, ver, "root", 2)
	if err != nil {
		t.Fatalf("GetNeighboursAtDepth: %v", err)
	}
	defer cur.Close()

	var found []string
	for cur.Next() {
		n, scanErr := cur.Scan()
		if scanErr != nil {
			t.Fatalf("Scan: %v", scanErr)
		}
		found = append(found, n.Name)
	}

	expected := map[string]bool{"ChildOne": true, "ChildTwo": true, "Grandchild": true}
	if len(found) != len(expected) {
		t.Errorf("expected %d neighbours, got %d: %v", len(expected), len(found), found)
	}
	for _, name := range found {
		if !expected[name] {
			t.Errorf("unexpected neighbour: %s", name)
		}
	}
}

func TestRecordBuild_RoundTrip(t *testing.T) {
	db, cleanup := tempDB(t)
	defer cleanup()
	ctx := t.Context()

	if err := db.RecordBuild(ctx, "proj", "v1", "hash123", 100, 500); err != nil {
		t.Fatalf("RecordBuild: %v", err)
	}

	ver, ok, err := db.GetCPGVersion(ctx, "proj")
	if err != nil {
		t.Fatalf("GetCPGVersion: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true after RecordBuild")
	}
	if ver != "v1" {
		t.Errorf("expected version v1, got %s", ver)
	}
}

func intToNodeID(i int) string {
	return fmt.Sprintf("n%07d", i)
}

func nodeName(i int) string {
	return fmt.Sprintf("func_%c_%d", 'A'+(i%26), i)
}
