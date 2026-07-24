//go:build integration

package cpg_engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// tempPostgresDB opens a DB against $DATABASE_URL, skipping the test if unset.
// Unlike the SQLite era (a fresh file per test), this connects to whatever
// disposable Postgres instance CI/local dev points DATABASE_URL at — rows
// aren't cleaned up between tests, so each test uses a distinct project ID.
func tempPostgresDB(t *testing.T) *postgres.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres-backed integration test")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSetDBBackend_PropagatesToNewGraphs(t *testing.T) {
	db := tempPostgresDB(t)
	srv := mockServer(t, func(q string) (string, bool) {
		return "[]", true
	})
	c := newTestClient(t, srv)

	// Graphs created before SetDBBackend — reads from Client, so nil
	g0 := c.newGraph(context.Background())
	if g0.pgDB() != nil {
		t.Error("expected nil db from Client before SetDBBackend")
	}

	// Set backend
	c.SetDBBackend(db, "proj-test", "v1")

	// g0 (created before) now picks up the backend via Client — this is the
	// critical behaviour that prevents stale-graph bugs in the scan pipeline.
	if g0.pgDB() == nil {
		t.Fatal("expected g0 to see backend via Client after SetDBBackend")
	}
	if g0.pgProjectID() != "proj-test" {
		t.Errorf("g0 projectID: got %q, want %q", g0.pgProjectID(), "proj-test")
	}
	if g0.pgCPGVersion() != "v1" {
		t.Errorf("g0 cpgVersion: got %q, want %q", g0.pgCPGVersion(), "v1")
	}

	// g1 (created after) should also see the backend.
	g1 := c.newGraph(context.Background())
	if g1.pgDB() == nil {
		t.Fatal("expected non-nil db after SetDBBackend")
	}
	if g1.pgProjectID() != "proj-test" {
		t.Errorf("g1 projectID: got %q, want %q", g1.pgProjectID(), "proj-test")
	}
	if g1.pgCPGVersion() != "v1" {
		t.Errorf("g1 cpgVersion: got %q, want %q", g1.pgCPGVersion(), "v1")
	}
}

func TestQueryNodes_ReadsFromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-sqlite"
	ver := "v1"

	// Pre-populate DB with method nodes
	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "m1", Name: "handleRequest", File: "server.go", Line: 10, Code: "def handleRequest"},
		{ID: "m2", Name: "validateInput", File: "validate.go", Line: 5, Code: "def validateInput"},
		{ID: "m3", Name: "processData", File: "process.go", Line: 20, Code: "def processData"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}

	// Mock server that should NOT be called (DB has data)
	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	nodes, err := g.QueryNodes(NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls when DB has data, got %d", httpCalls)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	if nodes[0].Name != "handleRequest" {
		t.Errorf("first node name: got %q, want %q", nodes[0].Name, "handleRequest")
	}
}

func TestQueryNodes_ReturnsEmptyFromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-empty"
	ver := "v1"

	// DB has no nodes — should return empty, NOT fall back to HTTP
	httpCalled := make(chan struct{}, 1)
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalled <- struct{}{}
		return jsonArray(t, []joernNode{
			{ID: "m1", Name: "fromHTTP", File: "fallback.go", Line: 1, Type: "METHOD"},
		}), true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	nodes, err := g.QueryNodes(NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	select {
	case <-httpCalled:
		t.Error("DB returned empty — should not have fallen back to HTTP")
	default:
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes from empty DB, got %d", len(nodes))
	}
}

func TestGetCallers_ReadsFromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-callers"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "caller1", Name: "AuthMiddleware"},
		{ID: "caller2", Name: "RateLimiter"},
		{ID: "target", Name: "HandleRequest"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []postgres.CPGEdge{
		{FromID: "caller1", ToID: "target", EdgeType: "CALL"},
		{FromID: "caller2", ToID: "target", EdgeType: "CALL"},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	callers, err := g.GetCallers("target")
	if err != nil {
		t.Fatalf("GetCallers: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls, got %d", httpCalls)
	}
	if len(callers) != 2 {
		t.Fatalf("expected 2 callers, got %d", len(callers))
	}
}

func TestGetCallees_ReadsFromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-callees"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "caller", Name: "MainHandler"},
		{ID: "callee1", Name: "ValidateInput"},
		{ID: "callee2", Name: "SanitizeOutput"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []postgres.CPGEdge{
		{FromID: "caller", ToID: "callee1", EdgeType: string(EdgeCall)},
		{FromID: "caller", ToID: "callee2", EdgeType: string(EdgeCall)},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	callees, err := g.GetCallees("caller")
	if err != nil {
		t.Fatalf("GetCallees: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls, got %d", httpCalls)
	}
	if len(callees) != 2 {
		t.Fatalf("expected 2 callees, got %d", len(callees))
	}
}

func TestGetCallGraph_FromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-cg"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "a", Name: "A"}, {ID: "b", Name: "B"}, {ID: "c", Name: "C"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []postgres.CPGEdge{
		{FromID: "a", ToID: "b", EdgeType: string(EdgeCall)},
		{FromID: "a", ToID: "c", EdgeType: string(EdgeCall)},
		{FromID: "b", ToID: "c", EdgeType: string(EdgeCall)},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	cg, err := g.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls, got %d", httpCalls)
	}
	if len(cg["a"]) != 2 {
		t.Errorf("expected 2 callees from 'a', got %d", len(cg["a"]))
	}
	if len(cg["b"]) != 1 {
		t.Errorf("expected 1 callee from 'b', got %d", len(cg["b"]))
	}
}

func TestGetNeighboursAtDepth_FromDBUsesRecursiveCTE(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-bfs"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "root", Name: "Root"},
		{ID: "l1a", Name: "Level1A"},
		{ID: "l1b", Name: "Level1B"},
		{ID: "l2", Name: "Level2"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}
	if err := db.IngestEdgeBatch(ctx, proj, ver, []postgres.CPGEdge{
		{FromID: "root", ToID: "l1a", EdgeType: string(EdgeCall)},
		{FromID: "root", ToID: "l1b", EdgeType: "CALL"},
		{FromID: "l1a", ToID: "l2", EdgeType: "CALL"},
	}); err != nil {
		t.Fatalf("IngestEdgeBatch: %v", err)
	}

	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	nodes, err := g.GetNeighboursAtDepth("root", 2)
	if err != nil {
		t.Fatalf("GetNeighboursAtDepth: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls (recursive CTE), got %d", httpCalls)
	}

	found := make(map[string]bool)
	for _, n := range nodes {
		found[n.Name] = true
	}
	for _, name := range []string{"Level1A", "Level1B", "Level2"} {
		if !found[name] {
			t.Errorf("missing neighbour: %s", name)
		}
	}
}

func TestQueryNodesByFile_FromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-file"
	ver := "v1"

	if err := db.IngestNodeBatch(ctx, proj, ver, string(NodeMethod), []postgres.CPGNode{
		{ID: "m1", Name: "Handler", File: "server.go"},
		{ID: "m2", Name: "Helper", File: "util.go"},
	}); err != nil {
		t.Fatalf("IngestNodeBatch: %v", err)
	}

	httpCalls := 0
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalls++
		return "[]", true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	nodes, err := g.QueryNodesByFile("server.go", NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodesByFile: %v", err)
	}
	if httpCalls > 0 {
		t.Errorf("expected 0 HTTP calls, got %d", httpCalls)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Name != "Handler" {
		t.Errorf("name: got %q, want %q", nodes[0].Name, "Handler")
	}
}

func TestQueryNodesByFile_EmptyFromDB(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-empty"
	ver := "v1"

	httpCalled := make(chan struct{}, 1)
	srv := mockServer(t, func(q string) (string, bool) {
		httpCalled <- struct{}{}
		return jsonArray(t, []joernNode{
			{ID: "m1", Name: "FromHTTP", File: "server.go", Type: "METHOD"},
		}), true
	})
	c := newTestClient(t, srv)
	c.SetDBBackend(db, proj, ver)
	g := c.GraphWithContext(ctx)

	nodes, err := g.QueryNodesByFile("server.go", NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodesByFile: %v", err)
	}
	select {
	case <-httpCalled:
		t.Error("DB returned empty — should not have fallen back to HTTP")
	default:
	}
	if len(nodes) != 0 {
		t.Errorf("expected empty result from DB, got %d nodes", len(nodes))
	}
}

func TestIngestCPGToDB_SinglePageDrain(t *testing.T) {
	db := tempPostgresDB(t)
	ctx := context.Background()
	proj := "proj-drain"
	ver := "v1"

	// Generate 50 methods and 50 calls (fits in one page of 500).
	var methods []joernNode
	var calls []joernNode
	for i := range 50 {
		methods = append(methods, joernNode{
			ID:   fmt.Sprintf("m%07d", i),
			Name: fmt.Sprintf("func_%d", i),
			File: fmt.Sprintf("file_%d.go", i%10),
			Line: i,
			Type: "METHOD",
		})
		calls = append(calls, joernNode{
			ID:   fmt.Sprintf("c%07d", i),
			Name: fmt.Sprintf("call_%d", i),
			File: fmt.Sprintf("file_%d.go", i%10),
			Line: i,
			Type: "CALL",
		})
	}
	var edges []joernEdge
	for i := range 100 {
		edges = append(edges, joernEdge{
			From: fmt.Sprintf("m%07d", i%50),
			To:   fmt.Sprintf("m%07d", (i+1)%50),
			Type: "CALL",
		})
	}

	methodJSON := jsonArray(t, methods)
	callJSON := jsonArray(t, calls)
	edgeJSON := jsonArray(t, edges)

	srv := mockServer(t, func(q string) (string, bool) {
		switch {
		case q == `1+1`:
			return "2", true
		case strings.Contains(q, ".drop(500)"):
			return "[]", true // page 2+ is empty
		case strings.Contains(q, "cpg.method"):
			return methodJSON, true
		case strings.Contains(q, "flatMap"):
			return edgeJSON, true
		case strings.Contains(q, "cpg.call"):
			return callJSON, true
		default:
			return "[]", true
		}
	})
	c := newTestClient(t, srv)
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	g := &joernGraph{client: c, ctx: ctx, cache: &joernGraphCache{
		methodCache: make(map[NodeType][]Node),
		edgeCache:   make(map[string][]Edge),
	}}

	if err := g.IngestCPGToDB(ctx, db, proj, ver); err != nil {
		t.Fatalf("IngestCPGToDB: %v", err)
	}

	// Verify nodes by type
	methodCur, err := db.QueryNodesByType(ctx, proj, ver, "METHOD")
	if err != nil {
		t.Fatalf("QueryNodesByType METHOD: %v", err)
	}
	defer methodCur.Close()
	methodCount := 0
	for methodCur.Next() {
		methodCount++
	}
	if methodCount != 50 {
		t.Errorf("expected 50 METHOD nodes, got %d", methodCount)
	}

	callCur, err := db.QueryNodesByType(ctx, proj, ver, "CALL")
	if err != nil {
		t.Fatalf("QueryNodesByType CALL: %v", err)
	}
	defer callCur.Close()
	callCount := 0
	for callCur.Next() {
		callCount++
	}
	if callCount != 50 {
		t.Errorf("expected 50 CALL nodes, got %d", callCount)
	}

	// Verify edges
	edgeCur, err := db.GetEdgesFrom(ctx, proj, ver, "m0000000")
	if err != nil {
		t.Fatalf("GetEdgesFrom: %v", err)
	}
	defer edgeCur.Close()
	eCount := 0
	for edgeCur.Next() {
		eCount++
	}
	if eCount == 0 {
		t.Error("expected at least 1 edge from m0000000")
	}
}
