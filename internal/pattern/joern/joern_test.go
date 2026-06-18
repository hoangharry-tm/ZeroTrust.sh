package joern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// mockServer starts an httptest.Server implementing the Joern async HTTP API:
//   - POST /query         → submit request, returns {success:true, uuid:"<id>"}
//   - GET  /result/{uuid} → poll for result, returns {success:bool, stdout:"...", ...}
//
// queryFn is called with the raw query string; it returns the stdout payload
// and whether the query should succeed.
func mockServer(t *testing.T, queryFn func(query string) (stdout string, success bool)) *httptest.Server {
	t.Helper()
	// pending holds submitted results keyed by uuid for GET /result/{uuid} retrieval.
	var mu sync.Mutex
	pending := make(map[string]queryResultResponse)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/query":
			var req queryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			stdout, ok := queryFn(req.Query)
			uuid := fmt.Sprintf("test-uuid-%d", len(pending)+1)
			result := queryResultResponse{UUID: uuid, Success: ok, Stdout: stdout}
			if !ok {
				result.Stderr = "mock server: query rejected"
			}
			mu.Lock()
			pending[uuid] = result
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(querySubmitResponse{UUID: uuid, Success: true})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/result/"):
			uuid := strings.TrimPrefix(r.URL.Path, "/result/")
			mu.Lock()
			result, ok := pending[uuid]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(result)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient builds a Client pointing at srv with fast ping settings.
func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(
		WithServerURL(srv.URL),
		WithQueryTimeout(5*time.Second),
		WithBuildTimeout(10*time.Second),
		WithPingRetries(3),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// jsonArray encodes v as a JSON array string for use as stdout in mock responses.
func jsonArray(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonArray: %v", err)
	}
	return string(b)
}

// ─── New ──────────────────────────────────────────────────────────────────────

func TestNew_DefaultsToLocalhost(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if c.serverURL != defaultServerURL {
		t.Errorf("serverURL = %q, want %q", c.serverURL, defaultServerURL)
	}
}

func TestNew_RejectsRemoteHost(t *testing.T) {
	cases := []struct {
		url  string
		want error
	}{
		{"http://example.com:8080", ErrInvalidServerURL},
		{"http://192.168.1.1:8080", ErrInvalidServerURL},
		{"http://10.0.0.1:8080", ErrInvalidServerURL},
	}
	for _, tc := range cases {
		_, err := New(WithServerURL(tc.url))
		if !errors.Is(err, tc.want) {
			t.Errorf("New(%q) error = %v, want %v", tc.url, err, tc.want)
		}
	}
}

func TestNew_AcceptsLocalhostVariants(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	}
	for _, u := range cases {
		_, err := New(WithServerURL(u))
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", u, err)
		}
	}
}

// ─── Ping ─────────────────────────────────────────────────────────────────────

func TestPing_Success(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return `"pong"`, true })
	c := newTestClient(t, srv)
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping() = %v, want nil", err)
	}
}

func TestPing_ReturnsCrashedWhenFlagSet(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "", true })
	c := newTestClient(t, srv)
	c.crashed.Store(true)

	err := c.Ping(context.Background())
	if !errors.Is(err, ErrJoernCrashed) {
		t.Errorf("Ping() with crashed=true: got %v, want ErrJoernCrashed", err)
	}
}

func TestPing_UnreachableAfterRetries(t *testing.T) {
	// Point at a port with no server.
	c, err := New(
		WithServerURL("http://127.0.0.1:19999"),
		WithPingRetries(2),
		WithQueryTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Ping(context.Background())
	if !errors.Is(err, ErrJoernUnreachable) {
		t.Errorf("Ping() = %v, want ErrJoernUnreachable", err)
	}
}

func TestPing_ContextCancellation(t *testing.T) {
	// Server never responds — ensures we don't hang.
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-blocked
	}))
	t.Cleanup(func() { close(blocked); srv.Close() })

	c, err := New(WithServerURL(srv.URL), WithPingRetries(5), WithQueryTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err = c.Ping(ctx)
	if err == nil {
		t.Error("Ping() = nil, want an error after context timeout")
	}
}

// ─── BuildCPG ─────────────────────────────────────────────────────────────────

func TestBuildCPG_RejectsEmptyPaths(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "", true })
	c := newTestClient(t, srv)
	err := c.BuildCPG(context.Background(), BuildConfig{})
	if !errors.Is(err, ErrEmptyPaths) {
		t.Errorf("BuildCPG(empty paths) = %v, want ErrEmptyPaths", err)
	}
}

func TestBuildCPG_RejectsPathTraversal(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "", true })
	c := newTestClient(t, srv)
	cases := []string{"../secret", "/tmp/../etc/passwd", "a/../../b"}
	for _, p := range cases {
		err := c.BuildCPG(context.Background(), BuildConfig{Paths: []string{p}})
		if !errors.Is(err, ErrPathTraversal) {
			t.Errorf("BuildCPG(%q) = %v, want ErrPathTraversal", p, err)
		}
	}
}

func TestBuildCPG_SendsImportCodeQuery(t *testing.T) {
	var gotQuery string
	srv := mockServer(t, func(q string) (string, bool) {
		gotQuery = q
		return `""`, true
	})
	c := newTestClient(t, srv)
	err := c.BuildCPG(context.Background(), BuildConfig{Paths: []string{"/project/src"}})
	if err != nil {
		t.Fatalf("BuildCPG() = %v", err)
	}
	if gotQuery == "" {
		t.Error("BuildCPG: no query sent to server")
	}
	// Query must reference importCode and the path.
	for _, want := range []string{"importCode", "/project/src"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("BuildCPG query %q missing %q", gotQuery, want)
		}
	}
}

func TestBuildCPG_WithLanguageOverride(t *testing.T) {
	var gotQuery string
	srv := mockServer(t, func(q string) (string, bool) { gotQuery = q; return `""`, true })
	c := newTestClient(t, srv)
	_ = c.BuildCPG(context.Background(), BuildConfig{
		Paths:    []string{"/project/src"},
		Language: "JAVASRC",
	})
	if !strings.Contains(gotQuery, "JAVASRC") {
		t.Errorf("BuildCPG with language: query %q missing JAVASRC", gotQuery)
	}
}

func TestBuildCPG_PropagatesServerError(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "", false })
	c := newTestClient(t, srv)
	err := c.BuildCPG(context.Background(), BuildConfig{Paths: []string{"/project/src"}})
	if err == nil {
		t.Error("BuildCPG: expected error when server returns success=false, got nil")
	}
}

// ─── HTTP transport ────────────────────────────────────────────────────────────

func TestDoQuery_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	c, _ := New(WithServerURL(srv.URL), WithQueryTimeout(2*time.Second))

	_, err := c.doQuery(context.Background(), "1+1")
	if !errors.Is(err, ErrMalformedResponse) {
		t.Errorf("doQuery malformed JSON: got %v, want ErrMalformedResponse", err)
	}
}

func TestDoQuery_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c, _ := New(WithServerURL(srv.URL), WithQueryTimeout(2*time.Second))

	_, err := c.doQuery(context.Background(), "1+1")
	if !errors.Is(err, ErrMalformedResponse) {
		t.Errorf("doQuery 500: got %v, want ErrMalformedResponse", err)
	}
}

func TestDoQuery_ServerReportsFailure(t *testing.T) {
	// success=false with non-empty stderr → real failure, must error.
	srv := mockServer(t, func(_ string) (string, bool) { return "", false })
	c := newTestClient(t, srv)
	_, err := c.doQuery(context.Background(), "bad query")
	if err == nil {
		t.Error("doQuery: expected error for success=false with stderr, got nil")
	}
}

func TestDoQuery_InitTimePollsUntilSuccess(t *testing.T) {
	// Simulates Joern cold-start: success=false + empty stdout+stderr for the
	// first N polls, then a real result. fetchResult must keep polling.
	const initPolls = 5
	var calls int
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/query":
			_ = json.NewEncoder(w).Encode(querySubmitResponse{UUID: "init-uuid", Success: true})
		case r.Method == http.MethodGet && r.URL.Path == "/result/init-uuid":
			mu.Lock()
			n := calls
			calls++
			mu.Unlock()
			if n < initPolls {
				// Simulate Joern REPL not ready yet: success=false, no stderr.
				_ = json.NewEncoder(w).Encode(queryResultResponse{UUID: "init-uuid", Success: false})
			} else {
				_ = json.NewEncoder(w).Encode(queryResultResponse{
					UUID: "init-uuid", Success: true, Stdout: `val res0: Int = 2`,
				})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithServerURL(srv.URL), WithQueryTimeout(2*time.Second), WithPingRetries(3))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.doQuery(ctx, "1+1")
	if err != nil {
		t.Fatalf("doQuery: %v (expected success after init polls)", err)
	}
	if string(out) == "" {
		t.Error("doQuery: expected non-empty result, got empty")
	}
}

// ─── parseStdout ──────────────────────────────────────────────────────────────

func TestParseStdout(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"bare JSON array", `[{"id":"1"}]`, `[{"id":"1"}]`},
		{"REPL annotation", `res0: String = "[{\"id\":\"1\"}]"`, `[{"id":"1"}]`},
		{"Scala string literal", `"[{\"id\":\"1\"}]"`, `[{"id":"1"}]`},
		{"trailing whitespace", `  [{"id":"1"}]  `, `[{"id":"1"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStdout(tc.input)
			if got != tc.want {
				t.Errorf("parseStdout(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─── QueryNodes ───────────────────────────────────────────────────────────────

func TestQueryNodes_Method(t *testing.T) {
	nodes := []joernNode{
		{ID: "1", Name: "getUser", File: "MainController.java", Line: 34},
		{ID: "2", Name: "search", File: "MainController.java", Line: 40},
	}
	srv := mockServer(t, func(_ string) (string, bool) { return jsonArray(t, nodes), true })
	c := newTestClient(t, srv)
	g := c.Graph()

	result, err := g.QueryNodes(cpg.NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("QueryNodes: got %d nodes, want 2", len(result))
	}
	if result[0].Name != "getUser" {
		t.Errorf("node[0].Name = %q, want %q", result[0].Name, "getUser")
	}
	if result[1].Line != 40 {
		t.Errorf("node[1].Line = %d, want 40", result[1].Line)
	}
}

func TestQueryNodes_EmptyResult(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	result, err := g.QueryNodes(cpg.NodeCall)
	if err != nil {
		t.Fatalf("QueryNodes empty: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("QueryNodes empty: got %d nodes, want 0", len(result))
	}
}

func TestQueryNodesByFile_RejectsEmptyPath(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.QueryNodesByFile("", cpg.NodeMethod)
	if err == nil {
		t.Error("QueryNodesByFile(\"\") expected error, got nil")
	}
}

// ─── QueryEdges ───────────────────────────────────────────────────────────────

func TestQueryEdges_BothEmptyReturnsError(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.QueryEdges("", "")
	if err == nil {
		t.Error("QueryEdges(\"\",\"\") expected error, got nil")
	}
}

func TestQueryEdges_FiltersByToID(t *testing.T) {
	edges := []joernEdge{
		{From: "1", To: "2", Type: "CALL"},
		{From: "1", To: "3", Type: "CALL"},
	}
	srv := mockServer(t, func(_ string) (string, bool) { return jsonArray(t, edges), true })
	c := newTestClient(t, srv)
	g := c.Graph()

	result, err := g.QueryEdges("1", "2")
	if err != nil {
		t.Fatalf("QueryEdges: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("QueryEdges filter: got %d edges, want 1", len(result))
	}
	if result[0].ToID != "2" {
		t.Errorf("edge.ToID = %q, want %q", result[0].ToID, "2")
	}
}

// ─── GetCallGraph ─────────────────────────────────────────────────────────────

func TestGetCallGraph_BuildsMap(t *testing.T) {
	edges := []joernEdge{
		{From: "fn:main", To: "fn:helper", Type: "CALL"},
		{From: "fn:main", To: "fn:auth", Type: "CALL"},
		{From: "fn:helper", To: "fn:db", Type: "CALL"},
	}
	srv := mockServer(t, func(_ string) (string, bool) { return jsonArray(t, edges), true })
	c := newTestClient(t, srv)
	g := c.Graph()

	cg, err := g.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph: %v", err)
	}
	if len(cg["fn:main"]) != 2 {
		t.Errorf("cg[main] = %v, want 2 callees", cg["fn:main"])
	}
	if len(cg["fn:helper"]) != 1 || cg["fn:helper"][0] != "fn:db" {
		t.Errorf("cg[helper] = %v, want [fn:db]", cg["fn:helper"])
	}
}

// ─── GetCallers / GetCallees ──────────────────────────────────────────────────

func TestGetCallers_RejectsEmptyID(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.GetCallers("")
	if err == nil {
		t.Error("GetCallers(\"\") expected error, got nil")
	}
}

func TestGetCallees_ReturnsNodes(t *testing.T) {
	nodes := []joernNode{{ID: "2", Name: "db.query", File: "Repo.java", Line: 10}}
	srv := mockServer(t, func(_ string) (string, bool) { return jsonArray(t, nodes), true })
	c := newTestClient(t, srv)
	g := c.Graph()

	result, err := g.GetCallees("1")
	if err != nil {
		t.Fatalf("GetCallees: %v", err)
	}
	if len(result) != 1 || result[0].Name != "db.query" {
		t.Errorf("GetCallees: got %v, want [{db.query}]", result)
	}
}

// ─── GetNeighboursAtDepth ─────────────────────────────────────────────────────

func TestGetNeighboursAtDepth_RejectsDepthOver6(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.GetNeighboursAtDepth("1", 7)
	if !errors.Is(err, ErrDepthExceeded) {
		t.Errorf("GetNeighboursAtDepth(depth=7) = %v, want ErrDepthExceeded", err)
	}
}

func TestGetNeighboursAtDepth_RejectsEmptyRoot(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.GetNeighboursAtDepth("", 2)
	if err == nil {
		t.Error("GetNeighboursAtDepth(\"\",2) expected error, got nil")
	}
}

func TestGetNeighboursAtDepth_BFS(t *testing.T) {
	// Topology: root(1) → A(2) → B(3); 1 has no callers; A has no callers.
	// At depth=2: A (depth 1 callee) + B (depth 2 callee) should be returned.
	callCount := 0
	srv := mockServer(t, func(q string) (string, bool) {
		callCount++
		switch {
		// callers of any node — return empty
		case strings.Contains(q, "caller"):
			return "[]", true
		// callees of root (id=1)
		case strings.Contains(q, "1") && strings.Contains(q, "callee"):
			return jsonArray(t, []joernNode{{ID: "2", Name: "A", File: "f.java", Line: 5}}), true
		// callees of A (id=2)
		case strings.Contains(q, "2") && strings.Contains(q, "callee"):
			return jsonArray(t, []joernNode{{ID: "3", Name: "B", File: "f.java", Line: 10}}), true
		default:
			return "[]", true
		}
	})
	c := newTestClient(t, srv)
	g := c.Graph()

	result, err := g.GetNeighboursAtDepth("1", 2)
	if err != nil {
		t.Fatalf("GetNeighboursAtDepth: %v", err)
	}
	// Expect A and B (not root itself).
	got := make(map[string]bool)
	for _, n := range result {
		got[n.Name] = true
	}
	if !got["A"] || !got["B"] {
		t.Errorf("GetNeighboursAtDepth BFS: got names %v, want A and B", got)
	}
}

// ─── TaintPaths ───────────────────────────────────────────────────────────────

func TestTaintPaths_RejectsEmptySources(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.TaintPaths(nil, []cpg.TaintSink{{NodeID: "1", Kind: cpg.SinkSQL}})
	if err == nil {
		t.Error("TaintPaths(nil sources) expected error, got nil")
	}
}

func TestTaintPaths_RejectsEmptySinks(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "[]", true })
	c := newTestClient(t, srv)
	g := c.Graph()

	_, err := g.TaintPaths([]cpg.TaintSource{{NodeID: "1"}}, nil)
	if err == nil {
		t.Error("TaintPaths(nil sinks) expected error, got nil")
	}
}

func TestTaintPaths_ParsesFindings(t *testing.T) {
	findings := []joernFinding{
		{
			ID: "f1",
			Evidence: []joernNode{
				{ID: "src", Name: "id", File: "MainController.java", Line: 34},
				{ID: "mid", Name: "sql", File: "MainController.java", Line: 35},
				{ID: "snk", Name: "executeQuery", File: "MainController.java", Line: 36},
			},
		},
	}
	callCount := 0
	srv := mockServer(t, func(q string) (string, bool) {
		callCount++
		if strings.Contains(q, "ossdataflow") {
			return `""`, true
		}
		return jsonArray(t, findings), true
	})
	c := newTestClient(t, srv)
	g := c.Graph()

	paths, err := g.TaintPaths(
		[]cpg.TaintSource{{NodeID: "src"}},
		[]cpg.TaintSink{{NodeID: "snk", Kind: cpg.SinkSQL}},
	)
	if err != nil {
		t.Fatalf("TaintPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("TaintPaths: got %d paths, want 1", len(paths))
	}
	if paths[0].Source.NodeID != "src" {
		t.Errorf("path.Source.NodeID = %q, want %q", paths[0].Source.NodeID, "src")
	}
	if paths[0].Sink.NodeID != "snk" {
		t.Errorf("path.Sink.NodeID = %q, want %q", paths[0].Sink.NodeID, "snk")
	}
	if len(paths[0].IntermediateNodes) != 1 {
		t.Errorf("path.IntermediateNodes: got %d, want 1", len(paths[0].IntermediateNodes))
	}
}

func TestTaintPaths_CapsAtMaxTaintPaths(t *testing.T) {
	// Build maxTaintPaths+5 findings, each with 2 evidence nodes.
	findings := make([]joernFinding, maxTaintPaths+5)
	for i := range findings {
		findings[i] = joernFinding{
			ID: fmt.Sprintf("f%d", i),
			Evidence: []joernNode{
				{ID: fmt.Sprintf("src%d", i), Name: "param"},
				{ID: fmt.Sprintf("snk%d", i), Name: "exec"},
			},
		}
	}
	srv := mockServer(t, func(q string) (string, bool) {
		if strings.Contains(q, "ossdataflow") {
			return `""`, true
		}
		return jsonArray(t, findings), true
	})
	c := newTestClient(t, srv)
	g := c.Graph()

	paths, err := g.TaintPaths(
		[]cpg.TaintSource{{NodeID: "s"}},
		[]cpg.TaintSink{{NodeID: "k", Kind: cpg.SinkSQL}},
	)
	if err != nil {
		t.Fatalf("TaintPaths: %v", err)
	}
	if len(paths) != maxTaintPaths {
		t.Errorf("TaintPaths cap: got %d paths, want %d", len(paths), maxTaintPaths)
	}
}

// ─── containsTraversal ────────────────────────────────────────────────────────

func TestContainsTraversal(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"../secret", true},
		{"/tmp/../etc/passwd", true},
		{"a/../../b", true},
		{"/project/src", false},
		{"relative/path", false},
		{".hidden/file", false},
	}
	for _, tc := range cases {
		got := containsTraversal(tc.path)
		if got != tc.want {
			t.Errorf("containsTraversal(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ─── checkPortAvailable ───────────────────────────────────────────────────────

func TestCheckPortAvailable_FreePort(t *testing.T) {
	// Pick a port that is very likely to be free. If the test environment
	// happens to have it bound, this test may flake — acceptable trade-off
	// for not spawning a subprocess in unit tests.
	if err := checkPortAvailable(context.Background(), "127.0.0.1", 19998); err != nil {
		t.Skipf("port 19998 is in use on this machine — skipping: %v", err)
	}
}

func TestCheckPortAvailable_BoundPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)

	// Extract the port from the test server's URL.
	var port int
	_, _ = fmt.Sscanf(srv.URL, "http://127.0.0.1:%d", &port)
	if port == 0 {
		t.Skip("could not parse port from httptest server URL")
	}

	err := checkPortAvailable(context.Background(), "127.0.0.1", port)
	if !errors.Is(err, ErrPortInUse) {
		t.Errorf("checkPortAvailable(bound port) = %v, want ErrPortInUse", err)
	}
}

// ─── validateServerURL ────────────────────────────────────────────────────────

func TestValidateServerURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://127.0.0.1:8080", false},
		{"http://localhost:8080", false},
		{"http://[::1]:8080", false},
		{"http://example.com:8080", true},
		{"http://192.168.0.1:8080", true},
		{"not-a-url", true},
	}
	for _, tc := range cases {
		err := validateServerURL(tc.url)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateServerURL(%q): err=%v, wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

// ─── Stop without Start ───────────────────────────────────────────────────────

func TestStop_WithoutStart_ReturnsNotManaged(t *testing.T) {
	srv := mockServer(t, func(_ string) (string, bool) { return "", true })
	c := newTestClient(t, srv)

	err := c.Stop(context.Background())
	if !errors.Is(err, ErrNotManaged) {
		t.Errorf("Stop() without Start = %v, want ErrNotManaged", err)
	}
}

// ─── commonParent ─────────────────────────────────────────────────────────────

func TestCommonParent(t *testing.T) {
	cases := []struct {
		paths []string
		want  string
	}{
		{[]string{"/a/b/c.java", "/a/b/d.java"}, "/a/b"},
		{[]string{"/a/b/c.java", "/a/x/d.java"}, "/a"},
		{[]string{"/a/b/c.java"}, "/a/b"},
		{[]string{}, "."},
	}
	for _, tc := range cases {
		got := commonParent(tc.paths)
		if got != tc.want {
			t.Errorf("commonParent(%v) = %q, want %q", tc.paths, got, tc.want)
		}
	}
}
