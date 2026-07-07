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

package joern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
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
	var queries []string
	srv := mockServer(t, func(q string) (string, bool) {
		queries = append(queries, q)
		if strings.Contains(q, "cpg.method.size") {
			return "42", true
		}
		return `""`, true
	})
	c := newTestClient(t, srv)
	err := c.BuildCPG(context.Background(), BuildConfig{Paths: []string{"/project/src"}})
	if err != nil {
		t.Fatalf("BuildCPG() = %v", err)
	}
	if len(queries) == 0 {
		t.Fatal("BuildCPG: no query sent to server")
	}
	// First query must reference importCode and the path.
	first := queries[0]
	for _, want := range []string{"importCode", "/project/src"} {
		if !strings.Contains(first, want) {
			t.Errorf("BuildCPG first query %q missing %q", first, want)
		}
	}
}

func TestBuildCPG_WithLanguageOverride(t *testing.T) {
	var queries []string
	srv := mockServer(t, func(q string) (string, bool) {
		queries = append(queries, q)
		if strings.Contains(q, "cpg.method.size") {
			return "1", true
		}
		return `""`, true
	})
	c := newTestClient(t, srv)
	_ = c.BuildCPG(context.Background(), BuildConfig{
		Paths:    []string{"/project/src"},
		Language: "JAVASRC",
	})
	if len(queries) == 0 || !strings.Contains(queries[0], "JAVASRC") {
		t.Errorf("BuildCPG with language: first query %v missing JAVASRC", queries)
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

func TestIsJoernConsoleError(t *testing.T) {
	if !isJoernConsoleError("io.joern.console.Error: No CPG loaded") {
		t.Error("expected true for console.Error prefix")
	}
	if !isJoernConsoleError("io.joern.console.ConsoleException: foo") {
		t.Error("expected true for ConsoleException prefix")
	}
	if isJoernConsoleError(`[{"id":"1"}]`) {
		t.Error("expected false for valid JSON")
	}
}

func TestDoQuery_ConsoleError(t *testing.T) {
	// Joern returns success=true but stdout is a console error — doQuery must error.
	errMsg := "io.joern.console.Error: No CPG loaded for project test"
	srv := mockServer(t, func(_ string) (string, bool) { return errMsg, true })
	c := newTestClient(t, srv)
	_, err := c.doQuery(context.Background(), "cpg.method.size")
	if err == nil {
		t.Fatal("doQuery: expected error for console error stdout, got nil")
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
		// Console-error strings have no = separator; parseStdout must return them as-is
		// so isJoernConsoleError can detect them in fetchResult.
		{"console Error passthrough", `io.joern.console.Error: No CPG loaded`, `io.joern.console.Error: No CPG loaded`},
		{"ConsoleException passthrough", `io.joern.console.ConsoleException: bad`, `io.joern.console.ConsoleException: bad`},
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
	var calls int
	srv := mockServer(t, func(_ string) (string, bool) {
		calls++
		if calls > 1 {
			return "[]", true
		}
		return jsonArray(t, nodes), true
	})
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
	var calls int
	srv := mockServer(t, func(_ string) (string, bool) {
		calls++
		if calls > 1 {
			return "[]", true
		}
		return jsonArray(t, edges), true
	})
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
	flows := []joernFlow{
		{
			Source: joernNode{ID: "src", Name: "id", File: "MainController.java", Line: 34},
			Intermediate: []joernNode{
				{ID: "mid", Name: "sql", File: "MainController.java", Line: 35},
			},
			Sink: joernNode{ID: "snk", Name: "executeQuery", File: "MainController.java", Line: 36},
		},
	}
	srv := mockServer(t, func(q string) (string, bool) {
		return jsonArray(t, flows), true
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
	// Build config.C.CPGMaxTaintPaths+5 flows, each with a source and sink (no intermediates).
	flows := make([]joernFlow, config.C.CPGMaxTaintPaths+5)
	for i := range flows {
		flows[i] = joernFlow{
			Source: joernNode{ID: fmt.Sprintf("src%d", i), Name: "param"},
			Sink:   joernNode{ID: fmt.Sprintf("snk%d", i), Name: "exec"},
		}
	}
	srv := mockServer(t, func(q string) (string, bool) {
		return jsonArray(t, flows), true
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
	if len(paths) != config.C.CPGMaxTaintPaths {
		t.Errorf("TaintPaths cap: got %d paths, want %d", len(paths), config.C.CPGMaxTaintPaths)
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

// ─── classifySourceKind ────────────────────────────────────────────────────────

func TestClassifySourceKind_JavaSource(t *testing.T) {
	got := classifySourceKind("getParameter", "app/MainController.java")
	if got != "http_param" {
		t.Errorf("classifySourceKind(getParameter) = %q, want %q", got, "http_param")
	}
}

func TestClassifySourceKind_JavaHeader(t *testing.T) {
	got := classifySourceKind("getHeader", "app/MainController.java")
	if got != "http_header" {
		t.Errorf("classifySourceKind(getHeader) = %q, want %q", got, "http_header")
	}
}

func TestClassifySourceKind_PythonEnvVar(t *testing.T) {
	got := classifySourceKind("os.environ", "app/routes.py")
	if got != "env_var" {
		t.Errorf("classifySourceKind(os.environ) = %q, want %q", got, "env_var")
	}
}

func TestClassifySourceKind_GoPostForm(t *testing.T) {
	got := classifySourceKind("r.PostFormValue", "app/handler.go")
	if got != "http_body" {
		t.Errorf("classifySourceKind(r.PostFormValue) = %q, want %q", got, "http_body")
	}
}

func TestClassifySourceKind_FallsBackToName(t *testing.T) {
	got := classifySourceKind("unknownFunction", "app/file.java")
	if got != "unknownFunction" {
		t.Errorf("classifySourceKind(unknown) = %q, want %q", got, "unknownFunction")
	}
}

func TestClassifySourceKind_UnsupportedLanguage(t *testing.T) {
	got := classifySourceKind("getParameter", "app/file.rs")
	if got != "getParameter" {
		t.Errorf("classifySourceKind(rust) = %q, want %q", got, "getParameter")
	}
}

// ─── PreFlagSinks ──────────────────────────────────────────────────────────────

func TestPreFlagSinks_JavaSQLSink(t *testing.T) {
	ctx := context.Background()
	c, err := New(WithServerURL("http://127.0.0.1:18081"), WithQueryTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "MainController.java")
	if err := os.WriteFile(f, []byte("ResultSet rs = stmt.executeQuery(sql);\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "ignored.rs"), []byte("fn main() {}\n"), 0o644)

	if err := c.PreFlagSinks(ctx, []string{f}); err != nil {
		t.Fatalf("PreFlagSinks: %v", err)
	}

	sinks := c.PreFlaggedSinks()
	if len(sinks) != 1 {
		t.Fatalf("PreFlaggedSinks: got %d sinks, want 1", len(sinks))
	}
	if sinks[0].Kind != cpg.SinkSQL {
		t.Errorf("sink.Kind = %v, want %v", sinks[0].Kind, cpg.SinkSQL)
	}
	if sinks[0].Line != 1 {
		t.Errorf("sink.Line = %d, want 1", sinks[0].Line)
	}
}

func TestPreFlagSinks_PythonEval(t *testing.T) {
	ctx := context.Background()
	c, err := New(WithServerURL("http://127.0.0.1:18082"), WithQueryTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "routes.py")
	code := "def process():\n    result = eval(user_input)\n    return result\n"
	if err := os.WriteFile(f, []byte(code), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := c.PreFlagSinks(ctx, []string{f}); err != nil {
		t.Fatalf("PreFlagSinks: %v", err)
	}

	sinks := c.PreFlaggedSinks()
	if len(sinks) == 0 {
		t.Fatal("PreFlaggedSinks: no sinks found, want at least 1")
	}
	if sinks[0].Kind != cpg.SinkEval {
		t.Errorf("sink.Kind = %v, want %v", sinks[0].Kind, cpg.SinkEval)
	}
	if sinks[0].Line != 2 {
		t.Errorf("sink.Line = %d, want 2", sinks[0].Line)
	}
}

func TestPreFlagSinks_UnsupportedLanguage(t *testing.T) {
	ctx := context.Background()
	c, err := New(WithServerURL("http://127.0.0.1:18083"), WithQueryTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "file.rs")
	_ = os.WriteFile(f, []byte("fn main() { eval(); }"), 0o644)

	if err := c.PreFlagSinks(ctx, []string{f}); err != nil {
		t.Fatalf("PreFlagSinks: %v", err)
	}
	if sinks := c.PreFlaggedSinks(); len(sinks) != 0 {
		t.Errorf("PreFlaggedSinks: got %d sinks for .rs file, want 0", len(sinks))
	}
}

func TestPreFlagSinks_ContextCancellation(t *testing.T) {
	c, err := New(WithServerURL("http://127.0.0.1:18084"), WithQueryTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = c.PreFlagSinks(ctx, []string{"some/file.java"})
	if err == nil {
		t.Error("PreFlagSinks with cancelled context: expected error, got nil")
	}
}

// ─── Version ───────────────────────────────────────────────────────────────────

func TestVersion_ReturnsCached(t *testing.T) {
	// Version is now a no-op that returns "unknown" without querying the Joern server.
	// Version checking was removed because: (1) joern.version is not a valid Scala identifier
	// in this Joern build; (2) cpg.metaData.version requires a loaded CPG; (3) joern --version
	// is not supported. Version is only used for CPG snapshot invalidation; "unknown" is safe.
	c := newTestClient(t, mockServer(t, func(q string) (string, bool) {
		t.Errorf("Version: unexpected server query %q", q)
		return "", false
	}))
	v1, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v1 != "unknown" {
		t.Errorf("Version = %q, want %q", v1, "unknown")
	}
	v2, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version (second call): %v", err)
	}
	if v2 != v1 {
		t.Errorf("Version second call = %q, want %q", v2, v1)
	}
}

// ─── VersionSnapshotPath ───────────────────────────────────────────────────────

func TestVersionSnapshotPath(t *testing.T) {
	got := VersionSnapshotPath("test-project")
	if !strings.Contains(got, "test-project") {
		t.Errorf("VersionSnapshotPath = %q, want path containing test-project", got)
	}
	if !strings.HasSuffix(got, ".version") {
		t.Errorf("VersionSnapshotPath = %q, want .version suffix", got)
	}
}

// ─── PreFlaggedSinks (graph) ───────────────────────────────────────────────────

func TestGraphPreFlaggedSinks(t *testing.T) {
	c, err := New(WithServerURL("http://127.0.0.1:18085"), WithQueryTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Pre-populate sinks directly (bypassing file scan).
	c.preFlaggedMu.Lock()
	c.preFlaggedSinks = []cpg.TaintSink{
		{Kind: cpg.SinkSQL, File: "test.java", Line: 10},
	}
	c.preFlaggedMu.Unlock()

	g := c.Graph()
	sinks, err := g.PreFlaggedSinks()
	if err != nil {
		t.Fatalf("PreFlaggedSinks: %v", err)
	}
	if len(sinks) != 1 {
		t.Fatalf("PreFlaggedSinks: got %d sinks, want 1", len(sinks))
	}
	if sinks[0].Kind != cpg.SinkSQL {
		t.Errorf("sink.Kind = %v, want %v", sinks[0].Kind, cpg.SinkSQL)
	}
}

// ─── TaintPathToFinding ────────────────────────────────────────────────────────

func TestTaintPathToFinding_SetsMatchedCode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "MainController.java")
	_ = os.WriteFile(f, []byte("package app;\nimport db.*;\nResultSet rs = stmt.executeQuery(sql);\n"), 0o644)

	path := cpg.TaintPath{
		Source: cpg.TaintSource{NodeID: "1", Kind: "http_param", File: f, Line: 1},
		Sink:   cpg.TaintSink{NodeID: "2", Kind: cpg.SinkSQL, File: f, Line: 3},
	}
	finding := TaintPathToFinding(path, LanguageJava)
	if finding.MatchedCode != "ResultSet rs = stmt.executeQuery(sql);" {
		t.Errorf("MatchedCode = %q, want %q", finding.MatchedCode, "ResultSet rs = stmt.executeQuery(sql);")
	}
}

func TestTaintPathToFinding_ConfidenceMapsToSeverity(t *testing.T) {
	path := cpg.TaintPath{
		Source: cpg.TaintSource{NodeID: "1", Kind: "http_param", File: "f.java", Line: 1},
		Sink:   cpg.TaintSink{NodeID: "2", Kind: cpg.SinkSQL, File: "f.java", Line: 3},
	}
	f := TaintPathToFinding(path, LanguageJava)
	if f.Confidence != 0.75 {
		t.Errorf("Confidence = %f, want 0.75", f.Confidence)
	}
	if want := finding.SeverityFromConfidence(0.75); f.SeverityLabel != want {
		t.Errorf("SeverityLabel = %q, want %q", f.SeverityLabel, want)
	}
}

func TestTaintPathToFinding_SSVCAutomatable(t *testing.T) {
	tests := []struct {
		kind cpg.SinkKind
		want string
	}{
		{cpg.SinkSQL, "Yes"},
		{cpg.SinkCommand, "Yes"},
		{cpg.SinkEval, "Yes"},
		{cpg.SinkFileWrite, "No"},
		{cpg.SinkDeserialization, "No"},
	}
	for _, tc := range tests {
		path := cpg.TaintPath{
			Source: cpg.TaintSource{NodeID: "1", Kind: "http_param", File: "f.java", Line: 1},
			Sink:   cpg.TaintSink{NodeID: "2", Kind: tc.kind, File: "f.java", Line: 3},
		}
		f := TaintPathToFinding(path, LanguageJava)
		if f.SSVC.Automatable != tc.want {
			t.Errorf("SSVC.Automatable for %v = %q, want %q", tc.kind, f.SSVC.Automatable, tc.want)
		}
	}
}

func TestTaintPathToFinding_SSVCTechnicalImpact(t *testing.T) {
	tests := []struct {
		kind cpg.SinkKind
		want string
	}{
		{cpg.SinkSQL, "Total"},
		{cpg.SinkCommand, "Total"},
		{cpg.SinkEval, "Total"},
		{cpg.SinkDeserialization, "Total"},
		{cpg.SinkFileWrite, "Partial"},
		{cpg.SinkTemplate, "Partial"},
	}
	for _, tc := range tests {
		path := cpg.TaintPath{
			Source: cpg.TaintSource{NodeID: "1", Kind: "http_param", File: "f.java", Line: 1},
			Sink:   cpg.TaintSink{NodeID: "2", Kind: tc.kind, File: "f.java", Line: 3},
		}
		f := TaintPathToFinding(path, LanguageJava)
		if f.SSVC.TechnicalImpact != tc.want {
			t.Errorf("SSVC.TechnicalImpact for %v = %q, want %q", tc.kind, f.SSVC.TechnicalImpact, tc.want)
		}
	}
}

func TestTaintPathToFinding_PoeContextPopulated(t *testing.T) {
	path := cpg.TaintPath{
		Source: cpg.TaintSource{NodeID: "src1", Kind: "http_param", File: "f.java", Line: 1},
		Sink:   cpg.TaintSink{NodeID: "snk2", Kind: cpg.SinkSQL, File: "f.java", Line: 5},
		IntermediateNodes: []cpg.Node{
			{ID: "n1", Name: "sanitize", File: "f.java", Line: 3},
		},
	}
	f := TaintPathToFinding(path, LanguageJava)
	if f.PoeContext == nil {
		t.Fatal("PoeContext is nil")
	}
	if f.PoeContext.SourceNode != "src1" {
		t.Errorf("PoeContext.SourceNode = %q, want %q", f.PoeContext.SourceNode, "src1")
	}
	if f.PoeContext.SinkNode != "snk2" {
		t.Errorf("PoeContext.SinkNode = %q, want %q", f.PoeContext.SinkNode, "snk2")
	}
}

// ─── TaintPathsToFindings ──────────────────────────────────────────────────────

func TestTaintPathsToFindings_EmptyInput(t *testing.T) {
	result := TaintPathsToFindings(nil, LanguageJava)
	if result != nil {
		t.Errorf("TaintPathsToFindings(nil) = %v, want nil", result)
	}
}

func TestTaintPathsToFindings_ComputesID(t *testing.T) {
	paths := []cpg.TaintPath{
		{
			Source: cpg.TaintSource{NodeID: "1", Kind: "http_param", File: "f.java", Line: 1},
			Sink:   cpg.TaintSink{NodeID: "2", Kind: cpg.SinkSQL, File: "f.java", Line: 3},
		},
	}
	result := TaintPathsToFindings(paths, LanguageJava)
	if len(result) != 1 {
		t.Fatalf("TaintPathsToFindings: got %d, want 1", len(result))
	}
	if result[0].ID == "" {
		t.Error("TaintPathsToFindings: ID is empty")
	}
	if result[0].CWE != "CWE-89" {
		t.Errorf("TaintPathsToFindings: CWE = %q, want %q", result[0].CWE, "CWE-89")
	}
	if result[0].RuleID != "JOERN-TAINT-sql" {
		t.Errorf("TaintPathsToFindings: RuleID = %q, want %q", result[0].RuleID, "JOERN-TAINT-sql")
	}
}

// ─── extractSnippet ────────────────────────────────────────────────────────────

func TestExtractSnippet_ReadsLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.java")
	_ = os.WriteFile(f, []byte("line1\nline2\nline3\n"), 0o644)

	got := extractSnippet(f, 2)
	if got != "line2" {
		t.Errorf("extractSnippet(line 2) = %q, want %q", got, "line2")
	}
}

func TestExtractSnippet_OutOfRange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.java")
	_ = os.WriteFile(f, []byte("line1\n"), 0o644)

	got := extractSnippet(f, 999)
	if got != "" {
		t.Errorf("extractSnippet(out of range) = %q, want empty", got)
	}
}

func TestExtractSnippet_MissingFile(t *testing.T) {
	got := extractSnippet("/nonexistent/file.java", 1)
	if got != "" {
		t.Errorf("extractSnippet(missing file) = %q, want empty", got)
	}
}
