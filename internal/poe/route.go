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

package poe

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// Route is the resolved HTTP entry point that reaches a finding's sink.
type Route struct {
	Method string // GET, POST, PUT, DELETE, PATCH
	Path   string // e.g. "/api/users/{id}"
}

// maxRouteWalkDepth bounds the caller-graph walk from a finding's function up
// to a recognized HTTP entry point. Mirrors the depth-5 taint-path
// correctness bound used elsewhere in the CPG engine (docs/research-papers.md);
// an HTTP entry point more than 5 calls away from the sink is vanishingly rare
// for the kind of thin-handler-then-service pattern web frameworks encourage.
const maxRouteWalkDepth = 5

// routeResolver finds the HTTP route (if any) that node itself declares,
// given node is a candidate entry point in projectRoot's source tree. Each
// supported language implements one, matching its own routing convention
// (annotations, decorators, or route-registration calls) — see
// route_java.go / route_python.go / route_js.go / route_go.go.
//
// ponytail: route discovery is a plain-text regex/text scan of source files,
// not a CPG query — cpg_engine has no Annotation/Decorator node type today,
// and four languages' routing conventions are too varied to express as one
// shared Scala query. Upgrade path: move to CPG-native structural queries if
// a later phase needs this to be more robust than regex matching.
type routeResolver func(projectRoot string, node cpg_engine.Node) (Route, bool)

var routeResolvers = map[string]routeResolver{
	"java":       javaRouteFromMethodNode,
	"python":     pythonRouteFromMethodNode,
	"javascript": jsRouteFromMethodNode,
	"typescript": jsRouteFromMethodNode, // artifact is expected to be the transpiled JS output
	"go":         goRouteFromMethodNode,
}

// resolveRoute walks the CPG call graph backward from f's enclosing method,
// looking for a recognized HTTP entry point (in f's language) within
// maxRouteWalkDepth hops. Returns false when no entry point is found —
// callers must not guess a route, since sending a request to the wrong path
// proves nothing.
func resolveRoute(graph cpg_engine.Graph, projectRoot string, f finding.Finding) (Route, bool) {
	slog.Debug("resolving route for finding",
		"finding_id", f.ID, "file", f.Path, "cwe", f.CWE)

	resolver, ok := routeResolvers[finding.LangFromPath(f.Path)]
	if !ok {
		slog.Debug("no route resolver for language",
			"language", finding.LangFromPath(f.Path))
		return Route{}, false
	}

	start, ok := enclosingMethod(graph, f)
	if !ok {
		slog.Debug("no enclosing method found", "finding_id", f.ID)
		return Route{}, false
	}
	if route, ok := resolver(projectRoot, start); ok {
		slog.Debug("route resolved directly",
			"method", start.Name, "route", route.Method+" "+route.Path)
		return route, true
	}

	visited := map[string]bool{start.ID: true}
	frontier := []cpg_engine.Node{start}

	for depth := range maxRouteWalkDepth {
		var next []cpg_engine.Node
		for _, n := range frontier {
			callers, err := graph.GetCallers(n.ID)
			if err != nil {
				slog.Debug("failed to get callers", "node", n.ID, "error", err)
				continue
			}
			for _, c := range callers {
				if visited[c.ID] {
					continue
				}
				visited[c.ID] = true
				if route, ok := resolver(projectRoot, c); ok {
					slog.Debug("route resolved via caller chain",
						"depth", depth+1, "method", c.Name,
						"route", route.Method+" "+route.Path)
					return route, true
				}
				next = append(next, c)
			}
		}
		frontier = next
		if len(frontier) == 0 {
			break
		}
	}
	slog.Debug("route not found within walk depth",
		"finding_id", f.ID, "max_depth", maxRouteWalkDepth)
	return Route{}, false
}

// enclosingMethod returns the CPG method node whose declaration line is the
// closest one at or before f.LineRange.Start in f.Path. Node lacks an end
// line, so "closest preceding method start" is the best available heuristic.
func enclosingMethod(graph cpg_engine.Graph, f finding.Finding) (cpg_engine.Node, bool) {
	methods, err := graph.QueryNodesByFile(f.Path, cpg_engine.NodeMethod)
	if err != nil || len(methods) == 0 {
		slog.Debug("no methods found in file", "file", f.Path, "error", err)
		return cpg_engine.Node{}, false
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i].Line < methods[j].Line })

	best := -1
	for i, m := range methods {
		if m.Line <= f.LineRange.Start {
			best = i
		}
	}
	if best == -1 {
		slog.Debug("no enclosing method for line",
			"file", f.Path, "line", f.LineRange.Start)
		return cpg_engine.Node{}, false
	}
	slog.Debug("enclosing method found",
		"method", methods[best].Name, "file", f.Path, "line", methods[best].Line)
	return methods[best], true
}

// joinPath concatenates a route prefix (e.g. a class/router-level base path)
// with a handler's own path, normalizing the slash between them.
func joinPath(prefix, path string) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return prefix + path
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// windowAbove returns the lines from a few lines before nodeLine (1-based) up
// to and including it, joined into one string — the region annotations or
// decorators sit in for idiomatic Java/Python code.
func windowAbove(lines []string, nodeLine, lookback int) string {
	start := max(nodeLine - lookback, 0)
	end := min(nodeLine, len(lines))
	return strings.Join(lines[start:end], "\n")
}

func absPath(projectRoot string, node cpg_engine.Node) string {
	return filepath.Join(projectRoot, node.File)
}
