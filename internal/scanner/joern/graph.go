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
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// joernGraphCache is a thread-safe lookaside cache bound to a single scan
// execution context. Eliminates redundant HTTP round-trips when the same
// node type or edge set is queried multiple times (e.g. QueryNodes called
// by both Run and queryIDORCandidates in the same targeting pass).
type joernGraphCache struct {
	mu          sync.RWMutex
	methodCache map[cpg.NodeType][]cpg.Node
	edgeCache   map[string][]cpg.Edge // key is "from:"+fromID or "to:"+toID
}

// joernGraph implements cpg.Graph via Joern HTTP JSON queries (Joern DSL over HTTP).
// ctx is the scan lifetime context propagated to every doQuery call so that
// Ctrl-C / deadline cancellation aborts in-flight Joern queries promptly.
// Use Client.GraphWithContext to supply a real scan context; Graph() falls back
// to context.Background() for callers that do not have one.
type joernGraph struct {
	client *Client
	ctx    context.Context //nolint:containedctx // intentional: scan lifetime, not request lifetime
	cache  *joernGraphCache
}

// config.C.CPGMaxTaintPaths caps the number of taint paths returned by TaintPaths.
// CPGs for large codebases can produce thousands of paths; this cap prevents
// unbounded memory growth. Paths are ranked by source-to-sink hop count before
// truncation — shorter (more direct) paths are kept.

// ─── wire types ───────────────────────────────────────────────────────────────

// joernNode is the JSON shape returned by all node-projection queries.
// The Type field maps to the node label (METHOD, CALL, METHOD_PARAMETER_IN, etc.)
// as emitted by the query templates.
type joernNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
	Type string `json:"type"`
	Code string `json:"code"`
}

// joernEdge is the JSON shape returned by all edge-projection queries.
type joernEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// joernFlow wraps a single taint flow returned by queryTaintFlows.
type joernFlow struct {
	Source       joernNode   `json:"source"`
	Sink         joernNode   `json:"sink"`
	Intermediate []joernNode `json:"intermediate"`
}

// ─── cpg.Graph implementation ─────────────────────────────────────────────────

// QueryNodes returns all nodes of nodeType across all ingested source files.
// Results are cached per nodeType so callers querying the same type (e.g. both
// Run and queryIDORCandidates requesting NodeMethod) share a single HTTP round-trip.
func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) {
	g.cache.mu.RLock()
	if nodes, ok := g.cache.methodCache[nodeType]; ok {
		g.cache.mu.RUnlock()
		slog.Debug("joern: QueryNodes cache hit", "type", nodeType, "count", len(nodes))
		return nodes, nil
	}
	g.cache.mu.RUnlock()

	q := nodeTypeQuery(nodeType)
	slog.Info("joern: QueryNodes — fetching all nodes", "type", nodeType)
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryNodes(%s): %w", nodeType, err)
	}
	nodes, err := parseNodes(raw)
	if err != nil {
		return nil, err
	}

	g.cache.mu.Lock()
	g.cache.methodCache[nodeType] = nodes
	g.cache.mu.Unlock()

	slog.Info("joern: QueryNodes done", "type", nodeType, "count", len(nodes))
	return nodes, nil
}

// QueryNodesByFile returns all nodes of nodeType in relPath.
func (g *joernGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	if relPath == "" {
		return nil, fmt.Errorf("joern: QueryNodesByFile: relPath must not be empty")
	}
	var q string
	switch nodeType {
	case cpg.NodeMethod:
		q = queryMethodsByFile(relPath)
	default:
		q = queryCallsByFile(relPath)
	}
	slog.Debug("joern: QueryNodesByFile query", "query", q, "relPath", relPath)
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryNodesByFile(%s, %s): %w", relPath, nodeType, err)
	}
	return parseNodes(raw)
}

// QueryEdges returns directed edges where fromID and toID match.
// Pass "" to match any node on that side (wildcard).
// Results are cached per node ID so redundant per-method QueryEdges calls
// (e.g. IsExternalInputNode + queryIDORCandidates on the same methods) hit
// the cache after the first fetch.
func (g *joernGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error) {
	if fromID == "" && toID == "" {
		return nil, fmt.Errorf("joern: QueryEdges: at least one of fromID or toID must be non-empty")
	}

	// Build a cache key matching the query direction.
	var cacheKey string
	switch {
	case fromID != "" && toID == "":
		cacheKey = "from:" + fromID
	case toID != "" && fromID == "":
		cacheKey = "to:" + toID
	default:
		cacheKey = "from:" + fromID // both set: query from-side
	}

	g.cache.mu.RLock()
	if edges, ok := g.cache.edgeCache[cacheKey]; ok {
		g.cache.mu.RUnlock()
		// If both sides were specified, filter in Go from the cached result.
		if fromID != "" && toID != "" {
			filtered := make([]cpg.Edge, 0, len(edges))
			for _, e := range edges {
				if e.ToID == toID {
					filtered = append(filtered, e)
				}
			}
			return filtered, nil
		}
		return edges, nil
	}
	g.cache.mu.RUnlock()

	var raw []byte
	var err error
	switch {
	case fromID != "" && toID == "":
		q := queryEdgesFrom(fromID)
		slog.Debug("joern: QueryEdges query", "query", q)
		raw, err = g.client.doQuery(g.ctx, q)
	case toID != "" && fromID == "":
		q := queryEdgesTo(toID)
		slog.Debug("joern: QueryEdges query", "query", q)
		raw, err = g.client.doQuery(g.ctx, q)
	default:
		// Both set: query from-side and filter by toID on the Go side.
		q := queryEdgesFrom(fromID)
		slog.Debug("joern: QueryEdges query", "query", q)
		raw, err = g.client.doQuery(g.ctx, q)
	}
	if err != nil {
		return nil, fmt.Errorf("joern: QueryEdges: %w", err)
	}

	all, err := parseEdges(raw)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryEdges: %w", err)
	}

	// Store in cache before filtering so subsequent callers with the same
	// fromID benefit from the full edge set.
	g.cache.mu.Lock()
	g.cache.edgeCache[cacheKey] = all
	g.cache.mu.Unlock()

	// Filter by toID if both sides were specified.
	if fromID != "" && toID != "" {
		filtered := make([]cpg.Edge, 0, len(all))
		for _, e := range all {
			if e.ToID == toID {
				filtered = append(filtered, e)
			}
		}
		return filtered, nil
	}
	return all, nil
}

// GetCallGraph returns the full inter-procedural call graph.
func (g *joernGraph) GetCallGraph() (cpg.CallGraph, error) {
	q := queryAllEdges()
	slog.Info("joern: GetCallGraph — querying all edges (may be slow on large CPGs)")
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: GetCallGraph: %w", err)
	}

	var edges []joernEdge
	if err := json.Unmarshal(raw, &edges); err != nil {
		return nil, fmt.Errorf("joern: GetCallGraph: %w: %w", ErrMalformedResponse, err)
	}

	cg := make(cpg.CallGraph, len(edges))
	for _, e := range edges {
		cg[e.From] = append(cg[e.From], e.To)
	}
	slog.Info("joern: GetCallGraph done", "edges", len(cg))
	return cg, nil
}

// GetCallers returns all functions that directly call the function with the
// given node ID.
func (g *joernGraph) GetCallers(functionID string) ([]cpg.Node, error) {
	if functionID == "" {
		return nil, fmt.Errorf("joern: GetCallers: functionID must not be empty")
	}
	if strings.HasPrefix(functionID, "-") {
		return nil, nil // ponytail: synthetic/virtual node
	}
	q := queryCallersByID(functionID)
	slog.Debug("joern: GetCallers",
		"function", g.resolveNodeName(functionID),
		"functionID", functionID,
	)
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: GetCallers(%s): %w", functionID, err)
	}
	return parseNodes(raw)
}

// GetCallees returns all functions directly called by the function with the
// given node ID.
func (g *joernGraph) GetCallees(functionID string) ([]cpg.Node, error) {
	if functionID == "" {
		return nil, fmt.Errorf("joern: GetCallees: functionID must not be empty")
	}
	if strings.HasPrefix(functionID, "-") {
		return nil, nil // ponytail: synthetic/virtual node — no real callees
	}
	q := queryCalleesByID(functionID)
	slog.Debug("joern: GetCallees",
		"function", g.resolveNodeName(functionID),
		"functionID", functionID,
	)
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: GetCallees(%s): %w", functionID, err)
	}
	return parseNodes(raw)
}

// GetNeighboursAtDepth performs a bidirectional BFS from rootID up to depth hops,
// collecting all reachable caller and callee nodes. Returns ErrDepthExceeded if
// depth > 6 (the taint-correctness cap from SOAP/PLDI 2025).
//
// The BFS is implemented as successive GetCallers+GetCallees calls on the Go
// side to avoid a complex recursive Joern script. Each depth level makes two
// HTTP round-trips.
func (g *joernGraph) GetNeighboursAtDepth(rootID string, depth int) ([]cpg.Node, error) {
	slog.Debug("joern: GetNeighboursAtDepth", "rootID", rootID, "depth", depth)
	if depth > 6 {
		return nil, ErrDepthExceeded
	}
	if depth < 0 {
		depth = 0
	}
	if rootID == "" {
		return nil, fmt.Errorf("joern: GetNeighboursAtDepth: rootID must not be empty")
	}

	visited := make(map[string]bool)
	visited[rootID] = true
	frontier := []string{rootID}
	var result []cpg.Node

	for d := 0; d < depth && len(frontier) > 0; d++ {
		nextFrontier := make([]string, 0, len(frontier)*2)
		for _, id := range frontier {
			callers, err := g.GetCallers(id)
			if err != nil {
				return nil, fmt.Errorf("joern: GetNeighboursAtDepth BFS callers at depth %d: %w", d, err)
			}
			callees, err := g.GetCallees(id)
			if err != nil {
				return nil, fmt.Errorf("joern: GetNeighboursAtDepth BFS callees at depth %d: %w", d, err)
			}
			for _, n := range append(callers, callees...) {
				if !visited[n.ID] {
					visited[n.ID] = true
					result = append(result, n)
					nextFrontier = append(nextFrontier, n.ID)
				}
			}
		}
		frontier = nextFrontier
	}
	return result, nil
}

// TaintPaths runs taint analysis using Joern's built-in reachableByFlows API
// and returns all discovered source-to-sink paths, capped at config.C.CPGMaxTaintPaths.
//
// Sources and sinks must be non-empty. The method uses the node ID from the
// first source/sink to build the method-scoped reachability query. Only intra-
// procedural flows within a single method are returned; inter-procedural flows
// are not yet supported.
func (g *joernGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("joern: TaintPaths: sources must not be empty")
	}
	if len(sinks) == 0 {
		return nil, fmt.Errorf("joern: TaintPaths: sinks must not be empty")
	}

	// Extract the method node ID from the first source or sink.
	methodID := ""
	for _, s := range sources {
		if s.NodeID != "" {
			methodID = s.NodeID
			break
		}
	}
	if methodID == "" {
		for _, s := range sinks {
			if s.NodeID != "" {
				methodID = s.NodeID
				break
			}
		}
	}
	if methodID == "" {
		return nil, fmt.Errorf("joern: TaintPaths: no node IDs provided in sources or sinks")
	}

	q := queryTaintFlows(methodID)
	slog.Debug("joern: TaintPaths query", "query", q, "sources", len(sources), "sinks", len(sinks))
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: reachableByFlows: %w", err)
	}

	var flows []joernFlow
	if err := json.Unmarshal(raw, &flows); err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: %w: %w", ErrMalformedResponse, err)
	}

	paths := make([]cpg.TaintPath, 0, min(len(flows), config.C.CPGMaxTaintPaths))
	for _, f := range flows {
		if len(paths) >= config.C.CPGMaxTaintPaths {
			break
		}

		// Classify the sink kind using the language-specific taint taxonomy.
		sinkKind := classifySinkKind(f.Sink.Name, f.Sink.File)

		// Classify source kind using the language-specific taint taxonomy.
		sourceKind := classifySourceKind(f.Source.Name, f.Source.File)
		if sourceKind == "" {
			sourceKind = f.Source.Type
		}

		path := cpg.TaintPath{
			Source: cpg.TaintSource{
				NodeID: f.Source.ID,
				Kind:   sourceKind,
				File:   f.Source.File,
				Line:   f.Source.Line,
			},
			Sink: cpg.TaintSink{
				NodeID: f.Sink.ID,
				Kind:   sinkKind,
				File:   f.Sink.File,
				Line:   f.Sink.Line,
			},
		}
		intermediate := make([]cpg.Node, len(f.Intermediate))
		for i, ev := range f.Intermediate {
			intermediate[i] = cpg.Node{
				ID:   ev.ID,
				Name: ev.Name,
				File: ev.File,
				Line: ev.Line,
			}
		}
		path.IntermediateNodes = intermediate
		paths = append(paths, path)
	}
	slog.Debug("joern: TaintPaths done", "paths", len(paths))
	return paths, nil
}

// PreFlaggedSinks returns dangerous sink nodes pre-flagged by PreFlagSinks.
// These are always in scope regardless of module segmentation mode.
// Returns the cached list populated before the CPG build.
func (g *joernGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) {
	return g.client.PreFlaggedSinks(), nil
}

// ─── parsing helpers ──────────────────────────────────────────────────────────

func parseNodes(raw []byte) ([]cpg.Node, error) {
	var jns []joernNode
	if err := json.Unmarshal(raw, &jns); err != nil {
		slog.Debug("joern: parseNodes raw input", "raw", string(raw))
		return nil, fmt.Errorf("%w: parse nodes: %w", ErrMalformedResponse, err)
	}
	nodes := make([]cpg.Node, len(jns))
	for i, jn := range jns {
		nodes[i] = cpg.Node{
			ID:   jn.ID,
			Type: cpg.NodeType(jn.Type),
			Name: jn.Name,
			File: jn.File,
			Line: jn.Line,
			Code: jn.Code,
		}
	}
	return nodes, nil
}

func parseEdges(raw []byte) ([]cpg.Edge, error) {
	var jes []joernEdge
	if err := json.Unmarshal(raw, &jes); err != nil {
		return nil, fmt.Errorf("%w: parse edges: %w", ErrMalformedResponse, err)
	}
	edges := make([]cpg.Edge, len(jes))
	for i, je := range jes {
		edges[i] = cpg.Edge{
			FromID: je.From,
			ToID:   je.To,
			Type:   cpg.EdgeType(je.Type),
			Label:  je.Label,
		}
	}
	return edges, nil
}

// resolveNodeName translates a Joern numeric node ID to a human-readable
// "filename:function_name" string by scanning the method cache. Returns the
// raw ID when the cache has not been populated yet or the ID is unknown.
func (g *joernGraph) resolveNodeName(id string) string {
	if id == "" {
		return id
	}
	g.cache.mu.RLock()
	defer g.cache.mu.RUnlock()
	for _, nodes := range g.cache.methodCache {
		for _, n := range nodes {
			if n.ID == id {
				if n.File != "" {
					return n.File + ":" + n.Name
				}
				return n.Name
			}
		}
	}
	return id
}

// nodeTypeQuery returns the Joern DSL query for the given node type.
// Falls back to CALL nodes for unrecognised types.
func nodeTypeQuery(nt cpg.NodeType) string {
	switch nt {
	case cpg.NodeMethod:
		return queryMethods()
	case cpg.NodeCall:
		return queryCalls()
	case cpg.NodeParameter:
		return queryParams()
	case cpg.NodeIdentifier:
		return queryIdentifiers()
	case cpg.NodeLiteral:
		return queryLiterals()
	default:
		return queryNodeTypeGeneric(string(nt))
	}
}

// escapeScalaString escapes a string for safe embedding in a Joern DSL query.
// Only double-quotes and backslashes require escaping.
func escapeScalaString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// classifySourceKind uses the language-specific taint taxonomy to determine the
// correct source kind for a Joern finding node. Falls back to the raw node type
// when the language or name is not in the taxonomy.
func classifySourceKind(name, filePath string) string {
	lang, ok := DetectLanguage(filePath)
	if !ok {
		return name
	}
	def, found := SourceDefForCall(lang, name)
	if !found {
		return name
	}
	return def.Kind
}

// classifySinkKind uses the language-specific taint taxonomy to determine the
// correct SinkKind for a Joern finding node. Falls back to generic detection
// when the language or name is not in the taxonomy.
func classifySinkKind(callName, filePath string) cpg.SinkKind {
	lang, ok := DetectLanguage(filePath)
	if !ok {
		return classifySinkKindGeneric(callName)
	}
	def, found := SinkDefForCall(lang, callName)
	if !found {
		return classifySinkKindGeneric(callName)
	}
	return def.Kind
}

// classifySinkKindGeneric attempts to classify a sink call name without
// language-specific knowledge. This is a fallback when the language is unknown.
func classifySinkKindGeneric(callName string) cpg.SinkKind {
	switch {
	case containsAnyFold(callName, "query", "execute", "find", "raw", "sql"):
		return cpg.SinkSQL
	case containsAnyFold(callName, "exec", "system", "popen", "spawn", "Popen", "fork", "shell"):
		return cpg.SinkCommand
	case containsAnyFold(callName, "readObject", "unserialize", "deserialize", "pickle", "yaml.load"):
		return cpg.SinkDeserialization
	case containsAnyFold(callName, "write", "FileWriter", "FileOutputStream", "Create", "copy"):
		return cpg.SinkFileWrite
	case containsAnyFold(callName, "render", "Template"):
		return cpg.SinkTemplate
	case containsAnyFold(callName, "redirect", "forward"):
		return cpg.SinkRedirect
	case containsAnyFold(callName, "eval", "compile"):
		return cpg.SinkEval
	default:
		return cpg.SinkUnknown
	}
}

// containsAnyFold reports whether s contains any of the substrings (case-insensitive).
func containsAnyFold(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
