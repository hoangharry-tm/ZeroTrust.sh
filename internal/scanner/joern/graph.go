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
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// joernNullStr is the literal "null" string Joern emits when a CPG node
// property (e.g. FILENAME on a CALL node) is absent. Guard against it
// propagating into file paths.
func joernNullStr(s string) string {
	if s == "null" || s == "<empty>" {
		return ""
	}
	return s
}

// pageSize is the number of elements per paginated Joern HTTP query.
// Matches the value used in IngestCPGToSQLite.
const pageSize = 500

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
// When a SQLite backend is set (via WithSQLiteBackend), all read queries hit SQLite
// instead of Joern HTTP — only TaintPaths remains as a Joern HTTP call.
// ctx is the scan lifetime context propagated to every doQuery call so that
// Ctrl-C / deadline cancellation aborts in-flight Joern queries promptly.
// Use Client.GraphWithContext to supply a real scan context; Graph() falls back
// to context.Background() for callers that do not have one.
type joernGraph struct {
	client *Client
	ctx    context.Context //nolint:containedctx // intentional: scan lifetime, not request lifetime
	cache  *joernGraphCache
}

// sqliteDB returns the Client's SQLite backend. Reads from the Client directly so
// SetSQLiteBackend takes effect for ALL graph instances — not just ones created
// after the call.
func (g *joernGraph) sqliteDB() *sqlite.DB { return g.client.sqliteDB }

func (g *joernGraph) sqliteProjectID() string { return g.client.sqliteProjectID }

func (g *joernGraph) sqliteCPGVersion() string { return g.client.sqliteCPGVersion }

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
// For project-wide queries, MethodID/MethodName/MethodFile carry the
// surface method metadata so Go-side code can key paths by method node ID.
type joernFlow struct {
	MethodID     string      `json:"method_id"`
	MethodName   string      `json:"method_name"`
	MethodFile   string      `json:"method_file"`
	Source       joernNode   `json:"source"`
	Sink         joernNode   `json:"sink"`
	Intermediate []joernNode `json:"intermediate"`
}

// ─── SQLite CPG ingestion ──────────────────────────────────────────────────────

// IngestCPGToSQLite drains the full CPG from Joern JVM memory into SQLite
// using paginated stable-sorted queries. After this call all graph queries
// (GetCallers, GetCallees, QueryNodes, etc.) can read from SQLite instead of
// hitting Joern HTTP — only TaintPaths remains as a Joern HTTP call.
//
// Parameters:
//   - ctx: cancellation context.
//   - db: target SQLite database (writer connection used for ingestion).
//   - projectID: owning project key for cpg_nodes/cpg_edges.
//   - cpgVersion: content-hash derived from the changed file set.
func (g *joernGraph) IngestCPGToSQLite(ctx context.Context, db *sqlite.DB, projectID, cpgVersion string) error {
	slog.Info("joern: IngestCPGToSQLite starting",
		"project_id", projectID, "cpg_version", cpgVersion)
	var totalNodes, totalEdges int

	// Drain METHOD nodes with stable pagination.
	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := queryMethodsPaginated(offset, pageSize)
		raw, err := g.client.doQuery(ctx, q)
		if err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite methods page %d: %w", offset, err)
		}
		var jns []joernNode
		if err := json.Unmarshal(raw, &jns); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite methods parse page %d: %w", offset, err)
		}
		if len(jns) == 0 {
			break
		}
		nodes := make([]sqlite.CPGNode, len(jns))
		for i, jn := range jns {
			nodes[i] = sqlite.CPGNode{ID: jn.ID, Name: jn.Name, File: jn.File, Line: jn.Line, Code: jn.Code}
		}
		if err := db.IngestNodeBatch(ctx, projectID, cpgVersion, string(cpg.NodeMethod), nodes); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite methods batch %d: %w", offset, err)
		}
		totalNodes += len(nodes)
		offset += pageSize
	}

	// Drain CALL nodes with stable pagination.
	offset = 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := queryCallsPaginated(offset, pageSize)
		raw, err := g.client.doQuery(ctx, q)
		if err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite calls page %d: %w", offset, err)
		}
		var jns []joernNode
		if err := json.Unmarshal(raw, &jns); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite calls parse page %d: %w", offset, err)
		}
		if len(jns) == 0 {
			break
		}
		nodes := make([]sqlite.CPGNode, len(jns))
		for i, jn := range jns {
			nodes[i] = sqlite.CPGNode{ID: jn.ID, Name: jn.Name, File: jn.File, Line: jn.Line, Code: jn.Code}
		}
		if err := db.IngestNodeBatch(ctx, projectID, cpgVersion, string(cpg.NodeCall), nodes); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite calls batch %d: %w", offset, err)
		}
		totalNodes += len(nodes)
		offset += pageSize
	}

	// Drain edges with stable pagination over calls.
	offset = 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := queryAllEdgesPaginated(offset, pageSize)
		raw, err := g.client.doQuery(ctx, q)
		if err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite edges page %d: %w", offset, err)
		}
		var jes []joernEdge
		if err := json.Unmarshal(raw, &jes); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite edges parse page %d: %w", offset, err)
		}
		if len(jes) == 0 {
			break
		}
		edges := make([]sqlite.CPGEdge, len(jes))
		for i, je := range jes {
			edgeType := je.Type
			if edgeType == "" {
				edgeType = "CALL"
			}
			edges[i] = sqlite.CPGEdge{FromID: je.From, ToID: je.To, EdgeType: edgeType}
		}
		if err := db.IngestEdgeBatch(ctx, projectID, cpgVersion, edges); err != nil {
			return fmt.Errorf("joern: IngestCPGToSQLite edges batch %d: %w", offset, err)
		}
		totalEdges += len(edges)
		offset += pageSize
	}

	if err := db.RecordBuild(ctx, projectID, cpgVersion, cpgVersion, totalNodes, totalEdges); err != nil {
		return fmt.Errorf("joern: IngestCPGToSQLite record build: %w", err)
	}

	slog.Info("joern: IngestCPGToSQLite complete",
		"nodes", totalNodes, "edges", totalEdges)
	return nil
}

// ─── cpg.Graph implementation ─────────────────────────────────────────────────

// QueryNodes returns all nodes of nodeType across all ingested source files.
// Results are cached per nodeType so callers querying the same type (e.g. both
// Run and queryIDORCandidates requesting NodeMethod) share a single HTTP round-trip.
// When a SQLite backend is available, reads from SQLite instead of Joern HTTP.
func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) {
	g.cache.mu.RLock()
	if nodes, ok := g.cache.methodCache[nodeType]; ok {
		g.cache.mu.RUnlock()
		slog.Debug("joern: QueryNodes cache hit", "type", nodeType, "count", len(nodes))
		return nodes, nil
	}
	g.cache.mu.RUnlock()

	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		nodes, err := g.queryNodesFromSQLite(string(nodeType))
		if err == nil {
			g.cache.mu.Lock()
			g.cache.methodCache[nodeType] = nodes
			g.cache.mu.Unlock()
			slog.Debug("joern: QueryNodes from SQLite", "type", nodeType, "count", len(nodes))
			return nodes, nil
		}
	}

	// Fallback: paginated Joern HTTP reads with stable sortBy drop/take ordering.
	var allNodes []cpg.Node
	offset := 0
	for {
		raw, err := g.client.doQuery(g.ctx, paginatedNodeQuery(nodeType, offset, pageSize))
		if err != nil {
			return nil, fmt.Errorf("joern: QueryNodes(%s) page %d: %w", nodeType, offset, err)
		}
		page, err := parseNodes(raw)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		allNodes = append(allNodes, page...)
		offset += pageSize
	}

	g.cache.mu.Lock()
	g.cache.methodCache[nodeType] = allNodes
	g.cache.mu.Unlock()

	slog.Info("joern: QueryNodes done", "type", nodeType, "count", len(allNodes))
	return allNodes, nil
}

// drainNodeCursor exhausts cur into a []cpg.Node slice, then closes it.
func drainNodeCursor(cur *sqlite.NodeCursor) ([]cpg.Node, error) {
	defer cur.Close()
	var nodes []cpg.Node
	for cur.Next() {
		row, err := cur.Scan()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, cpg.Node{ID: row.ID, Name: row.Name, File: row.File, Line: row.Line, Code: row.Code})
	}
	return nodes, nil
}

// drainEdgeCursor exhausts cur into a []cpg.Edge slice, then closes it.
func drainEdgeCursor(cur *sqlite.EdgeCursor) ([]cpg.Edge, error) {
	defer cur.Close()
	var edges []cpg.Edge
	for cur.Next() {
		row, err := cur.Scan()
		if err != nil {
			return nil, err
		}
		edges = append(edges, cpg.Edge{FromID: row.FromID, ToID: row.ToID, Type: cpg.EdgeType(row.EdgeType)})
	}
	return edges, nil
}

// queryNodesFromSQLite reads all nodes of a given type from the SQLite backend.
func (g *joernGraph) queryNodesFromSQLite(nodeType string) ([]cpg.Node, error) {
	cur, err := g.sqliteDB().QueryNodesByType(g.ctx, g.sqliteProjectID(), g.sqliteCPGVersion(), nodeType)
	if err != nil {
		return nil, err
	}
	return drainNodeCursor(cur)
}

// QueryNodesByFile returns all nodes of nodeType in relPath.
func (g *joernGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	if relPath == "" {
		return nil, fmt.Errorf("joern: QueryNodesByFile: relPath must not be empty")
	}
	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		nodes, err := g.queryNodesByFileFromSQLite(relPath, string(nodeType))
		if err == nil {
			return nodes, nil
		}
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

// queryNodesByFileFromSQLite reads nodes of a given type in a specific file from SQLite.
func (g *joernGraph) queryNodesByFileFromSQLite(relPath, nodeType string) ([]cpg.Node, error) {
	cur, err := g.sqliteDB().QueryNodesByFile(g.ctx, g.sqliteProjectID(), g.sqliteCPGVersion(), relPath, nodeType)
	if err != nil {
		return nil, err
	}
	return drainNodeCursor(cur)
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

	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		edges, err := g.queryEdgesFromSQLite(fromID, toID)
		if err == nil {
			g.cache.mu.Lock()
			g.cache.edgeCache[cacheKey] = edges
			g.cache.mu.Unlock()
			return edges, nil
		}
	}

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

// queryEdgesFromSQLite reads edges from the cpg_edges table.
func (g *joernGraph) queryEdgesFromSQLite(fromID, toID string) ([]cpg.Edge, error) {
	db := g.sqliteDB()
	proj, ver := g.sqliteProjectID(), g.sqliteCPGVersion()
	switch {
	case fromID != "" && toID == "":
		cur, err := db.GetEdgesFrom(g.ctx, proj, ver, fromID)
		if err != nil {
			return nil, err
		}
		return drainEdgeCursor(cur)
	case toID != "" && fromID == "":
		cur, err := db.GetEdgesTo(g.ctx, proj, ver, toID)
		if err != nil {
			return nil, err
		}
		return drainEdgeCursor(cur)
	default:
		cur, err := db.GetEdgesFrom(g.ctx, proj, ver, fromID)
		if err != nil {
			return nil, err
		}
		all, err := drainEdgeCursor(cur)
		if err != nil {
			return nil, err
		}
		if toID == "" {
			return all, nil
		}
		out := all[:0]
		for _, e := range all {
			if e.ToID == toID {
				out = append(out, e)
			}
		}
		return out, nil
	}
}

// GetCallGraph returns the full inter-procedural call graph.
func (g *joernGraph) GetCallGraph() (cpg.CallGraph, error) {
	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		cg, err := g.getCallGraphFromSQLite()
		if err == nil {
			return cg, nil
		}
	}
	// Fallback: paginated Joern HTTP reads with stable sortBy drop/take ordering.
	slog.Info("joern: GetCallGraph — querying paginated edges")
	var edges []joernEdge
	offset := 0
	for {
		q := queryAllEdgesPaginated(offset, pageSize)
		raw, err := g.client.doQuery(g.ctx, q)
		if err != nil {
			return nil, fmt.Errorf("joern: GetCallGraph page %d: %w", offset, err)
		}
		var page []joernEdge
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("joern: GetCallGraph: %w: %w", ErrMalformedResponse, err)
		}
		if len(page) == 0 {
			break
		}
		edges = append(edges, page...)
		offset += pageSize
	}

	cg := make(cpg.CallGraph, len(edges))
	for _, e := range edges {
		cg[e.From] = append(cg[e.From], e.To)
	}
	slog.Info("joern: GetCallGraph done", "edges", len(cg))
	return cg, nil
}

// getCallGraphFromSQLite builds a CallGraph from the SQLite cpg_edges table.
func (g *joernGraph) getCallGraphFromSQLite() (cpg.CallGraph, error) {
	rows, err := g.sqliteDB().Reader().QueryContext(g.ctx,
		`SELECT from_id, to_id FROM cpg_edges
		 WHERE project_id=? AND cpg_version=? AND edge_type='CALL'
		 ORDER BY from_id`, g.sqliteProjectID(), g.sqliteCPGVersion())
	if err != nil {
		return nil, fmt.Errorf("sqlite: getCallGraph: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	cg := make(cpg.CallGraph)
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			return nil, fmt.Errorf("sqlite: getCallGraph scan: %w", err)
		}
		cg[from] = append(cg[from], to)
	}
	return cg, rows.Err()
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
	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		nodes, err := g.getCallersFromSQLite(functionID)
		if err == nil {
			return nodes, nil
		}
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

// getCallersFromSQLite reads callers of functionID from the SQLite backend.
func (g *joernGraph) getCallersFromSQLite(functionID string) ([]cpg.Node, error) {
	cur, err := g.sqliteDB().GetCallers(g.ctx, g.sqliteProjectID(), g.sqliteCPGVersion(), functionID)
	if err != nil {
		return nil, err
	}
	return drainNodeCursor(cur)
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
	// Try SQLite fast path first.
	if g.sqliteDB() != nil {
		nodes, err := g.getCalleesFromSQLite(functionID)
		if err == nil {
			return nodes, nil
		}
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

// getCalleesFromSQLite reads callees of functionID from the SQLite backend.
func (g *joernGraph) getCalleesFromSQLite(functionID string) ([]cpg.Node, error) {
	cur, err := g.sqliteDB().GetCallees(g.ctx, g.sqliteProjectID(), g.sqliteCPGVersion(), functionID)
	if err != nil {
		return nil, err
	}
	return drainNodeCursor(cur)
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

	// Use SQLite recursive CTE when backend is available (single query vs N HTTP calls).
	if g.sqliteDB() != nil {
		cur, err := g.sqliteDB().GetNeighboursAtDepth(g.ctx, g.sqliteProjectID(), g.sqliteCPGVersion(), rootID, depth)
		if err == nil {
			return drainNodeCursor(cur)
		}
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

	// Extract method ID from source.
	methodID := ""
	for _, s := range sources {
		if s.NodeID != "" {
			methodID = s.NodeID
			break
		}
	}
	if methodID == "" {
		return nil, fmt.Errorf("joern: TaintPaths: no node ID in sources")
	}

	// Build sink names from language taint config.
	sinkNames := make([]string, 0)
	lang, ok := DetectLanguage(sources[0].File)
	if ok {
		if cfg, ok2 := TaintConfigs[lang]; ok2 {
			for _, sd := range cfg.Sinks {
				sinkNames = append(sinkNames, sd.JoernName())
			}
		}
	}
	if len(sinkNames) == 0 {
		// Hard fallback: common dangerous call names across languages
		sinkNames = []string{"executeQuery", "executeUpdate", "execute",
			"exec", "Runtime.exec", "eval", "readObject", "sendRedirect", "forward",
			"FileWriter", "FileOutputStream", "query", "rawQuery", "createNativeQuery"}
	}

	q := queryTaintFlows(methodID, sinkNames)
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

		sinkKind := classifySinkKind(f.Sink.Name, f.Sink.File)

		// Classify source kind using the language-specific taint taxonomy.
		sourceKind := classifySourceKind(f.Source.Name, f.Source.File)
		if sourceKind == "" {
			sourceKind = f.Source.Type
		}

		path := cpg.TaintPath{
			Source: cpg.TaintSource{
				NodeID: f.Source.ID,
			Name:   f.Source.Name,
				Kind:   sourceKind,
				File:   f.Source.File,
				Line:   f.Source.Line,
			},
			Sink: cpg.TaintSink{
				NodeID: f.Sink.ID,
				Name:   f.Sink.Name,
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

// ProjectWideTaintPaths runs taint analysis across all surface methods in a
// single project-wide query instead of one query per method. This enables
// Joern to discover inter-procedural flows that cross multiple method frames
// (e.g. controller → service → DAO → executeQuery).
//
// Parameters:
//   - surfaceIDs: Joern METHOD node IDs of all surface methods.
//   - lang: detected source language (used to select sink definitions from
//     TaintConfigs). If empty, the hard fallback sink list is used.
//
// Returns all discovered source-to-sink paths, capped at config.C.CPGMaxTaintPaths.
func (g *joernGraph) ProjectWideTaintPaths(surfaceIDs []string, lang string) ([]cpg.TaintPath, error) {
	if len(surfaceIDs) == 0 {
		return nil, fmt.Errorf("joern: ProjectWideTaintPaths: surfaceIDs must not be empty")
	}

	// Build sink names from language taint config.
	sinkNames := make([]string, 0)
	var constructorTypeNames []string
	if lang != "" {
		if cfg, ok := TaintConfigs[Language(lang)]; ok {
				for _, sd := range cfg.Sinks {
					sinkNames = append(sinkNames, sd.JoernName())
				}
				constructorTypeNames = ConstructorSinkTypeNames(Language(lang))
		}
	}
	if len(sinkNames) == 0 {
		sinkNames = []string{"executeQuery", "executeUpdate", "execute",
			"exec", "Runtime.exec", "eval", "readObject", "sendRedirect", "forward",
			"FileWriter", "FileOutputStream", "query", "rawQuery", "createNativeQuery"}
	}

	q := queryProjectWideTaintFlows(sinkNames, constructorTypeNames, surfaceIDs)
	slog.Debug("joern: ProjectWideTaintPaths query", "query", q, "surfaces", len(surfaceIDs))
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: ProjectWideTaintPaths: reachableByFlows: %w", err)
	}

	var flows []joernFlow
	if err := json.Unmarshal(raw, &flows); err != nil {
		return nil, fmt.Errorf("joern: ProjectWideTaintPaths: %w: %w", ErrMalformedResponse, err)
	}

	// Diagnostic: log raw flow count and sample method IDs before filtering.
	if len(flows) > 0 {
		sample := flows[0].MethodID
		if len(flows) > 1 {
			sample += ", " + flows[1].MethodID
		}
		slog.Debug("joern: ProjectWideTaintPaths raw", "total_flows", len(flows), "sample_method_ids", sample)
	}

	// Pass all flows through — surface attribution happens via BFS walk-up in
	// enrichment.go. Filtering here would discard inter-procedural paths whose
	// source method is a DAO/helper, not directly a surface controller.
	paths := make([]cpg.TaintPath, 0, min(len(flows), config.C.CPGMaxTaintPaths))
	for _, f := range flows {
		if len(paths) >= config.C.CPGMaxTaintPaths {
			break
		}
		// Drop phantom paths: Joern traces internal I/O and JDBC chains
		// (ResultSet, InputStream, ObjectInputStream) that are not user-controlled.
		// Signature: source parameter name is a known internal-type alias AND
		// the first few intermediate nodes are all single-word IO primitives.
		if isPhantomTaintPath(f) {
			continue
		}

		// Joern path order is SINK→SOURCE: elems.head = CALL (sink), elems.last = MethodParameterIn (source).
		// The Scala template labels them "source"/"sink" by position, so the JSON fields are inverted:
		//   f.Source = head = the dangerous CALL (e.g. executeQuery)
		//   f.Sink   = last = the MethodParameterIn (taint entry point)
		sinkKind := classifySinkKind(f.Source.Name, f.Source.File)

		sourceKind := classifySourceKind(f.MethodName, f.MethodFile)
		if sourceKind == "" {
			sourceKind = f.Sink.Type
		}

		// Prefer the CALL node's own file (f.Source.File after location.filename fix).
		// Fall back to the surface method file for intra-procedural paths where they match.
		sinkFile := joernNullStr(f.Source.File)
		if sinkFile == "" {
			sinkFile = joernNullStr(f.MethodFile)
		}

		// If the CALL node's lineNumber is 0, scan intermediate nodes for the first
		// one that has a non-zero line in the same file — gives a fallback anchor.
		sinkLine := f.Source.Line
		if sinkLine == 0 && sinkFile != "" {
			for _, iv := range f.Intermediate {
				if iv.Line > 0 && joernNullStr(iv.File) == sinkFile {
					sinkLine = iv.Line
					break
				}
			}
		}

		path := cpg.TaintPath{
			Source: cpg.TaintSource{
				NodeID: f.MethodID,
				Name:   f.MethodName,
				Kind:   sourceKind,
				File:   joernNullStr(f.MethodFile),
				Line:   0,
			},
			Sink: cpg.TaintSink{
				NodeID: f.Source.ID,
				Name:   f.Source.Name,
				Kind:   sinkKind,
				File:   sinkFile,
				Line:   sinkLine,
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
	slog.Info("joern: ProjectWideTaintPaths done", "surfaces", len(surfaceIDs), "paths", len(paths))
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

// paginatedNodeQuery returns the paginated query for the given node type.
func paginatedNodeQuery(nt cpg.NodeType, offset, take int) string {
	switch nt {
	case cpg.NodeMethod:
		return queryMethodsPaginated(offset, take)
	case cpg.NodeCall:
		return queryCallsPaginated(offset, take)
	case cpg.NodeParameter:
		return queryParamsPaginated(offset, take)
	case cpg.NodeIdentifier:
		return queryIdentifiersPaginated(offset, take)
	case cpg.NodeLiteral:
		return queryLiteralsPaginated(offset, take)
	default:
		return nodeTypeQuery(nt)
	}
}

// internalSourceNames are parameter names that are JDBC/IO types, not user input.
// Taint paths whose source parameter matches these produce phantom flows.
var internalSourceNames = map[string]bool{
	"is": true, "in": true, "out": true, "rs": true, "results": true,
	"ois": true, "buf": true, "buffer": true, "inputStream": true,
	"outputStream": true, "reader": true, "writer": true, "conn": true,
	"connection": true, "stmt": true, "ps": true, "pstmt": true,
}

// internalIntermediateNames are node names that appear in internal IO/JDBC chains.
var internalIntermediateNames = map[string]bool{
	"is": true, "in": true, "read": true, "results": true, "rs": true,
	"buf": true, "buffer": true, "ois": true, "out": true, "len": true,
	"n": true, "b": true, "inputStream": true, "outputStream": true,
	"FileCopyUtils": true, "copyToByteArray": true, "getEncoder": true,
	"encode": true, "encodeToString": true, "toByteArray": true,
	"getMetaData": true, "resultsMetaData": true, "getColumnCount": true,
	"getColumnName": true, "getColumnType": true, "findFirst": true,
	"cols": true, "col": true, "i": true, "canWrite": true,
}

// isPhantomTaintPath returns true when a Joern flow is an internal I/O or JDBC
// chain rather than a real user-input taint path. These arise because
// reachableByFlows uses ALL method parameters as sources, including ResultSet,
// InputStream, and ObjectInputStream parameters that are not user-controlled.
//
// Detection uses three independent conditions (OR):
//
//  1. Source param name is a known internal alias AND ≥3 of first 5
//     intermediate nodes are internal IO/JDBC primitives (the DAO-param case).
//
//  2. The intermediate chain is dominated by internal names regardless of the
//     source param name — ≥4 of first 8 intermediates are internal (catches
//     paths that start from a real user param but cross into JDBC/IO internals).
//
//  3. Very long paths (>500 hops) whose first intermediate is internal — a
//     fast-path for unbounded internal IO chains (e.g. ResultSet metadata
//     enumeration that produces thousands of nodes).
func isPhantomTaintPath(f joernFlow) bool {
	// ── condition 1: internal source param corroborated by intermediates ──
	srcName := f.Sink.Name
	if internalSourceNames[srcName] {
		check := f.Intermediate
		if len(check) > 5 {
			check = check[:5]
		}
		internalCount := 0
		for _, n := range check {
			if internalIntermediateNames[n.Name] {
				internalCount++
			}
		}
		if internalCount >= 3 {
			return true
		}
	}

	// ── condition 2: intermediate-chain domination heuristic ──
	check := f.Intermediate
	if len(check) > 8 {
		check = check[:8]
	}
	internalCount := 0
	for _, n := range check {
		if internalIntermediateNames[n.Name] {
			internalCount++
		}
	}
	if internalCount >= 4 {
		return true
	}

	// ── condition 3: very long internal IO chains ──
	if len(f.Intermediate) > 500 && internalIntermediateNames[f.Intermediate[0].Name] {
		return true
	}

	return false
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
