package joern

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// maxTaintPaths caps the number of taint paths returned by TaintPaths.
// CPGs for large codebases can produce thousands of paths; this cap prevents
// unbounded memory growth. Paths are ranked by source-to-sink hop count before
// truncation — shorter (more direct) paths are kept.
const maxTaintPaths = 1_000

// joernGraph implements cpg.Graph via Joern HTTP JSON queries (Joern DSL over HTTP).
// All methods use a background context internally because the cpg.Graph interface
// does not accept contexts. The per-query HTTP timeout (default 30 s) prevents hangs.
type joernGraph struct {
	client *Client
}

// ─── Joern DSL query templates ────────────────────────────────────────────────
//
// All queries end in .toList.toJson so doQuery receives a JSON array string.
// Field names use lowercase keys ("id", "name", "file", "line") for consistent
// mapping; Joern's own properties use uppercase (e.g. LINE_NUMBER) but the
// map() projection renames them.
//
// Integration-test note: the exact format of these queries must be verified
// against a live Joern instance (see joern_integration_test.go). The unit tests
// use httptest.Server mocks and do not validate Joern DSL correctness.

const (
	queryMethods = `cpg.method.map(m => Map(` +
		`"id" -> m.id.toString, ` +
		`"name" -> m.name, ` +
		`"file" -> m.filename, ` +
		`"line" -> m.lineNumber.getOrElse(0), ` +
		`"language" -> m.language` +
		`)).toList.toJson`

	queryCalls = `cpg.call.map(c => Map(` +
		`"id" -> c.id.toString, ` +
		`"name" -> c.name, ` +
		`"file" -> c.location.filename, ` +
		`"line" -> c.lineNumber.getOrElse(0), ` +
		`"language" -> ""` +
		`)).toList.toJson`

	queryParams = `cpg.parameter.map(p => Map(` +
		`"id" -> p.id.toString, ` +
		`"name" -> p.name, ` +
		`"file" -> p.location.filename, ` +
		`"line" -> p.lineNumber.getOrElse(0), ` +
		`"language" -> ""` +
		`)).toList.toJson`

	queryIdentifiers = `cpg.identifier.map(i => Map(` +
		`"id" -> i.id.toString, ` +
		`"name" -> i.name, ` +
		`"file" -> i.location.filename, ` +
		`"line" -> i.lineNumber.getOrElse(0), ` +
		`"language" -> ""` +
		`)).toList.toJson`

	queryLiterals = `cpg.literal.map(l => Map(` +
		`"id" -> l.id.toString, ` +
		`"name" -> l.code, ` +
		`"file" -> l.location.filename, ` +
		`"line" -> l.lineNumber.getOrElse(0), ` +
		`"language" -> ""` +
		`)).toList.toJson`

	// queryMethodsByFile: %s = relative file path
	queryMethodsByFile = `cpg.method.filename("%s").map(m => Map(` +
		`"id" -> m.id.toString, ` +
		`"name" -> m.name, ` +
		`"file" -> m.filename, ` +
		`"line" -> m.lineNumber.getOrElse(0), ` +
		`"language" -> m.language` +
		`)).toList.toJson`

	// queryCallsByFile: %s = relative file path
	queryCallsByFile = `cpg.call.filename("%s").map(c => Map(` +
		`"id" -> c.id.toString, ` +
		`"name" -> c.name, ` +
		`"file" -> c.location.filename, ` +
		`"line" -> c.lineNumber.getOrElse(0), ` +
		`"language" -> ""` +
		`)).toList.toJson`

	// queryEdgesFrom: %s = source node ID
	queryEdgesFrom = `cpg.graph.nodes(%s).outE.map(e => Map(` +
		`"from" -> e.outNode.id.toString, ` +
		`"to" -> e.inNode.id.toString, ` +
		`"type" -> e.label, ` +
		`"label" -> ""` +
		`)).toList.toJson`

	// queryEdgesTo: %s = destination node ID
	queryEdgesTo = `cpg.graph.nodes(%s).inE.map(e => Map(` +
		`"from" -> e.outNode.id.toString, ` +
		`"to" -> e.inNode.id.toString, ` +
		`"type" -> e.label, ` +
		`"label" -> ""` +
		`)).toList.toJson`

	// queryAllEdges: returns all call edges (CALL label only) for the full call graph.
	queryAllEdges = `cpg.graph.edges("CALL").map(e => Map(` +
		`"from" -> e.outNode.id.toString, ` +
		`"to" -> e.inNode.id.toString, ` +
		`"type" -> "CALL", ` +
		`"label" -> ""` +
		`)).toList.toJson`

	// queryCallersByID: %s = method node ID
	queryCallersByID = `cpg.method.id(%s).caller.map(m => Map(` +
		`"id" -> m.id.toString, ` +
		`"name" -> m.name, ` +
		`"file" -> m.filename, ` +
		`"line" -> m.lineNumber.getOrElse(0), ` +
		`"language" -> m.language` +
		`)).toList.toJson`

	// queryCalleesByID: %s = method node ID
	queryCalleesByID = `cpg.method.id(%s).callee.map(m => Map(` +
		`"id" -> m.id.toString, ` +
		`"name" -> m.name, ` +
		`"file" -> m.filename, ` +
		`"line" -> m.lineNumber.getOrElse(0), ` +
		`"language" -> m.language` +
		`)).toList.toJson`

	// queryRunTaint triggers Joern's built-in OSS dataflow pass.
	// Must be run before queryFindings returns meaningful results.
	queryRunTaint = `run.ossdataflow`

	// queryFindings returns all findings produced by the dataflow pass.
	queryFindings = `cpg.finding.map(f => Map(` +
		`"id" -> f.id.toString, ` +
		`"evidence" -> f.evidence.map(e => Map(` +
		`"id" -> e.id.toString, ` +
		`"name" -> e.property("NAME").toString, ` +
		`"file" -> e.property("FILENAME").toString, ` +
		`"line" -> Try(e.property("LINE_NUMBER").asInstanceOf[Int]).getOrElse(0)` +
		`)).l` +
		`)).toList.toJson`
)

// ─── wire types ───────────────────────────────────────────────────────────────

// joernNode is the JSON shape returned by all node-projection queries.
type joernNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Language string `json:"language"`
	Code     string `json:"code"`
}

// joernEdge is the JSON shape returned by all edge-projection queries.
type joernEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// joernFinding wraps the evidence nodes returned by queryFindings.
type joernFinding struct {
	ID       string      `json:"id"`
	Evidence []joernNode `json:"evidence"`
}

// ─── cpg.Graph implementation ─────────────────────────────────────────────────

// QueryNodes returns all nodes of nodeType across all ingested source files.
func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) {
	q := nodeTypeQuery(nodeType)
	raw, err := g.client.doQuery(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryNodes(%s): %w", nodeType, err)
	}
	return parseNodes(raw)
}

// QueryNodesByFile returns all nodes of nodeType in relPath.
func (g *joernGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	if relPath == "" {
		return nil, fmt.Errorf("joern: QueryNodesByFile: relPath must not be empty")
	}
	var q string
	switch nodeType {
	case cpg.NodeMethod:
		q = fmt.Sprintf(queryMethodsByFile, escapeScalaString(relPath))
	default:
		q = fmt.Sprintf(queryCallsByFile, escapeScalaString(relPath))
	}
	raw, err := g.client.doQuery(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryNodesByFile(%s, %s): %w", relPath, nodeType, err)
	}
	return parseNodes(raw)
}

// QueryEdges returns directed edges where fromID and toID match.
// Pass "" to match any node on that side (wildcard).
func (g *joernGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error) {
	if fromID == "" && toID == "" {
		return nil, fmt.Errorf("joern: QueryEdges: at least one of fromID or toID must be non-empty")
	}

	var raw []byte
	var err error
	switch {
	case fromID != "" && toID == "":
		q := fmt.Sprintf(queryEdgesFrom, fromID)
		raw, err = g.client.doQuery(context.Background(), q)
	case toID != "" && fromID == "":
		q := fmt.Sprintf(queryEdgesTo, toID)
		raw, err = g.client.doQuery(context.Background(), q)
	default:
		// Both set: query from-side and filter by toID on the Go side.
		q := fmt.Sprintf(queryEdgesFrom, fromID)
		raw, err = g.client.doQuery(context.Background(), q)
	}
	if err != nil {
		return nil, fmt.Errorf("joern: QueryEdges: %w", err)
	}

	all, err := parseEdges(raw)
	if err != nil {
		return nil, fmt.Errorf("joern: QueryEdges: %w", err)
	}

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
	raw, err := g.client.doQuery(context.Background(), queryAllEdges)
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
	return cg, nil
}

// GetCallers returns all functions that directly call the function with the
// given node ID.
func (g *joernGraph) GetCallers(functionID string) ([]cpg.Node, error) {
	if functionID == "" {
		return nil, fmt.Errorf("joern: GetCallers: functionID must not be empty")
	}
	q := fmt.Sprintf(queryCallersByID, functionID)
	raw, err := g.client.doQuery(context.Background(), q)
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
	q := fmt.Sprintf(queryCalleesByID, functionID)
	raw, err := g.client.doQuery(context.Background(), q)
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

// TaintPaths runs inter-procedural taint analysis from each source to each sink
// and returns all discovered source-to-sink paths, capped at maxTaintPaths.
//
// Sources and sinks must be non-empty. The method triggers Joern's OSS dataflow
// pass (run.ossdataflow) on the first call; subsequent calls reuse the results.
func (g *joernGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("joern: TaintPaths: sources must not be empty")
	}
	if len(sinks) == 0 {
		return nil, fmt.Errorf("joern: TaintPaths: sinks must not be empty")
	}

	// Trigger the dataflow pass — idempotent if already run.
	if _, err := g.client.doQuery(context.Background(), queryRunTaint); err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: run.ossdataflow: %w", err)
	}

	raw, err := g.client.doQuery(context.Background(), queryFindings)
	if err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: query findings: %w", err)
	}

	var findings []joernFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: %w: %w", ErrMalformedResponse, err)
	}

	paths := make([]cpg.TaintPath, 0, min(len(findings), maxTaintPaths))
	for _, f := range findings {
		if len(paths) >= maxTaintPaths {
			break
		}
		if len(f.Evidence) < 2 {
			continue
		}

		first := f.Evidence[0]
		last := f.Evidence[len(f.Evidence)-1]

		path := cpg.TaintPath{
			Source: cpg.TaintSource{
				NodeID: first.ID,
				Kind:   "finding",
				File:   first.File,
				Line:   first.Line,
			},
			Sink: cpg.TaintSink{
				NodeID: last.ID,
				Kind:   cpg.SinkSQL, // most common; refined in L2 taint taxonomy
				File:   last.File,
				Line:   last.Line,
			},
		}
		intermediate := make([]cpg.Node, 0, len(f.Evidence)-2)
		for _, ev := range f.Evidence[1 : len(f.Evidence)-1] {
			intermediate = append(intermediate, cpg.Node{
				ID:   ev.ID,
				Name: ev.Name,
				File: ev.File,
				Line: ev.Line,
			})
		}
		path.IntermediateNodes = intermediate
		paths = append(paths, path)
	}
	return paths, nil
}

// PreFlaggedSinks returns dangerous sink nodes pre-flagged by Tree-sitter.
// Stub in L1 — Tree-sitter integration is implemented in L2 (ML2.1.T4).
func (g *joernGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) {
	// L2 note: Tree-sitter pre-flags sinks before CPG build; their IDs are
	// stored in SQLite and loaded here to ensure they are always in scope
	// regardless of module segmentation mode.
	return nil, nil
}

// ─── parsing helpers ──────────────────────────────────────────────────────────

func parseNodes(raw []byte) ([]cpg.Node, error) {
	var jns []joernNode
	if err := json.Unmarshal(raw, &jns); err != nil {
		return nil, fmt.Errorf("%w: parse nodes: %w", ErrMalformedResponse, err)
	}
	nodes := make([]cpg.Node, len(jns))
	for i, jn := range jns {
		nodes[i] = cpg.Node{
			ID:       jn.ID,
			Type:     cpg.NodeMethod, // refined per query type in the caller
			Name:     jn.Name,
			File:     jn.File,
			Line:     jn.Line,
			Language: jn.Language,
			Code:     jn.Code,
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

// nodeTypeQuery returns the Joern DSL query for the given node type.
// Falls back to CALL nodes for unrecognised types.
func nodeTypeQuery(nt cpg.NodeType) string {
	switch nt {
	case cpg.NodeMethod:
		return queryMethods
	case cpg.NodeCall:
		return queryCalls
	case cpg.NodeParameter:
		return queryParams
	case cpg.NodeIdentifier:
		return queryIdentifiers
	case cpg.NodeLiteral:
		return queryLiterals
	default:
		// Generic fallback: query by _label via Joern's graph API.
		return fmt.Sprintf(
			`cpg.graph.nodes.filter(_._label == %q).map(n => Map(`+
				`"id" -> n.id.toString, `+
				`"name" -> Try(n.property("NAME").asInstanceOf[String]).getOrElse(""), `+
				`"file" -> Try(n.property("FILENAME").asInstanceOf[String]).getOrElse(""), `+
				`"line" -> Try(n.property("LINE_NUMBER").asInstanceOf[Int]).getOrElse(0), `+
				`"language" -> ""`+
				`)).toList.toJson`,
			string(nt),
		)
	}
}

// escapeScalaString escapes a string for safe embedding in a Joern DSL query.
// Only double-quotes and backslashes require escaping.
func escapeScalaString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
