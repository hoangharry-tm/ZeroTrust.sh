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
// ctx is the scan lifetime context propagated to every doQuery call so that
// Ctrl-C / deadline cancellation aborts in-flight Joern queries promptly.
// Use Client.GraphWithContext to supply a real scan context; Graph() falls back
// to context.Background() for callers that do not have one.
type joernGraph struct {
	client *Client
	ctx    context.Context //nolint:containedctx // intentional: scan lifetime, not request lifetime
}

// ─── Joern DSL query templates ────────────────────────────────────────────────
//
// All queries construct JSON manually via Scala 3 string interpolation
// (s"""...""") to avoid any library dependency (upickle/toJson were removed in
// Joern 4.0.550; spray-json compat is untested). The final .toList.mkString("[",
// ",", "]") builds a JSON array string that parseStdout unwraps correctly.
//
// Field names use lowercase keys ("id", "name", "file", "line") for consistent
// mapping; Joern's own properties use uppercase (e.g. LINE_NUMBER) but the
// interpolation renames them.
//
// Integration-test note: the exact format of these queries must be verified
// against a live Joern instance (see joern_integration_test.go). The unit tests
// use httptest.Server mocks and do not validate Joern DSL correctness.

const (
	queryMethods = `cpg.method.map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	queryCalls = `cpg.call.map(c => s"""{"id":"${c.id.toString}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	queryParams = `cpg.parameter.map(p => s"""{"id":"${p.id.toString}","name":"${p.name}","file":"${p.location.filename}","line":${p.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	queryIdentifiers = `cpg.identifier.map(i => s"""{"id":"${i.id.toString}","name":"${i.name}","file":"${i.location.filename}","line":${i.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	queryLiterals = `cpg.literal.map(l => s"""{"id":"${l.id.toString}","name":"${l.code}","file":"${l.location.filename}","line":${l.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	// queryMethodsByFile: %s = relative file path
	queryMethodsByFile = `cpg.method.filename("%s").map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	// queryCallsByFile: %s = relative file path
	queryCallsByFile = `cpg.call.filename("%s").map(c => s"""{"id":"${c.id.toString}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	// queryEdgesFrom: %s = source node ID
	// NOTE: limited to METHOD nodes in this version; CALL and other node types
	// require a flatgraph API not exposed in the Joern DSL.
	queryEdgesFrom = `cpg.method.filter(_.id == %[1]sL).out.map(n => s"""{"from":"%[1]s","to":"${n.id.toString}","type":"","label":""}""").toList.mkString("[", ",", "]")`

	// queryEdgesTo: %s = destination node ID
	// NOTE: limited to METHOD nodes in this version; see queryEdgesFrom.
	queryEdgesTo = `cpg.method.filter(_.id == %[1]sL).in.map(n => s"""{"from":"${n.id.toString}","to":"%[1]s","type":"","label":""}""").toList.mkString("[", ",", "]")`

	// queryAllEdges: returns all caller→callee edges for the full call graph.
	// Uses cpg.call.flatMap(_.callee) to enumerate every call target (flatgraph's
	// edges() API is not exposed to the Joern DSL in v4.0.550).
	queryAllEdges = `cpg.call.flatMap(call => call.callee.map(callee => s"""{"from":"${call.id.toString}","to":"${callee.id.toString}","type":"CALL","label":""}""")).toList.mkString("[", ",", "]")`

	// queryCallersByID: %s = method node ID
	queryCallersByID = `cpg.method.id(%s).caller.map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	// queryCalleesByID: %s = method node ID
	queryCalleesByID = `cpg.method.id(%s).callee.map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""").toList.mkString("[", ",", "]")`

	// queryTaintFlows uses Joern's modern reachableByFlows API (not run.ossdataflow
	// + cpg.finding, which produce no findings in Joern 4.0.550). It takes a method
	// node ID (%[1]s) and returns all taint flows from parameters to calls within
	// that method as a JSON array.
	//
	// The template uses try/catch (not scala.util.Try, which is not in scope) and
	// avoids nested s"""...""" inside the outer interpolation by computing
	// intermediateJson as a separate val.
	queryTaintFlows = `cpg.method.filter(_.id == %[1]sL).call.reachableByFlows(cpg.method.filter(_.id == %[1]sL).parameter).map(p => {val elems = p.elements.toList; val first = elems.head; val last = elems.last; val intermediateJson = elems.slice(1, elems.size-1).map(n => s"""{"id":"${n.id.toString}","name":"${n match{case c:Call=>c.name;case mp:MethodParameterIn=>mp.name;case i:Identifier=>i.name;case _=>""}}","file":"${try{n.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{n.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${n.label}"}""").mkString(","); s"""{"source":{"id":"${first.id.toString}","name":"${first match{case mp:MethodParameterIn=>mp.name;case m:Method=>m.name;case c:Call=>c.name;case _=>""}}","file":"${try{first.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{first.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${first.label}"},"sink":{"id":"${last.id.toString}","name":"${last match{case c:Call=>c.name;case m:Method=>m.name;case _=>""}}","file":"${try{last.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{last.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${last.label}"},"intermediate":[${intermediateJson}]}"""}).toList.mkString("[", ",", "]")`
)

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
func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) {
	q := nodeTypeQuery(nodeType)
	raw, err := g.client.doQuery(g.ctx,q)
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
	raw, err := g.client.doQuery(g.ctx,q)
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
		raw, err = g.client.doQuery(g.ctx,q)
	case toID != "" && fromID == "":
		q := fmt.Sprintf(queryEdgesTo, toID)
		raw, err = g.client.doQuery(g.ctx,q)
	default:
		// Both set: query from-side and filter by toID on the Go side.
		q := fmt.Sprintf(queryEdgesFrom, fromID)
		raw, err = g.client.doQuery(g.ctx,q)
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
	raw, err := g.client.doQuery(g.ctx,queryAllEdges)
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
	raw, err := g.client.doQuery(g.ctx,q)
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
	raw, err := g.client.doQuery(g.ctx,q)
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

// TaintPaths runs taint analysis using Joern's built-in reachableByFlows API
// and returns all discovered source-to-sink paths, capped at maxTaintPaths.
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

	q := fmt.Sprintf(queryTaintFlows, methodID)
	raw, err := g.client.doQuery(g.ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: reachableByFlows: %w", err)
	}

	var flows []joernFlow
	if err := json.Unmarshal(raw, &flows); err != nil {
		return nil, fmt.Errorf("joern: TaintPaths: %w: %w", ErrMalformedResponse, err)
	}

	paths := make([]cpg.TaintPath, 0, min(len(flows), maxTaintPaths))
	for _, f := range flows {
		if len(paths) >= maxTaintPaths {
			break
		}

		// Classify the sink kind using the language-specific taint taxonomy.
		sinkKind := classifySinkKind(f.Sink.Name, f.Sink.File)

		path := cpg.TaintPath{
			Source: cpg.TaintSource{
				NodeID: f.Source.ID,
				Kind:   f.Source.Type,
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
			ID:   jn.ID,
			Type: cpg.NodeMethod, // refined per query type in the caller
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
			`cpg.graph.nodes.filter(_._label == %q).map(n => s"""{"id":"${n.id.toString}","name":"${Try(n.property("NAME").asInstanceOf[String]).getOrElse("")}","file":"${Try(n.property("FILENAME").asInstanceOf[String]).getOrElse("")}","line":${Try(n.property("LINE_NUMBER").asInstanceOf[Int]).getOrElse(0)}}""").toList.mkString("[", ",", "]")`,
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
