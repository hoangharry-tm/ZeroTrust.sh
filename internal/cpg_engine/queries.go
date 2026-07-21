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

package cpg_engine

import (
	"embed"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

// ─── Joern DSL query builders ─────────────────────────────────────────────
//
// Every query sent to Joern is real Scala 3, kept in its own *.scala /
// *.scala.tmpl file under queries/ so it can be read, diffed, and
// syntax-highlighted as Scala rather than as a Go string literal. Templated
// queries (*.scala.tmpl) use Go's {{.Field}} substitution — visually
// distinct from Scala's own ${expr} string interpolation, so a reader is
// never left guessing which language a given token belongs to.
//
// All queries build JSON manually via Scala string interpolation (no
// upickle/toJson — removed in Joern 4.0.550); the final
// .toList.mkString("[", ",", "]") produces a JSON array string that
// parseStdout unwraps.
//
// Field names use lowercase keys ("id", "name", "file", "line") for
// consistent mapping; Joern's own properties use uppercase (e.g.
// LINE_NUMBER) but the interpolation renames them.

//go:embed queries/*.scala queries/*.scala.tmpl
var queryFS embed.FS

var queryTemplates = template.Must(template.ParseFS(queryFS, "queries/*.scala.tmpl"))

// renderQuery executes the named template (queries/<name>.scala.tmpl) with data.
// A render failure means a template/data field mismatch — a programming bug,
// not a runtime condition — so it panics rather than silently sending Joern
// malformed Scala.
func renderQuery(name string, data any) string {
	var sb strings.Builder
	if err := queryTemplates.ExecuteTemplate(&sb, name, data); err != nil {
		panic(fmt.Sprintf("cpg_engine: query template %q: %v", name, err))
	}
	return sb.String()
}

// staticQuery reads a parameterless query file (queries/<name>.scala) as-is.
func staticQuery(name string) string {
	b, err := queryFS.ReadFile("queries/" + name + ".scala")
	if err != nil {
		panic(fmt.Sprintf("cpg_engine: static query %q: %v", name, err))
	}
	return string(b)
}

// nodeQuery builds a Joern DSL query for traversal, mapping each node to a
// JSON object with id/name/file/line/code fields. The code field is sanitised
// to remove backslashes, double-quotes, and control characters so that Scala
// string-interpolation always produces valid JSON.
func nodeQuery(traversal, alias, nameExpr, fileExpr string) string {
	return renderQuery("node_query.scala.tmpl", struct {
		Traversal, Alias, NameExpr, FileExpr string
	}{traversal, alias, nameExpr, fileExpr})
}

// queryMethods returns a DSL expression for all METHOD nodes.
func queryMethods() string { return nodeQuery("cpg.method", "m", "m.name", "m.filename") }

// queryCalls returns a DSL expression for all CALL nodes.
func queryCalls() string {
	return nodeQuery("cpg.call", "c", "c.name", "c.location.filename")
}

// queryParams returns a DSL expression for all METHOD_PARAMETER_IN nodes.
func queryParams() string {
	return nodeQuery("cpg.parameter", "p", "p.name", "p.location.filename")
}

// queryIdentifiers returns a DSL expression for all IDENTIFIER nodes.
func queryIdentifiers() string {
	return nodeQuery("cpg.identifier", "i", "i.name", "i.location.filename")
}

// queryLiterals returns a DSL expression for all LITERAL nodes.
func queryLiterals() string {
	return nodeQuery("cpg.literal", "l", "l.code", "l.location.filename")
}

// queryMethodsByFile returns a DSL expression for METHOD nodes in a file.
func queryMethodsByFile(relPath string) string {
	traversal := fmt.Sprintf(`cpg.method.where(_.file.name("%s"))`, escapeScalaString(relPath))
	return nodeQuery(traversal, "m", "m.name", "m.filename")
}

// queryCallsByFile returns a DSL expression for CALL nodes in a file.
func queryCallsByFile(relPath string) string {
	traversal := fmt.Sprintf(`cpg.call.where(_.file.name("%s"))`, escapeScalaString(relPath))
	return nodeQuery(traversal, "c", "c.name", "c.location.filename")
}

// queryEdgesFrom returns a DSL expression for outgoing edges from a node.
// Limited to METHOD nodes — flatgraph's edges() API is not exposed in the DSL.
func queryEdgesFrom(nodeID string) string {
	return renderQuery("edges_from.scala.tmpl", struct{ NodeID string }{nodeID})
}

// queryEdgesTo returns a DSL expression for incoming edges to a node.
// Limited to METHOD nodes — see queryEdgesFrom.
func queryEdgesTo(nodeID string) string {
	return renderQuery("edges_to.scala.tmpl", struct{ NodeID string }{nodeID})
}

// queryAllEdges returns a DSL expression for the full caller METHOD→callee METHOD edge set.
// from = caller METHOD node id; to = callee METHOD node id.
func queryAllEdges() string {
	return staticQuery("all_edges")
}

// queryMethodsPaginated returns a DSL expression for METHOD nodes with stable
// sortBy-based pagination. Used by IngestCPGToSQLite to drain in batches.
func queryMethodsPaginated(skip, take int) string {
	traversal := fmt.Sprintf("cpg.method\n  .sortBy(_.id)\n  .drop(%d)\n  .take(%d)", skip, take)
	return nodeQuery(traversal, "m", "m.name", "m.filename")
}

// queryCallsPaginated returns a DSL expression for CALL nodes with stable pagination.
func queryCallsPaginated(skip, take int) string {
	traversal := fmt.Sprintf("cpg.call\n  .sortBy(_.id)\n  .drop(%d)\n  .take(%d)", skip, take)
	return nodeQuery(traversal, "c", "c.name", "c.location.filename")
}

// queryParamsPaginated returns a DSL expression for METHOD_PARAMETER_IN nodes
// with stable pagination.
func queryParamsPaginated(skip, take int) string {
	traversal := fmt.Sprintf("cpg.parameter\n  .sortBy(_.id)\n  .drop(%d)\n  .take(%d)", skip, take)
	return nodeQuery(traversal, "p", "p.name", "p.location.filename")
}

// queryIdentifiersPaginated returns a DSL expression for IDENTIFIER nodes
// with stable pagination.
func queryIdentifiersPaginated(skip, take int) string {
	traversal := fmt.Sprintf("cpg.identifier\n  .sortBy(_.id)\n  .drop(%d)\n  .take(%d)", skip, take)
	return nodeQuery(traversal, "i", "i.name", "i.location.filename")
}

// queryLiteralsPaginated returns a DSL expression for LITERAL nodes
// with stable pagination.
func queryLiteralsPaginated(skip, take int) string {
	traversal := fmt.Sprintf("cpg.literal\n  .sortBy(_.id)\n  .drop(%d)\n  .take(%d)", skip, take)
	return nodeQuery(traversal, "l", "l.code", "l.location.filename")
}

// queryAllEdgesPaginated returns a DSL expression for the full caller→callee
// edge set with stable pagination over the outer call iterator. Each page
// processes up to `take` call nodes through flatMap.
func queryAllEdgesPaginated(skip, take int) string {
	return renderQuery("all_edges_paginated.scala.tmpl", struct{ Skip, Take int }{skip, take})
}

// queryCallersByID returns a DSL expression for callers of a method.
func queryCallersByID(functionID string) string {
	traversal := fmt.Sprintf("cpg.method.id(%sL)\n  .caller\n  .filterNot(_.id < 0)", functionID)
	return nodeQuery(traversal, "m", "m.name", "m.filename")
}

// queryCalleesByID returns a DSL expression for callees of a method.
func queryCalleesByID(functionID string) string {
	traversal := fmt.Sprintf("cpg.method.id(%sL)\n  .callee\n  .filterNot(_.id < 0)", functionID)
	return nodeQuery(traversal, "m", "m.name", "m.location.filename")
}

// queryProjectWideTaintFlows returns a DSL expression for taint flows across
// all surface methods in a single query. Unlike queryTaintFlows (which runs one
// query per method), this builds a Set of surface method IDs and runs
// reachableByFlows against all of them at once, enabling Joern to discover
// inter-procedural flows that cross multiple method frames.
//
// Parameters:
//   - sinkNames: call names to match as regular sinks (e.g. "executeQuery", "exec").
//   - constructorTypeNames: type names for constructor-based sinks matched against
//     c.typeFullName when c.name == "<init>". Empty slice is valid.
//   - surfaceMethodIDs: Joern node IDs (as decimal strings) of surface methods
//     whose parameters are treated as sources. Currently unused by the query
//     itself — see the ponytail note below — kept in the signature because
//     Go-side filtering to these IDs happens after unmarshal.
func queryProjectWideTaintFlows(sinkNames, constructorTypeNames []string, surfaceMethodIDs []string) string {
	// ponytail: global query — flatMap per-method breaks Joern's inter-procedural
	// DFG context (returns 0). Run globally, annotate each path with the enclosing
	// method of the sink call (first path element) via cpg.call.id().method.
	// Filtering to surface methods is done in Go after unmarshal.
	_ = surfaceMethodIDs

	return renderQuery("project_wide_taint_flows.scala.tmpl", struct {
		SinkSet, CtorSinkSet string
	}{
		SinkSet:     scalaStringSet(sinkNames),
		CtorSinkSet: scalaStringSet(constructorTypeNames),
	})
}

// queryTaintFlows returns a DSL expression for taint flows within a method.
// Uses reachableByFlows (modern Joern API) — not run.ossdataflow + cpg.finding
// (which produce zero findings in Joern 4.0.550).
//
// The id is substituted directly into the query as a Long literal.
// Supports both METHOD node IDs and CALL node IDs — if the ID refers to a
// CALL node, the query navigates to its parent METHOD automatically.
//
// Deprecated: Use queryProjectWideTaintFlows for new code. Kept for integration
// test backward compatibility.
func queryTaintFlows(methodID string, sinkNames []string) string {
	return renderQuery("taint_flows.scala.tmpl", struct {
		MethodID, SinkSet string
	}{
		MethodID: methodID,
		SinkSet:  scalaStringSet(sinkNames),
	})
}

// queryNodeTypeGeneric returns a fallback DSL expression for unrecognised node
// types. Queries by _label via the graph API.
func queryNodeTypeGeneric(nt string) string {
	return renderQuery("node_type_generic.scala.tmpl", struct{ QuotedLabel string }{strconv.Quote(nt)})
}

// scalaStringSet renders a Go string slice as a Scala Set(...) string literal.
func scalaStringSet(items []string) string {
	return `Set("` + strings.Join(items, `","`) + `")`
}
