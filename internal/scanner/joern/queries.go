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
	"fmt"
	"strings"
)

// ─── Joern DSL query builders ─────────────────────────────────────────────
//
// All queries construct JSON manually via Scala 3 string interpolation
// (s"""...""") to avoid any library dependency (upickle/toJson were removed in
// Joern 4.0.550). The final .toList.mkString("[", ",", "]") builds a JSON array
// string that parseStdout unwraps.
//
// Field names use lowercase keys ("id", "name", "file", "line") for consistent
// mapping; Joern's own properties use uppercase (e.g. LINE_NUMBER) but the
// interpolation renames them.
//
// Key Scala-REPL rules enforced in all templates:
//   - try/catch instead of scala.util.Try (not in scope)
//   - val-blocks to isolate nested s"""...""" from outer interpolation
//   - method chains continue via leading dot on next line (Scala 3 "leading
//     infix operator" rule: newline + `.foo` is parsed as `.foo` continuation)

// nodeQuery builds a Joern DSL query for traversal, mapping each node to a
// JSON object with id/name/file/line/code fields. The code field is sanitised
// to remove backslashes, double-quotes, and control characters so that Scala
// string-interpolation always produces valid JSON. _c is used as the sanitise
// lambda variable to avoid shadowing the outer alias.
func nodeQuery(traversal, alias, nameExpr, fileExpr string) string {
	return fmt.Sprintf(
		"%s\n"+
			`  .map(%s => { val sc=%s.code.map(_c => if (_c=='\\'||_c=='"'||_c<32||_c>126) ' ' else _c).mkString; `+
			`s"""{"id":"${%s.id.toString}","name":"${%s}","file":"${%s}","line":${%s.lineNumber.getOrElse(0)},"code":"${sc}"}""" })`+"\n"+
			`  .toList`+"\n"+
			`  .mkString("[", ",", "]")`,
		traversal, alias, alias, alias, nameExpr, fileExpr, alias,
	)
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
	escaped := escapeScalaString(relPath)
	return fmt.Sprintf(`cpg.call.where(_.file.name("%s"))
  .map(c => { val sc=c.code.map(cp => if (cp=='\\'||cp=='"'||cp<32||cp>126) ' ' else cp).mkString; s"""{"id":"${c.id.toString}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)},"code":"${sc}"}""" })
  .toList
  .mkString("[", ",", "]")`, escaped)
}

// queryEdgesFrom returns a DSL expression for outgoing edges from a node.
// Limited to METHOD nodes — flatgraph's edges() API is not exposed in the DSL.
func queryEdgesFrom(nodeID string) string {
	// Uses %[1]s to reuse the same nodeID argument in both the filter and the JSON.
	return fmt.Sprintf(`cpg.method
  .filter(_.id == %[1]sL)
  .out
  .map(n => s"""{"from":"%[1]s","to":"${n.id.toString}","type":"","label":""}""")
  .toList
  .mkString("[", ",", "]")`, nodeID)
}

// queryEdgesTo returns a DSL expression for incoming edges to a node.
// Limited to METHOD nodes — see queryEdgesFrom.
func queryEdgesTo(nodeID string) string {
	return fmt.Sprintf(`cpg.method
  .filter(_.id == %[1]sL)
  .in
  .map(n => s"""{"from":"${n.id.toString}","to":"%[1]s","type":"","label":""}""")
  .toList
  .mkString("[", ",", "]")`, nodeID)
}

// queryAllEdges returns a DSL expression for the full caller METHOD→callee METHOD edge set.
// from = caller METHOD node id; to = callee METHOD node id.
// Previously used call.id (CALL node) as from, which mismatched QueryCallees (keyed by METHOD id).
func queryAllEdges() string {
	return `cpg.call
  .flatMap(call => call.callee.map(callee =>
    s"""{"from":"${call.method.id.toString}","to":"${callee.id.toString}","type":"CALL","label":""}"""
  ))
  .toList
  .mkString("[", ",", "]")`
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

// queryAllEdgesPaginated returns a DSL expression for the full caller→callee
// edge set with stable pagination over the outer call iterator. Each page
// processes up to `take` call nodes through flatMap.
func queryAllEdgesPaginated(skip, take int) string {
	return fmt.Sprintf(`cpg.call
  .sortBy(_.id)
  .drop(%d)
  .take(%d)
  .flatMap(call => call.callee.map(callee =>
    s"""{"from":"${call.method.id.toString}","to":"${callee.id.toString}","type":"CALL","label":""}"""
  ))
  .toList
  .mkString("[", ",", "]")`, skip, take)
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

// queryTaintFlows returns a DSL expression for taint flows within a method.
// Uses reachableByFlows (modern Joern API) — not run.ossdataflow + cpg.finding
// (which produce zero findings in Joern 4.0.550).
//
// The methodID is substituted directly into the query as a Long literal.
func queryTaintFlows(methodID string) string {
	const tmpl = `cpg.method
  .filter(_.id == $IDL)
  .call
  .reachableByFlows(cpg.method.filter(_.id == $IDL).parameter)
  .map(p => {
    val elems = p.elements.toList
    val first = elems.head
    val last = elems.last
    val intermediateJson = elems
      .slice(1, elems.size - 1)
      .map(n => s"""{"id":"${n.id.toString}","name":"${n match{case c:Call=>c.name;case mp:MethodParameterIn=>mp.name;case i:Identifier=>i.name;case _=>""}}","file":"${try{n.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{n.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${n.label}"}""")
      .mkString(",")
    s"""{"source":{"id":"${first.id.toString}","name":"${first match{case mp:MethodParameterIn=>mp.name;case m:Method=>m.name;case c:Call=>c.name;case _=>""}}","file":"${try{first.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{first.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${first.label}"},"sink":{"id":"${last.id.toString}","name":"${last match{case c:Call=>c.name;case m:Method=>m.name;case _=>""}}","file":"${try{last.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{last.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${last.label}"},"intermediate":[${intermediateJson}]}"""
  })
  .toList
  .mkString("[", ",", "]")`
	return strings.ReplaceAll(tmpl, "$ID", methodID)
}

// queryNodeTypeGeneric returns a fallback DSL expression for unrecognised node
// types. Queries by _label via the graph API.
func queryNodeTypeGeneric(nt string) string {
	return fmt.Sprintf(`cpg.graph
  .nodes
  .filter(_._label == %q)
  .map(n => { val sc=try{n.property("CODE").asInstanceOf[String]}catch{case _=>""}; val safesc=sc.map(c => if (c=='\\'||c=='"'||c<32||c>126) ' ' else c).mkString; s"""{"id":"${n.id.toString}","name":"${try{n.property("NAME").asInstanceOf[String]}catch{case _=>""}}","file":"${try{n.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{n.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${n.label}","code":"${safesc}"}""" })
  .toList
  .mkString("[", ",", "]")`, nt)
}
