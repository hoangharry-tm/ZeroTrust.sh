// Copyright 2026 hoangharry-tm
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

// queryMethods returns a DSL expression for all METHOD nodes.
func queryMethods() string {
	return `cpg.method
  .map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`
}

// queryCalls returns a DSL expression for all CALL nodes.
func queryCalls() string {
	return `cpg.call
  .map(c => s"""{"id":"${c.id.toString}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`
}

// queryParams returns a DSL expression for all METHOD_PARAMETER_IN nodes.
func queryParams() string {
	return `cpg.parameter
  .map(p => s"""{"id":"${p.id.toString}","name":"${p.name}","file":"${p.location.filename}","line":${p.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`
}

// queryIdentifiers returns a DSL expression for all IDENTIFIER nodes.
func queryIdentifiers() string {
	return `cpg.identifier
  .map(i => s"""{"id":"${i.id.toString}","name":"${i.name}","file":"${i.location.filename}","line":${i.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`
}

// queryLiterals returns a DSL expression for all LITERAL nodes.
func queryLiterals() string {
	return `cpg.literal
  .map(l => s"""{"id":"${l.id.toString}","name":"${l.code}","file":"${l.location.filename}","line":${l.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`
}

// queryMethodsByFile returns a DSL expression for METHOD nodes in a file.
func queryMethodsByFile(relPath string) string {
	escaped := escapeScalaString(relPath)
	return fmt.Sprintf(`cpg.method.filename("%s")
  .map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`, escaped)
}

// queryCallsByFile returns a DSL expression for CALL nodes in a file.
func queryCallsByFile(relPath string) string {
	escaped := escapeScalaString(relPath)
	return fmt.Sprintf(`cpg.call.filename("%s")
  .map(c => s"""{"id":"${c.id.toString}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)}}""")
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

// queryAllEdges returns a DSL expression for the full caller→callee edge set.
// Uses cpg.call.flatMap(_.callee) because flatgraph's edges() is not exposed.
func queryAllEdges() string {
	return `cpg.call
  .flatMap(call => call.callee.map(callee =>
    s"""{"from":"${call.id.toString}","to":"${callee.id.toString}","type":"CALL","label":""}"""
  ))
  .toList
  .mkString("[", ",", "]")`
}

// queryCallersByID returns a DSL expression for callers of a method.
func queryCallersByID(functionID string) string {
	return fmt.Sprintf(`cpg.method.id(%s)
  .caller
  .map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`, functionID)
}

// queryCalleesByID returns a DSL expression for callees of a method.
func queryCalleesByID(functionID string) string {
	return fmt.Sprintf(`cpg.method.id(%s)
  .callee
  .map(m => s"""{"id":"${m.id.toString}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""")
  .toList
  .mkString("[", ",", "]")`, functionID)
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
  .map(n => s"""{"id":"${n.id.toString}","name":"${try{n.property("NAME").asInstanceOf[String]}catch{case _=>""}}","file":"${try{n.property("FILENAME").asInstanceOf[String]}catch{case _=>""}}","line":${try{n.property("LINE_NUMBER").asInstanceOf[Int]}catch{case _=>0}},"type":"${n.label}"}""")
  .toList
  .mkString("[", ",", "]")`, nt)
}
