# Joern HTTP API — Spike Notes

> **Status**: L1 spike contract. All query formats must be verified against a
> live Joern instance. If a query returns unexpected output, update this document
> before adjusting the Go code.

---

## Server Launch

```sh
joern-server --host 127.0.0.1 --port 8080
```

**Security invariant**: always bind to `127.0.0.1`. Never `0.0.0.0`.
The Go client enforces this via `validateServerURL` and passes `--host 127.0.0.1`
when spawning the subprocess.

**Health check** (polled by `waitReady` during startup):

```
GET http://127.0.0.1:8080/ready
→ 200 OK when the JVM is warm and ready to accept queries
```

---

## Query Endpoint

```
POST http://127.0.0.1:8080/query
Content-Type: application/json

{"query": "<joern-scala-expression>"}
```

**Response schema**:

```json
{
  "uuid":    "string",
  "success": true | false,
  "stdout":  "string",
  "stderr":  "string"
}
```

- `success: false` → `stderr` contains the Joern/Scala error message.
- `stdout` may be wrapped in a Scala REPL annotation (`res0: Type = ...`) in
  some Joern builds. `parseStdout` normalises all three known forms:
  - Bare JSON: `[{"id":"1",...}]`
  - REPL annotation: `res0: String = "[{\"id\":...}]"`
  - Scala string literal: `"[{\"id\":...}]"`

---

## CPG Operations

### Build (first scan)

```scala
importCode(inputPath="/path/to/src")
importCode(inputPath="/path/to/src", language="JAVASRC")
```

Supported language strings: `JAVASRC`, `PYTHONSRC`, `GOLANG`, `JSSRC`, `RUBYSRC`.
Empty `language` → Joern auto-detects.

The call blocks until the build completes (synchronous in Joern's HTTP server).
Use `WithBuildTimeout` to configure the deadline (default 120 s).

### Save / Load (incremental scans)

```scala
cpg.save
importCpg(path="/path/to/saved.cpg")
```

> **Spike verification needed**: confirm exact `save` command syntax; may be
> `workspace.getActiveProject.foreach(_.cpg.save("/path"))` in Joern v4.

### Incremental patch

Not directly exposed as a single command. Implemented in Go as:
1. Evict deleted files: `cpg.file.nameExact("f").foreach(_.start.ast.foreach(_.delete()))`
2. Re-import changed functions: `cpg.method.fullName("fn").filename.l.foreach(f => importCode.incrementally(f))`

> **Spike verification needed**: `importCode.incrementally` API may differ in
> Joern v4. If unavailable, fall back to full `BuildCPG` for every scan.

---

## Node Queries

All queries end in `.toList.toJson`. The projected map uses lowercase keys
(`id`, `name`, `file`, `line`, `language`) for consistent Go-side parsing.

### METHOD nodes

```scala
cpg.method.map(m => Map(
  "id"       -> m.id.toString,
  "name"     -> m.name,
  "file"     -> m.filename,
  "line"     -> m.lineNumber.getOrElse(0),
  "language" -> m.language
)).toList.toJson
```

### CALL nodes

```scala
cpg.call.map(c => Map(
  "id"   -> c.id.toString,
  "name" -> c.name,
  "file" -> c.location.filename,
  "line" -> c.lineNumber.getOrElse(0)
)).toList.toJson
```

### Filter by file

```scala
cpg.method.filename("MainController.java").map(m => Map(...)).toList.toJson
```

---

## Edge / Call Graph Queries

### All CALL edges (for GetCallGraph)

```scala
cpg.graph.edges("CALL").map(e => Map(
  "from" -> e.outNode.id.toString,
  "to"   -> e.inNode.id.toString,
  "type" -> "CALL",
  "label" -> ""
)).toList.toJson
```

### Callers of a method node

```scala
cpg.method.id(<id>L).caller.map(m => Map(...)).toList.toJson
```

> **Note**: Joern method IDs are `Long`. Pass the string ID stored in `cpg.Node.ID`
> with an `L` suffix in the query. Example: `cpg.method.id(1234L)`.

### Callees of a method node

```scala
cpg.method.id(<id>L).callee.map(m => Map(...)).toList.toJson
```

---

## Taint Analysis

### Step 1 — trigger dataflow pass

```scala
run.ossdataflow
```

This is idempotent. Must complete before `cpg.finding` returns results.

### Step 2 — query findings

```scala
cpg.finding.map(f => Map(
  "id" -> f.id.toString,
  "evidence" -> f.evidence.map(e => Map(
    "id"   -> e.id.toString,
    "name" -> e.property("NAME").toString,
    "file" -> e.property("FILENAME").toString,
    "line" -> Try(e.property("LINE_NUMBER").asInstanceOf[Int]).getOrElse(0)
  )).l
)).toList.toJson
```

> **Spike verification needed**: `f.evidence` traversal and property access may
> vary by Joern version. If `cpg.finding` is empty after `run.ossdataflow`, check
> `cpg.finding.p` interactively to inspect the raw output format.

---

## Known Gaps (to verify in integration tests)

| Gap | Impact | Verification test |
|-----|--------|-------------------|
| `cpg.method.id(n)` accepts Long, not String | GetCallers/GetCallees may fail on large IDs | `TestIntegration_GetCallers_CalleeRoundTrip` |
| `run.ossdataflow` may not produce `cpg.finding` for JAVASRC | TaintPaths returns empty | `TestIntegration_TaintPath_SQLInjection` |
| `importCode.incrementally` availability in v4 | IncrementalPatch falls back to full rebuild | Manual test in L2 |
| `f.evidence` property access syntax | TaintPaths parse error | `TestIntegration_TaintPath_SQLInjection` |
| `m.language` field populated on method nodes | QueryNodes Language field empty | `TestIntegration_BuildCPG_SpringBoot` |

---

## Go/No-Go Decision (L1 checkpoint)

**Pass** if all of the following hold after `TestIntegration_TaintPath_SQLInjection`:
- Joern starts and /ready returns 200 ✓
- `BuildCPG` completes without timeout ✓
- `QueryNodes(METHOD)` returns ≥ 1 node including `getUser` ✓
- `GetCallGraph()` returns non-empty map ✓
- `TaintPaths` returns ≥ 1 path for `getUser → executeQuery` ✓

**Fail** → trigger fallback:
- Joern scope narrowed to JAVASRC and PYTHONSRC only
- Go source covered by OpenGrep taint rules instead
- Incremental CPG deferred to post-demo
- Decision recorded in this file and in `CLAUDE.md`
