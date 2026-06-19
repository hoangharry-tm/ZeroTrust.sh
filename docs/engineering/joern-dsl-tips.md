# Joern DSL Query Writing — Lessons Learned

Templates run in a **Scala 3.7 REPL** inside Joern 4.0.550 (Homebrew). This is not a sandboxed
Scala environment — many standard library features (`Try`, some `java.lang` types) are **not**
imported automatically.

## 1. No `Try`, no `scala.util._`

`scala.util.Try` is **not in scope** in the Joern REPL. Using it causes:

```
-- [E006] Not Found Error: ...
    Not found: Try
```

**Don't:** `Try(expr).getOrElse(fallback)`
**Do:** `try { expr } catch { case _ => fallback }`

`Throwable` and `Exception` are available (they're in `java.lang`). If unsure, use `case _ =>`
(catches everything).

## 2. Avoid nested `s"""..."""` interpolations

Nesting `s"""..."""` inside `${...}` of an outer `s"""..."""` causes Scala parser confusion.
The parser may not correctly identify where the inner triple-quoted string ends.

**Don't:**
```scala
s"""outer ${inner.map(x => s"""{"id":"${x.id}"}""")} outer"""
```

**Do** — extract the inner result to a `val`, then interpolate the val:
```scala
map(f => {
  val json = inner.map(x => s"""{"id":"${x.id}"}""").mkString(",")
  s"""outer [${json}] outer"""
})
```

The inner `s"""..."""` is in a `val` statement separated by `;` from the outer
`s"""...""""`. The parser sees them as two independent string interpolations.

## 3. `s"""..."""` is safer than `json`/`upickle`

Joern 4.0.550 removed `.toJson`. `uPickle` is on the classpath but:

- `upickle.default.write(Map("k" -> 1, "k2" -> "abc"))` fails with
  `E172 — missing implicit Writer[Map[String, Any]]` because upickle cannot infer
  a `Writer` when the value type is heterogeneous (`Int | String`).

**Use `s"""..."""` with manual JSON construction instead.** The Scala REPL writes
the result as a raw string that `parseStdout` unwraps correctly.

## 4. `parseStdout` unwrap rules

The HTTP API returns `{ stdout: "val resN: String = \"...\"" }` where the actual
output is double-escaped inside the outer JSON string. `parseStdout` on the Go side:

1. Strips the `val resN: Type = ` prefix
2. Unwraps one level of Scala escaping
3. Returns the raw JSON array string for `json.Unmarshal`

A valid result looks like:
```
val res1: String = "[{\"id\":\"42\"}]"
```

An empty traversal produces:
```
val res1: String = "[]"
```

## 5. Methods vs calls vs edges — API quirks

| What you want | Joern DSL | Notes |
|---|---|---|
| All methods | `cpg.method` | `.name`, `.filename`, `.lineNumber` |
| All calls | `cpg.call` | `.name`, `.code`, `.lineNumber` |
| All parameters | `cpg.parameter` | `.name` |
| Call graph edges | `cpg.call.flatMap(_.callee)` | `cpg.graph.edges()` **not exposed** |
| Callers of method | `cpg.method.id(N).caller` | N is a Long |
| Callees of method | `cpg.method.id(N).callee` | N is a Long |
| Edges from node | `cpg.method.filter(_.id == N).out` | Only METHOD nodes |
| Edges to node | `cpg.method.filter(_.id == N).in` | Only METHOD nodes |

- `cpg.graph.edges()` is **not a member** of the Flatgraph API exposed in v4.0.550.
- `cpg.graph.nodes(id)` returns a single node with **no traversal methods** (no `.map`, no `.outE`).
- Filter with `.filter(_.id == N)` on typed traversals like `cpg.method`.
- Use `N + "L"` (Go `fmt.Sprintf("%sL", id)`) for Long literals in the DSL.

## 6. `m.language` does not exist

`Method` nodes have **no** `.language` property. Querying it causes:

```
-- [E008] Not Found Error: value language is not a member of Method ...
```

Properties available on `Method`:
- `.name` → String
- `.filename` → String
- `.lineNumber` → `Option[Int]` (use `.getOrElse(0)` before interpolation)
- `.id` → Long
- `.code` → String (full method body as text)

## 7. Taint analysis API (modern Joern)

`run.ossdataflow` + `cpg.finding` **produces no findings** in Joern 4.0.550. The command
succeeds but `cpg.finding` is always empty.

**Use `reachableByFlows` instead** — it's self-contained (no prior `run.` command needed):

```scala
// Intra-procedural: params → all calls within a method
cpg.method.filter(_.id == METHOD_ID_L)
  .call
  .reachableByFlows(cpg.method.filter(_.id == METHOD_ID_L).parameter)
```

This returns a `List[Path]` where each `Path` has `.elements` (`List[Node]`).
The first element is the source, the last is the sink, and intermediate nodes
are in between.

For sink-specific narrowing:
```scala
cpg.method.filter(_.id == METHOD_ID_L)
  .call.name("executeQuery|queryForList")  // filter to SQL sinks
  .reachableByFlows(cpg.method.filter(_.id == METHOD_ID_L).parameter)
```

`.reachableBy` returns **only sink nodes** (not full paths). Use
`.reachableByFlows` to get the complete path with intermediate nodes.

## 8. Debugging workflow

1. **Test the DSL with curl against a live Joern server** first, before embedding
   in Go templates:
   ```bash
   curl -s -X POST http://127.0.0.1:18080/query \
     -d '{"query": "cpg.method.size"}' | jq -r '.stdout // .uuid'
   ```

2. **Poll the result** with `GET /result/{uuid}` if you need to wait for completion.

3. **Use `mkString` for flat output**, `s"""..."""` for JSON arrays.

4. **Start simply**: test `cpg.method.filter(_.id == N).call.reachableByFlows(...).size`
   before attempting full JSON serialization.

5. **Common Scala compile errors in the REPL:**
   - `Not found: Try` → use `try/catch`
   - `value xxx is not a member of` → wrong property name or node type
   - `missing implicit` in upickle → switch to manual `s"""` JSON

6. **Error format**: Joern REPL errors start with `-- [E00N]` in stdout.
   `parseStdout` will fail `json.Unmarshal` with "invalid character '-'".
   The raw error text can be inspected via `--debug` flags or direct curl.

## 9. Scala 3 pattern matching reference

Inside `s"""...${...}"""`, use compact pattern match for type-based dispatch:

```scala
${first match {
  case mp: MethodParameterIn => mp.name
  case m: Method => m.name
  case c: Call => c.name
  case _ => ""
}}
```

Keep matches on one line inside templates to avoid confusing the Scala parser
with newlines inside the `${}` interpolation block.

## 10. Testing against mocked vs live server

- **Unit tests** (no `//go:build integration` tag): use `httptest.Server` with
  `mockServer(t, queryFn)`. The mock returns whatever JSON you define — it
  **does not validate Joern DSL correctness**.
- **Integration tests** (`//go:build integration` tag): use
  `startIntegrationClient(t)` + `buildTestCPG(t, c)` to start a real Joern
  server and import the Spring Boot testbed. These are the ground truth.

Always run integration tests before merging DSL template changes. The unit test
mocks will not catch:
- Missing Scala features (`Try`, etc.)
- Changes to the Joern type hierarchy (removed methods, renamed properties)
- Flatgraph API gaps (`graph.edges()` not exposed, etc.)
