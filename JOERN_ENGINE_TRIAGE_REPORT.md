# Joern Engine Triage Report

**Date:** 2026-07-01
**Scope:** `internal/scanner/joern/`, `internal/semantic/targeting/`, `internal/semantic/enrichment/`, `internal/semantic/assembler/`, `internal/ingestion/diffindex/expand.go`, `internal/tuning/tuning.go`

---

## 1. Verification Matrix

| ID  | Suspected Bottleneck                 | Verified? | File Path & Line Numbers                                                                                                                                                                                                                                                                                                                                                                                                    | Impact   |
| --- | ------------------------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| 1   | N+1 Query Pattern                    | **Yes**   | `targeting.go:188-204` (queryExternalInputNodes), `targeting.go:383-404` (Run loop), `targeting.go:209-248` (buildCallGraph), `enrichment.go:160-171` (Enrich), `assembler.go:181-219` (dfsCallees), `idor.go:64-138` (queryIDORCandidates), `expand.go:44-72` (ExpandWithCPG), `modules.go:104-119` (ExpandModuleScope), `graph.go:238-258` (GetNeighboursAtDepth)                                                         | **HIGH** |
| 2   | Missing Total Counts                 | **Yes**   | `http.go:39-42` (querySubmitResponse has only UUID+Success), `http.go:47-52` (queryResultResponse has no total/progress fields), `graph.go:75-88` (QueryNodes buffers entire response before surfacing count)                                                                                                                                                                                                               | **MED**  |
| 3   | Silent Execution Blocks              | **Yes**   | `targeting.go:148-162` (IsExternalInputNode — zero logs), `idor.go:64-138` (queryIDORCandidates — zero logs), `targeting.go:148-162` (IsAuthBoundaryNode — zero logs), `graph.go:148-162` (QueryNodesByFile — no step-level logs), `assembler.go:181-219` (dfsCallees — no per-node logs)                                                                                                                                   | **HIGH** |
| 4   | Opaque Logging                       | **Yes**   | `graph.go:188` (GetCallers logs `functionID` as raw numeric ID), `graph.go:206` (GetCallees logs same), `queries.go:132-149` (DSL queries use `cpg.method.id(12345L)` — opaque graph primitives)                                                                                                                                                                                                                            | **MED**  |
| 5   | Redundant Traversals (Missing Cache) | **Yes**   | `targeting.go:367` (Run calls QueryNodes), `idor.go:65` (queryIDORCandidates calls QueryNodes again — same data), `targeting.go:383-404` (Run calls IsExternalInputNode per-method), `idor.go:73-95` (queryIDORCandidates calls QueryEdges per-method — same edge set), `targeting.go:415` (buildCallGraph computes callees), `enrichment.go:160-171` (Enrich re-queries GetCallers/GetCallees — ignoring prior call graph) | **HIGH** |
| 6   | Unbounded Polling / Macro Hangs      | **Yes**   | `http.go:64-84` (doQuery: per-call 30s timeout), `http.go:135-245` (fetchResult: context-based exit, but high-level loops have no wall-clock bound), `targeting.go:383-404` (Run: 15K+ serial HTTP calls, no overall deadline), `http.go:152-158` (JoernIdleTimeout=120s is dead code — 30s query timeout fires first)                                                                                                      | **HIGH** |
| 7   | No Velocity Metrics                  | **Yes**   | `targeting.go:383-404` (Run progress logs count+pct only — no elapsed/rate/ETA), `graph.go:75-88` (QueryNodes: no elapsed), `buildCallGraph:210-246` (count-only progress), `enrichment.go:142-188` (no per-surface timing), `expand.go:33-102` (no timing), `assembler.go:125-153` (count+pct only)                                                                                                                        | **MED**  |

---

## 2. Deep Dive of Verified & Newly Discovered Issues

### 2.1 N+1 Query Pattern (Issue #1) — HIGH

**Root Cause:** The codebase treats every CPG node traversal as an independent HTTP round-trip to Joern. Methods like `GetCallers`, `GetCallees`, and `QueryEdges` fire one Joern DSL query per node. The callers — `queryExternalInputNodes`, `buildCallGraph`, `Enrich`, `dfsCallees`, `Run`, `ExpandWithCPG`, `ExpandModuleScope` — all iterate over node sets and call these per-node methods serially. For a codebase with 5,000 methods, `Run()` alone fires ~15,000 serial HTTP round-trips.

**Triage Fix Strategy:**

- **Bulk `GetCallGraph` reuse:** `Run` calls `buildCallGraph` (via `GetCallees` per node) after the `IsExternalInputNode` loop — but the call graph from `GetCallGraph()` (`queryAllEdges`, a single query) is never used. Replace the BFS-based `buildCallGraph` with a single `GetCallGraph()` call that fetches all edges in one query. Reuse this `CallGraph` map in `Enrich` and any downstream stage.
- **Batch `QueryEdges`:** Replace per-method `QueryEdges` calls in `queryExternalInputNodes` and `queryIDORCandidates` with a single batch call that fetches all PDG edges at once, then filters in Go (O(1) map lookup).
- **Worker pool for isolated queries:** For queries that remain per-node after batching (e.g., `GetNeighboursAtDepth` frontier expansion), introduce a fixed-size worker pool (`errgroup.WithLimit`) to pipeline HTTP round-trips concurrently.

### 2.2 Missing Total Counts (Issue #2) — MED

**Root Cause:** The `querySubmitResponse` and `queryResultResponse` structs in `http.go:39-52` expose only `UUID` and `Success`. The Joern HTTP API returns the entire result set as a single blob when ready. There is no pagination, no `X-Total-Count` header, and no streaming. `QueryNodes` in `graph.go:75-88` must buffer the full response (4 MB cap at `http.go:184`) before it can report the count to callers.

**Triage Fix Strategy:**

- **Pre-flight count query:** Before issuing the data query (e.g., `cpg.method.map(...)`), issue a lightweight count query: `cpg.method.size`. Only 1 extra round-trip per bulk fetch. This gives the caller an immediate total before the data arrives.
- **Streaming-aware client:** Extend `fetchResult` (or add a streaming variant) that progressively reads the JSON array from the response body rather than buffering the full 4 MB. This enables incremental node emission and partial progress reporting. Joern supports `toJson` which streams — replace `.toList.mkString("[", ",", "]")` with `.toJson` in all query templates.
- **Surface count upstream:** Thread the pre-flight count through to progress logs so `Run` can show "Fetching 5,000 methods (42% done)".

### 2.3 Silent Execution Blocks (Issue #3) — HIGH

**Root Cause:** Several hot-path functions lack any instrumentation:

- `IsExternalInputNode` (`targeting.go:148-162`): zero logs despite being called for every method (thousands of times).
- `IsAuthBoundaryNode` (`targeting.go:167-184`): same.
- `queryIDORCandidates` (`idor.go:64-138`): zero logs despite iterating all methods + edges + calling `TaintPaths`.
- `dfsCallees` (`assembler.go:181-219`): zero per-node/debug logs inside the recursive callee walk.
- `Enrich` loop (`enrichment.go:153-185`): no per-surface progress indicator (only a start log for the first surface).

When `Run` stalls for 5+ minutes on a 5,000-method codebase, operators see only "targeting: scanning methods" with no visibility into which sub-stage is executing.

**Triage Fix Strategy:**

- **Add step-level start/done logs** with elapsed time to `IsExternalInputNode`, `queryIDORCandidates`, and `dfsCallees`.
- **Instrument every 100th call** in hot loops (matching the existing pattern in `Run:384-390`) so operators see monotonic progress without log spam.
- **Wrap each `buildCallGraph`, `queryExternalInputNodes`, `queryIDORCandidates` call site** in a `slog.Info` + `slog.Debug` bracket with a unique phase name and wall-clock elapsed.

### 2.4 Opaque Logging (Issue #4) — MED

**Root Cause:** Query logs emit raw Joern DSL fragments and numeric node IDs instead of human-readable `file:function` signatures.

- `graph.go:188`: `slog.Debug("joern: GetCallers query", "query", q, "functionID", functionID)` — logs the numerical ID (e.g., `12345L`).
- `queries.go:132-149`: The DSL uses `cpg.method.id(12345L).caller...` — an operator reading the log has no idea which source function this refers to.
- `http.go:68`: `slog.Debug("joern: doQuery submitting", "query", query)` — logs the raw Scala DSL expression, not the semantic purpose.

When Joern stalls on a query, the debug log tells the operator `cpg.method.id(12345L)` but not `com.example.web.UserController.getProfile()`. This makes debugging in production impossible without correlating with other log sources.

**Triage Fix Strategy:**

- **Map resolution at log sites:** Change all log sites that receive a `functionID` to resolve it through a `cpg.Node` cache before logging. E.g., instead of logging `"functionID", "12345"`, log `"function", "UserController.getProfile()", "file", "src/controllers/user.go"`.
- **Log query intent, not DSL:** Replace raw DSL logs with a semantic label (e.g., `"phase", "GetCallers", "target", "UserController.getProfile()"`).
- **Name-aware query builders:** Modify `queryCallersByID` and `queryCalleesByID` to optionally accept a human-readable label that callers pass via a `slog.With` context.

### 2.5 Redundant Traversals / Missing Cache (Issue #5) — HIGH

**Root Cause:** No in-memory caching layer exists between stages that query overlapping node/edge sets.

1. **`QueryNodes(cpg.NodeMethod)` called twice:** `Run` at `targeting.go:367` queries all methods. `queryIDORCandidates` at `idor.go:65` queries all methods again — same HTTP response, re-parsed.
2. **`QueryEdges` per method called twice per method:** `Run` calls `IsExternalInputNode` (which calls `QueryEdges(node.ID, "")`) for every method. `queryIDORCandidates` calls `QueryEdges(m.ID, "")` for every method again — same edge data.
3. **Call graph computed, then ignored:** `buildCallGraph` at `targeting.go:415` computes a full `CallGraph` from callee edges. `Enrich` at `enrichment.go:166` re-fetches `GetCallees(s.ID)` per surface — the already-computed `CallGraph` map could supply this.
4. **`GetNeighboursAtDepth` re-entrant BFS:** `ExpandModuleScope` at `modules.go:110` calls `GetNeighboursAtDepth` per method. If two methods in the same file share neighbours, the BFS is re-executed.

**Triage Fix Strategy:**

- **In-memory `MethodCache`:** Add a `sync.Map` (or a plain `map` + `sync.RWMutex`) on the `joernGraph` struct that caches `QueryNodes` results keyed by `NodeType`. Set TTL to the scan lifetime. This eliminates redundant method fetches.
- **Edge cache:** Add a `map[string][]cpg.Edge` cache keyed by node ID for `QueryEdges`. Populate lazily on first call, serve subsequent calls from cache.
- **Call graph reuse:** Modify `Run` to return the `CallGraph` alongside surfaces. Have `Enrich` accept the pre-built `CallGraph` as a dependency instead of re-querying `GetCallers`/`GetCallees`.
- **Deduplicate BFS roots in `ExpandModuleScope`:** Before calling `GetNeighboursAtDepth` per method, deduplicate method IDs across all changed files in the module to avoid re-expanding the same function.

### 2.6 Unbounded Polling / Macro Hangs (Issue #6) — HIGH

**Root Cause:** Two levels of unboundedness:

1. **Per-query timeout masks idle detection:** `doQuery` at `http.go:71` sets `queryTimeout = 30s`. This creates a per-call deadline, but the idle-freeze detection at `http.go:152` waits 120s before firing — it will never trigger since the 30s query timeout fires first. The idle detection is dead code under default configuration.

2. **No macro-level wall-clock bound:** Each individual `GetCallers`/`GetCallees` call is bounded to 30s, but the high-level loops that issue thousands of these calls — `Run` (targeting.go:383-404), `buildCallGraph` (targeting.go:209-248), `Enrich` (enrichment.go:153-185), `dfsCallees` (assembler.go:181-219), `ExpandWithCPG` (expand.go:44-72) — have no overall timeout. A scan with 5,000 methods could remain stuck for hours if each individual call completes within its 30s budget but the serial chain is long.

3. **Context.Background risk:** `Graph()` at `joern.go:438` uses `context.Background()` — no timeout at all. Callers using `Graph()` instead of `GraphWithContext()` lose all deadline propagation.

**Triage Fix Strategy:**

- **Reduce idle timeout below query timeout:** Set `JoernIdleTimeout` to `20s` (below `JoernQueryTimeout` at 30s) so freeze detection is effective.
- **Phase-level deadlines:** Inject a `context.WithTimeout` at each phase boundary (`Run`, `Enrich`, `Assemble`) with a calibrated timeout: `num_nodes * avg_query_latency * safety_factor`. This bounds the entire phase, not just individual calls.
- **Context propagation audit:** Audit all callers to use `GraphWithContext(ctx)` with a meaningful scan context instead of `Graph()`. Ban `Graph()` for production paths.
- **Early termination circuit breaker:** Add a pre-configured max-query-count guard per phase (e.g., "fail after 10,000 queries in buildCallGraph"). This prevents pathological codebases from stalling the scan.

### 2.7 No Velocity Metrics (Issue #7) — MED

**Root Cause:** Every hot loop tracks only count or percentage — never elapsed time, throughput (calls/sec), or estimated completion. The only `time.Since` usage is in `BuildCPG` at `cpg.go:99` and `fetchResult` at `http.go:138` — both for single-query timing, not macro-phase throughput.

- `Run` loop at `targeting.go:383-390`: `slog.Info("targeting: progress", "done", i, "total", total, "pct", "42%")` — no elapsed, no rate, no ETA.
- `buildCallGraph` at `targeting.go:226-231`: "expanded 50" — count only.
- `Enrich` at `enrichment.go:142-188`: start + end only — no per-surface timing.

When a scan is slow, operators have zero information to distinguish "10 minutes of normal work" from "10 minutes of hanging."

**Triage Fix Strategy:**

- **Instrument each hot loop with elapsed + throughput:** Before each loop, `start := time.Now()`. Every N iterations, log `slog.Duration("elapsed", time.Since(start))`, `slog.Float64("calls_per_sec", float64(i)/time.Since(start).Seconds())`, `slog.Duration("eta", time.Duration(float64(time.Since(start))/float64(i)*float64(total-i)))`.
- **Phase-level telemetry:** Add a `PhaseTimer` helper that wraps a phase (e.g., `buildCallGraph`) and emits: `slog.Info("phase: buildCallGraph completed", "elapsed", "...", "nodes", N, "rate", ".../sec")`.
- **Emit to a dedicated telemetry channel** (in addition to `slog`) so a future observability dashboard can consume query velocity without parsing log lines.

---

## 3. Newly Discovered Anti-Patterns

### 3.1 Fully Serial Execution with No Concurrency — HIGH

**File:** `targeting.go:383-404`, `targeting.go:209-248`, `enrichment.go:153-185`, `assembler.go:129-153`, `expand.go:44-72`

The `Run` method iterates all methods serially, calling `IsExternalInputNode` and `IsAuthBoundaryNode` for each. `buildCallGraph` processes the BFS queue serially. `Enrich` processes surfaces one-by-one. None of these hot loops use worker pools, `errgroup`, or any concurrency primitive — despite each iteration being an I/O-bound HTTP round-trip to Joern.

Each `GetCallers`/`GetCallees`/`QueryEdges` call spends most of its wall-clock time waiting for Joern to respond. These calls are embarrassingly parallel for independent nodes (callers of method X don't depend on callers of method Y).

**Triage Fix Strategy:**

- Introduce `errgroup.WithLimit(ctx, runtime.GOMAXPROCS(0)` or a configurable concurrency cap around the iteration loops that call `IsExternalInputNode`, `IsAuthBoundaryNode`, and `GetCallees` in `buildCallGraph`.
- For `buildCallGraph`: replace the serial queue with a concurrent frontier expansion using `errgroup`. Each frontier batch processes nodes concurrently.
- For `Enrich`: process surfaces concurrently with `errgroup`, since surface enrichment is independent per surface.

### 3.2 Three Separate BFS / Traversal Implementations — MED

**Files:**

- `graph.go:221-260` — `GetNeighboursAtDepth` (bidirectional BFS, HTTP-backed)
- `targeting.go:209-248` — `buildCallGraph` (callee BFS, HTTP-backed)
- `assembler.go:181-219` — `dfsCallees` (DFS, HTTP-backed)
- `modules.go:89-124` — `ExpandModuleScope` (calls `GetNeighboursAtDepth` per method)
- `expand.go:33-102` — `ExpandWithCPG` (one-hop caller+callee)
- `targeting.go:250-300` — `bfsHopDepths` (in-memory, fine)

Three distinct HTTP-backed graph traversal implementations exist with overlapping behaviour but different node/edge semantics. `buildCallGraph` re-implements a BFS that `GetNeighboursAtDepth` plus a filter could already provide. This duplication multiplies the surface area for concurrency bugs and makes performance tuning harder.

**Triage Fix Strategy:**

- Unify on a single `CallGraph`-backed traversal: fetch the full call graph once via `GetCallGraph()` (1 HTTP call → `queryAllEdges`), then build all in-memory traversal helpers (`bfsHopDepths`, call chain building, neighbour expansion) from that single map. Eliminate HTTP-backed BFS/DFS in favour of in-memory map walking.

### 3.3 Dead Idle-Freeze Detection — MED

**File:** `http.go:152-158`

```go
if time.Since(idleStart) > tuning.JoernIdleTimeout { // JoernIdleTimeout = 120s
```

This will never trigger because `doQuery` at `http.go:71` sets a 30-second `queryTimeout` context — the `qctx` will expire long before 120s of consecutive 202s accumulates. The idle-freeze detection is completely dead code under default configuration.

**Triage Fix Strategy:**

- Lower `JoernIdleTimeout` to 20s or remove the query-level context timeout for the polling loop (separate the "query submit" timeout from the "result poll" timeout). Only the idle timeout should govern the poll loop; the query submit should have a short timeout (5s).

### 3.4 Repeated Full Method Query in queryIDORCandidates — MED

**File:** `idor.go:64-138`

`queryIDORCandidates` calls `t.graph.QueryNodes(cpg.NodeMethod)` at line 65, then for each method calls `t.graph.QueryEdges(m.ID, "")` at line 74. This re-queries all method nodes (already fetched by `Run` at `targeting.go:367`) and then re-queries PDG edges for each method (already queried by `IsExternalInputNode` in the `Run` loop). The method and edge data from `Run` could be passed into `queryIDORCandidates` to eliminate the redundant query.

**Triage Fix Strategy:**

- Refactor `Run` to pass the already-fetched `[]cpg.Node` methods and edge results (or the edge cache) into `queryIDORCandidates`.

### 3.5 No Pre-Allocation in queryIDORCandidates Builders — LOW

**File:** `idor.go:71-72`

```go
var sources []cpg.TaintSource
var sinks []cpg.TaintSink
```

These slices are not pre-allocated, despite iterating over all methods and edges. For a 5,000-method CPG with 50,000 edges, the slices grow via amortised reallocation. While this is not a bottleneck (slice growth is O(log N) allocations), it creates unnecessary GC pressure.

**Triage Fix Strategy:**

- Estimate capacity from the method count and pre-allocate: `sources := make([]cpg.TaintSource, 0, len(methods)/2)`, `sinks := make([]cpg.TaintSink, 0, len(methods)/2)`.

### 3.6 BuildCPG N+1 importCode Retry — LOW

**File:** `cpg.go:146-170`

The loop retries `importCode` with different languages (line 147), and for each success, verifies with a separate `cpg.method.size` query (line 164). This is at most 2-3 queries, so not a performance issue — but the double-round-trip pattern is architecturally similar to N+1. Not urgent.

---

## 4. Summary Verdict

The Joern integration has **three systemic bottlenecks** that prevent it from scaling to large codebases:

| Bottleneck                     | Root Primitive                           | Estimated Speedup       |
| ------------------------------ | ---------------------------------------- | ----------------------- |
| **N+1 + redundant traversals** | Serial per-node HTTP calls with no cache | 50-100x                 |
| **No concurrency**             | I/O-bound loops running single-threaded  | 4-8x (with worker pool) |
| **No phase-level deadline**    | Loops without wall-clock bound           | Eliminates hangs        |

A 5,000-method codebase that currently takes ~50 minutes (15,000 serial HTTP calls at 200ms avg) should complete in under 1 minute after: (a) bulk call graph fetch, (b) edge-result caching, (c) worker-pool concurrency, and (d) in-memory traversal from a shared `CallGraph` map.
