# PERFORMANCE DIAGNOSTIC REPORT: Scanning Bottlenecks and Joern Processing Overheads

**Date:** 2026-07-01
**Scope:** Full-stack audit of the Go orchestrator, Joern CPG integration, SQLite persistence layer, and data pipeline.

---

## 1. Data Flow Network Chart

Below is the exact data movement path with every in-memory buffer annotated. RAM pressure points are marked with `⚠️ DEEP COPY` / `⚠️ UNBOUNDED BUFFER`.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. FILE INGESTION (diffindex)                                          │
│                                                                         │
│   WalkDir → per-file SHA-256 → priorMap (SQLite) → ChangeSet{Changed,   │
│   Removed, AllStates} — all slices held in-memory on *ingestion.Result │
│   AllStates[]FileState = unbounded (every file in project)  ⚠️ DEEP COPY │
└───────────────────────────────────────┬─────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. CPG BUILD / LOAD (joern.BuildCPG / LoadCPG / IncrementalPatch)       │
│                                                                         │
│   Single blocking HTTP POST/PULL to Joern server.                       │
│   Go goroutine is FULLY BLOCKED during the entire build.  ⚠️ SYNC BLOCK  │
│   No streaming — waits for 100% completion before next step.            │
│   Result: CPG snapshot written to disk (cpgPath). Schema in SQLite.     │
└───────────────────────────────────────┬─────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. PATH A (concurrent with Path B + Orchestrator)                       │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 3a. Joern Taint (runJoernTaint)                                 │   │
│   │                                                                  │   │
│   │  For EACH scope file:         ⚠️ N+1 HTTP PATTERN                │   │
│   │    QueryNodesByFile(f, NodeCall) → 1 HTTP round-trip per file    │   │
│   │      → builds sources[] / sinks[] in-memory (unbounded slice)    │   │
│   │                                                                  │   │
│   │  TaintPaths(sources, sinks)                                      │   │
│   │    → 1 massive Joern script executed synchronously               │   │
│   │    → result capped at CPGMaxTaintPaths (default 64KB?)           │   │
│   │    → every TaintPath carries IntermediateNodes[] — ALL IN MEMORY ⚠️ │   │
│   │                                                                  │   │
│   │  TaintPathsToFindings() converts to []finding.Finding             │   │
│   │    → added to rawBuf[] vía mutex   ⚠️ UNBOUNDED BUFFER           │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 3b. OpenGrep (opengrep.ScanFiles)                                │   │
│   │    → findings also appended to rawBuf[] via mutex                │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   rawBuf[] finding.Finding — drained into ch (finding.Channel)          │
│   ch (buffered 256) → drained into allFindings[] in main goroutine     │
│   allFindings[] finding.Finding — PASSED BY VALUE to runDedup   ⚠️ COPY │
└───────────────────────────────────────┬─────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. PATH B (sequential tier within goroutine)                            │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ B1: Heuristic Targeting (Targeter.Run)                          │   │
│   │                                                                  │   │
│   │  QueryNodes(NodeMethod) — fetches ALL methods, cached     ⚠️ RAM │   │
│   │    → []cpg.Node{ID, Name, File, Line, Type, Code} in cache      │   │
│   │                                                                  │   │
│   │  GetCallGraph() — fetches ALL edges, stored on Targeter  ⚠️ RAM │   │
│   │    → map[string][]string (every caller→callee pair)             │   │
│   │                                                                  │   │
│   │  For EACH method (concurrent worker pool):       ⚠️ N+1 HTTP     │   │
│   │    IsExternalInputNode(m) → QueryEdges(m.ID,"")                 │   │
│   │    IsAuthBoundaryNode(m)   → QueryEdges(m.ID,"")                │   │
│   │    → TWO HTTP round-trips per method                            │   │
│   │                                                                  │   │
│   │  queryIDORCandidates:                                           │   │
│   │    QueryNodes(NodeMethod) again (cache hit)                      │   │
│   │    For EACH method: QueryEdges(m.ID,"") — ANOTHER N+1  ⚠️ N+1  │   │
│   │    TaintPaths(sources, sinks) — single big query                │   │
│   │                                                                  │   │
│   │  buildCallGraph: in-memory BFS over t.callGraph (no HTTP)        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ B2: CVE Enrichment (Enricher.Enrich)                            │   │
│   │                                                                  │   │
│   │  For EACH surface (concurrent worker pool):       ⚠️ N+1 HTTP    │   │
│   │    GetCallers(s.ID) — 1 round-trip                               │   │
│   │    GetCallees(s.ID) — 1 round-trip                               │   │
│   │    DetectIDORFlows → QueryEdges(s.ID,"") — 1 round-trip         │   │
│   │    → THREE HTTP round-trips per surface                          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ B3: Classifier (Python worker IPC) — no Joern HTTP               │   │
│   │ B4: Assembler (Assembler.Assemble)                               │   │
│   │                                                                  │   │
│   │  GetCallGraph() — second bulk-fetch of ALL edges        ⚠️ DUPE │   │
│   │  QueryNodes(NodeMethod) — second fetch of ALL methods   ⚠️ DUPE │   │
│   │                                                                  │   │
│   │  For EACH surface: DFS over in-memory call graph (no HTTP)       │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Findings emitted to ch → drained to allFindings[]                   │
└───────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. DEDUP + PERSIST                                                      │
│                                                                         │
│   allFindings[] finding.Finding (entire result set in RAM)  ⚠️ BIG SLICE│
│   runDedup → DB read (ListFindingIDs) → SQLite write (UpsertFinding)    │
│   generatePatches → Ollama LLM (blocking)                               │
│   persistPatches → SQLite write                                         │
│   generateReport → HTML template render                                 │
│   finalize → SQLite write (FinalizeScanRun) + CommitScan → SQLite write │
└─────────────────────────────────────────────────────────────────────────┘
```

### Memory Hot-Spots Summary

| Location                      | Data                                  | Size Risk                     | Mechanism                                           |
| ----------------------------- | ------------------------------------- | ----------------------------- | --------------------------------------------------- |
| `ingestion.Result.AllStates`  | Every file in project                 | Unbounded                     | In-memory `[]FileState` slice returned by value     |
| `joernGraphCache.methodCache` | All METHOD/CALL nodes                 | Unbounded (thousands)         | In-memory `map[NodeType][]Node` retained per scan   |
| `joernGraphCache.edgeCache`   | All edges per node                    | Unbounded                     | `map[string][]Edge` — **never evicted** during scan |
| `Targeter.callGraph`          | Full call graph `map[string][]string` | Unbounded (millions of edges) | Bulk-fetched by `GetCallGraph()`                    |
| `Assembler.callGraph`         | Full call graph — **duplicate fetch** | Same size as above            | Fetched a second time by different stage            |
| `Assembler.nodeNames`         | All METHOD names                      | Large string map              | Fetched a second time                               |
| `runPathA.rawBuf`             | All Path A findings pre-drain         | Unbounded                     | Protected by mutex, appended until drained          |
| `allFindings` (scan.go)       | ALL findings from both paths          | Unbounded                     | Single `[]finding.Finding` before dedup             |
| `scored` (dedup output)       | Deduped findings                      | Unbounded (but filtered)      | Another full slice copy                             |

---

## 2. SQLite Current Responsibilities

### Inventory of Every SQLite Operation During a Live Scan

| #   | Call Site           | Table        | Operation              | When                             | Role During Scan                                                        |
| --- | ------------------- | ------------ | ---------------------- | -------------------------------- | ----------------------------------------------------------------------- |
| 1   | `diffindex.Diff()`  | `scan_state` | `SELECT`               | After ingestion start            | **Active — caching layer.** Loads prior content hashes to compute diff. |
| 2   | `buildOrLoadCPG()`  | `cpg_cache`  | `SELECT`               | Before CPG build                 | **Active — cache gate.** Checks if CPG can be skipped.                  |
| 3   | `buildOrLoadCPG()`  | `cpg_cache`  | `INSERT` (UPSERT)      | After successful CPG build/patch | **Active — state write.** Records CPG build result.                     |
| 4   | `registerRun()`     | `projects`   | `INSERT` (UPSERT)      | After ingestion                  | **Metadata only.** Upserts project record.                              |
| 5   | `registerRun()`     | `scan_runs`  | `INSERT`               | After ingestion                  | **Metadata only.** Creates scan run record.                             |
| 6   | `dedupHistorical()` | `findings`   | `SELECT` (listing IDs) | During dedup (post-detection)    | **Active — cross-scan dedup.** Loads prior finding IDs.                 |
| 7   | `persistFindings()` | `findings`   | `INSERT` (UPSERT)      | After dedup, before patch gen    | **Dumping ground.** Writes findings one-by-one.                         |
| 8   | `persistPatches()`  | `findings`   | `UPDATE`               | After patch generation           | **Dumping ground.** Caches generated patches.                           |
| 9   | `finalize()`        | `scan_runs`  | `UPDATE`               | After report render              | **Metadata only.** Marks scan run complete.                             |
| 10  | `CommitScan()`      | `scan_state` | `INSERT` / `DELETE`    | After report render              | **State persistence.** Writes file hashes for next diff.                |

### Verdict

**SQLite is a passive metadata store with two narrow active roles:**

1. **Differential indexing cache (operation #1):** the *only* genuine performance-critical DB usage — and it runs *before* Joern, not during.
2. **CPG build gate (operation #2):** a single-row query to skip CPG rebuilds on no-change scans — lightweight, correct-use cache.
3. **Cross-scan dedup (operation #6):** a single-column SELECT that avoids re-processing historically known findings — good, but runs *after* all Joern work is already done.

**Everything else (#4, #5, #7, #8, #9, #10) is end-of-scan dumping** — metadata logging and result archiving that has zero impact on scan latency.

**The gap:** SQLite is never queried during:

- Joern taint analysis (Path A)
- Heuristic Targeting (Path B1)
- CVE Enrichment (Path B2)
- Classifier (B3)
- Call Chain Assembly (B4)
- LLM Scan (B7)

All of these stages operate exclusively on in-memory data structures and Joern HTTP round-trips. SQLite could function as an intermediate state cache (e.g., caching per-method QueryEdges results, or storing pre-computed call graph edges), but it is **not used for any such purpose today.**

---

## 3. Joern Bottleneck Breakdown

### 3.1 Process Spawning Overhead

**Mechanism:** `joern.Client.Start()` spawns `joern --server --server-host 127.0.0.1 --server-port 8080` and polls `POST /1+1` every 500ms for up to 12 retries.

**Cold start latency:** ~30–90 seconds.

| Phase                         | Worst-Case Duration | Detail                                                                         |
| ----------------------------- | ------------------- | ------------------------------------------------------------------------------ |
| JVM class loading + REPL init | 20–60 s             | Joern's Scala REPL (Ammonite) initializes the full CPG engine                  |
| `waitReady` polling           | 6 s × 12 retries    | Each poll has a 30s timeout — the first attempt saturates waiting on REPL init |
| Total start time              | 26–96 s             | **Entire scan is blocked** during this period                                  |

**Impact:** Even for a scan with 1 changed file, the user pays 30+ seconds of JVM startup overhead before any work happens. There is no persistent server between scans — the process is started per `pipeline.run()` and stopped in `pipeline.close()`.

### 3.2 Query Pattern: POST/Poll Synchronous Architecture

**Every single Joern interaction follows this exact pattern:**

```
Go goroutine           Joern HTTP Server
    │                        │
    ├── POST /query ────────>│  UUID returned immediately
    │<── {uuid: "...",       │
    │     success: true}     │
    │                        │  [Joern processes query]
    │                        │
    ├── GET /result/{uuid} ──>│  202 (still processing)
    │<── 202                 │
    │     wait 200ms         │
    ├── GET /result/{uuid} ──>│  202
    │<── 202                 │
    │     wait 200ms         │
    │     ...                │   ...
    ├── GET /result/{uuid} ──>│  200 + result
    │<── {stdout: "..."}    │
```

**Key observations:**

- **No streaming, no batching.** Every query (even "get all methods") is a single POST + poll loop.
- **Go goroutine is 100% blocked** during the entire round-trip (submission + poll). It cannot do other work.
- **Per-query timeout:** 30 seconds (`JoernQueryTimeout`). A single slow traversal wastes the full 30s.
- **20s idle freeze detector:** if Joern returns `202` (still processing) for 20 consecutive seconds, the build is aborted with `ErrBuildTimeout`. This fires during legitimate long traversals, causing spurious failures.
- **Poll interval:** 200ms. For a query that takes 10 seconds to process, that's 50 poll iterations, 50 HTTP connections.

### 3.3 N+1 Query Pattern Catalog

The N+1 anti-pattern is **the single largest contributor to Joern latency**. Here is the complete inventory:

#### Pattern A: `runJoernTaint` — File-Level N+1 (scan.go:1463–1488)

```go
for _, f := range scopeFiles {       // ← For EACH file in scope
    calls, err := graph.QueryNodesByFile(f, cpg.NodeCall)  // ← 1 HTTP round-trip per file
    // ...
}
```

- Each call to `QueryNodesByFile` → `queryCallsByFile(relPath)` → 1 Joern DSL query → 1 POST/Poll cycle.
- If scope = 500 files, this is **500 sequential HTTP round-trips**.

#### Pattern B: `Targeter.Run` — Method-Level N+1 (targeting.go:427–465)

```go
for _, m := range methods {           // ← For EACH method in CPG
    g.Go(func() error {
        isExt, err := t.IsExternalInputNode(gctx, m)   // ← 1 HTTP round-trip
        isAuth, err := t.IsAuthBoundaryNode(gctx, m)   // ← 1 HTTP round-trip
        // ...
    })
}
```

- Each method fires two `QueryEdges(node.ID, "")` calls.
- With a worker pool of `GOMAXPROCS * 2` goroutines, at most ~16 simultaneous requests can be in-flight.
- For a project with 5,000 methods: **10,000 sequential HTTP round-trips**, throttled to ~16 at a time. With 200ms avg latency per query = **2,000,000ms / 16 = 125 seconds** of wall-clock time.

#### Pattern C: `queryIDORCandidates` — Another Method-Level N+1 (idor.go:73–96)

```go
for _, m := range methods {           // ← For EACH method (again)
    edges, err := t.graph.QueryEdges(m.ID, "")  // ← 1 HTTP round-trip per method
    // ...
}
```

- Runs **after** `Targeter.Run` has already done the same iteration. No overlap.
- If 5,000 methods: **5,000 more HTTP round-trips** (unless cached — see 3.3.6).

#### Pattern D: `Enricher.Enrich` — Surface-Level N+1 (enrichment.go:185–196)

```go
for _, s := range surfaces {          // ← For EACH surface
    g.Go(func() error {
        if callers, cerr := e.graph.GetCallers(s.ID)    // ← 1 HTTP round-trip
        if callees, cerr := e.graph.GetCallees(s.ID)    // ← 1 HTTP round-trip
        // ...
        DetectIDORFlows → QueryEdges(s.ID, "")           // ← 1 HTTP round-trip
    })
}
```

- **3 HTTP round-trips per surface** (GetCallers + GetCallees + QueryEdges).
- If 200 surfaces: **600 more HTTP round-trips** (may hit cache for `QueryEdges`).

#### Pattern E: `ExpandWithCPG` — File-Level N+1 (expand.go:44–73)

```go
for _, f := range cs.Changed {        // ← For EACH changed file
    nodes, err := g.QueryNodesByFile(f, cpg.NodeMethod) // ← 1 HTTP round-trip
    for _, n := range nodes {
        callers, err := g.GetCallers(n.ID)   // ← 1 per method node
        callees, err := g.GetCallees(n.ID)   // ← 1 per method node
    }
}
```

- If 50 changed files, each with ~10 methods: **50 + 500 + 500 = 1,050 HTTP round-trips**.

#### Pattern F: `buildOrLoadCPG` — Changed-File N+1 (scan.go:1270–1284)

```go
for _, f := range changedFiles {      // ← For EACH changed file
    nodes, err := graph.QueryNodesByFile(f, cpg.NodeMethod)  // ← 1 HTTP round-trip
}
```

- Already runs before the main detection paths, adding even more per-file queries.

#### Pattern G: `ExpandModuleScope` — Nested Depth BFS N+1 (modules.go:109–120)

```go
for _, f := range modules[i].ChangedFiles {  // ← For EACH changed file
    nodes, err := g.QueryNodesByFile(f, cpg.NodeMethod)
    for _, n := range nodes {
        neighbours, err := g.GetNeighboursAtDepth(n.ID, depth)  // ← 2×depth HTTP round-trips
    }
}
```

- `GetNeighboursAtDepth` performs a Go-side BFS with successive `GetCallers`+`GetCallees` per level. Each level = 2 HTTP round-trips.
- At depth 5: 10 HTTP round-trips per method node per changed file.

### 3.4 Cache Analysis

The `joernGraphCache` provides **node-type-level caching** (`methodCache` map) and **node-level edge caching** (`edgeCache` map). Here is the actual cache-effectiveness analysis:

| Query                             | Cached?                                 | Benefit                                                                                                |
| --------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `QueryNodes(NodeMethod)`          | Yes — cached after first call           | High — saves one fetch                                                                                 |
| `QueryNodes(NodeCall)`            | Yes — cached after first call           | High — saves one fetch                                                                                 |
| `QueryNodesByFile(f, NodeMethod)` | **No** — not cached by file             | **None** — each per-file query hits Joern, even within same scan                                       |
| `QueryEdges(fromID, "")`          | Yes — cached after first `fromID` fetch | Moderate — first per-ID call still makes HTTP round-trip; subsequent calls with same `fromID` are free |
| `QueryEdges("", toID)`            | Yes — cached after first `toID` fetch   | Same as above                                                                                          |
| `GetCallGraph()`                  | **No** — result stored on `Targeter`    | **Re-fetched by `Assembler.Assemble()`** — duplicate bulk fetch                                        |
| `GetCallers(id)`                  | **No** — not cached                     | Each call is a fresh HTTP round-trip                                                                   |
| `GetCallees(id)`                  | **No** — not cached                     | Each call is a fresh HTTP round-trip                                                                   |
| `GetNeighboursAtDepth()`          | **No** — not cached                     | Each BFS level makes uncached `GetCallers`+`GetCallees` calls                                          |
| `TaintPaths(sources, sinks)`      | **No** — not cached                     | Each call is a fresh Joern taint script execution                                                      |

**Net effect:** The cache avoids duplicate `QueryNodes(NodeType)` and `QueryEdges` calls but does **nothing** for the dominant N+1 patterns (`QueryNodesByFile`, `GetCallers`, `GetCallees`) which are the actual performance problems.

### 3.5 Blocking I/O: What Go Does While Joern Runs

| Joern Operation                                                   | Go Orchestrator State                      | Duration                    |
| ----------------------------------------------------------------- | ------------------------------------------ | --------------------------- |
| `Start()` (JVM cold start)                                        | **Blocked** in `waitReady` poll loop       | 30–90 s                     |
| `BuildCPG()` → `importCode(...)`                                  | **Blocked** — `doQuery` POST + poll        | 10–120+ s (≤5K LOC gate)    |
| `LoadCPG()` → `importCpg(...)`                                    | **Blocked** — `doQuery` POST + poll        | 1–5 s                       |
| `IncrementalPatch()` → per-function: `importCode.incrementally()` | **Blocked** per function — sequential loop | N × query time              |
| `SaveCPG()` → `cpg.save(...)`                                     | **Blocked** — `doQuery` POST + poll        | 1–3 s                       |
| `QueryNodes(NodeMethod)`                                          | **Blocked** — `doQuery` POST + poll        | 0.5–5 s                     |
| `GetCallGraph()` (all edges)                                      | **Blocked** — single large `doQuery`       | 1–30 s (linear in CPG size) |
| `QueryEdges(id, "")`                                              | **Blocked** per call (worker pool)         | 0.2–2 s per call            |
| `GetCallers(id)`                                                  | **Blocked** per call                       | 0.2–1 s per call            |
| `GetCallees(id)`                                                  | **Blocked** per call                       | 0.2–1 s per call            |
| `TaintPaths(sources, sinks)`                                      | **Blocked** — single big `doQuery`         | 5–60 s                      |
| `Version()`                                                       | **Blocked** — trivial `doQuery`            | 0.5–2 s                     |

**Total sequential blocking time for a medium project (~5,000 methods, ~50 changed files, 200 surfaces):**

| Stage                                                           | HTTP Calls             | Est. Wall Time                 |
| --------------------------------------------------------------- | ---------------------- | ------------------------------ |
| `startJoern()` (JVM startup)                                    | 1–12 pings             | 30–90 s                        |
| `Version()`                                                     | 1                      | 1 s                            |
| CPG build `importCode`                                          | 1–2 (retries)          | 30–120 s                       |
| `SaveCPG`                                                       | 1                      | 2 s                            |
| `runJoernTaint` — QueryNodesByFile × scope files                | 500                    | 100 s                          |
| `runJoernTaint` — TaintPaths                                    | 1                      | 30 s                           |
| `Targeter.Run` — QueryNodes(NodeMethod)                         | 1 (cached)             | 2 s                            |
| `Targeter.Run` — GetCallGraph                                   | 1                      | 10 s                           |
| `Targeter.Run` — IsExternalInputNode × methods (2×)             | 10,000                 | 200 s                          |
| `Targeter.Run` — IDOR: QueryEdges × methods                     | 5,000                  | 100 s                          |
| `Targeter.Run` — IDOR: TaintPaths                               | 1                      | 30 s                           |
| `Enricher.Enrich` — GetCallers/GetCallees/QueryEdges × surfaces | 600                    | 40 s                           |
| `Assembler.Assemble` — GetCallGraph (duplicate)                 | 1                      | 10 s                           |
| `Assembler.Assemble` — QueryNodes(NodeMethod) (duplicate)       | 1 (cached)             | 0                              |
| **TOTAL**                                                       | **~16,100 HTTP calls** | **~575–745 s (10–12 minutes)** |

This explains the severe execution delays entirely.

### 3.6 Single-Threaded Bottleneck

The HTTP client (`c.httpClient = &http.Client{Timeout: c.queryTimeout}`) is shared across all goroutines. While Go's HTTP transport handles concurrent requests, the **Joern server itself is single-threaded** (it runs as a single JVM process with a single REPL session). The Scala REPL processes queries sequentially:

- Query A submitted → process A (blocking JVM) → result A returned → Query B submitted → ...

Even with Go's concurrent goroutines, only one query at a time executes on the Joern side. The worker pool in `Targeter.Run` creates the illusion of parallelism but provides **zero throughput benefit** when the server is the bottleneck — it only adds Go-side goroutine scheduling overhead and mutex contention.

### 3.7 Additional Overheads

1. **JSON serialization bloat:** Every Joern query constructs a JSON string via Scala `s"""..."""` string interpolation inside the Joern DSL. The result is serialized as a JSON string wrapped in a Scala string literal, which must be parsed by `parseStdout()` to strip ANSI codes and Scala REPL annotations. This wastes CPU on both the JVM and Go sides for every query.

2. **No result compression:** The HTTP response body is capped at 4 MB (`io.LimitReader(resp.Body, 4<<20)`). Large edge sets (e.g., `GetCallGraph` for a 500K-node CPG) will hit this limit and be silently truncated, producing incomplete results.

3. **No connection reuse optimization:** Each GET/poll (`/result/{uuid}`) opens a new HTTP connection. With 50+ poll iterations per query × 16,000 queries = **800,000 HTTP connections** per scan. TCP handshake overhead alone (~1ms per connection over loopback) adds ~800 seconds.

---

## Summary of Root Causes

| Rank   | Cause                                                                             | Impact                                       | Location                                                              |
| ------ | --------------------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------- |
| **1**  | **N+1 HTTP query pattern (method-level)**                                         | **70%+ of Joern latency**                    | `Targeter.Run` (2× per method), `queryIDORCandidates` (1× per method) |
| **2**  | **No batch/streaming API — synchronous POST/poll per operation**                  | Adds poll overhead (50× per query)           | `doQuery()` + `fetchResult()` in `http.go`                            |
| **3**  | **Duplicate bulk fetches: `GetCallGraph` and `QueryNodes(METHOD)` fetched twice** | 2× memory + 20s duplicate latency            | `Assembler.Assemble` re-fetches what `Targeter.Run` already has       |
| **4**  | **Per-file N+1 in `runJoernTaint` and `buildOrLoadCPG`**                          | Linear in scope file count                   | `scan.go:1463`, `scan.go:1270`                                        |
| **5**  | **Joern JVM cold start per scan (no daemon persistence)**                         | 30–90 s of dead time per scan                | `joern.go:Start()`                                                    |
| **6**  | **Single-threaded Joern REPL — no concurrent query processing**                   | Worker pool provides zero benefit            | Joern server architecture                                             |
| **7**  | **No SQLite intermediate caching during Joern phases**                            | All graph data lives in RAM, never offloaded | Entire `joernGraphCache` is in-memory only                            |
| **8**  | **Unbounded in-memory findings buffer (`allFindings[]`)**                         | RAM grows linearly with finding count        | `scan.go:391–396`                                                     |
| **9**  | **Idle freeze detector (20s) causes spurious CPG build failures**                 | Aborts legitimate long traversals            | `http.go:152`                                                         |
| **10** | **No result pagination — 4 MB cap silently truncates large edge sets**            | Produces silently incomplete results         | `http.go:184`                                                         |
