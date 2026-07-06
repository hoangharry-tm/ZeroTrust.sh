# REMEDIATION PLAN: Production-Grade Performance Overhaul

**Target:** ZeroTrust.sh scanning pipeline
**Core thesis:** Move from batch-pipeline accumulation to event-driven streaming. Components no longer pass data — they pass signals. Data lives in SQLite; components query what they need and forget it.

**Coverage:** Resolves all 10 root causes from PERFORMANCE_DIAGNOSTIC_REPORT.md.

| Diagnostic Issue                                       | Phase              | Status   |
| :----------------------------------------------------- | :----------------- | :------- |
| #1 N+1 method-level (Targeter + IDOR)                  | 1.5, 1.6, 2.5      | Resolved |
| #2 Synchronous POST/poll per operation                 | 1.8, 2.7           | Resolved |
| #3 Duplicate bulk fetches                              | 1.1                | Resolved |
| #4 Per-file N+1 (runJoernTaint + buildOrLoadCPG)       | 1.4, 1.7, 2.5      | Resolved |
| #5 Per-scan JVM cold start                             | 2.6                | Resolved |
| #6 Single-threaded Joern REPL (no concurrency benefit) | 1.5, 1.6, 1.7, 2.5 | Resolved |
| #7 Passive SQLite — graph data never offloaded         | 2.2, Gap A (done)  | Resolved |
| #8 Unbounded in-memory findings buffer                 | 2.2g, 3.1          | Resolved |
| #9 Idle freeze detector (20s) spurious failures        | 1.2                | Resolved |
| #10 4 MB cap silently truncates edge sets              | 1.3                | Resolved |

---

## Phase 1: High-Impact "Low-Hanging Fruit" (Immediate Tactical Wins)

### 1.1 Eliminate Duplicate Bulk Fetches (Targeter ↔ Assembler)

**Problem:** `Targeter.Run()` calls `GetCallGraph()` and `QueryNodes(NodeMethod)`. `Assembler.Assemble()` calls the exact same two functions again. Each call is a full CPG traversal over HTTP (~10–30 s each).

**Mechanism:** Store bulk-fetched data on the shared `pipeline` struct after Targeter completes, and pass it to Assembler via constructor injection. No Joern queries duplicated.

**Changes to `pipeline` struct** (`cmd/zerotrust/scan.go`):

```go
type pipeline struct {
    sharedCpgData *cpg.SharedData
}
```

**New shared type** (`pkg/cpg/cpg.go`):

```go
type SharedData struct {
    CallGraph    CallGraph          // caller ID → []callee ID
    ReverseGraph CallGraph          // callee ID → []caller ID (built in Go, free)
    NodeNames    map[string]string  // node ID → name
    Methods      []Node
}

// BuildReverseGraph constructs callee→callers index from CallGraph at O(edges) cost.
// Used by Phase 1.5 to eliminate per-method IsExternal/IsAuth HTTP calls.
func (s *SharedData) BuildReverseGraph() {
    s.ReverseGraph = make(CallGraph, len(s.CallGraph))
    for callerID, callees := range s.CallGraph {
        for _, calleeID := range callees {
            s.ReverseGraph[calleeID] = append(s.ReverseGraph[calleeID], callerID)
        }
    }
}
```

**Targeter change** (`internal/semantic/targeting/targeting.go`):

```go
func (t *Targeter) Run(ctx context.Context) ([]Surface, *cpg.SharedData, error) {
    // ... existing code, then:
    shared := &cpg.SharedData{
        CallGraph: cg,
        NodeNames: buildNodeNames(methods),
        Methods:   methods,
    }
    shared.BuildReverseGraph()   // free — O(edges), no HTTP
    return out, shared, nil
}
```

**Assembler receives shared data** (`internal/semantic/assembler/assembler.go`):

```go
func (a *Assembler) WithSharedData(d *cpg.SharedData) {
    a.callGraph = d.CallGraph
    a.nodeNames = d.NodeNames
}

func (a *Assembler) Assemble(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]CallChain, error) {
    if a.callGraph == nil {
        // fallback: fetch from Joern HTTP
        cg, _ := a.graph.GetCallGraph()
        a.callGraph = cg
        methods, _ := a.graph.QueryNodes(cpg.NodeMethod)
        a.nodeNames = buildNodeNames(methods)
    }
    // use a.callGraph and a.nodeNames directly — no HTTP
}
```

**Impact:** Eliminates ~20–40 s of duplicate Joern queries per scan. Diagnostic issue #3.

---

### 1.2 Fix Spurious Idle-Freeze Timeout

**Problem:** `http.go:152` aborts the scan after 20 consecutive seconds of `202/204` responses. CPG traversals legitimately exceed 20 s.

**Mechanism:** Increase `JoernIdleTimeout` from 20 s to 90 s. Reset idle timer on *every* HTTP response, not just non-202/204.

**Change** (`internal/tuning/tuning.go`):

```go
const JoernIdleTimeout = 90 * time.Second
```

**Fix in `fetchResult`** (`internal/scanner/joern/http.go`):

```go
// Reset BEFORE the 202/204 check — every response (including 202) resets the timer.
idleStart = time.Now()

if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
    continue
}
```

**Impact:** Eliminates spurious CPG build failures on legitimate long traversals. Diagnostic issue #9.

---

### 1.3 Fix Silent 4 MB Edge Set Truncation

**Problem:** `fetchResult` reads only 4 MB of response body. `GetCallGraph()` for large CPGs routinely exceeds this — truncated silently.

**Mechanism:** Paginate `GetCallGraph` with `.sortBy(_.id).skip(N).take(M)` in the Joern DSL. The `.sortBy(_.id)` is mandatory — without it, traversal order is non-deterministic and pages overlap or miss edges silently.

**Stable pagination** (`internal/scanner/joern/queries.go`):

```go
// queryAllEdgesPaginated returns call edges page N, sorted by caller ID for stable pages.
// sortBy(_.id) is required — skip/take without a total order produces overlapping pages.
func queryAllEdgesPaginated(page, pageSize int) string {
    return fmt.Sprintf(`cpg.call
  .sortBy(_.id)
  .flatMap(call => call.callee.map(callee =>
    s"""{"from":"${call.id.toString}","to":"${callee.id.toString}","type":"CALL","label":""}"""
  ))
  .skip(%d)
  .take(%d)
  .toList
  .mkString("[", ",", "]")`, page*pageSize, pageSize)
}

// queryNodesPaginated returns nodes of a given type, page N, stable-sorted by ID.
func queryNodesPaginated(nt cpg.NodeType, page, pageSize int) string {
    base := nodeTypeQuery(string(nt))
    return fmt.Sprintf(`%s
  .sortBy(_.id)
  .map(n => s"""{"id":"${n.id.toString}","name":"${n.name}","file":"${n.filename}","line":${n.lineNumber.getOrElse(0)}}""")
  .skip(%d)
  .take(%d)
  .toList
  .mkString("[", ",", "]")`, base, page*pageSize, pageSize)
}
```

**Updated `GetCallGraph`** (`internal/scanner/joern/graph.go`):

```go
func (g *joernGraph) GetCallGraph() (cpg.CallGraph, error) {
    pageSize := 10000
    cg := make(cpg.CallGraph)
    for page := 0; ; page++ {
        raw, err := g.client.doQuery(g.ctx, queryAllEdgesPaginated(page, pageSize))
        if err != nil {
            return nil, fmt.Errorf("joern: GetCallGraph page %d: %w", page, err)
        }
        if len(raw) <= 2 {
            break
        }
        var edges []joernEdge
        if err := json.Unmarshal(raw, &edges); err != nil {
            return nil, fmt.Errorf("joern: GetCallGraph page %d unmarshal: %w", page, err)
        }
        if len(edges) == 0 {
            break
        }
        for _, e := range edges {
            cg[e.From] = append(cg[e.From], e.To)
        }
        if len(edges) < pageSize {
            break
        }
    }
    return cg, nil
}
```

**Response size increase** (`internal/scanner/joern/http.go`):

```go
raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB
```

**Impact:** Zero silent truncation. Correctness guaranteed regardless of CPG size. Diagnostic issue #10.

---

### 1.4 Fix `runJoernTaint` N+1 — Single Bulk CALL Query

**Problem:** `runJoernTaint` (scan.go:1463–1488) iterates over every scope file calling `QueryNodesByFile(f, NodeCall)` — one HTTP round-trip per file (Diagnostic Pattern A). The original plan proposed a 16-goroutine worker pool; this is **incorrect** — Joern is single-threaded so concurrent goroutines produce zero throughput gain and add scheduling overhead.

**Mechanism:** Replace the per-file loop with a single Joern query that returns all CALL nodes across all scope files in one traversal. Go classifies sources/sinks from the result.

**New bulk query** (`internal/scanner/joern/queries.go`):

```go
// queryCallsInFiles returns all CALL nodes whose file is in the provided set.
// Uses a Scala Set for O(1) membership — no per-file queries.
func queryCallsInFiles(relPaths []string) string {
    var sb strings.Builder
    sb.WriteString("val _f = Set(")
    for i, p := range relPaths {
        if i > 0 {
            sb.WriteByte(',')
        }
        fmt.Fprintf(&sb, "%q", p)
    }
    sb.WriteString("); cpg.call")
    sb.WriteString(`.where(_.file.name.filter(_f.contains))`)
    sb.WriteString(`.sortBy(_.id)`)
    sb.WriteString(`.map(c => s"""{"id":"${c.id}","name":"${c.name}","file":"${c.location.filename}","line":${c.lineNumber.getOrElse(0)}}""")`)
    sb.WriteString(`.toList.mkString("[",",","]")`)
    return sb.String()
}
```

**Updated `runJoernTaint`** (`cmd/zerotrust/scan.go`):

```go
func runJoernTaint(ctx context.Context, graph cpg.Graph, scopeFiles []string) ([]finding.Finding, error) {
    lang, ok := joern.DetectLanguageFromFiles(scopeFiles)
    if !ok {
        return nil, nil
    }

    // One HTTP call for all files — replaces N sequential per-file calls.
    q := joern.QueryCallsInFiles(scopeFiles)
    raw, err := graph.(*joernGraphImpl).client.doQuery(ctx, q)
    if err != nil {
        return nil, fmt.Errorf("runJoernTaint bulk query: %w", err)
    }
    calls, err := parseNodes(raw)
    if err != nil {
        return nil, err
    }

    var sources []cpg.TaintSource
    var sinks   []cpg.TaintSink
    for _, c := range calls {
        if sd, ok := joern.SourceDefForCall(lang, c.Name); ok {
            sources = append(sources, cpg.TaintSource{NodeID: c.ID, Kind: sd.Kind, File: c.File, Line: c.Line})
        }
        if sd, ok := joern.SinkDefForCall(lang, c.Name); ok {
            sinks = append(sinks, cpg.TaintSink{NodeID: c.ID, Kind: sd.Kind, File: c.File, Line: c.Line})
        }
    }
    // ... TaintPaths call unchanged
}
```

**Impact:** Reduces `runJoernTaint` Joern HTTP calls from `len(scopeFiles)` → **1**. Diagnostic Pattern A, issue #4.

---

### 1.5 Fix Targeter.Run N+1 — In-Memory Classification via SharedData

**Problem:** `Targeter.Run` calls `IsExternalInputNode` and `IsAuthBoundaryNode` once per method via `QueryEdges(methodID, "")` — one HTTP round-trip per method (Diagnostic Pattern B). For 5,000 methods: **10,000 HTTP calls** (~200 s wall time even with a pool, because Joern serializes them).

**Root cause:** The worker pool creates the illusion of parallelism but Joern processes queries sequentially — all goroutines wait behind the same single-threaded REPL.

**Mechanism:** `IsExternalInputNode` and `IsAuthBoundaryNode` both ask "who calls this method?" — which is exactly what `SharedData.ReverseGraph` (built for free in §1.1) answers. Replace all HTTP edge queries with in-memory reverse graph lookups.

**Replacement logic** (`internal/semantic/targeting/targeting.go`):

```go
// classifyMethodsFromSharedData replaces the per-method HTTP loop.
// Uses SharedData.ReverseGraph (callee→callers) and NodeNames for Go-side matching.
// Zero HTTP calls.
func classifyMethodsFromSharedData(shared *cpg.SharedData, externalPatterns, authPatterns []string) (extSet, authSet map[string]bool) {
    extSet  = make(map[string]bool)
    authSet = make(map[string]bool)

    for methodID, callerIDs := range shared.ReverseGraph {
        for _, callerID := range callerIDs {
            callerName := shared.NodeNames[callerID]
            for _, p := range externalPatterns {
                if strings.Contains(callerName, p) {
                    extSet[methodID] = true
                }
            }
            for _, p := range authPatterns {
                if strings.Contains(callerName, p) {
                    authSet[methodID] = true
                }
            }
        }
        // Also check method name itself for annotation-based patterns
        methodName := shared.NodeNames[methodID]
        for _, p := range externalPatterns {
            if strings.Contains(methodName, p) {
                extSet[methodID] = true
            }
        }
    }
    return
}
```

**Updated `Targeter.Run` loop** — replaces the errgroup worker pool:

```go
extSet, authSet := classifyMethodsFromSharedData(shared, externalInputPatterns, authBoundaryPatterns)

var surfaces []Surface
for _, m := range shared.Methods {
    isExt  := extSet[m.ID]
    isAuth := authSet[m.ID]
    if isExt || isAuth {
        surfaces = append(surfaces, newSurface(m, isExt, isAuth))
    }
}
```

**Impact:** Eliminates ~10,000 HTTP calls → 0. Wall time for targeting phase: ~200 s → <1 ms. Diagnostic Pattern B, issues #1, #6.

---

### 1.6 Fix IDOR N+1 — Reuse SharedData Call Graph

**Problem:** `queryIDORCandidates` (idor.go:73–96) iterates all methods calling `graph.QueryEdges(m.ID, "")` to find IDOR-relevant edge patterns — one HTTP round-trip per method (Diagnostic Pattern C, ~5,000 calls).

**Mechanism:** `SharedData.CallGraph` already contains all outgoing edges (caller→callees). `SharedData.ReverseGraph` contains incoming edges. Rewire `queryIDORCandidates` to use these in-memory maps. Zero HTTP.

```go
// queryIDORCandidatesFromSharedData replaces the per-method QueryEdges loop.
func queryIDORCandidatesFromSharedData(shared *cpg.SharedData, idorPatterns []string) []cpg.Node {
    var candidates []cpg.Node
    for _, m := range shared.Methods {
        // Check outgoing calls for IDOR-relevant sink names
        for _, calleeID := range shared.CallGraph[m.ID] {
            calleeName := shared.NodeNames[calleeID]
            for _, p := range idorPatterns {
                if strings.Contains(calleeName, p) {
                    candidates = append(candidates, m)
                    goto nextMethod
                }
            }
        }
        nextMethod:
    }
    return candidates
}
```

Pass `shared` to the IDOR detector via constructor injection (same pattern as §1.1 Assembler).

**Impact:** Eliminates ~5,000 HTTP calls → 0. Diagnostic Pattern C, issues #1, #6.

---

### 1.7 Fix ExpandWithCPG + buildOrLoadCPG + ExpandModuleScope N+1

**Problem (Patterns E, F, G):**

- `ExpandWithCPG` (expand.go:44–73): `QueryNodesByFile(f, NodeMethod)` per changed file + `GetCallers`/`GetCallees` per method node.
- `buildOrLoadCPG` (scan.go:1270–1284): `QueryNodesByFile(f, NodeMethod)` per changed file.
- `ExpandModuleScope` (modules.go:109–120): `QueryNodesByFile` per file + `GetNeighboursAtDepth` per method (BFS with HTTP per level).

Combined: ~1,050+ HTTP calls for 50 changed files with ~10 methods each.

**Mechanism:**

**Fix E + F** — one bulk query for all changed files (same pattern as §1.4):

```go
// queryMethodsInFiles returns all METHOD nodes across a set of files in one call.
func queryMethodsInFiles(relPaths []string) string {
    var sb strings.Builder
    sb.WriteString("val _f = Set(")
    for i, p := range relPaths {
        if i > 0 {
            sb.WriteByte(',')
        }
        fmt.Fprintf(&sb, "%q", p)
    }
    sb.WriteString("); cpg.method")
    sb.WriteString(`.where(_.filename.filter(_f.contains))`)
    sb.WriteString(`.sortBy(_.id)`)
    sb.WriteString(`.map(m => s"""{"id":"${m.id}","name":"${m.name}","file":"${m.filename}","line":${m.lineNumber.getOrElse(0)}}""")`)
    sb.WriteString(`.toList.mkString("[",",","]")`)
    return sb.String()
}
```

One call returns all method nodes for all changed files. Replace both per-file loops.

**Fix G** — replace `GetNeighboursAtDepth` BFS (which does 2×depth HTTP calls per method) with Go-side BFS using `SharedData.CallGraph` and `SharedData.ReverseGraph`:

```go
// bfsFromSharedData does call-chain expansion in Go with zero HTTP calls.
// Replaces GetNeighboursAtDepth for the ExpandModuleScope path.
func bfsFromSharedData(shared *cpg.SharedData, rootID string, maxDepth int) []cpg.Node {
    visited := map[string]bool{rootID: true}
    frontier := []string{rootID}
    var result []cpg.Node

    for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
        var next []string
        for _, id := range frontier {
            for _, callerID := range shared.ReverseGraph[id] {
                if !visited[callerID] {
                    visited[callerID] = true
                    next = append(next, callerID)
                    if n, ok := shared.MethodByID[callerID]; ok {
                        result = append(result, n)
                    }
                }
            }
            for _, calleeID := range shared.CallGraph[id] {
                if !visited[calleeID] {
                    visited[calleeID] = true
                    next = append(next, calleeID)
                    if n, ok := shared.MethodByID[calleeID]; ok {
                        result = append(result, n)
                    }
                }
            }
        }
        frontier = next
    }
    return result
}
```

Add `MethodByID map[string]cpg.Node` to `SharedData` (populated from `Methods []Node` at build time).

**Impact:** Eliminates ~1,050 HTTP calls → 2 (one bulk methods query + shared data already fetched). Diagnostic Patterns E, F, G, issue #4.

---

### 1.8 Fix HTTP Connection Bloat — Transport Keep-Alive

**Problem:** Go's default `http.Client` reuses connections via keep-alive, but the default `IdleConnTimeout` (90 s) and `MaxIdleConnsPerHost` (2) are insufficient for the poll-heavy pattern: 50 polls × 16,000 queries = 800,000 nominal connections before Phase 2 lands. Even with keep-alive, TCP connections expire between polls if idle timeout is shorter than the poll interval.

**Mechanism:** Configure a dedicated transport with enough idle connections to hold open across polls.

```go
// In joern Client constructor (internal/scanner/joern/joern.go or http.go):
c.httpClient = &http.Client{
    Timeout: c.queryTimeout,
    Transport: &http.Transport{
        MaxIdleConnsPerHost: 4,           // hold 4 idle conns to Joern between polls
        IdleConnTimeout:     120 * time.Second, // outlasts any realistic poll sequence
        DisableCompression:  true,        // Joern responses are already compact JSON
    },
}
```

**Impact:** TCP handshake overhead drops from ~800 s (1 ms × 800K) to near-zero — connections reused across all polls for the lifetime of a scan. Diagnostic issue #2 (interim, before Phase 2.7 pipe replaces HTTP entirely).

---

## Phase 2: Core Architectural Redesign — Sequential Pipeline + SQLite Work Queue

### 2.1 Architecture Principle: SQLite as the Pipeline

**Current model (broken):**

```
Stage A ──([]T in RAM)──> Stage B ──([]U in RAM)──> Stage C
         accumulate          accumulate          accumulate
         memory: O(n)        memory: O(m)        memory: O(k)
```

**New model:**

```
Orchestrator calls stages in sequence. Each stage reads work from
SQLite and writes results back to SQLite. No channels, no goroutine
fan-out, no event routing logic.

  run() {
    target.Run(ctx, scanID)      // writes surfaces to work_items
    enrich.Run(ctx, scanID)      // reads surfaces, writes enriched rows
    classify.Run(ctx, scanID)    // reads enriched, writes classified rows
    assemble.Run(ctx, scanID)    // reads classified, writes chains
    llmscan.Run(ctx, scanID)     // reads chains, writes pending_findings
    dedup.Run(ctx, scanID)       // reads pending_findings, writes findings
  }
```

**Rules:**

1. Stages are called **sequentially**. The pipeline is inherently sequential by data dependency — Targeter must finish before Enricher can read its output.
2. Each stage reads its input from SQLite (`work_items` or a typed table) and writes its output back to SQLite. No in-memory passing between stages.
3. Each stage processes one row at a time via a cursor or `LIMIT/OFFSET` batch. Maximum in-flight memory per stage = one batch (~100 rows × ~128 bytes = ~15 KB).
4. SQLite is the durable checkpoint. A scan can be restarted at any stage by querying `status='pending'` rows. No work is lost on crash.
5. Polling overhead: one indexed SQLite query at ~50 µs per row — negligible next to LLM calls that take seconds.

**`work_items` schema** (added to migration 4 in `pkg/sqlite/sqlite.go`):

```sql
CREATE TABLE IF NOT EXISTS work_items (
    scan_id    TEXT    NOT NULL,
    component  TEXT    NOT NULL,  -- 'enricher','classifier','assembler','llm_scan','dedup'
    surface_id TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'pending',  -- 'pending','done','error'
    payload    TEXT,              -- JSON metadata (enriched surface, chain, etc.)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scan_id, component, surface_id)
);
CREATE INDEX IF NOT EXISTS idx_work_pending
    ON work_items (scan_id, component, status);
```

---

### 2.2 SQLite as the Source of Truth — Not Just a Cache

**Architecture:** After CPG build completes, bulk-fetch **all** CPG nodes and edges into SQLite tables in paginated Joern HTTP calls (using stable pagination from §1.3). Then serve **every** subsequent graph query from SQLite indexed lookups. This eliminates ~99.9% of Joern HTTP traffic.

#### 2.2a Schema

Migration 4 (already applied to `pkg/sqlite/sqlite.go`), with `work_items` and `pending_findings` added:

```sql
CREATE TABLE IF NOT EXISTS cpg_nodes (
    project_id   TEXT    NOT NULL,
    cpg_version  TEXT    NOT NULL,
    node_id      TEXT    NOT NULL,
    node_type    TEXT    NOT NULL,
    name         TEXT    NOT NULL DEFAULT '',
    file         TEXT    NOT NULL DEFAULT '',
    line         INTEGER NOT NULL DEFAULT 0,
    code         TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, cpg_version, node_id)
);
CREATE INDEX IF NOT EXISTS idx_cpn_type ON cpg_nodes (project_id, cpg_version, node_type);
CREATE INDEX IF NOT EXISTS idx_cpn_file ON cpg_nodes (project_id, cpg_version, file);

CREATE TABLE IF NOT EXISTS cpg_edges (
    project_id  TEXT NOT NULL,
    cpg_version TEXT NOT NULL,
    from_id     TEXT NOT NULL,
    to_id       TEXT NOT NULL,
    edge_type   TEXT NOT NULL DEFAULT 'CALL',
    PRIMARY KEY (project_id, cpg_version, from_id, to_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_cpe_from ON cpg_edges (project_id, cpg_version, from_id);
CREATE INDEX IF NOT EXISTS idx_cpe_to   ON cpg_edges (project_id, cpg_version, to_id);

CREATE TABLE IF NOT EXISTS cpg_builds (
    project_id   TEXT PRIMARY KEY,
    cpg_version  TEXT    NOT NULL,
    changed_hash TEXT    NOT NULL,
    node_count   INTEGER NOT NULL DEFAULT 0,
    edge_count   INTEGER NOT NULL DEFAULT 0,
    built_at     INTEGER NOT NULL
);

-- Durable finding store: LLM scanner writes here BEFORE publishing EvLLMFinding.
-- Prevents silent finding loss if the dedup channel is full (diagnostic issue #8).
CREATE TABLE IF NOT EXISTS pending_findings (
    scan_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    data       TEXT NOT NULL,   -- JSON-encoded finding.Finding
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
```

#### 2.2b Fix Ingestion Streaming — Eliminate `AllStates []FileState`

**Problem:** The ingestion phase builds `AllStates []FileState` — an unbounded in-memory slice of every file in the project. For a 100K-file monorepo this can be hundreds of MB before CPG build even starts. This is the same accumulation pattern that was fixed everywhere else.

**Mechanism:** Stream each file's hash + state directly into `scan_state` as it is walked. No slice accumulates.

```go
// Before: collect then write
var allStates []FileState
filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
    allStates = append(allStates, FileState{...})  // ← unbounded
    return nil
})
for _, s := range allStates {
    db.UpsertScanState(ctx, ...)
}

// After: walk and write in one pass
filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
    hash, err := hashFile(path)
    if err != nil {
        return nil  // skip unreadable files
    }
    return db.UpsertScanState(ctx, ScanStateRow{
        ProjectID:     projectID,
        FilePath:      path,
        ContentHash:   hash,
        LastScannedAt: time.Now().Unix(),
    })
})
```

**Impact:** Ingestion memory footprint drops from O(files) to O(1). Diagnostic issue #8 (same root cause as `allFindings[]`).

---

#### 2.2c Bulk-Fetch CPG Ingestion (The Phase 2 Critical Path)

This runs once immediately after CPG build succeeds, before any targeting work. It triggers the first stage of the sequential pipeline.

```go
// internal/scanner/joern/cpg_ingest.go

const ingestBatchSize = 2000

// IngestCPGToSQLite bulk-fetches all METHOD and CALL nodes plus all CALL edges
// from Joern and writes them into cpg_nodes/cpg_edges using batched transactions.
// Uses stable paginated queries (sortBy + skip/take) from §1.3.
func IngestCPGToSQLite(ctx context.Context, client *Client, db *sqlite.DB, projectID, cpgVersion string) error {
    for _, nt := range []cpg.NodeType{cpg.NodeMethod, cpg.NodeCall} {
        if err := ingestNodes(ctx, client, db, projectID, cpgVersion, nt); err != nil {
            return fmt.Errorf("ingest %s nodes: %w", nt, err)
        }
    }
    if err := ingestEdges(ctx, client, db, projectID, cpgVersion); err != nil {
        return fmt.Errorf("ingest edges: %w", err)
    }
    return recordBuild(ctx, db, projectID, cpgVersion)
}

func ingestNodes(ctx context.Context, client *Client, db *sqlite.DB, projectID, cpgVersion string, nt cpg.NodeType) error {
    for page := 0; ; page++ {
        raw, err := client.doQuery(ctx, queryNodesPaginated(nt, page, ingestBatchSize))
        if err != nil {
            return fmt.Errorf("page %d: %w", page, err)
        }
        nodes, err := parseNodes(raw)
        if err != nil || len(nodes) == 0 {
            break
        }
        tx, err := db.Writer().BeginTx(ctx, nil)
        if err != nil {
            return err
        }
        stmt, _ := tx.PrepareContext(ctx,
            `INSERT OR REPLACE INTO cpg_nodes (project_id,cpg_version,node_id,node_type,name,file,line,code)
             VALUES (?,?,?,?,?,?,?,?)`)
        for _, n := range nodes {
            stmt.ExecContext(ctx, projectID, cpgVersion, n.ID, string(nt), n.Name, n.File, n.Line, n.Code)
        }
        stmt.Close()
        if err := tx.Commit(); err != nil {
            tx.Rollback() //nolint:errcheck
            return err
        }
        if len(nodes) < ingestBatchSize {
            break
        }
    }
    return nil
}

func ingestEdges(ctx context.Context, client *Client, db *sqlite.DB, projectID, cpgVersion string) error {
    for page := 0; ; page++ {
        raw, err := client.doQuery(ctx, queryAllEdgesPaginated(page, ingestBatchSize))
        if err != nil {
            return fmt.Errorf("page %d: %w", page, err)
        }
        edges, err := parseEdges(raw)
        if err != nil || len(edges) == 0 {
            break
        }
        tx, _ := db.Writer().BeginTx(ctx, nil)
        stmt, _ := tx.PrepareContext(ctx,
            `INSERT OR REPLACE INTO cpg_edges (project_id,cpg_version,from_id,to_id,edge_type)
             VALUES (?,?,?,?,?)`)
        for _, e := range edges {
            stmt.ExecContext(ctx, projectID, cpgVersion, e.From, e.To, "CALL")
        }
        stmt.Close()
        if err := tx.Commit(); err != nil {
            tx.Rollback() //nolint:errcheck
            return err
        }
        if len(edges) < ingestBatchSize {
            break
        }
    }
    return nil
}

func recordBuild(ctx context.Context, db *sqlite.DB, projectID, cpgVersion string) error {
    _, err := db.Writer().ExecContext(ctx,
        `INSERT OR REPLACE INTO cpg_builds (project_id,cpg_version,changed_hash,built_at)
         VALUES (?,?,?,?)`,
        projectID, cpgVersion, cpgVersion, time.Now().Unix())
    return err
}
```

#### 2.2d Streaming Iterator — Not Materialized Slices

Replace every `[]Node` / `[]Edge` / `CallGraph` return type with a **cursor-based row iterator**. No slice is ever materialized in memory.

```go
type NodeCursor struct{ rows *sql.Rows }
func (c *NodeCursor) Next() bool             { return c.rows.Next() }
func (c *NodeCursor) Scan() (cpg.Node, error) {
    var n cpg.Node
    return n, c.rows.Scan(&n.ID, &n.Name, &n.File, &n.Line, &n.Code)
}
func (c *NodeCursor) Close() { c.rows.Close() }

type EdgeCursor struct{ rows *sql.Rows }
func (c *EdgeCursor) Next() bool              { return c.rows.Next() }
func (c *EdgeCursor) Scan() (cpg.Edge, error) {
    var e cpg.Edge
    return e, c.rows.Scan(&e.From, &e.To, &e.Type)
}
func (c *EdgeCursor) Close() { c.rows.Close() }
```

**Old return types → New:**

```go
// Before (entire graph in RAM):
QueryNodes(nodeType) ([]Node, error)
GetCallGraph() (CallGraph, error)    // map[string][]string
GetCallers(id) ([]Node, error)
GetCallees(id) ([]Node, error)

// After (one row at a time):
QueryNodes(nodeType) (*NodeCursor, error)
GetCallGraph() (*EdgeCursor, error)
GetCallers(id) (*NodeCursor, error)
GetCallees(id) (*NodeCursor, error)
```

`StorageGraph` interface (`internal/scanner/joern/sqlite_graph.go`):

```go
type StorageGraph interface {
    QueryNodes(nodeType cpg.NodeType) (*NodeCursor, error)
    QueryNodesByFile(file string, nodeType cpg.NodeType) (*NodeCursor, error)
    GetCallGraph() (*EdgeCursor, error)
    GetCallers(functionID string) (*NodeCursor, error)
    GetCallees(functionID string) (*NodeCursor, error)
    GetEdgesFrom(nodeID string) (*EdgeCursor, error)
    GetEdgesTo(nodeID string) (*EdgeCursor, error)
}

// SQLiteGraph implements StorageGraph — zero Joern HTTP calls.
type SQLiteGraph struct {
    db         *sqlite.DB
    projectID  string
    cpgVersion string
}
```

#### 2.2e SQLite Query Examples (Indexed, Sub-Millisecond)

```go
func (g *SQLiteGraph) QueryNodes(nodeType cpg.NodeType) (*NodeCursor, error) {
    rows, err := g.db.Reader().QueryContext(ctx, `
        SELECT node_id, name, file, line, code
        FROM cpg_nodes
        WHERE project_id = ? AND cpg_version = ? AND node_type = ?
        ORDER BY node_id`,
        g.projectID, g.cpgVersion, string(nodeType))
    if err != nil {
        return nil, err
    }
    return &NodeCursor{rows: rows}, nil
}

func (g *SQLiteGraph) GetCallers(functionID string) (*NodeCursor, error) {
    rows, err := g.db.Reader().QueryContext(ctx, `
        SELECT n.node_id, n.name, n.file, n.line, n.code
        FROM cpg_edges e
        JOIN cpg_nodes n ON n.node_id = e.from_id
            AND n.project_id = e.project_id AND n.cpg_version = e.cpg_version
        WHERE e.project_id = ? AND e.cpg_version = ?
            AND e.to_id = ? AND e.edge_type = 'CALL'
        ORDER BY n.node_id`,
        g.projectID, g.cpgVersion, functionID)
    return &NodeCursor{rows: rows}, err
}

func (g *SQLiteGraph) GetCallees(functionID string) (*NodeCursor, error) {
    rows, err := g.db.Reader().QueryContext(ctx, `
        SELECT n.node_id, n.name, n.file, n.line, n.code
        FROM cpg_edges e
        JOIN cpg_nodes n ON n.node_id = e.to_id
            AND n.project_id = e.project_id AND n.cpg_version = e.cpg_version
        WHERE e.project_id = ? AND e.cpg_version = ?
            AND e.from_id = ? AND e.edge_type = 'CALL'
        ORDER BY n.node_id`,
        g.projectID, g.cpgVersion, functionID)
    return &NodeCursor{rows: rows}, err
}
```

#### 2.2f BFS Without Materializing the Call Graph — Recursive CTE

Replace `buildCallGraph`'s in-memory BFS with a SQL recursive CTE:

```go
func (g *SQLiteGraph) GetNeighboursAtDepth(rootID string, depth int) (*NodeCursor, error) {
    rows, err := g.db.Reader().QueryContext(ctx, `
        WITH RECURSIVE bfs(id, d) AS (
            SELECT ?, 0
            UNION ALL
            SELECT e.to_id, bfs.d + 1
            FROM cpg_edges e JOIN bfs ON e.from_id = bfs.id
            WHERE e.edge_type = 'CALL' AND bfs.d < ?
            UNION ALL
            SELECT e.from_id, bfs.d + 1
            FROM cpg_edges e JOIN bfs ON e.to_id = bfs.id
            WHERE e.edge_type = 'CALL' AND bfs.d < ?
        )
        SELECT DISTINCT n.node_id, n.name, n.file, n.line, n.code
        FROM bfs
        JOIN cpg_nodes n ON n.node_id = bfs.id
            AND n.project_id = ? AND n.cpg_version = ?
        WHERE bfs.id != ?
        ORDER BY n.node_id`,
        rootID, depth, depth, g.projectID, g.cpgVersion, rootID)
    return &NodeCursor{rows: rows}, err
}
```

**Memory:** Zero. The CTE runs inside SQLite. No `map[string][]string` in Go.

#### 2.2g The Only Remaining Joern HTTP Calls

After Phase 2.2 lands, only two Joern HTTP interactions remain per scan:

```go
// cpg.Graph shrinks to these three methods:
type Graph interface {
    // CPG build — unavoidable, runs once.
    BuildCPG(ctx context.Context, path string) error
    // Taint analysis — Joern's dataflow engine cannot be replicated in SQLite.
    TaintPaths(sources []TaintSource, sinks []TaintSink) ([]TaintPath, error)
    // Version query for logging.
    Version(ctx context.Context) (string, error)
}
```

All other graph operations are pure SQLite indexed lookups via `StorageGraph`.

#### 2.2h Eliminate Unbounded `allFindings[]` — Streaming SQLite Writes

**Problem:** `allFindings[]` (scan.go:391–396) accumulates every finding in RAM and grows linearly with finding count. For large scans this is unbounded. Diagnostic issue #8.

**Mechanism:** The LLM scanner writes each finding to `pending_findings` **before** publishing `EvLLMFinding`. The event carries only the finding ID. Dedup reads from SQLite rather than from the event body. This also resolves the silent finding-drop risk (R5): if the dedup channel is full and the event is dropped, the finding is already durable in SQLite and can be recovered.

```go
// In LLM scan component — write-before-publish pattern.
func (c *LLMScanner) publishFinding(ctx context.Context, f finding.Finding) error {
    data, err := json.Marshal(f)
    if err != nil {
        return err
    }
    // Durable write first. If the channel send below is dropped, finding survives.
    if _, err := c.db.Writer().ExecContext(ctx,
        `INSERT OR REPLACE INTO pending_findings (scan_id, finding_id, data, created_at)
         VALUES (?, ?, ?, ?)`,
        c.scanID, f.ID, string(data), time.Now().Unix()); err != nil {
        return fmt.Errorf("persist finding: %w", err)
    }
    // Event carries ID only — not the full blob.
    c.pub <- Event{Kind: EvLLMFinding, ScanID: c.scanID, Body: f.ID}
    return nil
}
```

Dedup component reads from SQLite on `EvLLMFinding`:

```go
func (d *Dedup) handle(ctx context.Context, ev Event) {
    switch ev.Kind {
    case EvLLMFinding:
        findingID := ev.Body.(string)
        // Fetch from SQLite — zero in-memory accumulation.
        row := d.db.Reader().QueryRowContext(ctx,
            `SELECT data FROM pending_findings WHERE scan_id = ? AND finding_id = ?`,
            d.scanID, findingID)
        var data string
        if err := row.Scan(&data); err != nil {
            slog.Error("dedup: missing pending finding", "id", findingID, "err", err)
            return
        }
        var f finding.Finding
        json.Unmarshal([]byte(data), &f)
        // Gate 1+2: O(1) hash lookup, streaming
        if d.isDuplicate(ctx, f) {
            return
        }
        d.survivors = append(d.survivors, f)  // bounded: gate 1+2 filter ~80%
    }
}
```

**Memory guarantee:** `allFindings[]` is gone. Only Gate 1+2 survivors accumulate (typically < 200 findings). Diagnostic issue #8.

---

### 2.3 Sequential Pipeline Component Design

Each component is a plain function: read pending work from SQLite, process it, mark done. No goroutines, no channels, no routing logic.

#### 2.3a Targeter (Surface Selection)

```go
// Run streams METHOD nodes from SQLite, classifies each, inserts surfaces as work_items.
func (t *Targeter) Run(ctx context.Context, scanID string) error {
    cursor, err := t.graph.QueryNodes(cpg.NodeMethod)
    if err != nil {
        return err
    }
    defer cursor.Close()

    const batchSize = 100
    var batch []workItem
    flush := func() error {
        if len(batch) == 0 {
            return nil
        }
        return insertWorkItems(ctx, t.db, batch)
    }

    for cursor.Next() {
        method, _ := cursor.Scan()
        isExt  := t.classifyExternal(ctx, method.ID)   // SQLite GetEdgesFrom, ~50 µs
        isAuth := t.classifyAuth(ctx, method.ID)
        if isExt || isAuth {
            batch = append(batch, workItem{
                ScanID: scanID, Component: "enricher",
                SurfaceID: method.ID, Status: "pending",
                CreatedAt: time.Now().Unix(),
            })
        }
        if len(batch) >= batchSize {
            if err := flush(); err != nil {
                return err
            }
            batch = batch[:0]
        }
    }
    return flush()
}

// classifyExternal: single indexed SQLite edge lookup — no HTTP.
func (t *Targeter) classifyExternal(ctx context.Context, methodID string) bool {
    cursor, _ := t.graph.GetEdgesFrom(methodID)
    defer cursor.Close()
    for cursor.Next() {
        edge, _ := cursor.Scan()
        for _, p := range externalInputPatterns {
            if strings.Contains(edge.Label, p) {
                return true
            }
        }
    }
    return false
}
```

#### 2.3b Enricher

```go
// Run reads pending enricher work_items, enriches each, inserts classifier work_items.
func (e *Enricher) Run(ctx context.Context, scanID string) error {
    rows, err := e.db.Reader().QueryContext(ctx,
        `SELECT surface_id FROM work_items
         WHERE scan_id = ? AND component = 'enricher' AND status = 'pending'
         ORDER BY surface_id`, scanID)
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var surfaceID string
        rows.Scan(&surfaceID) //nolint:errcheck
        callers, _ := e.graph.GetCallers(surfaceID)
        callees, _ := e.graph.GetCallees(surfaceID)
        enriched := e.buildEnrichedSurface(surfaceID, callers, callees)
        if err := e.writeClassifierItem(ctx, scanID, surfaceID, enriched); err != nil {
            return err
        }
        e.db.Writer().ExecContext(ctx, //nolint:errcheck
            `UPDATE work_items SET status='done', updated_at=?
             WHERE scan_id=? AND component='enricher' AND surface_id=?`,
            time.Now().Unix(), scanID, surfaceID)
    }
    return rows.Err()
}
```

#### 2.3c Assembler

```go
// Run reads classified work_items, builds call chains via SQLite CTE, writes to work_items.
func (a *Assembler) Run(ctx context.Context, scanID string) error {
    rows, err := a.db.Reader().QueryContext(ctx,
        `SELECT surface_id, payload FROM work_items
         WHERE scan_id = ? AND component = 'assembler' AND status = 'pending'
         ORDER BY surface_id`, scanID)
    if err != nil {
        return err
    }
    defer rows.Close()

    for rows.Next() {
        var surfaceID, payload string
        rows.Scan(&surfaceID, &payload) //nolint:errcheck
        // BFS via recursive CTE — zero materialisation, zero HTTP.
        cursor, _ := a.graph.GetNeighboursAtDepth(surfaceID, maxDepth)
        var chain CallChain
        for cursor.Next() {
            node, _ := cursor.Scan()
            chain.Functions = append(chain.Functions, FunctionContext{Node: node})
        }
        cursor.Close()
        // chain.Functions bounded by maxDepth (default 3) — at most 7 elements.
        a.writeLLMScanItem(ctx, scanID, surfaceID, chain) //nolint:errcheck
        a.db.Writer().ExecContext(ctx, //nolint:errcheck
            `UPDATE work_items SET status='done', updated_at=?
             WHERE scan_id=? AND component='assembler' AND surface_id=?`,
            time.Now().Unix(), scanID, surfaceID)
    }
    return rows.Err()
}
```

---

### 2.4 Sequential Orchestrator

No channels, no fan-out goroutine, no event routing. The orchestrator calls stages in order and returns the first error.

```go
func (p *pipeline) run(ctx context.Context) error {
    // Stage 1: CPG ingestion into SQLite (fires once after BuildCPG).
    if err := IngestCPGToSQLite(ctx, p.joernClient, p.db, p.projectID, p.cpgVersion); err != nil {
        return fmt.Errorf("cpg ingest: %w", err)
    }

    // Stage 2: Targeting — classifies methods, writes enricher work_items.
    if err := p.target.Run(ctx, p.scanID); err != nil {
        return fmt.Errorf("targeting: %w", err)
    }

    // Stage 3: Enrichment — reads enricher items, writes classifier items.
    if err := p.enrich.Run(ctx, p.scanID); err != nil {
        return fmt.Errorf("enrichment: %w", err)
    }

    // Stage 4: Classification — reads classifier items, writes assembler items.
    if err := p.clf.Run(ctx, p.scanID); err != nil {
        return fmt.Errorf("classification: %w", err)
    }

    // Stage 5: Assembly — reads assembler items, writes llm_scan items.
    if err := p.asm.Run(ctx, p.scanID); err != nil {
        return fmt.Errorf("assembly: %w", err)
    }

    // Stage 6: LLM scan — reads llm_scan items, writes pending_findings.
    if err := p.scan.Run(ctx, p.scanID); err != nil {
        return fmt.Errorf("llm scan: %w", err)
    }

    // Stage 7: Dedup — reads pending_findings, writes findings table.
    return p.dedup.Run(ctx, p.scanID)
}
```

**Restart semantics:** if the process dies mid-scan, re-running queries `status='pending'` items from the last completed stage and continues. No work is replayed from the start.

---

### 2.5 Eliminate N+1 via SQLite — Complete Pattern Coverage

All 7 N+1 patterns from the diagnostic are addressed:

| Pattern                                   | Location          | HTTP Calls Before | Phase 1 Fix                               | Phase 2 Fix                                                       |
| :---------------------------------------- | :---------------- | :---------------- | :---------------------------------------- | :---------------------------------------------------------------- |
| A — `runJoernTaint` per file              | scan.go:1463      | 500               | §1.4: one bulk CALL query                 | SQLite `WHERE file IN (...)`                                      |
| B — `Targeter.Run` per method (2×)        | targeting.go:427  | 10,000            | §1.5: reverseGraph in-memory lookup       | SQLiteGraph.GetEdgesFrom cursor                                   |
| C — `queryIDORCandidates` per method      | idor.go:73        | 5,000             | §1.6: SharedData.CallGraph lookup         | SQLiteGraph.GetEdgesFrom cursor                                   |
| D — `Enricher.Enrich` per surface (3×)    | enrichment.go:185 | 600               | None (Phase 2 only)                       | SQLiteGraph.GetCallers/GetCallees (3 indexed joins, ~100 µs each) |
| E — `ExpandWithCPG` per file + per method | expand.go:44      | 1,050             | §1.7: bulk methods query + SharedData BFS | SQLiteGraph recursive CTE                                         |
| F — `buildOrLoadCPG` per changed file     | scan.go:1270      | 50                | §1.7: bulk methods query                  | SQLite `WHERE file IN (...)`                                      |
| G — `ExpandModuleScope` BFS per method    | modules.go:109    | N×2×depth         | §1.7: SharedData Go-BFS                   | SQLiteGraph.GetNeighboursAtDepth CTE                              |

**Total HTTP calls eliminated:**

| Stage                          | Before      | After Phase 1 | After Phase 2 |
| :----------------------------- | :---------- | :------------ | :------------ |
| Patterns A + B + C + E + F + G | ~16,700     | ~3            | 0             |
| Pattern D (Enricher)           | 600         | 600           | 0             |
| TaintPaths                     | 1           | 1             | 1             |
| CPG build                      | 1–2         | 1–2           | 1–2           |
| **Total**                      | **~16,100** | **~606**      | **~2**        |

Pattern D has no Phase 1 fix because `GetCallers`/`GetCallees` results are not in SharedData (call graph is caller→callee, not full node metadata). This is acceptable: 600 calls at ~0.2 s each = ~120 s, reduced to 0 in Phase 2. If urgently needed in Phase 1: add `CallersByID map[string][]Node` to SharedData from a secondary bulk query.

---

### 2.6 Persistent Joern Daemon (Eliminate Per-Scan JVM Cold Start)

**Mechanism:** Run Joern as an OS daemon (launchd/systemd). Go connects to the already-running server. No per-scan JVM start/stop.

```go
func (c *Client) ensureRunning(ctx context.Context) error {
    if err := c.Ping(ctx); err == nil {
        return nil // daemon alive
    }
    return c.startDaemon(ctx)
}

func (c *Client) startDaemon(ctx context.Context) error {
    pidPath := filepath.Join(os.TempDir(), "joern-daemon.pid")
    if _, err := os.Stat(pidPath); err == nil {
        if c.Ping(ctx) == nil {
            return nil
        }
        os.Remove(pidPath) //nolint:errcheck
    }
    cmd := exec.Command(c.binaryPath, "--server", "--server-host", "127.0.0.1",
        "--server-port", strconv.Itoa(c.port))
    // start, wait for ready...
    os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0600) //nolint:errcheck
    return nil
}
```

`Stop()` becomes a no-op for the daemon. Diagnostic issue #5.

---

### 2.7 Replace HTTP Poll Loop with Stdin/Stdout Pipe

**Problem:** Even with fewer queries, the remaining ones (bulk ingest, taint) still suffer 50× poll overhead per query.

**Mechanism:** Switch from HTTP REST to Joern's stdin/stdout REPL protocol.

```go
type pipeJoern struct {
    stdin  io.WriteCloser
    stdout *bufio.Reader
    stderr io.ReadCloser
    mu     sync.Mutex  // Joern REPL is single-threaded; serialize all commands
}

func (j *pipeJoern) Exec(query string) (string, error) {
    j.mu.Lock()
    defer j.mu.Unlock()

    // Capture stderr asynchronously so it doesn't block stdout reads.
    var stderrBuf strings.Builder
    go io.Copy(&stderrBuf, j.stderr) //nolint:errcheck

    fmt.Fprintf(j.stdin, "%s\n", query) //nolint:errcheck

    // Read until the REPL prompt appears. Use a 64 MB scanner to handle
    // large result payloads without truncation.
    scanner := bufio.NewScanner(j.stdout)
    scanner.Buffer(make([]byte, 64<<20), 64<<20)

    var buf strings.Builder
    echoed := false
    for scanner.Scan() {
        line := scanner.Text()
        // Skip echo-back of the submitted query (first line after write).
        if !echoed && line == query {
            echoed = true
            continue
        }
        // Skip REPL annotations: "res0: List[...] = ..."
        if reREPLAnnotation.MatchString(line) {
            continue
        }
        // Prompt line signals end of output.
        if line == "joern> " {
            break
        }
        buf.WriteString(line)
        buf.WriteByte('\n')
    }
    if err := scanner.Err(); err != nil {
        return "", fmt.Errorf("pipe read: %w (stderr: %s)", err, stderrBuf.String())
    }
    if s := strings.TrimSpace(stderrBuf.String()); s != "" {
        slog.Warn("joern pipe stderr", "output", s)
    }
    return strings.TrimSpace(buf.String()), nil
}

// reREPLAnnotation matches Scala REPL annotation lines like "res0: List[...] = ..."
var reREPLAnnotation = regexp.MustCompile(`^res\d+:`)
```

**Impact:** Zero polling. Latency per query = execution time + pipe round-trip (~0.05 ms vs 50 polls × 200 ms). Diagnostic issues #2, #6.

---

### 2.8 TaintPaths Sources/Sinks Construction from SQLite

**Problem:** `runJoernTaint`'s per-file N+1 loop (§1.4) builds `[]TaintSource` and `[]TaintSink`. In Phase 2, `QueryNodesByFile` no longer hits Joern — it hits SQLite. This section specifies the exact construction path. Diagnostic issue #4.

```go
// buildSourcesSinks replaces the per-file loop in runJoernTaint for Phase 2.
// Two indexed SQLite queries cover all scope files.
func buildSourcesSinks(ctx context.Context, db *sqlite.DB, projectID, cpgVersion string,
    lang joern.Lang, scopeFiles []string) ([]cpg.TaintSource, []cpg.TaintSink, error) {

    placeholders := strings.Repeat("?,", len(scopeFiles))
    placeholders = placeholders[:len(placeholders)-1]

    args := make([]any, 0, len(scopeFiles)+3)
    args = append(args, projectID, cpgVersion, string(cpg.NodeCall))
    for _, f := range scopeFiles {
        args = append(args, f)
    }

    rows, err := db.Reader().QueryContext(ctx, fmt.Sprintf(`
        SELECT node_id, name, file, line
        FROM cpg_nodes
        WHERE project_id = ? AND cpg_version = ? AND node_type = ?
          AND file IN (%s)
        ORDER BY node_id`, placeholders), args...)
    if err != nil {
        return nil, nil, err
    }
    defer rows.Close() //nolint:errcheck

    var sources []cpg.TaintSource
    var sinks   []cpg.TaintSink
    for rows.Next() {
        var n cpg.Node
        rows.Scan(&n.ID, &n.Name, &n.File, &n.Line) //nolint:errcheck
        if sd, ok := joern.SourceDefForCall(lang, n.Name); ok {
            sources = append(sources, cpg.TaintSource{NodeID: n.ID, Kind: sd.Kind, File: n.File, Line: n.Line})
        }
        if sd, ok := joern.SinkDefForCall(lang, n.Name); ok {
            sinks = append(sinks, cpg.TaintSink{NodeID: n.ID, Kind: sd.Kind, File: n.File, Line: n.Line})
        }
    }
    return sources, sinks, rows.Err()
}
```

One indexed query replaces the entire per-file N+1 loop. `TaintPaths(sources, sinks)` is then called unchanged.

---

### 2.9 Phase 2 Migration Strategy

| Step | What                                                                                              | Risk                     | Rollback          |
| :--- | :------------------------------------------------------------------------------------------------ | :----------------------- | :---------------- |
| 2.1  | Schema migration 4 (`cpg_nodes`, `cpg_edges`, `cpg_builds`, `pending_findings`) — already applied | None (additive)          | Drop tables       |
| 2.2  | `IngestCPGToSQLite` + `SQLiteGraph` + cursor iterators behind feature flag                        | Medium                   | Flip flag off     |
| 2.3  | Event bus wiring in `pipeline.run()` — keep old pipeline as fallback                              | High (new concurrency)   | Toggle flag       |
| 2.4  | Migrate `Targeter` to subscriber model                                                            | Controlled per-component | Revert component  |
| 2.5  | Migrate `Enricher`, `Assembler`                                                                   | Same                     | Same              |
| 2.6  | `buildSourcesSinks` from SQLite (§2.8)                                                            | Low                      | Revert function   |
| 2.7  | Remove old pipeline, remove flag                                                                  | Low                      | Git revert        |
| 2.8  | Persistent daemon + pipe transport                                                                | Medium                   | Fall back to HTTP |
| 2.9  | Remove most of `joernGraph` (keep `BuildCPG`, `TaintPaths`, `Version`)                            | Low                      | Git revert        |

---

## Phase 3: Robustness, Memory, & Scale Guardrails

### 3.1 Bounded Memory via Streaming Dedup

**Problem:** Gate 3+4 (embedding + AST edit distance) needs a set of survivors. `allFindings[]` in scan.go accumulates ALL findings unboundedly before dedup runs. Diagnostic issue #8.

**Solution:** Gates 1+2 are fully streaming (§2.2g already handles this). Gate 3+4 runs only on the survivor set which is bounded by the circuit breaker.

```go
func (d *Dedup) handle(ctx context.Context, ev Event) {
    switch ev.Kind {
    case EvLLMFinding:
        findingID := ev.Body.(string)
        var data string
        if err := d.db.Reader().QueryRowContext(ctx,
            `SELECT data FROM pending_findings WHERE scan_id = ? AND finding_id = ?`,
            d.scanID, findingID).Scan(&data); err != nil {
            slog.Error("dedup: missing pending finding", "id", findingID)
            return
        }
        var f finding.Finding
        json.Unmarshal([]byte(data), &f) //nolint:errcheck

        // Gate 1+2: O(1) streaming hash check — no accumulation.
        if d.isDuplicate(ctx, f) {
            return
        }
        d.survivorsMu.Lock()
        d.survivors = append(d.survivors, f)  // only ~20% of findings reach here
        d.survivorsMu.Unlock()

    case EvDone:
        // Gate 3+4 on bounded survivor set (circuit breaker: max 200).
        scored := d.runGates34(ctx, d.survivors)
        for _, s := range scored {
            d.persist(ctx, s)
        }
        // Clean up pending_findings for this scan.
        d.db.Writer().ExecContext(ctx, //nolint:errcheck
            `DELETE FROM pending_findings WHERE scan_id = ?`, d.scanID)
    }
}
```

**Memory guarantee:** Gate 1+2 filters ~80% of findings. `DedupGate3MaxSurvivors` (default 200) circuit-breaks the rest. Even a 10,000-finding scan holds at most 200 findings in memory.

### 3.2 Memory-Mapped SQLite for Large Caches

Already applied via `pkg/sqlite/sqlite.go` Gap B:

```sql
PRAGMA mmap_size=1073741824  -- 1 GB, reader connection only
PRAGMA cache_size=-131072    -- 128 MB page cache per connection
PRAGMA page_size=16384       -- 16 KB pages for large sequential rows
```

### 3.3 Adaptive Timeout Strategy

Replace the static idle freeze detector with an adaptive timer that tracks the running p99 of query durations:

```go
type queryTimer struct {
    mu        sync.Mutex
    durations []time.Duration
}

func (t *queryTimer) p99Timeout() time.Duration {
    t.mu.Lock()
    defer t.mu.Unlock()
    if len(t.durations) < 10 {
        return 90 * time.Second
    }
    sorted := make([]time.Duration, len(t.durations))
    copy(sorted, t.durations)
    sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
    idx := int(float64(len(sorted)) * 0.99)
    return sorted[idx] * 3 // 3× safety margin
}
```

### 3.4 Graceful Degradation on SQLite Failure

Every `SQLiteGraph` method falls back to Joern HTTP on any DB error:

```go
func (g *SQLiteGraph) QueryNodes(nodeType cpg.NodeType) (*NodeCursor, error) {
    cursor, err := g.queryFromSQLite(nodeType)
    if err != nil {
        slog.Warn("sqlite graph miss, falling back to Joern HTTP", "err", err)
        nodes, _ := g.joernGraph.QueryNodes(nodeType)
        return sliceToCursor(nodes), nil
    }
    return cursor, nil
}
```

### 3.5 Periodic Cache Compaction

```go
func (db *DB) maintainCPGCache(ctx context.Context) {
    ticker := time.NewTicker(24 * time.Hour)
    for {
        select {
        case <-ticker.C:
            cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()
            db.Writer().ExecContext(ctx, //nolint:errcheck
                `DELETE FROM cpg_nodes WHERE (project_id, cpg_version) NOT IN
                 (SELECT project_id, cpg_version FROM cpg_builds WHERE built_at > ?)`, cutoff)
            db.Writer().ExecContext(ctx, //nolint:errcheck
                `DELETE FROM cpg_edges WHERE (project_id, cpg_version) NOT IN
                 (SELECT project_id, cpg_version FROM cpg_builds WHERE built_at > ?)`, cutoff)
            db.Writer().ExecContext(ctx, "PRAGMA incremental_vacuum") //nolint:errcheck
        case <-ctx.Done():
            return
        }
    }
}
```

---

## Summary: End-State Architecture

```
  Orchestrator (sequential)
  ─────────────────────────
  IngestCPG → Targeter → Enricher → Classifier → Assembler → LLMScan → Dedup

  Each stage: SELECT pending FROM work_items → process → INSERT next stage rows
  No channels. No fan-out. No lost events.

  ┌────────────────────────────────────────────────────────────────────────────┐
  │                            SQLite Database                                 │
  │                                                                            │
  │  cpg_nodes      cpg_edges     cpg_builds    scan_state (streaming walk)   │
  │  work_items     pending_findings             findings                      │
  │                                                                            │
  │  WAL mode · writer=1 conn · reader pool=8 · 1 GB mmap · 16 KB pages       │
  └────────────────────────────────────────────────────────────────────────────┘

  Joern HTTP:    CPG build (1×) + TaintPaths (1×) per scan
  Joern daemon:  persistent JVM — zero cold start
  Joern pipe:    stdin/stdout after Phase 2.7 — zero poll overhead

  Memory:        O(1) per stage (100-row batch × ~128 B = ~15 KB max)
  allFindings[]: gone — pending_findings table + streaming dedup
  AllStates[]:   gone — walk-and-write streaming into scan_state
  HTTP calls:    2 per scan (was ~16,100)
  Stage restart: query status='pending' from last completed stage
```

**Projected wall time for a medium project (~5,000 methods, ~50 changed files, 200 surfaces):**

| Stage             | Before        | After Phase 1           | After Phase 2 |
| :---------------- | :------------ | :---------------------- | :------------ |
| JVM cold start    | 30–90 s       | 30–90 s                 | 0 s (daemon)  |
| CPG build         | 30–120 s      | 30–120 s                | 30–120 s      |
| N+1 Joern queries | ~475 s        | ~120 s (Pattern D only) | 0 s           |
| TaintPaths        | 30 s          | 30 s                    | 30 s          |
| SQLite graph ops  | 0             | 0                       | ~N × <1 ms    |
| **Total**         | **575–745 s** | **~180–330 s**          | **~60–150 s** |
