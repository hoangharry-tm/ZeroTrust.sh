# HIGH_TODO — Performance Remediation Execution Plan

> **Goal**: Drive scan time from 575–745 s → ~60–150 s by eliminating 16,098 redundant
> Joern HTTP calls, replacing in-memory graph data with SQLite-backed streaming queries,
> and bounding every unbounded slice accumulation.
>
> All 10 diagnostic root causes are addressed across three phases.
> SQLite infrastructure (`pkg/sqlite/`) is already complete as of 2026-07-01.

---

## Phase 1 — Joern HTTP Reduction (tactical, no architecture change)

**Target**: 16,100 HTTP calls → ~606. Pure Go changes, no Python touch.

### 1.1 — SharedData: build ReverseGraph once in Go

**Problem**: Targeter and IDOR checker make per-method Joern HTTP calls to discover callers.
The full call graph is already fetched once by `buildCallGraph` — we just need to invert it in Go.

**Files**:
- `internal/scanner/joern/graph.go` — add `SharedData` struct with `CallGraph map[string][]string` + `ReverseGraph map[string][]string`; populate `ReverseGraph` by inverting `CallGraph` after `buildCallGraph` returns
- `internal/semantic/targeting/targeting.go` — replace per-method Joern HTTP in `IsExternalInputNode` / `IsAuthBoundaryNode` with `SharedData.ReverseGraph` lookups
- `internal/semantic/targeting/idor.go` — replace `GetCallers` HTTP chain with `SharedData.ReverseGraph` walk
- `cmd/zerotrust/scan.go` — thread `SharedData` through to Targeter and IDOR

**Eliminates**: Patterns A (Targeter per-method), C (IDOR per-method) — ~14,000 calls

---

### 1.2 — Fix idle timeout: 20 s → 90 s

**Problem**: Joern REPL goes idle after 20 s of inactivity; scanner kills + restarts it mid-scan.

**Files**:
- `internal/scanner/joern/joern.go` — change idle timeout constant from `20s` to `90s`

**Eliminates**: Root cause #7 (restart overhead). One-liner.

---

### 1.3 — Stable pagination + 64 MB response cap

**Problem**: Joern responses are truncated at 4 MB; pagination uses unstable sort causing overlapping
pages and missed nodes.

**Files**:
- `internal/scanner/joern/graph.go` — add `.sortBy(_.id).skip(N).take(M)` to all paginated
  queries (`QueryNodes`, `buildCallGraph` edge fetch); raise response size limit to 64 MB
- `internal/scanner/joern/joern.go` — raise `maxResponseSize` constant

**Eliminates**: Root cause #3 (truncation), root cause #4 (pagination overlap).

---

### 1.4 — Bulk CALL query replacing worker pool

**Problem**: `QueryNodes` fires one HTTP request per method to check call relationships;
a single Joern query can return the full call table.

**Files**:
- `internal/scanner/joern/graph.go` — replace the per-method HTTP loop in `QueryNodes` with
  a single bulk Gremlin query returning all `(caller_id, callee_id)` pairs; parse result into
  `CallGraph` in one pass
- `internal/scanner/joern/modules.go` — replace `ExpandModule` HTTP loop with bulk file-scoped
  query returning all methods for a given file list

**Eliminates**: Patterns B (QueryNodes loop), D (ExpandModule loop) — ~1,600 calls

---

### 1.5 — HTTP keep-alive transport

**Problem**: Default `http.DefaultTransport` closes TCP connections between requests; each of
~16,000 Joern calls opens a new TCP connection.

**Files**:
- `internal/scanner/joern/joern.go` — replace `http.DefaultClient` with a custom `http.Client`
  using `http.Transport{MaxIdleConns: 10, IdleConnTimeout: 120s, DisableKeepAlives: false}`

**Eliminates**: Root cause #9 (TCP handshake overhead). One-time init change.

---

### Phase 1 Verification

```bash
make build
make run-integration   # check log: "joern http calls: NNN" should be < 700
```

---

## Phase 2 — SQLite Replaces Joern as Graph Store

**Target**: ~606 HTTP calls → 2 (CPG build + TaintPaths only). Requires Phase 1 complete.

### 2.1 — IngestCPGToSQLite: bulk-ingest nodes + edges after CPG build

**Problem**: CPG graph lives only in Joern JVM memory. Every graph query hits HTTP.
After the one-time CPG build, we drain everything to SQLite in paginated stable-sorted batches.

**Files**:
- `internal/scanner/joern/graph.go` — add `IngestCPGToSQLite(ctx, db, projectID, cpgVersion)`
  function: paginate `cpg.method.l` and `cpg.call.l` with `.sortBy(_.id).skip(N).take(500)`;
  call `db.IngestNodeBatch` and `db.IngestEdgeBatch` per page (already in `pkg/sqlite/sqlite_cpg.go`)
- `cmd/zerotrust/scan.go` — call `IngestCPGToSQLite` immediately after CPG build succeeds;
  pass `db` handle and `cpgVersion` (content hash of changed files)

**Uses existing**: `pkg/sqlite/sqlite_cpg.go` — `IngestNodeBatch`, `IngestEdgeBatch`, `RecordBuild`

---

### 2.2 — Replace all graph HTTP queries with SQLite reads

**Problem**: After ingestion, `GetCallers`, `GetCallees`, `QueryNodes`, `ExpandModule` still
hit Joern HTTP. They should read from `cpg_nodes`/`cpg_edges`.

**Files**:
- `internal/semantic/targeting/targeting.go` — replace Joern HTTP calls in node-type lookups
  with `db.QueryNodesByType` / `db.QueryNodesByFile`
- `internal/semantic/targeting/idor.go` — replace `GetCallers` HTTP with `db.GetCallers`
- `internal/semantic/assembler/assembler.go` — replace `ExpandModule` / `buildOrLoad` HTTP
  with `db.QueryNodesByFile` + `db.GetCallees`
- `internal/scanner/joern/graph.go` — add `QueryNodesFromSQLite(db, projectID, cpgVersion, ...)`
  as drop-in replacement for the HTTP version; switch call sites

**Uses existing**: `pkg/sqlite/sqlite_cpg.go` — `QueryNodesByType`, `QueryNodesByFile`,
  `GetCallers`, `GetCallees`, `GetNeighboursAtDepth`

---

### 2.3 — Sequential pipeline via work_items queue

**Problem**: Current pipeline uses goroutine fan-out channels with potential drop under back-pressure.
Sequential stages reading from SQLite is simpler and crash-resumable.

**Files**:
- `cmd/zerotrust/scan.go` — replace channel-based dispatch with sequential stage calls:
  `Targeter → Enricher → Classifier → Assembler → LLMScan → Dedup`; each stage calls
  `db.PollWorkItems(scanID, "stage_name")`, processes rows one at a time via cursor,
  writes next-stage rows with `db.InsertWorkItems`
- `internal/semantic/llmscan/llmscan.go` — call `db.WritePendingFinding` before marking
  work_item done (write-before-publish: no finding loss on crash)
- `internal/dedup/dedup.go` — read from `pending_findings` table instead of in-memory slice;
  call `db.DeletePendingFindings` after commit

**Uses existing**: `pkg/sqlite/sqlite_pipeline.go` — `InsertWorkItems`, `PollWorkItems`,
  `MarkWorkItemDone`, `WritePendingFinding`, `DeletePendingFindings`

---

### 2.4 — Persistent Joern daemon (stdin/stdout pipe)

**Problem**: Joern starts fresh per scan; JVM startup adds 15–30 s. HTTP poll adds latency.

**Files**:
- `internal/scanner/joern/joern.go` — add `StartDaemon()` that launches Joern with
  `cmd.Stdin = pipe`; send queries as newline-delimited JSON over stdin; read results from
  stdout; keep process alive across queries in the same scan session
- `internal/scanner/joern/graph.go` — update `doQuery` to write to pipe instead of HTTP POST
  when daemon mode is active; fall back to HTTP if pipe fails

**Eliminates**: Root causes #5 (JVM restart), #10 (HTTP poll overhead per query).

---

### 2.5 — TaintPaths sources from SQLite

**Problem**: `runJoernTaint` constructs source lists by querying Joern HTTP per method;
sources should come from `cpg_nodes` WHERE `node_type='SOURCE'`.

**Files**:
- `internal/scanner/joern/graph.go` — in `runJoernTaint`, replace per-method HTTP source
  queries with `db.QueryNodesByType(ctx, projectID, cpgVersion, "SOURCE")`; only the final
  taint-path execution query stays as Joern HTTP

---

### Phase 2 Verification

```bash
make build
make run-integration   # log: "joern http calls: 2"
# Check db has populated cpg_nodes/cpg_edges:
sqlite3 tests/integration/spring-boot-app/.zerotrust/scans.db \
  "SELECT node_type, COUNT(*) FROM cpg_nodes GROUP BY node_type;"
```

---

## Phase 3 — Memory Bounds + Robustness

**Target**: Eliminate unbounded slice accumulations; add crash-resume.

### 3.1 — Streaming ingestion: kill AllStates[]

**Problem**: `ingestion.go` accumulates all file states into `[]AllStates` before writing to
SQLite; on a 10k-file repo this is 100+ MB in-memory.

**Files**:
- `internal/ingestion/ingestion.go` — in the file walk loop, call `db.UpsertScanState(row)`
  per file instead of appending to a slice; remove the post-walk bulk-write call

**Uses existing**: `pkg/sqlite/sqlite_state.go` — `UpsertScanState`

---

### 3.2 — Streaming dedup: kill allFindings[]

**Problem**: `dedup.go` loads all finding IDs into `[]string` before dedup; large scans OOM.

**Files**:
- `internal/dedup/dedup.go` — replace `ListFindingIDs` slice load with a `*sql.Rows` cursor;
  stream one finding at a time through the hash-set dedup logic

---

### 3.3 — Adaptive timeout per query type

**Problem**: All Joern queries share one timeout; bulk ingestion queries need more time than
simple lookups.

**Files**:
- `internal/scanner/joern/joern.go` — replace single `queryTimeout` constant with a
  `timeoutFor(queryType string) time.Duration` helper:
  `ingest→120s`, `taint→90s`, `lookup→15s`

---

### Phase 3 Verification

```bash
# Run on large repo (WebGoat ~1084 files) and watch RSS:
make run-integration 2>&1 | grep -E "rss|alloc|findings"
# Should stay under 500 MB RSS throughout scan
```

---

## Execution Order

| Order | Section | Effort | Risk |
|-------|---------|--------|------|
| 1 | §1.2 idle timeout | 1 line | zero |
| 2 | §1.5 HTTP keep-alive | 5 lines | zero |
| 3 | §1.3 stable pagination + 64 MB cap | low | low |
| 4 | §1.1 SharedData + ReverseGraph | medium | medium |
| 5 | §1.4 bulk CALL query | medium | medium |
| 6 | §2.1 IngestCPGToSQLite | high | low (additive) |
| 7 | §2.2 SQLite graph reads | high | medium |
| 8 | §3.1 streaming AllStates | low | low |
| 9 | §3.2 streaming dedup | low | low |
| 10 | §2.3 work_items pipeline | high | medium |
| 11 | §2.5 TaintPaths from SQLite | medium | low |
| 12 | §2.4 Joern daemon pipe | high | high (last) |
| 13 | §3.3 adaptive timeout | low | zero |

---

## Files NOT Changed

- `pkg/sqlite/` — complete, all tables + helpers already implemented
- `worker/` — Python worker untouched in Phase 1–2; LLM handler protocol unchanged
- `rules/`, `docs/`, `pipeline/` — not affected
- `internal/dedup/sidecar.go` — sidecar process protocol unchanged

---

## Key Constraints

- `pkg/sqlite/sqlite_cpg.go` cursors (`NodeCursor`, `EdgeCursor`) must be used everywhere
  instead of `[]CPGNode` slices — this is the whole point of Phase 2
- Writer must remain `MaxOpenConns=1`; never pass `db.Writer()` to concurrent goroutines
- All Joern paginated queries must use `.sortBy(_.id)` — without this, skip/take overlaps
  and nodes are silently missed (root cause #4)
- `WritePendingFinding` must be called before `MarkWorkItemDone` — never reverse this order
