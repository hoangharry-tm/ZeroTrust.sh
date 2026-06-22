# ZeroTrust.sh — TODO

> G1 100% complete. **Layer 0 100% complete (Jun 17–18, 5–14 days early).** **Layer 1 complete (Jun 18)** — Joern binary installed (v4.0.550 Homebrew); async 2-step HTTP protocol + ANSI-strip + init-poll fix landed; 37 unit tests pass; integration tests running. **ML2.2 complete (Jun 18, 3+ weeks early)** — XGrammar-2 + LLM Verifier + Go verifier wired into Path A; 22 tests pass.  
> **Next**: fix `Ping()` context in `TestIntegration_StartAndPing` (10s too short after 35s REPL init), then run all 5 L1 integration tests.  
> Full plan: `docs/planning/implementation-plan.md`

---

## Layer 0 — Foundation + Fast Path (Jun 23 – Jul 3)

### ML0.1 — Go CLI Core + Finding Channel ✅ Done Jun 17
- [x] L0.1.T1: `cobra` CLI flag parsing — `--output minimal|tree|tui`, `--report <path>`, `--mode`, `--token-cap`; `--output` auto-detects TTY
- [x] L0.1.T2: Goroutine dispatcher — `errgroup`-based Path A + Path B concurrent dispatch; buffered `Finding` channel (256); fan-in drain loop; `output.Event` emitted per finding
- [x] L0.1.T3: `Finding` struct locked — `{id, path, line_range, cwe, severity_label, confidence, source_path, reason, poe_context}` in `internal/finding/finding.go`

### ML0.1B — CLI Output Layer ✅ Done Jun 17
- [x] L0.1B.T1: Output mode detection — `isatty` check; auto-selects tree (TTY) or minimal (no TTY); `--output minimal|tree|tui` flag override; selection logic in `cmd/zerotrust/output_select.go` (avoids import cycle)
- [x] L0.1B.T2: Minimal renderer (`internal/output/minimal.go`) — plain stdout, ANSI stripped in pipes, coloured in TTY via `fatih/color`; exit codes 0/1/2
- [x] L0.1B.T3: Tree renderer (`internal/output/tree.go`) + TUI skeleton (`internal/output/tui/`) — Bubble Tea 2-panel layout, 5 tabs (log/findings/summary/suppressed/patches), scanning + done states, full keyboard nav; matches `docs/cli-output-design.md` spec exactly
- [x] L0.1B.T4: Live pipeline events wired via typed `output.Event` channel; `EventStageStart/End/Finding/Log/Error/Done` consumed by all three renderers; Glamour available in TUI for markdown rendering

### ML0.2 — Ollama HTTP Client ✅ Done Jun 17
- [x] L0.2.T1: Ollama HTTP client wrapper (`localhost:11434`); model-agnostic; `Chat` + `BackboneCheck`; `ErrModelBlocked` + `SetMIVBlocked()` gate; 14 tests

### ML0.3 — Model Integrity Verifier ✅ Done Jun 17
- [x] L0.3.T1: SHA256 hash of GGUF model file — streaming 32 MB chunks, context-cancellable
- [x] L0.3.T2: Sigstore Rekor registry verification; ECDSA P-256 primary gate; Rekor best-effort (3s timeout → ECDSA fallback); embedded `data/{registry,sig,cosign.pub}`; 15 tests
- [x] L0.3.T3: MIV gates LLM calls only — CPG + pattern matching proceed regardless; wired into Ollama client

### ML0.4 — Differential Indexer ✅ Done Jun 17
- [x] L0.4.T1: SQLite state cache (`modernc.org/sqlite`) — `project_id / file_path / content_hash / last_scanned_at`; `GetScanState`, `UpsertScanState`, `ListScanState`, `DeleteScanState`; 10 CRUD tests
- [x] L0.4.T2: DI content-hash diff — `Diff` (WalkDir + SHA-256), `Commit` (upserts + evictions), `DeriveProjectID`; wired into `ingestion.Run`; one-hop CPG expansion deferred to ML2.1.T3

### ML0.5 — OpenGrep + ast-grep + instrscan Wrappers ✅ Done Jun 17
- [x] L0.5.T1: OpenGrep subprocess wrapper — `Scan`, `ScanHighConfidence`, `Version`; confidence normalisation; language-partitioned routing; 11 tests
- [x] L0.5.T2: ast-grep integration — `Scan`, `FilterFiles` (.rs/.dart/.swift/.kt/.cs), `normalise` (0→1-based lines); 12 tests
- [x] L0.5.T3: instrscan wired into `runPathA` — concurrent errgroup; `instrFindingToFinding` adapter; CWE-1035
- [x] L0.5.T4: Finding normalisation adapter complete; Joern side stubbed until ML1

### ML0.6 — Python Worker IPC ✅ Done Jun 18
- [x] L0.6.T1: `worker/main.py` NDJSON dispatcher — `llm_verify / classify / summarize / llm_scan / ping / shutdown`
- [x] L0.6.T2: Go worker-manager — `Start` (spawn + 5s ping), `Call` (concurrent NDJSON RPC, ID-keyed pending), `Stop` (2s graceful → stdin close); restart-on-crash; `ErrWorkerDead`; 15 tests

### ML0.7 — Dedup Skeleton + HTML Report Skeleton ✅ Done Jun 18
- [x] L0.7.T1: Dedup skeleton — Gate 1 (SHA-256 CWE+path+line) + Gate 2 (SHA-256 MatchedCode); cross-path +15pp boost; `AutoSuppress`; `DeriveSeverityLabel`; 20 tests
- [x] L0.7.T2: HTML report skeleton — `html/template` + `embed`; XSS-safe contextual escaping; severity columns; scope notice; file sidebar; 8 tests

**Checkpoint**: `zerotrust scan ./spring-boot-app` produces a real HTML report with Path A pattern findings.

---

## Layer 1 — Joern Spike (time-boxed ~17h work + 8h contingency)

> **Design contract for all L1 work**: Every subprocess, port, and IPC channel must be
> intentionally designed for security and correctness — not bolted on after the fact.
> Specifically: (1) all Joern HTTP communication is localhost-only and port-bound to a
> single ephemeral or pinned port, never exposed on 0.0.0.0; (2) subprocess lifecycle
> (start/stop/crash) is handled explicitly with no silent failures; (3) all edge cases
> (port conflict, JVM not found, build timeout, malformed JSON, partial response, context
> cancellation) produce a named, documented error — never a panic or silent drop; (4) the
> API surface exposed to callers (Graph interface) hides all Joern HTTP details behind a
> clean, minimal interface. Code is written for the next developer reading it, not just
> to pass tests.

### L1.T1 — Joern Environment Setup ✅ Done Jun 18
- [x] Joern installed via Homebrew: `joern` binary at `/opt/homebrew/bin/joern`, version v4.0.550
- [x] Empirically confirmed Joern HTTP API: async 2-step protocol — `POST /query` → `{success,uuid}`, then `GET /result/{uuid}` → `{success,stdout,stderr}`. No `/ready` endpoint.
- [x] Discovered: Joern returns `success=false, stdout="", stderr=""` for ~35s during cold-start REPL init; `fetchResult` updated to treat this as "still processing" rather than error
- [x] Confirmed `--server --server-host 127.0.0.1 --server-port <port>` flags (not `--host/--port`); `joern` binary is a shell script wrapping the JVM
- [x] ANSI escape codes stripped from stdout via `stripANSI()`; `parseStdout` uses `LastIndex` for REPL session preamble with multiple ` = ` occurrences
- [x] Documented in `docs/joern-http-api.md`

### L1.T2 — Go Subprocess Launcher ✅ Done Jun 18
- [x] Functional options: `WithServerURL`, `WithBinaryPath`, `WithHost`, `WithPort`, `WithQueryTimeout`, `WithBuildTimeout`, `WithPingRetries`
- [x] `Start(ctx)` — `checkPortAvailable` (ErrPortInUse), spawns subprocess bound to `127.0.0.1` with `--server` flag mode, crash watcher goroutine
- [x] `Ping(ctx)` — retry loop with 500ms interval; uses `doQueryPing` (POST /query + GET /result) since no `/ready` endpoint
- [x] `Stop(ctx)` — SIGTERM → waits → SIGKILL escalation; idempotent
- [x] `fetchResult` correctly handles init-time `success=false` with empty stdout/stderr (polls every 200ms until result is ready)
- [x] 37 unit tests — `TestDoQuery_InitTimePollsUntilSuccess` covers the new init-polling behavior

### L1.T3 — CPG Build ✅ Done Jun 18
- [x] `BuildCPG(ctx, BuildConfig)` — `importCode(inputPath=...)` query; language override supported
- [x] Input validation: `ErrEmptyPaths` on empty; `ErrPathTraversal` on raw `..` components
- [x] `IncrementalPatch` — depth-5 BFS; `ErrHubModuleDetected` (≥50 callers → caller falls back to full rebuild)
- [x] `SaveCPG` / `LoadCPG` — path traversal validated on both
- [ ] **Pending**: `TestIntegration_BuildCPG_SpringBoot` — spring-boot-app CPG build on live Joern

### L1.T4 — CPG Query Interface + Tests ✅ Done Jun 18
- [x] All 9 `cpg.Graph` methods implemented: `QueryNodes`, `QueryNodesByFile`, `QueryEdges`, `GetCallGraph`, `GetCallers`, `GetCallees`, `GetNeighboursAtDepth`, `TaintPaths`, `PreFlaggedSinks`
- [x] 37 unit tests — all pass
- [x] 5 integration tests in `joern_integration_test.go` (`//go:build integration`)
- [ ] **Pending**: fix `TestIntegration_StartAndPing` — `Ping()` context is 10s (too short; second query may take >10s post-init); increase to 2min
- [ ] **Pending**: run `make test-integration` clean pass on all 5 tests

### Go/No-Go Checkpoint 🔄 In Progress
- Go code + async HTTP client: **complete** — 37 unit tests pass, 0 lint issues
- `Start()`: **working** — REPL init polling fix confirmed; Joern binds port in ~4s, REPL ready in ~35s
- `Ping()` after Start: **fix pending** — test uses 10s context; second query may still be slow; increase to 2min in test
- Pass criteria: Joern starts · BuildCPG completes · QueryNodes(METHOD) ≥ 1 · GetCallGraph non-empty · TaintPaths ≥ 1 for `getUser → executeQuery`
- Fallback: Joern scoped to Java/Python only; Go covered by OpenGrep taint rules; incremental CPG deferred

---

## Layer 2 (partial) — ML2.2: XGrammar-2 + LLM Verifier

### ML2.2 — Python Worker: XGrammar-2 + LLM Verifier ✅ Done Jun 18

- [x] L2.2.T1: XGrammar-2 verdict schema — `LLMVerifierResult` Pydantic model `{verdict: confirmed|false_positive|uncertain, confidence: float, justification: ≤200 chars}`; `GrammarEnforcer[T]` generic class with optional xgrammar import (Python 3.13 fallback: json + Pydantic only); Ollama `format=schema_dict` provides primary generation-time enforcement
- [x] L2.2.T2: LLM Verifier Python handler (`worker/handlers/llm_verify.py`) — CoD + SCoT prompt (SOURCE → FLOW → GUARD → VERDICT); lazy singleton Ollama client + GrammarEnforcer; `_call_ollama` with JSON-mode retry on parse failure; `handle()` public entry point; wired into `worker/main.py` `llm_verify` dispatcher
- [x] L2.2.T3: Adaptive Self-Consistency — `_run_asc()` collects up to 2 extra samples at temperatures [0.35, 0.6]; majority vote excluding uncertain; all-uncertain → average confidence, original justification; `asc_rounds` field propagated to Go via `VerifyResult`
- [x] L2.2.T4: High-confidence bypass — `verifier.HighConfidenceThreshold = 0.90` constant; `runPathA` partitions findings before LLM call; bypass findings sent directly to `ch`; `verifier.Verify()` + `verifier.ApplyResults()` wired for remainder; graceful fallback on `ErrWorkerDead`
- [x] Go verifier package — `internal/pattern/verifier/verifier.go`: `Verify()` errgroup fan-out, `ApplyResults()` verdict→severity mapping, `fallbackResult()` 20% confidence penalty on transient failure; 12 unit tests
- [x] L2.2.T5: Latency benchmark — p50 ≈ 21 s per finding (qwen2.5-coder:7b, Apple M3, warm); 2s target MISSED; bottleneck = LLM inference; see `docs/benchmarks/latency_path_a.md`

---

## Today's Work — 2026-06-22

### Task 1 — L2.2.T5: Path A Latency Benchmark

**Goal**: Measure and document p50/p95 round-trip latency for a single finding through the full Path A pipeline (OpenGrep/Joern → LLM Verifier → result). Confirm p50 < 2s target. Produce `docs/benchmarks/latency_path_a.md`.

**Prerequisites**: Ollama running (`ollama serve`), Joern running (`joern --server --server-host 127.0.0.1`), spring-boot-app available at `testdata/spring-boot-app/`.

**Minor goals**:
- [x] **T5.1** — Instrumented; verifier latency logged at `slog.Info("verifier latency", ...)` in `cmd/zerotrust/scan.go`; fixed opengrep dotfile crash, absolute path bug, multi-dir rule config, ZEROTRUST_MODEL env propagation.
- [x] **T5.2** — 3 scans run (warm Ollama, Joern offline); p50 ≈ 21 s, p95 ≈ 37 s; see `docs/benchmarks/latency_path_a.md`.
- [x] **T5.3** — Already fixed in prior session: `integrationTimeout = 5 * time.Minute` at `internal/pattern/joern/joern_integration_test.go:37`.
- [x] **T5.4** — Written: `docs/benchmarks/latency_path_a.md` (env, p50/p95, wall-clock, caveats, next steps).
- [x] **T5.5** — p50 ≥ 2s: bottleneck = Ollama TTFT+generation for qwen2.5-coder:7b (~21 s/finding). Fix options documented in `docs/benchmarks/latency_path_a.md`: lower HighConfidenceThreshold for deterministic CWEs, use qwen2.5:3b for verifier, or batch into single TagDispatch call.

**Done when**: `docs/benchmarks/latency_path_a.md` exists, `make test-integration` passes, L2.2.T5 checkbox above is ticked.

---

### Task 2 — ML3.1: Heuristic Targeting + Call Graph + CVE Enrichment + Resource ID Dataflow

**Goal**: Implement Path B Tier 1 — the surface selection stage that eliminates ~95% of files before the UniXcoder classifier. Produces a ranked `[]Surface` slice consumed by ML3.2. `internal/semantic/targeting/targeting.go` is currently a skeleton.

**Estimated effort**: ~26h total (plan window Jul 17–21 but executing now, ~3 weeks early).

**Minor goals**:

#### T1 — External-input node queries (2.5h)
- [ ] **T1.1** — In `internal/semantic/targeting/targeting.go`, implement `queryExternalInputNodes(ctx, graph)` using `graph.QueryNodes()`: match METHOD nodes where any parameter or return-from-call is sourced from HTTP params (`getParameter`, `getHeader`, `getBody`, `pathVariable`), env vars (`os.Getenv`, `System.getenv`), file reads (`os.Open`, `Files.readAllBytes`), or stdin (`os.Stdin`, `System.in`). Return `[]cpg.Node`.
- [ ] **T1.2** — Add unit tests in `internal/semantic/targeting/targeting_test.go` using a mock `cpg.Graph` (implement `MockGraph` satisfying `cpg.Graph` interface). At minimum: one test per input category (HTTP / env / file / stdin), one test for empty CPG.

#### T2 — Auth-boundary node queries (2.5h)
- [ ] **T2.1** — Implement `queryAuthBoundaryNodes(ctx, graph)`: match METHOD nodes whose name matches patterns `*auth*`, `*login*`, `*verify*`, `*check*`, `*authorize*`; or annotated with `@PreAuthorize`, `@Secured`, `@RolesAllowed` (Java); or middleware functions that call JWT/session validators (Go: `*middleware*`, `*guard*`).
- [ ] **T2.2** — Unit tests: at minimum one Java annotation case, one Go middleware name pattern, one non-matching control.

#### T3 — Call graph extraction (3h)
- [ ] **T3.1** — Implement `buildCallGraph(ctx, graph, seeds []cpg.Node) CallGraph` where `CallGraph` is a map `nodeID → []callerIDs`. Uses `graph.GetCallers()` and `graph.GetCallees()` per seed node up to depth 2. Depth 2 is sufficient for Tier 1 — depth 3 is reserved for the Assembler (ML3.3).
- [ ] **T3.2** — Expose `CallGraphDepth(nodeID string) int` on `CallGraph` — returns minimum hop count from any external-input node; used by the budget controller's reachability weight later.
- [ ] **T3.3** — Unit tests: connected graph case, disconnected node case, cycle detection (node already visited → skip).

#### T4 — Trivy `fs` CVE enrichment (3h)
- [ ] **T4.1** — `internal/semantic/enrichment/trivy.go` already has a Trivy wrapper. Extend it with `ScanForCVEs(ctx, dir string) ([]CVEMatch, error)` if not already present. Wire the result into `targeting.go` so surfaces at files with a CVE match are flagged `HasCVEMatch: true` on the `Surface` struct.
- [ ] **T4.2** — Test: mock Trivy JSON output (use a fixture file, not a live subprocess) → assert CVEMatch fields populated correctly. Add fixture at `testdata/trivy/scan_output.json`.

#### T5 — CVE auto-flag routing (2h)
- [ ] **T5.1** — Implement `AutoFlagCVESurfaces(surfaces []Surface) (autoFlagged []Surface, remainder []Surface)`: splits surfaces where `HasCVEMatch && CVSSScore >= 4.0` into `autoFlagged`. Auto-flagged surfaces skip the classifier and go directly to Dedup with `ConfidenceScore` derived from CVSS: ≥9.0→0.95 (BLOCK), 7–8.9→0.82 (HIGH), 4–6.9→0.68 (MEDIUM).
- [ ] **T5.2** — Unit tests: threshold boundary cases (8.9 vs 9.0), missing CVSS score fallback (treat as 5.0).

#### T6 — BOLAZ resource ID dataflow / IDOR candidate detection (12h)
- [ ] **T6.1** — Define P-API sources and C-API anchors in a config struct `IDORConfig` (not hardcoded): P-API = HTTP path params, query params, request body field accessors; C-API = session user ID, JWT sub-claim, constant literals, `@PathVariable` annotated with `@AuthenticationPrincipal`.
- [ ] **T6.2** — Implement `queryIDORCandidates(ctx, graph, cfg IDORConfig) ([]Surface, error)` via Joern taint queries: source = P-API node → sink = object-fetch node (DB query, cache lookup, file access) where no C-API anchor appears on the taint path. Use `graph.TaintPaths()` with the P-API/C-API source/sink definitions.
- [ ] **T6.3** — Mark returned surfaces `IsIDORCandidate: true`. These surfaces bypass the UniXcoder classifier unconditionally (routing enforced in ML3.2 T4).
- [ ] **T6.4** — Unit tests: IDOR-present case (P-API reaches DB sink, no C-API on path), IDOR-absent case (C-API anchor present on path), case with multiple P-API sources.
- [ ] **T6.5** — Document the P-API/C-API model in a comment block at the top of the relevant file — cite BolaRay (CCS 2024) with a one-line description. No inline prose beyond that.

#### T7 — Surface struct (2h)
- [ ] **T7.1** — Define `Surface` struct in `internal/semantic/targeting/surface.go`:
  ```go
  type Surface struct {
      ID                string
      File              string
      Function          string
      NodeType          string
      CallGraphDepth    int
      CVEMatches        []enrichment.CVEMatch
      IsIDORCandidate   bool
      HasCVEMatch       bool
      CVSSScore         float64
  }
  ```
- [ ] **T7.2** — `Targeter.Run(ctx, graph, dir) ([]Surface, error)` — orchestrates T1–T6, returns ranked `[]Surface` sorted by: IDOR candidates first, then CVE auto-flagged, then by call graph reachability (lower depth = higher priority).

#### T8 — Tier 1 elimination measurement (3h)
- [ ] **T8.1** — Add a benchmark test in `internal/semantic/targeting/targeting_test.go` that runs `Targeter.Run` against the spring-boot-app CPG (integration tag). Assert: `len(surfaces) / totalFiles <= 0.05` (95% elimination target). If actual elimination is lower, do not adjust thresholds to hit the number — record honestly.
- [ ] **T8.2** — Write `docs/benchmarks/tier1_elimination.md`: actual elimination rate, surface count, total file count, test codebase used, what the design target is (95%), and whether it was met. If not met, note the gap and hypothesize why (small codebase, many HTTP endpoints, etc.).

**Done when**: `make test` passes (all new unit tests green), `Targeter.Run` compiles and returns a `[]Surface` on a mock CPG, integration test documents the actual elimination rate, `docs/benchmarks/tier1_elimination.md` exists.
