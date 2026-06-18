# ZeroTrust.sh — TODO

> G1 100% complete. **Layer 0 100% complete (Jun 17–18, 5–14 days early).** **Layer 1 Go code complete (Jun 18, 2 weeks early)** — 30 unit tests pass, integration tests ready, pending Joern binary install. **ML2.2 complete (Jun 18, 3+ weeks early)** — XGrammar-2 + LLM Verifier + Go verifier wired into Path A; 22 tests pass.
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

### L1.T1 — Joern Environment Setup (~2h) 🔄 In Progress
- [ ] Install Joern + Java 17 — user running `./joern-install.sh --interactive` (takes time)
- [ ] Verify `joern-server --port 8080 --host 127.0.0.1` starts, serves HTTP, and shuts down cleanly
- [x] Document Joern HTTP API request/response schema in `docs/joern-http-api.md` — contract written; gaps table + Go/No-Go criteria included
- [x] Confirmed `--host 127.0.0.1` flag enforces loopback binding; validated in `validateServerURL` + subprocess spawn args

### L1.T2 — Go Subprocess Launcher ✅ Done Jun 18
- [x] Functional options: `WithServerURL`, `WithBinaryPath`, `WithHost`, `WithPort`, `WithQueryTimeout`, `WithBuildTimeout`, `WithPingRetries`
- [x] `Start(ctx)` — `checkPortAvailable` (ErrPortInUse), spawns subprocess bound to `127.0.0.1`, crash watcher goroutine sets `atomic.Bool` + closes `done` channel
- [x] `Ping(ctx)` — retry loop with 500ms interval; `ErrJoernUnreachable` on timeout; `ErrJoernCrashed` if flag set
- [x] `Stop(ctx)` — SIGTERM → waits → SIGKILL escalation; idempotent; `ErrNotManaged` if not self-managed
- [x] Wired into `scan.go` pre-start (non-blocking; Joern crash does not block Path A)
- [x] Tests: ping success/crashed/unreachable/cancelled; port conflict; stop-without-start; context cancellation

### L1.T3 — CPG Build ✅ Done Jun 18
- [x] `BuildCPG(ctx, BuildConfig)` — `importCode(inputPath=...)` query; `ErrBuildTimeout` after 120s; language override supported
- [x] Input validation: `ErrEmptyPaths` on empty; `ErrPathTraversal` on raw `..` components (checked before `filepath.Clean`)
- [x] `IncrementalPatch` — depth-5 BFS (Li et al. ICSE 2024 + Effendi et al. SOAP/PLDI 2025); `ErrHubModuleDetected` (≥50 callers → caller falls back to full rebuild)
- [x] `SaveCPG` / `LoadCPG` — path traversal validated on both
- [x] `ErrMalformedResponse` on invalid JSON; raw body included in error message
- [ ] **Pending**: run on `testdata/spring-boot-app/` and confirm METHOD node count > 0 (blocked on L1.T1 binary install)

### L1.T4 — CPG Query Interface + Tests ✅ Done Jun 18
- [x] All 9 `cpg.Graph` methods implemented in `graph.go`: `QueryNodes`, `QueryNodesByFile`, `QueryEdges`, `GetCallGraph`, `GetCallers`, `GetCallees`, `GetNeighboursAtDepth`, `TaintPaths`, `PreFlaggedSinks`
- [x] `TaintPaths` — `run.ossdataflow` then `cpg.finding`; capped at 1000 paths; `ErrEmptyPaths` guard
- [x] `GetNeighboursAtDepth` — BFS via multiple HTTP calls; `ErrDepthExceeded` if depth > 6
- [x] Shared `http.Client` with 30s per-query timeout; 4 MB response body cap; keep-alive reuse
- [x] 30 unit tests (`joern_test.go`) — `httptest.Server` mocks; all 9 methods + transport errors + traversal + BFS topology
- [x] Integration test file ready (`joern_integration_test.go`, `//go:build integration`) — 5 tests incl. golden SQL injection taint path
- [x] 12 sentinel errors in `errors.go`; compile-time `cpg.Graph` interface check in `graph.go`
- [ ] **Pending**: `make test-integration` (blocked on L1.T1 binary install)

### Go/No-Go Checkpoint
- Go code: **complete** — 30 unit tests pass, 0 lint issues
- Integration run: **pending** Joern binary install (`make test-integration`)
- Pass criteria (from `docs/joern-http-api.md`): Joern /ready returns 200 · BuildCPG completes · QueryNodes(METHOD) ≥ 1 · GetCallGraph non-empty · TaintPaths ≥ 1 for `getUser → executeQuery`
- Fallback: Joern scoped to Java/Python only; Go covered by OpenGrep taint rules; incremental CPG deferred

---

## Layer 2 (partial) — ML2.2: XGrammar-2 + LLM Verifier

### ML2.2 — Python Worker: XGrammar-2 + LLM Verifier ✅ Done Jun 18

- [x] L2.2.T1: XGrammar-2 verdict schema — `LLMVerifierResult` Pydantic model `{verdict: confirmed|false_positive|uncertain, confidence: float, justification: ≤200 chars}`; `GrammarEnforcer[T]` generic class with optional xgrammar import (Python 3.13 fallback: json + Pydantic only); Ollama `format=schema_dict` provides primary generation-time enforcement
- [x] L2.2.T2: LLM Verifier Python handler (`worker/handlers/llm_verify.py`) — CoD + SCoT prompt (SOURCE → FLOW → GUARD → VERDICT); lazy singleton Ollama client + GrammarEnforcer; `_call_ollama` with JSON-mode retry on parse failure; `handle()` public entry point; wired into `worker/main.py` `llm_verify` dispatcher
- [x] L2.2.T3: Adaptive Self-Consistency — `_run_asc()` collects up to 2 extra samples at temperatures [0.35, 0.6]; majority vote excluding uncertain; all-uncertain → average confidence, original justification; `asc_rounds` field propagated to Go via `VerifyResult`
- [x] L2.2.T4: High-confidence bypass — `verifier.HighConfidenceThreshold = 0.90` constant; `runPathA` partitions findings before LLM call; bypass findings sent directly to `ch`; `verifier.Verify()` + `verifier.ApplyResults()` wired for remainder; graceful fallback on `ErrWorkerDead`
- [x] Go verifier package — `internal/pattern/verifier/verifier.go`: `Verify()` errgroup fan-out, `ApplyResults()` verdict→severity mapping, `fallbackResult()` 20% confidence penalty on transient failure; 12 unit tests
- [ ] L2.2.T5: Latency benchmark — target < 2s per finding round-trip; log p50/p95 to `docs/benchmarks/latency_path_a.md` *(requires live Ollama + Joern; deferred to ML2.3 integration test)*
