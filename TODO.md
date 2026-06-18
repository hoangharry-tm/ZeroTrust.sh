# ZeroTrust.sh — TODO

> G1 100% complete. **ML0.1 + ML0.1B done (Jun 17)**. Next: ML0.2 → ML0.7, window Jun 23 – Jul 3.
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

### ML0.2 — Ollama HTTP Client (Jun 24)
- [ ] L0.2.T1: Ollama HTTP client wrapper (`localhost:11434`); model-agnostic (model name is config, not code); shared by LLM Verifier, LLM Scan, patch gen

### ML0.3 — Model Integrity Verifier (Jun 25–27)
- [ ] L0.3.T1: SHA256 hash of GGUF model file
- [ ] L0.3.T2: Sigstore Rekor registry verification; bundled maintainer public key; fallback: local `sha256sums.json` + `crypto/ecdsa` if Rekor call fails after 3s; tiered: WARN (unrecognised ID) · BLOCK (known ID + hash mismatch)
- [ ] L0.3.T3: MIV gates LLM calls only — CPG + pattern matching proceed regardless; wire gate into Ollama client wrapper

### ML0.4 — Differential Indexer (Jun 27–28)
- [ ] L0.4.T1: SQLite state cache (`modernc.org/sqlite`) — `project_id / file_path / content_hash / last_scanned_at / module_path / cpg_included`; methods: `GetScanState`, `UpsertScanState`, `ListScanState`, `DeleteScanState`, `IsSuppressed`, `AddSuppression`, `ListSuppressions`
- [ ] L0.4.T2: DI content-hash diff — emit dirty-file set to pipeline; full scan on first invocation (one-hop CPG expansion added post-Joern spike in ML2.1.T3)

### ML0.5 — OpenGrep + ast-grep + instrscan Wrappers (Jun 28 – Jul 1)
- [ ] L0.5.T1: OpenGrep subprocess wrapper + config file generation from G1 rules; language-partitioned routing
- [ ] L0.5.T2: ast-grep integration for language gaps (Dart, Swift, Rust, Kotlin, C#, Ruby, PHP); wire AG-005→AG-016 (already exist from G1 bonus)
- [ ] L0.5.T3: Wire G1 instrscan into CLI pipeline (Unicode scan + keyword match + MCP schema) — already implemented; plumbing only
- [ ] L0.5.T4: Finding normalisation adapter — OpenGrep schema → unified `Finding` struct (Joern side stubbed until ML1)

### ML0.6 — Python Worker IPC (Jul 1–2)
- [ ] L0.6.T1: `worker/main.py` NDJSON dispatcher — `llm_verify / classify / summarize / llm_scan / ping / shutdown`; only `ping` + `shutdown` implemented here
- [ ] L0.6.T2: Go worker-manager — spawn via `os/exec`; health-check ping; restart-on-crash; fallback to direct Ollama HTTP on second failure

### ML0.7 — Dedup Skeleton + HTML Report Skeleton (Jul 2–3)
- [ ] L0.7.T1: Dedup skeleton — gate 1 (CWE + file + line hash) + gate 2 (MD5 code fingerprint); pluggable interface for gates 3–4
- [ ] L0.7.T2: HTML report skeleton — `html/template` + `embed`; severity label columns; stub data; renders without real findings

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

### L1.T1 — Joern Environment Setup (~2h)
- [ ] Install Joern + Java 17 via Homebrew/direct download; pin version in `Makefile` (`JOERN_VERSION`)
- [ ] Verify `joern --server --port 8080` starts, serves HTTP, and shuts down cleanly
- [ ] Document confirmed Joern HTTP API request/response schema in `docs/joern-http-api.md` (method, payload, response, error codes) — this is the contract for L1.T2–T4
- [ ] Confirm the HTTP server only binds to `127.0.0.1` (not `0.0.0.0`); document the flag if explicit binding is required

### L1.T2 — Go Subprocess Launcher (~4h)
- [ ] Add `Start(ctx context.Context, port int) error` to `joern.Client` — spawns `joern --server --port <port>` as a managed subprocess; binds **only** to `127.0.0.1`
- [ ] Port conflict detection before spawning: if `127.0.0.1:<port>` is already in use, return `ErrPortInUse` (never silently re-use an unknown process)
- [ ] Implement `Ping(ctx) error` with configurable retry (default: 10 attempts, 500ms backoff, total cap 5s); returns `ErrJoernUnreachable` on timeout — not a generic error
- [ ] `Stop(ctx) error` — sends SIGTERM, waits up to 5s, escalates to SIGKILL, waits for exit; always cleans up temp files; never leaks the subprocess
- [ ] Crash detection: background goroutine watches `cmd.Wait()`; on unexpected exit sets `ErrJoernCrashed` and closes the client; callers checking `Ping` after crash get a clear error, not a hang
- [ ] Wire `Start` into `scan.go` pre-start goroutine (non-blocking, alongside MIV+DI); MIV-gate respected (Joern crash does not block Path A pattern matching)
- [ ] Test: start → ping → stop roundtrip; port conflict; ping timeout; crash detection; context cancellation mid-start

### L1.T3 — CPG Build on Spring Boot Codebase (~3h)
- [ ] Implement `BuildCPG(ctx, BuildConfig) error` — POST to Joern HTTP API; poll or stream build status; return `ErrBuildTimeout` after configurable deadline (default 120s)
- [ ] Input validation: reject empty `Paths`; reject paths that escape the project root (`../`); reject files >5K LOC per module segmentation rule
- [ ] Run CPG build on `testdata/spring-boot-app/`; assert METHOD node count >0; assert known-vulnerable `UserController.java` is present in the CPG
- [ ] Validate Go CPG frontend quality on the known-vulnerable snippet; document any gaps or degraded coverage in `docs/joern-http-api.md` spike note
- [ ] All HTTP responses validated against expected schema before use; malformed JSON returns `ErrMalformedResponse` with the raw body in the error message for debuggability

### L1.T4 — CPG Query Interface + Golden-file Tests (~8h)
- [ ] Implement all 9 `joernGraph` methods: `QueryNodes`, `QueryNodesByFile`, `QueryEdges`, `GetCallGraph`, `GetCallers`, `GetCallees`, `GetNeighboursAtDepth`, `TaintPaths`, `PreFlaggedSinks`
- [ ] Each method: validates inputs, maps Joern HTTP JSON → `cpg.*` structs, returns typed errors (never `fmt.Errorf("something went wrong")`)
- [ ] `TaintPaths`: enforce source/sink non-empty precondition; cap result set at 1000 paths to prevent memory exhaustion on large CPGs; document the cap
- [ ] `GetNeighboursAtDepth`: enforce `depth ≤ 6` (SOAP/PLDI 2025 bound); return `ErrDepthExceeded` if violated — callers must not silently get a truncated result
- [ ] HTTP transport: shared `http.Client` with a read timeout (default 30s per query); no unbounded waits; connection reuse via keep-alive
- [ ] Golden-file integration test (`joern_integration_test.go`, build tag `//go:build integration`): build CPG on Spring Boot codebase; assert taint path `HTTP param → SQL sink` detected in `UserController.java`; assert `GetCallGraph()` non-empty; assert `GetCallers`/`GetCallees` round-trip
- [ ] Unit tests using a fixture CPG (recorded HTTP responses via `httptest.Server`): all 9 methods covered; malformed response handling; timeout handling; context cancellation
- [ ] Godoc on every exported symbol; all error variables defined as package-level `var Err* = errors.New(...)` — never inline strings

### Go/No-Go Checkpoint
Golden-file integration tests pass + taint path detected → proceed to Layer 2.
Otherwise: trigger fallback (Joern scoped to Java/Python only; Go covered by OpenGrep taint rules; incremental CPG deferred post-demo). Decision recorded in `docs/joern-http-api.md`.
