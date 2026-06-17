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

## Layer 1 — Joern Spike (Jul 3–7, time-boxed 20h)

- [ ] L1.T1: Joern install + JVM (Java 11+) + version-pin; confirm `joern --server` starts and responds
- [ ] L1.T2: Go subprocess — spawn Joern HTTP server (`localhost:8080`); health-check + retry loop; pre-start at launch alongside MIV+DI
- [ ] L1.T3: CPG build on Spring Boot test codebase; validate Go CPG frontend quality on known-vulnerable snippet
- [ ] L1.T4: Shared CPG query interface — `QueryNodes(type)`, `QueryEdges(src, dst)`, `GetCallGraph()` + fixture CPG + golden-file integration tests

**Go/No-Go Jul 7**: Working CPG query + golden-file test pass → proceed to L2. Otherwise trigger fallback (Joern Java/Python only; Go via OpenGrep taint rules).
