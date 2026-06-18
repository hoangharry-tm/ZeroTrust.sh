# ZeroTrust.sh — Implementation Plan

**Hard deadline: August 6, 2026**

> **Replanned Jun 16 (layer-by-layer execution).** Original Approach 1→2→3 phasing dropped in favour of layer-by-layer delivery ordered by architectural dependency. No tasks cut; scope preserved. Three structural changes from original plan: (1) Joern promoted to a time-boxed spike before any dependent work starts; (2) DI CPG expansion moved to after Joern spike; (3) named buffer rows added to every layer. TPM-flagged estimates revised upward where research evidence supported it.
>
> **Model selection:** application is model-agnostic by design. Ollama HTTP wrapper and XGrammar-2 output schema are the only integration points — swapping models is a config change. Development default: Qwen2.5-3B-Instruct-Q4\_K\_M (Summarizer) · Qwen2.5-7B-Instruct (Verifier + LLM Scan). Documented as development defaults, not production recommendations.

---

## G1 — OpenGrep PoC (Complete)

**Window**: Jun 9–20 · ~50h · **100% complete**

All 42 rules deployed (PY-001→010, JV-001→009, GN-001→007, AG-001→016), Go instrscan with 8 unit tests, Spring Boot test codebase with 12 findings across 10 rule variants, 0 FP on clean controls. Presentation narrative complete Jun 17 — 3 days ahead of schedule.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **M1.1** | **Research & Setup** | Jun 9 | 5.0 | Done | |
| **M1.2** | **Python Custom Rules (PY-001→PY-010)** | Jun 10–11 | 12.0 | Done | 10 rules · 0 FP |
| **M1.3** | **Java Custom Rules (JV-001→JV-009)** | Jun 12–13 | 13.0 | Done | 9 rules · 0 FP |
| **M1.4** | **AI Agent Instruction File Scanning** | Jun 16–17 | 8.0 | Done | GN-001→007 · Go instrscan · Unicode + keyword + MCP schema |
| **M1.5** | **Test Codebase + Detection Demo** | Jun 18 | 7.0 | Done | Spring Boot · 12 findings · dual-engine demo script |
| **M1.6** | **Presentation Narrative** | Jun 19–20 | 5.0 | Done | Figma deck + design decisions doc |
| **M1.7** | **[BONUS] Multi-Language ast-grep Rules (AG-005→AG-016)** | Jun 16 | 0.0 | Done | 12 rules · 5 languages · ahead of L2 schedule |

---

## Layer 0 — Foundation + Fast Path

**Window**: Jun 23 – Jul 3 · ~70h available · **~57h work + 13h buffer**
**ML0.1–ML0.7 all delivered Jun 17–18 — 6–14 days early. Layer 0 complete.**

Build the Go binary skeleton, ingestion layer (MIV + DI content-hash), pattern detection wrappers, Python worker IPC, and a minimal Dedup + HTML report skeleton. Joern-free. Delivers a working end-to-end pipeline with Path A pattern findings in an HTML report before any Joern risk is taken.

**Checkpoint**: `zerotrust scan ./spring-boot-app` produces a real HTML report with Path A pattern findings.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **ML0.1** | **Go CLI Core + Finding Channel** | Jun 17 | 10.0 | **Done** | Delivered Jun 17 — 6 days early |
| L0.1.T1 | Go module init + CLI flag parsing (`cobra`) | Jun 17 | 2.0 | Done | `--output minimal\|tree\|tui`; `--report <path>`; `--output` renamed from HTML path |
| L0.1.T2 | Goroutine dispatcher: spawn Path A + Path B goroutines; Finding channel interface | Jun 17 | 5.0 | Done | `errgroup`-based; buffered channel 256; fan-in drain; `output.Event` per finding |
| L0.1.T3 | Finding struct: `{id, path, line_range, cwe, severity_label, confidence, source_path, reason, poe_context}` | Jun 17 | 3.0 | Done | Locked in `internal/finding/finding.go`; `poe_context` forward-compatible |
| **ML0.1B** | **CLI Output Layer** | Jun 17 | 10.0 | **Done** | Delivered Jun 17 — 7 days early |
| L0.1B.T1 | Output mode detection: `isatty` check on `os.Stdout`; auto-select minimal (no TTY) or tree (TTY); `--output minimal\|tree\|tui` flag override | Jun 17 | 1.5 | Done | Selection in `cmd/zerotrust/output_select.go` — avoids `output`→`output/tui`→`output` import cycle |
| L0.1B.T2 | Minimal renderer: plain stdout, ANSI stripped in pipe, coloured in TTY; exit codes 0/1/2 | Jun 17 | 3.0 | Done | `internal/output/minimal.go`; `fatih/color` for severity labels |
| L0.1B.T3 | TUI skeleton: Bubble Tea 2-panel layout; 5 tabs (log · findings · summary · suppressed · patches); scanning + done states | Jun 17 | 4.0 | Done | `internal/output/tui/{model,update,view}.go`; matches `docs/cli-output-design.md` spec; tree renderer added as Option C (`internal/output/tree.go`) |
| L0.1B.T4 | Wire live pipeline events into TUI panels; keyboard navigation; Glamour for markdown | Jun 17 | 1.5 | Done | Typed `output.Event` channel; `EventStageStart/End/Finding/Log/Error/Done`; all renderers consume same channel |
| **ML0.2** | **Ollama HTTP Client** | Jun 17 | 4.0 | **Done** | Delivered Jun 17 — 7 days early |
| L0.2.T1 | Ollama HTTP client wrapper (Go → `localhost:11434`); model-agnostic — model name is config, not code | Jun 17 | 4.0 | Done | `Chat` + `BackboneCheck` implemented; `ErrModelBlocked` + `SetMIVBlocked()` gate; 14 tests |
| **ML0.3** | **Model Integrity Verifier** | Jun 17 | 17.5 | **Done** | Delivered Jun 17 — 8 days early |
| L0.3.T1 | MIV: SHA256 hash of GGUF model file | Jun 17 | 2.5 | Done | Streaming in 32 MB chunks; context-cancellable; `internal/ingestion/miv/hash.go` |
| L0.3.T2 | MIV: cosign/Sigstore Rekor registry verification; bundled maintainer public key | Jun 17 | 12.0 | Done | ECDSA P-256 primary gate (stdlib); Rekor best-effort transparency check (3s timeout → ECDSA fallback); embedded `data/{registry.json,registry.json.sig,cosign.pub}`; 15 tests |
| L0.3.T3 | MIV gates LLM calls only — CPG + pattern matching proceed regardless; wire gate into Ollama client wrapper | Jun 17 | 3.0 | Done | `ingestion.Run` calls `verifier.Verify`; `BlockLLM` flag → `ollama.Client.SetMIVBlocked()` in `scan.go` |
| **ML0.4** | **Differential Indexer (content-hash only)** | Jun 17 | 5.5 | **Done** | Delivered Jun 17 — 10 days early |
| L0.4.T1 | SQLite state cache (`modernc.org/sqlite`): `project_id / file_path / content_hash / last_scanned_at`; CRUD helpers (`GetScanState`, `UpsertScanState`, `ListScanState`, `DeleteScanState`) | Jun 17 | 3.5 | Done | Pure-Go; `INSERT OR REPLACE` upsert; 10 CRUD tests in `pkg/sqlite/sqlite_test.go` |
| L0.4.T2 | DI: `Diff` (WalkDir + SHA-256 content-hash diff, skipDirs/binaryExts, ChangeSet.AllStates); `Commit` (upserts + evictions); `DeriveProjectID`; wired into `ingestion.Run` + `CommitScan` in `scan.go` | Jun 17 | 2.0 | Done | 14 tests in `diffindex_test.go`; one-hop CPG expansion scheduled post-Joern spike |
| **ML0.5** | **OpenGrep + ast-grep + instrscan Wrappers** | Jun 17 | 10.0 | **Done** | Delivered Jun 17 — 11 days early |
| L0.5.T1 | OpenGrep subprocess wrapper: `Scan`, `ScanHighConfidence`, `Version`; exit-code 0/1 handling; `normalise` (confidence HIGH→0.90/MEDIUM→0.65/LOW→0.40; CWE from metadata); language-partitioned routing | Jun 17 | 3.0 | Done | 11 tests in `opengrep_test.go`; subprocess tests deferred to ML2 integration |
| L0.5.T2 | ast-grep integration: `Scan` (JSON array output), `FilterFiles` (owns .rs/.dart/.swift/.kt/.kts/.cs), `Version`, `normalise` (0→1-based line conversion; CWE from rule ID convention AG-NNN-cwe-NNN) | Jun 17 | 3.0 | Done | 12 tests in `astgrep_test.go` |
| L0.5.T3 | Wire instrscan into `runPathA` (concurrent errgroup; `instrFindingToFinding` adapter; CWE-1035; MCP schema → 0.90 / keyword → 0.65 / unicode → 0.75) | Jun 17 | 1.0 | Done | OpenGrep + ast-grep + instrscan run concurrently; non-fatal binary-missing errors |
| L0.5.T4 | Finding normalisation adapter: `severityFromScore` in `scan.go`; Joern side stubbed until ML1 delivers real schema | Jun 17 | 3.0 | Done | Joern side remains stub; `instrFindingToFinding` complete |
| **ML0.6** | **Python Worker IPC** | Jun 18 | 6.5 | **Done** | Delivered Jun 18 — 13 days early |
| L0.6.T1 | Python worker `worker/main.py`: NDJSON dispatcher — `llm_verify / classify / summarize / llm_scan / ping / shutdown` | Jun 18 | 3.5 | Done | Already fully implemented; handlers route to stubs in `handlers/`; `ping` + `shutdown` built-in |
| L0.6.T2 | Go worker-manager: `Start` (spawn + 5s ping), `Call` (concurrent NDJSON RPC, ID-keyed pending map), `Ping`, `Stop` (2s graceful → stdin close); restart-on-crash (one attempt, `restarted` flag); `ErrWorkerDead` for callers to detect fallback | Jun 18 | 3.0 | Done | 15 tests in `worker_test.go`; `echo` Python inline script avoids real model dependency |
| **ML0.7** | **Dedup Skeleton + HTML Report Skeleton** | Jun 18 | 4.0 | **Done** | Delivered Jun 18 — 14 days early |
| L0.7.T1 | Dedup skeleton: Gate 1 (SHA-256 of CWE+path+startLine) + Gate 2 (SHA-256 of MatchedCode); cross-path +15pp boost (capped at 1.0); `AutoSuppress` (test file patterns + testDirs); `DeriveSeverityLabel` (5-tier); `ProcessWithStats` returns MergeRecords + Stats | Jun 18 | 2.0 | Done | 20 tests in `dedup_test.go`; Gates 3–4 (embedding + AST edit distance) deferred to G4 |
| L0.7.T2 | HTML report skeleton: already fully implemented with `html/template` + `embed`; XSS-safe contextual escaping; severity columns; scope notice; file sidebar; 8 tests | Jun 18 | 2.0 | Done | Report package was pre-built; no additional work needed |
| **ML0.BUFFER** | **Buffer — MIV/IPC/infra overrun** | — | 13.0 | — | Named buffer. All ML0.1–ML0.7 delivered Jun 17–18; buffer fully absorbed; Layer 0 complete. |

---

## Layer 1 — Joern Spike (Time-Boxed)

**Window**: Jul 3 – Jul 7 · **strictly time-boxed 4 days / 20h**

Prove Joern works in this environment before committing any production Joern work. The spike either closes with a working CPG query interface and golden-file tests, or it doesn't — there is no partial credit. Decision is binary on Jul 7.

**Checkpoint**: Go client sends a query to Joern HTTP server, receives non-empty CPG response on the Spring Boot test codebase. Golden-file test passes. Known-vulnerable file produces at least one taint finding.

**Go/No-Go Jul 7**: If spike overruns 20h by more than 50% (>30h spent with no working CPG), trigger the fallback: Joern scope reduced to Java/Python only; Go covered by OpenGrep taint rules; incremental CPG deferred to post-demo. Do not spend more time diagnosing — take the fallback and move.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **ML1** | **Joern Spike** | Jul 3–7 | 20.0 | — | Time-boxed. No production Joern work until spike closes. |
| L1.T1 | Joern install + JVM (Java 11+) + version-pin; confirm `joern --server` starts and responds | Jul 3 | 3.0 | | Expect environment pain; budget it here, not later |
| L1.T2 | Go subprocess: spawn Joern HTTP server (`localhost:8080`); health-check + retry loop; pre-start at CLI launch alongside MIV+DI | Jul 4 | 4.0 | | |
| L1.T3 | CPG build on Spring Boot test codebase (one real Java file); validate Go frontend output quality on a known-vulnerable snippet | Jul 4–5 | 4.0 | | Validate the Go frontend too — documented in CLAUDE.md as "less battle-tested"; if Go CPG is unreliable, document and scope Joern to Java/Python only |
| L1.T4 | Shared CPG query interface: `QueryNodes(type)`, `QueryEdges(src, dst)`, `GetCallGraph()` + fixture CPG + golden-file integration tests | Jul 5–7 | 9.0 | | **Revised from 3.5h → 9h.** Highest-risk interface: 3 consumers depend on it (taint layer, targeting, assembler). Golden-file tests are non-negotiable — they are the evidence that the spike passed |
| **ML1.BUFFER** | **Spike overrun contingency** | — | 8.0 | — | Part of the 4-day window. If spike finishes early, pull forward L2.T1 (taint taxonomy research) |

---

## Layer 2 — Path A Complete

**Window**: Jul 7 – Jul 17 · ~70h available · **~56h work + 14h buffer**

Complete Path A: Joern production integration (taint taxonomy, module segmentation, incremental CPG), DI one-hop CPG expansion, LLM Verifier. Joern spike must have passed before this layer starts.

**Checkpoint**: Path A produces LLM-verified taint findings on the synthetic codebase. Latency p50 < 2s per finding. DI confirms only changed files reprocessed on repeat scan.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **ML2.1** | **Joern Production Integration** | Jul 7–12 | 26.0 | — | |
| L2.1.T1 | Taint query layer: source / sanitizer / sink taxonomy per language — Java, Python, JS/TS, Go | Jul 7–9 | 10.0 | | **Revised from 5h → 10h** (4 languages × ~2.5h each). Do not rush — taint taxonomy accuracy is the foundation of all Path A inter-procedural findings |
| L2.1.T2 | CPG generation: invoke on DI dirty-file set; enforce ≤5K LOC gate; log build time; target build < 60s | Jul 9–10 | 5.0 | | Original target was 30s; revised to 60s based on documented empirical build times |
| L2.1.T3 | DI: one-hop CPG caller/callee expansion for changed files (Joern call graph); fallback to full scan if no prior CPG | Jul 10 | 3.0 | | Now schedulable — Joern query interface exists |
| L2.1.T4 | Module segmentation: detect working modules + depth-2 module neighbors; Tree-sitter pre-flag dangerous sinks in all modules regardless of depth | Jul 10–11 | 4.0 | | Scan modes: Default (depth-2) · `--thorough` (depth-3 + sink-flagged) · `--full` (entire codebase) |
| L2.1.T5 | Incremental CPG: serialize to `~/.zerotrust/{project_id}.cpg`; repeat scans use `importCpg` + depth-5 BFS patch; hub-module fallback (≥50 callers → full rebuild); invalidate on Joern version change | Jul 11–12 | 15.0 | | **Revised from 4h → 15h.** The paper describes the algorithm, not a callable API. importCpg + BFS patch construction requires substantial Go-side graph traversal. Hub-module detection requires call-graph degree query. This is the most implementation-intensive Joern task. |
| L2.1.T6 | Integration test: CPG non-empty; taint paths detected on synthetic codebase; repeat scan only processes changed files | Jul 12 | 2.5 | | |
| **ML2.2** | **Python Worker: XGrammar-2 + LLM Verifier** | Jul 12–15 | 13.0 | — | |
| L2.2.T1 | XGrammar-2 verdict schema: `{verdict: confirmed\|false_positive\|uncertain, confidence: float, justification: ≤200 chars}` — malformed output impossible by construction | Jul 12–13 | 3.5 | | |
| L2.2.T2 | LLM Verifier handler in Python worker: SCoT + CoD taint-flow prompt; wire `llm_verify` dispatcher type | Jul 13–14 | 4.0 | | |
| L2.2.T3 | Adaptive Self-Consistency escalation on uncertain: resample ×2, majority-vote verdict, average confidence; ~1.3× overhead bound | Jul 14 | 2.0 | | |
| L2.2.T4 | High-confidence rule bypass: rules tagged `confidence: high` route directly to Dedup, skip verifier | Jul 14 | 2.0 | | |
| L2.2.T5 | Latency benchmark: target < 2s per finding round-trip; log p50/p95 to `docs/benchmarks/latency_path_a.md` | Jul 15 | 1.5 | | |
| **ML2.3** | **Finding Normalisation + Integration Test** | Jul 15–16 | 3.5 | — | |
| L2.3.T1 | Complete finding normalisation adapter: Joern schema → unified Finding struct (OpenGrep side done in L0) | Jul 15 | 2.0 | | |
| L2.3.T2 | Path A end-to-end integration test: OpenGrep + Joern findings → LLM Verifier → Dedup skeleton → HTML skeleton | Jul 16 | 1.5 | | |
| **ML2.BUFFER** | **Buffer — Joern taint taxonomy + incremental CPG overrun** | — | 14.0 | — | Named buffer. Incremental CPG (L2.1.T5) is the most likely overflow point |

---

## Layer 3 — Path B: Three-Tier Semantic Funnel

**Window**: Jul 17 – Jul 28 · ~77h available · **~69h work + 8h buffer**

Build the full Path B pipeline: Heuristic Targeting → Classifier → Assembler → Summarizer → Budget Controller → LLM Scan. Joern CPG query interface must be stable before this layer starts.

**Checkpoint**: Path B detects an IDOR vulnerability spanning caller + surface + callee in the synthetic multi-function test case. ≤25% of surfaces reach the LLM tier on the Spring Boot test codebase.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **ML3.1** | **Heuristic Targeting + Call Graph + CVE Enrichment + Resource ID Dataflow** | Jul 17–21 | 26.0 | — | |
| L3.1.T1 | CPG queries: external-input nodes (HTTP params, env vars, file reads, stdin) | Jul 17 | 2.5 | | Language-agnostic via shared CPG schema from L1.T4 |
| L3.1.T2 | CPG queries: auth-boundary nodes (`*auth*`, `*login*`, `@PreAuthorize`, `@Secured`, etc.) | Jul 17–18 | 2.5 | | |
| L3.1.T3 | Call graph extraction from Joern CPG (no separate build step — reuses shared interface) | Jul 18 | 3.0 | | |
| L3.1.T4 | Trivy `fs` subprocess (Apache 2.0): manifest scan → OSV + NVD + GitHub Advisory | Jul 18–19 | 3.0 | | Online default; `--skip-db-update --offline-scan` flags for air-gapped environments |
| L3.1.T5 | CVE exact-match auto-flag: skip classifier + LLM; score from CVSS directly; ≥9.0→BLOCK · 7–8.9→HIGH · 4–6.9→MEDIUM · <4→LOW | Jul 19 | 2.0 | | |
| L3.1.T6 | BOLAZ zero-trust resource ID tracking: P-API/C-API taint model via Joern queries; flag IDOR candidates where P-API (HTTP params/headers as untrusted source) reaches object-fetch sink without C-API (constant/verified anchor) authorization; IDOR candidates always escalate to LLM regardless of classifier verdict | Jul 19–21 | 12.0 | | **Revised from 4h → 12h.** BOLAZ is a research paper, not a library. Implementation is via Joern taint queries modeling the P-API/C-API distinction. Budget reflects that this requires authoring and validating multiple taint source/sink definitions plus routing logic. |
| L3.1.T7 | Surface struct: `{id, file, function, node_type, call_graph_depth, cve_matches, is_idor_candidate}` | Jul 21 | 2.0 | | |
| L3.1.T8 | Tier 1 elimination measurement: assert ~95% file elimination on test codebase; document in `docs/benchmarks/tier1_elimination.md` | Jul 21 | 3.0 | | Design target pending CVEFixes benchmark; document honestly |
| **ML3.2** | **UniXcoder Classifier Gate** | Jul 21–24 | 19.0 | — | A-18 blocking dependency; operate in high-recall mode throughout |
| L3.2.T1 | UniXcoder-Base-Nine model load in Python worker; extend dispatcher with `classify` request type | Jul 21–22 | 3.0 | | |
| L3.2.T2 | Go IPC: classify request/response; reuse NDJSON protocol from ML0.6 | Jul 22 | 2.0 | | |
| L3.2.T3 | 3-band threshold calibration: safe / uncertain / vulnerable; target uncertain band = 15–25% of surfaces | Jul 22–23 | 3.0 | | Conservative threshold until CVEFixes benchmark — document this caveat in all outputs |
| L3.2.T4 | Routing: high-confidence-vulnerable → Dedup direct; high-confidence-safe → dismiss; IDOR candidates always escalate regardless of classifier verdict | Jul 23 | 2.0 | | |
| L3.2.T5 | Unsupported-language bypass: Rust / Kotlin / Swift / C# → route directly to LLM Semantic Scan tier | Jul 23 | 1.5 | | |
| L3.2.T6 | A-18 gap measurement: run UniXcoder on 50 labeled AI-generated code snippets; record F1 / precision / recall; document gap vs BigVul C/C++ claim in `docs/benchmarks/a18_gap.md` | Jul 24 | 4.0 | | Scoped: 50-sample labeled evaluation on available AI-generated code. No fine-tuning. No CVEFixes benchmark. Do not claim 94.73% F1 without caveat. |
| L3.2.T7 | Funnel stats: assert ≤25% of surfaces reach LLM tier; log to benchmark doc | Jul 24 | 3.5 | | |
| **ML3.3** | **Call Chain Context Assembler + Semantic Function Summarizer** | Jul 24–26 | 18.0 | — | Single-pass union schema replaces prior 3-pass design (~3× cheaper) |
| L3.3.T1 | Call chain traversal depth 3 from Joern CPG; callee-first (bottom-up) order | Jul 24–25 | 4.0 | | Callee-first required for SCSS correctness and token-budget integrity |
| L3.3.T2 | Multi-function context assembly: `CallChainContext` struct | Jul 25 | 3.0 | | |
| L3.3.T3 | Single-pass union schema per function: `{taint_flow: {...}, auth_guard: {...}, logic_flaw: {...}}` — one XGrammar-2 JSON object covers all 3 vulnerability classes via TagDispatch without recompilation; all `check_location` fields: `framework_annotation\|explicit_code\|middleware\|unknown` | Jul 25 | 4.0 | | |
| L3.3.T4 | Batch inference: up to 5 surfaces per prompt; amortizes model-load + context-window overhead | Jul 26 | 3.0 | | |
| L3.3.T5 | CPG-derived fields injected as ground-truth; LLM fills semantic interpretation only; LLM never sees raw code in main reasoning scan | Jul 26 | 2.0 | | |
| L3.3.T6 | Token footprint benchmark: assert ≥60% reduction vs raw call chain; log to `docs/benchmarks/token_footprint.md` | Jul 26 | 1.5 | | |
| L3.3.T7 | Multi-function vulnerability detection test: IDOR spanning caller + surface + callee | Jul 26 | 1.5 | | This is the Layer 3 checkpoint test |
| **ML3.4** | **Token Budget Controller + LLM Semantic Scan + SCSS** | Jul 26–28 | 17.5 | — | T7–T9 (SCSS) are explicit drop-first candidates if layer is behind |
| L3.4.T1 | Surface priority ranking: `w1×cvss + w2×(1-classifier_confidence) + w3×reachability_from_entry`; `reachability` = inverse hop count from external-input node | Jul 26 | 2.5 | | |
| L3.4.T2 | Hard per-scan token cap (default 50K); exhausted surfaces → `SUPPRESSED reason:budget_exhausted`; never silent drop | Jul 27 | 2.0 | | |
| L3.4.T3 | ReAct step 1: transfer constraint (tainted data flow from caller to surface?); backbone capability check at scan start; single-pass CoD+SCoT fallback for sub-threshold models | Jul 27 | 2.5 | | Max 3 steps |
| L3.4.T4 | ReAct step 2: callee taint (does surface propagate taint to callees?) | Jul 27 | 2.5 | | |
| L3.4.T5 | ReAct step 3: trigger constraint at sink; XGrammar-2 output schema; Path A HIGH/BLOCK surfaces pre-filtered; path independence preserved | Jul 28 | 2.5 | | |
| L3.4.T6 | `uncertain` verdicts → `SUPPRESSED reason:uncertain`; never silent drop | Jul 28 | 1.5 | | |
| L3.4.T7 | **[DROP FIRST]** SCSS: in-memory CPG-neighbor graph; inference nodes keyed by Joern function ID | Jul 28 | 3.0 | | Drop saves 9.5h recovered into buffer if L3 is behind |
| L3.4.T8 | **[DROP FIRST]** SCSS: read/write hooks on each ReAct LLM call | Jul 28 | 2.0 | | |
| L3.4.T9 | **[DROP FIRST]** Cross-surface vulnerability detection test | Jul 28 | 4.5 | | |
| **ML3.BUFFER** | **Buffer — BOLAZ + classifier calibration + LLM Scan overrun** | — | 8.0 | — | Named buffer. If SCSS (T7–T9) is dropped, the 9.5h recovered supplements this buffer |

---

## Layer 4 — Dedup Complete + Report + Final Integration

**Window**: Jul 28 – Aug 6 · ~63h available · **~50h work + 13h buffer**

Complete the Dedup pipeline, SSVC scoring, HTML report, patch suggestions, and run end-to-end integration. Dedup skeleton from L0 is already in place — this layer completes it.

**Checkpoint**: `zerotrust scan ./test-codebase` runs the full pipeline (Path A + Path B), deduplicates, scores, generates a self-contained HTML report with patch suggestions. Repo clean, README present.

| ID | Name | Dates | E (h) | Status | Notes |
| :---: | --- | :---: | :---: | :---: | --- |
| **ML4.1** | **Dedup Complete + SSVC-Inspired Confidence Scoring** | Jul 28 – Aug 1 | 22.0 | — | Gates 1+2 already in place from L0 skeleton |
| L4.1.T1 | Dedup gate 3: embedding similarity via MiniLM-L6-v2 (Python worker); reaches only ~10–20% of findings after gates 1+2 | Jul 28–29 | 4.0 | | |
| L4.1.T2 | Dedup gate 4: AST edit distance (last resort, <5% of findings); `tree-sitter` parse + edit distance | Jul 29–30 | 2.0 | | |
| L4.1.T3 | SSVC dimension sourcing: Exploitation (CISA KEV monthly bundle + EPSS via FIRST API + NVD API v2.0) · Automatable (CWE lookup table) · Technical Impact (CVSS from Trivy + CWE map) | Jul 30–31 | 10.0 | | **Revised from 5h → 10h.** Three live API integrations with offline fallback. CISA KEV: use monthly JSON bundle download (not real-time API) to avoid rate limits. EPSS: FIRST REST API. NVD API v2: API key required, rate-limited. |
| L4.1.T4 | Score → label: BLOCK ≥0.92 · HIGH 0.75–0.91 · MEDIUM 0.60–0.74 · LOW 0.30–0.59 · SUPPRESSED <0.30; CVE auto-flagged findings scored from CVSS directly; Path A high-confidence bypass gets MEDIUM floor + SSVC upgrade | Jul 31 | 3.0 | | |
| L4.1.T5 | Cross-path +15pp additive boost; capped at 1.0; BLOCK not boosted | Aug 1 | 2.0 | | |
| L4.1.T6 | Auto-suppression: test file path patterns + framework-safe suppression per language; `reason` field always set; `.zerotrust-suppressions.yaml` sidecar for user overrides; sidecar read by DI on next scan | Aug 1 | 3.0 | | |
| L4.1.T7 | `poe_context` field population: `{source_node, sink_node, taint_path_summary, required_input_conditions}` from Path B LLM Scan output | Aug 1 | 3.0 | | Forward-compatible with future Approach 3 PoE layer |
| **ML4.2** | **HTML Report + Patch Suggestions** | Aug 1–5 | 20.0 | — | Skeleton from L0; this adds full data, filtering, and patch tabs |
| L4.2.T1 | Complete HTML report: `html/template` + `embed`; SSVC-inspired severity labels; filtering by severity / file / detection path; search; expandable findings (Evidence / SSVC / Patch tabs) | Aug 1–2 | 5.0 | | All free-text fields via contextual escaping; no `template.HTML()`; scope notice states which modules were scanned |
| L4.2.T2 | XSS mitigations: `<meta http-equiv="Content-Security-Policy" ...>` tag + synthetic XSS test case for `justification` + `file_path` + `matched_code` fields (attacker-controlled strings) | Aug 2 | 2.5 | | |
| L4.2.T3 | Patch generation: zero-shot unified diff via Ollama; CVE few-shot context injection for BLOCK+HIGH CVE matches (Trivy data already available) | Aug 3 | 5.0 | | Combined from original T3 + T6 |
| L4.2.T4 | Patch validation: `go-gitdiff` in-memory apply; `patch_status:malformed` if hunk headers fail; off-by-one hunk headers are the primary LLM diff failure mode | Aug 3 | 3.0 | | |
| L4.2.T5 | Patch scope labels: `single_hunk` (~22%) / `multi_hunk` (~12%) / `multi_file` (0–7.7%) with PatchEval-grounded reliability note | Aug 4 | 2.5 | | |
| L4.2.T6 | Suppression sidecar: write `.zerotrust-suppressions.yaml` from user override action in report UI | Aug 4 | 2.0 | | |
| **ML4.3** | **End-to-End Integration + Final Delivery** | Aug 5–6 | 8.0 | — | |
| L4.3.T1 | Full pipeline run: `zerotrust scan ./test-codebase`; Path A + Path B findings; Dedup; SSVC scoring; HTML report generated | Aug 5 | 3.0 | | |
| L4.3.T2 | Precision/recall vs G1 baseline; document improvement in `docs/benchmarks/final_eval.md` | Aug 5 | 2.0 | | |
| L4.3.T3 | Performance: total wall-clock on 5K LOC; memory peak; log to `docs/benchmarks/performance.md` | Aug 6 | 1.5 | | |
| L4.3.T4 | Final delivery: repo clean, `CLAUDE.md` accurate, README present, `make build` + `make test` + `make demo` all pass | Aug 6 | 1.5 | | |
| **ML4.BUFFER** | **Buffer — SSVC API integration + report polish overrun** | — | 13.0 | — | Named buffer. If SSVC APIs (L4.1.T3) overrun, reduce to CVSS-only scoring and document |

---

## Summary

| Layer | Window | Budget | Primary Risk |
| --- | --- | --- | --- |
| G1 — OpenGrep PoC | Jun 9–20 | ~50h | **100% done** — completed Jun 17, 3 days early |
| L0 — Foundation + Fast Path | Jun 23 – Jul 3 | 57h + 13h buffer | **ML0.1 + ML0.1B done Jun 17** (early); ML0.2–ML0.7 remaining; MIV cosign / Sigstore Rekor integration is next primary risk |
| L1 — Joern Spike (time-boxed) | Jul 3 – Jul 7 | 20h + 8h contingency | Joern JVM + Go CPG frontend quality |
| L2 — Path A Complete | Jul 7 – Jul 17 | 56h + 14h buffer | Incremental CPG implementation (15h task) |
| L3 — Path B | Jul 17 – Jul 28 | 69h + 8h buffer | BOLAZ taint model (12h task); A-18 calibration |
| L4 — Dedup + Report + Integration | Jul 28 – Aug 6 | 50h + 13h buffer | SSVC 3-API sourcing; compressed 9-day window |
| **Total** | **Jun 23 – Aug 6** | **252h work + 56h buffer = 308h** | |

**Drop sequence** — pre-agreed in priority order, execute only when a layer is behind:

| # | Drop | Hours freed | What is lost |
| --- | --- | --- | --- |
| 1 | L3 SCSS (T7–T9) | 9.5h | Cross-surface vulnerability detection |
| 2 | L2 Incremental CPG (L2.1.T5) → fall back to full rebuild | 15h | Repeat-scan CPG speed (correctness preserved) |
| 3 | L0 DI one-hop CPG expansion (L0.4.T2 → L2.1.T3) | 5h | Missed findings on utility-function changes |
| 4 | L4 Embedding dedup gate (L4.1.T1) | 4h | 3-gate dedup instead of 4 |
| 5 | L4 SSVC live APIs → CVSS-only scoring | 8h | Exploitation + Automatable SSVC dimensions |
| 6 | L4 Patch suggestions (L4.2.T3–T6) | 12.5h | Report shows findings only, no diffs |

**Do not drop**: Finding channel interface · HTML report · Path A pattern matching · end-to-end integration · Go/No-Go Joern spike decision.

**A-18 note**: UniXcoder operates in high-recall mode throughout. Do not publish accuracy figures until the 50-sample A-18 evaluation (L3.2.T6) is complete. Document the gap honestly in all demos and the final report.

**Joern Go CPG note**: Go frontend is community-contributed and less battle-tested than Java/C++. Spike (L1.T3) explicitly validates Go CPG quality. If Go CPG is unreliable, Joern scope is narrowed to Java/Python only and Go coverage falls back to OpenGrep taint rules — document this in CLAUDE.md and the demo narrative.

---

## [BONUS] R&D — Model Selection Notebook

**When**: Jun 16–22 (before L0 engineering starts) or post-Aug 6 demo.
**Not in the 308h budget.** Does not affect the drop sequence. Optional.

> Rationale: the application is model-agnostic by design. Model selection is a config change, not a code change. This notebook is an impressive post-demo artifact, not a prerequisite for delivery.

| ID | Name | E (h) | Notes |
| :---: | --- | :---: | --- |
| RnD.T1 | Literature synthesis: compare Phi-3-mini, Qwen2.5-3B, Qwen2.5-7B, Llama-3.2-3B, Mistral-7B on instruction following, structured JSON output, CoT reasoning depth, code understanding, CPU inference speed (Q4 tokens/sec) | 3.0 | Sources: model papers + HumanEval/BigCodeBench + any available security-task benchmarks |
| RnD.T2 | Empirical benchmark (via Ollama): 20 synthetic test cases across 3 tasks — vulnerability classification, CoD/SCoT reasoning on a taint path description, XGrammar schema adherence under grammar constraint | 5.0 | Run on 3 models: Qwen2.5-3B + Qwen2.5-7B + one wildcard. Measure: accuracy on known-answer cases, JSON validity rate, p50/p95 latency on development machine |
| RnD.T3 | Notebook write-up: recommendation table + rationale; update MIV registry defaults if changed | 2.0 | Deliverable: `notebooks/model_selection.ipynb` |
| **RnD total** | | **10h** | Hard time-box. If at 10h without a clear winner, ship the literature synthesis (T1) and use architecture defaults. |

---

## [BONUS] R&D — A-18 Resolution: QLoRA Fine-Tuning on CVEFixes

**When**: Post-Aug 6 demo. Not in the 308h budget. Does not affect the drop sequence.
**Prerequisite**: L3.2.T6 gap measurement complete — use its per-language F1 results to prioritise which language splits to fine-tune first.

> Rationale: L3.2.T6 produces an honest measurement of the A-18 gap on 50 labeled samples. This plan closes the gap properly via QLoRA fine-tuning on CVEFixes, enabling the confidence threshold to be raised from the conservative 0.80 to ~0.85–0.90 and reducing LLM escalation rate in the cost funnel.

| ID | Name | E (h) | Notes |
| :---: | --- | :---: | --- |
| **A18.T1** | **CVEFixes data pipeline** | 6.0 | Download CVEFixes SQLite DB; query `file_change` + `fixes` + `commits`; filter to function-level samples overlapping the diff hunk via Tree-sitter (already in project); split by language; output per-language JSONL: `{code, label, language, cve_id}` |
| **A18.T2** | **Class balancing + train/val/test splits** | 2.0 | CVEFixes is ~10:1 safe:vulnerable at function level; oversample vulnerable or use weighted loss; stratified split per language (80/10/10); document sample counts per language in `docs/benchmarks/a18_gap.md` |
| **A18.T3** | **QLoRA fine-tune per language** | 6.0 | `microsoft/unixcoder-base-nine` + `BitsAndBytesConfig` (4-bit NF4); LoRA rank=16, alpha=32, target `query`+`value` attention layers; 5 epochs, lr=2e-4, batch=16, fp16; ~1.5M trainable params (1.2% of 125M); run per-language split; ~30–90 min per language on A40 (RunPod); estimated cloud cost $15–25 total |
| **A18.T4** | **Per-language evaluation** | 3.0 | F1 / precision / recall on held-out test split per language; compare against BigVul C/C++ baseline (94.73%); append results to `docs/benchmarks/a18_gap.md`; identify any language below acceptable threshold (target F1 ≥ 0.80) |
| **A18.T5** | **Save LoRA adapter + wire into Python worker** | 2.0 | `model.save_pretrained()` outputs adapter weights (~6MB per language, not 500MB); load in `worker/handlers/classify.py` via `PeftModel.from_pretrained()`; base model loads once, adapter hot-swapped per language tag on classify request |
| **A18.T6** | **Threshold recalibration** | 1.0 | Raise `uncertain` band threshold from conservative 0.80 → empirically validated value per language (target 0.85–0.90); re-run funnel stats benchmark; update `docs/benchmarks/tier1_elimination.md` with new LLM escalation rate |
| **A18.T7** | **Update accuracy claims** | 0.5 | Replace A-18 caveat language in CLAUDE.md, README, and report output with validated per-language F1 figures; remove "high-recall mode" warnings where threshold has been validated |
| **A18 total** | | **20.5h** | Hard time-box. If Go or Ruby splits are too thin (<1.5k samples) for reliable fine-tuning, document and keep high-recall mode for those languages only. |

---

## Design-Conformance Assessment (Jun 16)

### G1 Rule Coverage vs Architecture Requirements

| Design Requirement | As-Built | Verdict |
| --- | --- | --- |
| 10 Python OpenGrep rules (PY-001→PY-010) | 10 rules, 62 TP / 0 FP | ✅ Exceeds |
| 9 Java OpenGrep rules (JV-001→JV-009) | 9 rules, 54 TP / 0 FP | ✅ Exceeds |
| 7 generic instruction-file rules (GN-001→GN-007) | 7 rules, 20 TP / 0 FP | ✅ Meets |
| 4 ast-grep rules for language gaps (Dart, Swift, Rust, Go) | 4 existing + 12 bonus = 16 total | ✅ Significantly exceeds (5 extra languages) |
| Each rule has `bad/` + `ok/` test pair | 65/69 rules have 0 FP on ok/ set | ✅ Meets (4 LLM rules: 1 known FP each, MEDIUM confidence) |
| AI-specific threats: prompt injection, hallucinated packages, cheat patterns | Covered across PY, JV, GN, AG rulesets | ✅ Design complete |
| Multi-language coverage ≥7 languages | 12 languages (Python, Java, Rust, Go, Swift, Dart, JS/TS, Kotlin, C#, Ruby, PHP + generic) | ✅ Exceeds design |

### Layer Pre-Completion (Ahead of Schedule)

AG-005→AG-016 (12 ast-grep rules, 5 languages) covers L0.5.T2 ("ast-grep integration for language gaps"). Go instrscan covers L0.5.T3 ("wire instrscan into CLI pipeline"). Layer 0 has a ~16h head start from G1 bonus work.
