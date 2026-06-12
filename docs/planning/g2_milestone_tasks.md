# G2 — Path A: CPG + Taint + LLM Verifier
**Goal window**: 2026-06-30 → 2026-07-18 · 19 days · ~101 committed hours
**Prerequisite**: G1 complete — Go CLI binary exists, Finding channel interface locked, Differential Indexer operational, synthetic test codebase in place.
**Checkpoint**: Path A runs end-to-end (Semgrep + ast-grep + Joern CPG + LLM Verifier). Precision/recall baseline measured. Joern CPG wired as shared infrastructure for G3. Python worker IPC operational and reusable by all G3 ML components.

> **Complexity spike**: Joern is Java-based; CPG build time scales with codebase size. Hard cap: ≤5K LOC on test codebase during this goal. CPG build must complete in < 30 seconds per scan.

---

## Column Guide

| Column | Description |
|---|---|
| **ID** | `2.Mx` = milestone · `2.Mx.Ty` = task · `2.BUF` = buffer row |
| **Name** | Plain English — no jargon |
| **Type** | `MILESTONE` · `TASK` · `BUFFER` |
| **Start Date** | `YYYY-MM-DD` |
| **End Date** | `YYYY-MM-DD` (inclusive) |
| **O** | Optimistic hours (PERT) — milestone rows only |
| **ML** | Most Likely hours (PERT) — milestone rows only |
| **P** | Pessimistic hours (PERT) — milestone rows only |
| **E (hrs)** | PERT estimate = (O + 4×ML + P) / 6 — all rows |
| **Actual (hrs)** | Fill in as work progresses |
| **Status** | `Not Started` · `In Progress` · `Complete` · `Blocked` · `At Risk` |
| **Owner** | Default: `Hoang` |
| **Notes** | Blockers, decisions, dependencies |

**PERT formula**: E = (O + 4 × ML + P) / 6

---

## Task Register

| ID | Name | Type | Start Date | End Date | O | ML | P | E (hrs) | Actual (hrs) | Status | Owner | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **2.M1** | **Joern CPG Build Pipeline** | MILESTONE | 2026-06-30 | 2026-07-07 | 16 | 25 | 40 | 26.0 | | Not Started | Hoang | Highest-risk milestone in plan; Joern env setup is the most common blocker in tools that integrate it; plan for 1–2 debug days |
| 2.M1.T1 | Joern installation + JVM setup + version-pin | TASK | 2026-06-30 | 2026-06-30 | — | — | — | 2.0 | | Not Started | Hoang | Pin exact Joern version in config (e.g. v4.x); Java 11+; confirm `joern --version` exits 0 |
| 2.M1.T2 | Joern server startup verification | TASK | 2026-06-30 | 2026-07-01 | — | — | — | 2.5 | | Not Started | Hoang | Start Joern in server mode; send a no-op query; confirm response; measure cold-start time |
| 2.M1.T3 | Go subprocess wrapper: spawn Joern process via os/exec | TASK | 2026-07-01 | 2026-07-02 | — | — | — | 4.0 | | Not Started | Hoang | `exec.Command`; capture stdout/stderr; handle premature exit; log all Joern stderr to debug file |
| 2.M1.T4 | Go subprocess wrapper: health check + retry logic | TASK | 2026-07-02 | 2026-07-02 | — | — | — | 2.5 | | Not Started | Hoang | Poll Joern REST endpoint or REPL; max 3 retries; fail scan with clear error if Joern unresponsive |
| 2.M1.T5 | CPG generation: invoke Joern on source directory, capture output | TASK | 2026-07-02 | 2026-07-04 | — | — | — | 4.5 | | Not Started | Hoang | Feed only dirty files from Differential Indexer; enforce ≤5K LOC gate before invoking; measure build time |
| 2.M1.T6 | CPG serialization format decision + implementation | TASK | 2026-07-04 | 2026-07-05 | — | — | — | 4.0 | | Not Started | Hoang | Decision: in-memory graph vs file-based export (e.g. .bin or .dot); chosen format must be readable by both Path A taint queries and Path B heuristic targeting without re-parse |
| 2.M1.T7 | Shared CPG access interface (Path A + Path B) | TASK | 2026-07-05 | 2026-07-06 | — | — | — | 3.5 | | Not Started | Hoang | Go interface with at least: QueryNodes(type), QueryEdges(src, dst), GetCallGraph(); G3 components read from this interface |
| 2.M1.T8 | Codebase size gate (≤5K LOC) + query timeout handling | TASK | 2026-07-06 | 2026-07-06 | — | — | — | 2.0 | | Not Started | Hoang | Count LOC before CPG build; reject with user-facing error if over limit; kill Joern process on timeout (configurable, default 60s) |
| 2.M1.T9 | Integration test: CPG built successfully on synthetic test codebase | TASK | 2026-07-07 | 2026-07-07 | — | — | — | 1.3 | | Not Started | Hoang | Assert CPG non-empty; assert node types present (Method, Call, Identifier); assert build time < 30s |
| **2.M2** | **Taint Analysis Query Layer** | MILESTONE | 2026-07-07 | 2026-07-11 | 14 | 22 | 34 | 22.7 | | Not Started | Hoang | Taint paths produced here are the evidence fed into M2.3 LLM Verifier prompt |
| 2.M2.T1 | Source / sanitizer / sink taxonomy definition per language | TASK | 2026-07-07 | 2026-07-07 | — | — | — | 3.0 | | Not Started | Hoang | Languages: Java, Python, JS/TS, Go; document each category in a YAML taxonomy file; used by query layer and LLM prompt |
| 2.M2.T2 | Joern traversal queries: external-input source nodes | TASK | 2026-07-07 | 2026-07-08 | — | — | — | 3.5 | | Not Started | Hoang | Scala DSL; sources: HTTP params, env vars, file reads, stdin, deserialized objects; test on synthetic inputs |
| 2.M2.T3 | Joern traversal queries: sanitizer nodes | TASK | 2026-07-08 | 2026-07-09 | — | — | — | 3.5 | | Not Started | Hoang | Sanitizers: input validation, HTML encoding, parameterized queries, allowlist checks; false negative risk if sanitizer list is incomplete |
| 2.M2.T4 | Joern traversal queries: dangerous sink nodes | TASK | 2026-07-09 | 2026-07-10 | — | — | — | 3.5 | | Not Started | Hoang | Sinks: eval, exec/system, SQL string concat, deserialize, file write to user-controlled path, SSRF URL construction |
| 2.M2.T5 | Taint flow → Finding struct mapping + CWE assignment | TASK | 2026-07-10 | 2026-07-10 | — | — | — | 3.5 | | Not Started | Hoang | Each taint flow serialized: source node, sanitizer gaps, sink node, traversal path; CWE assigned by sink type (e.g. SQL sink → CWE-89) |
| 2.M2.T6 | Multi-language taint query test suite | TASK | 2026-07-10 | 2026-07-11 | — | — | — | 3.0 | | Not Started | Hoang | One taint case per language (Java, Python, JS/TS, Go); each must be detected; add to CI harness from M1.1.T9 |
| 2.M2.T7 | False positive baseline measurement on synthetic clean code | TASK | 2026-07-11 | 2026-07-11 | — | — | — | 2.7 | | Not Started | Hoang | Run taint queries on clean-code control set; count FPs; record as baseline before LLM Verifier is applied in M2.3 |
| **2.M3** | **Python Worker Bootstrap + LLM Verifier (False Positive Filter)** | MILESTONE | 2026-07-11 | 2026-07-16 | 18 | 29 | 42 | 29.3 | | Not Started | Hoang | Two parts: (1) IPC boundary — built once, reused by all G3 ML components; (2) LLM Verifier using XGrammar. XGrammar is Python-only — Go cannot call it directly. |
| 2.M3.T1 | Python venv setup + requirements.txt | TASK | 2026-07-11 | 2026-07-11 | — | — | — | 1.5 | | Not Started | Hoang | Packages: xgrammar, ollama (Python client), httpx; pin versions; venv at worker/venv/; add venv activation to Go startup |
| 2.M3.T2 | Python worker main.py: message dispatcher | TASK | 2026-07-11 | 2026-07-12 | — | — | — | 3.0 | | Not Started | Hoang | Reads NDJSON from stdin in a loop; dispatches by `type` field (llm_verify, classify, summarize, llm_scan, ping, shutdown); writes response to stdout |
| 2.M3.T3 | Go worker-manager: spawn Python worker via os/exec + pipe setup | TASK | 2026-07-12 | 2026-07-13 | — | — | — | 3.5 | | Not Started | Hoang | `exec.Command("python3", "-u", "worker/main.py")`; `-u` flag disables Python output buffering; pipe stdin + stdout; route stderr to log |
| 2.M3.T4 | Go worker-manager: health-check ping + restart-on-crash logic | TASK | 2026-07-13 | 2026-07-13 | — | — | — | 2.5 | | Not Started | Hoang | Send `{"id":"ping","type":"ping"}`; await `{"id":"ping","status":"ok"}`; detect closed stdout pipe; attempt 1 restart; fallback to direct Ollama HTTP on second failure (R-05) |
| 2.M3.T5 | NDJSON protocol: request/response schema + Go client library | TASK | 2026-07-13 | 2026-07-14 | — | — | — | 3.0 | | Not Started | Hoang | Request: `{id, type, payload}`; Response: `{id, status, result}` or `{id, status, error}`; Go client: Send(req) → Response; thread-safe for future multi-worker extension |
| 2.M3.T6 | Python worker: Ollama HTTP client integration | TASK | 2026-07-14 | 2026-07-14 | — | — | — | 2.5 | | Not Started | Hoang | Call Ollama REST API (`/api/generate`); pass model name from config; handle timeout; verify model loaded before first call |
| 2.M3.T7 | Python worker: XGrammar JSON schema enforcement on LLM output | TASK | 2026-07-14 | 2026-07-15 | — | — | — | 3.0 | | Not Started | Hoang | Define verdict JSON schema: `{verified: bool, confidence: float, rationale: str}`; XGrammar enforces at generation time — malformed output impossible; no retry logic needed |
| 2.M3.T8 | Taint-flow prompt template | TASK | 2026-07-15 | 2026-07-15 | — | — | — | 3.5 | | Not Started | Hoang | Template inputs: taint flow path, sink type, reachability condition, sanitizer gaps; output: verdict JSON per M2.3.T7 schema; test with 5+ real taint flows |
| 2.M3.T9 | Verdict routing back to Go Finding channel | TASK | 2026-07-15 | 2026-07-16 | — | — | — | 2.0 | | Not Started | Hoang | verified=true → write Finding to channel; verified=false → discard; confidence score written to Finding.Confidence field |
| 2.M3.T10 | Latency benchmark: per-finding round-trip time | TASK | 2026-07-16 | 2026-07-16 | — | — | — | 2.0 | | Not Started | Hoang | Target: < 2s per finding (Go send → Python process → Ollama → XGrammar → Go receive); log p50/p95; if > 2s, investigate Ollama model load vs inference split |
| 2.M3.T11 | Accuracy test: TP/FP rate on synthetic taint findings | TASK | 2026-07-16 | 2026-07-16 | — | — | — | 2.8 | | Not Started | Hoang | Run LLM Verifier on taint findings from M2.2; compare to M2.2.T7 FP baseline; target ≥ 88% FP reduction; record result as A-18 pre-check |
| **2.M4** | **Path A Integration Test Suite** | MILESTONE | 2026-07-16 | 2026-07-18 | 6 | 10 | 16 | 10.3 | | Not Started | Hoang | Natural pause point before G3; Joern CPG confirmed as shared infra; mentor review can be scheduled here |
| 2.M4.T1 | Synthetic test case set: 10+ vulnerable functions (one per CWE class) | TASK | 2026-07-16 | 2026-07-17 | — | — | — | 3.0 | | Not Started | Hoang | CWE classes to cover: CWE-89 SQL injection, CWE-78 OS command injection, CWE-22 path traversal, CWE-502 deserialization, CWE-611 XXE, CWE-918 SSRF, CWE-79 XSS, CWE-327 weak crypto, CWE-798 hardcoded creds, CWE-94 code injection |
| 2.M4.T2 | End-to-end pipeline run (ingestion → Joern → taint → LLM Verifier → Finding output) | TASK | 2026-07-17 | 2026-07-17 | — | — | — | 2.0 | | Not Started | Hoang | Single `zerotrust scan ./test-codebase` command; all 10+ CWE cases must produce Findings; Python worker must start and stop cleanly |
| 2.M4.T3 | Precision/recall baseline measurement | TASK | 2026-07-17 | 2026-07-18 | — | — | — | 2.0 | | Not Started | Hoang | True positives, false positives, false negatives on test case set; record in docs/benchmarks/g2_baseline.md; this is the baseline G3 Path B will improve on |
| 2.M4.T4 | Integration break fixes | TASK | 2026-07-18 | 2026-07-18 | — | — | — | 2.0 | | Not Started | Hoang | Resolve any failures found in T2/T3; if a fix takes > 4h, escalate as At Risk and consume buffer |
| 2.M4.T5 | Performance profiling: full scan time on 5K LOC synthetic codebase | TASK | 2026-07-18 | 2026-07-18 | — | — | — | 1.3 | | Not Started | Hoang | Measure: CPG build time, taint query time, LLM Verifier time, total wall clock; target total < 5 min on 5K LOC |
| **2.BUF** | **G2 Buffer** | BUFFER | 2026-06-30 | 2026-07-18 | — | — | — | 13.0 | | | Hoang | Primary risk absorbed: R-01 Joern env setup surprises (OOM, non-termination, Scala DSL learning curve); secondary: mentor review cycle; cut M2.4 stretch items before touching buffer |

---

## G2 Totals

| | O (hrs) | ML (hrs) | P (hrs) | E (hrs) |
|---|---|---|---|---|
| 2.M1 — Joern CPG Build Pipeline | 16 | 25 | 40 | 26.0 |
| 2.M2 — Taint Analysis Query Layer | 14 | 22 | 34 | 22.7 |
| 2.M3 — Python Worker Bootstrap + LLM Verifier | 18 | 29 | 42 | 29.3 |
| 2.M4 — Path A Integration Test Suite | 6 | 10 | 16 | 10.3 |
| **Subtotal (milestones)** | **54** | **86** | **132** | **88.3** |
| 2.BUF — Buffer (explicit row) | — | — | — | 13.0 |
| **G2 Committed Total** | — | — | — | **101.3** |

> **Arithmetic note**: M2.3 uses ML=29h (not 28h) to produce E=29.3h correctly. Plan draft showed ML=28h — that was a rounding error; corrected here.

---

## Task Count

| Milestone | Tasks |
|---|---|
| 2.M1 | 9 |
| 2.M2 | 7 |
| 2.M3 | 11 |
| 2.M4 | 5 |
| **Total** | **32 tasks + 4 milestones + 1 buffer = 37 rows** |

---

## Inter-Goal Dependencies

| G2 Component | Depends on (G1) | Blocks (G3) |
|---|---|---|
| Joern CPG (2.M1) | Differential Indexer (1.M3) | Heuristic Targeting (3.M1), Call Graph (3.M1) |
| Taint query layer (2.M2) | Shared CPG interface (2.M1.T7) | — |
| Python worker IPC (2.M3.T2–T5) | Finding channel interface (1.M4) | UniXcoder gate (3.M2), Semantic Summarizer (3.M3), LLM ReAct (3.M4) |
| LLM Verifier (2.M3.T6–T9) | Python worker IPC, Ollama model loaded | — |
| Precision/recall baseline (2.M4.T3) | Full pipeline run (2.M4.T2) | A-18 calibration in 3.M2 |

---

## Status Color Key (for manual Excel formatting)

| Status | Fill | Font |
|---|---|---|
| Complete | `#D4EDDA` | `#1E7B34` |
| In Progress | `#FFF3CD` | `#B45309` |
| Blocked | `#F8D7DA` | `#842029` |
| At Risk | `#FFE5B4` | `#8B4513` |
| Not Started | `#F5F5F5` | `#666666` |
| Header rows | `#1F3864` | `#FFFFFF` |
| Milestone rows | `#2E5FA3` | `#FFFFFF` |
