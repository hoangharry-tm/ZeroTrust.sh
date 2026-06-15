# ZeroTrust.sh — Implementation Plan
**Hard deadline: August 6, 2026**

---

## Goal 1 — Approach 1: OpenGrep PoC
**Window**: Jun 9–20 · Presentation: Jun 20

Deliverables: 10+ Python rules + 9 Java rules + AI agent instruction file scanning rules + fake Spring Boot test codebase + CLI demo + narrative. Tool: OpenGrep (LGPL-2.1, Semgrep CE fork, 100% rule-format compatible).

| ID | Name | Dates | E (h) | Status | Notes |
|---|---|---|---|---|---|
| **M1.1** | **Research & Setup** | Jun 9 | 5.0 | Done | OpenGrep CLI installed; first rule fired |
| 1.1.T1 | OpenGrep install + first toy rule end-to-end | Jun 9 | 2.0 | Done | |
| 1.1.T2 | Repo scaffold: `rules/`, `tests/`, `scripts/` | Jun 9 | 1.5 | Done | |
| 1.1.T3 | Read OpenGrep/Semgrep operator + YAML rule docs | Jun 9 | 1.5 | Done | |
| **M1.2** | **Python Custom Rules (PY-001→PY-010)** | Jun 10–11 | 12.0 | Active | |
| 1.2.T1 | PY-001–004: LLM prompt injection (OpenAI / Anthropic / LangChain / unsanitized f-string) | Jun 10 | 4.0 | | |
| 1.2.T2 | PY-005–007: AI bypass comments + hardcoded AI API keys (`sk-`, `sk-ant-`, `hf_`) | Jun 10 | 3.0 | | |
| 1.2.T3 | PY-008–010: Cheat-detection — `return True` in `*auth*`, TODO-then-skip, disabled assertions | Jun 11 | 3.0 | | **New from arch**: cheat-detection patterns |
| 1.2.T4 | `bad.py` / `ok.py` test pairs for all 10 rules; zero FP on `ok.py` | Jun 11 | 2.0 | | |
| **M1.3** | **Java Custom Rules (JV-001→JV-009)** | Jun 12–13 | 13.0 | Active | |
| 1.3.T1 | JV-001–003: Spring Boot prompt injection + SQL injection via string concat | Jun 12 | 4.0 | | Validate AST with `opengrep --dump-ast` first |
| 1.3.T2 | JV-004–006: AI bypass annotations + hardcoded creds + empty security catch | Jun 12 | 4.0 | | |
| 1.3.T3 | JV-007–009: Cheat-detection — `return null/true` in auth methods, TODO-then-skip | Jun 13 | 3.0 | | **New from arch**: cheat-detection patterns |
| 1.3.T4 | `bad.java` / `ok.java` test pairs for all 9 rules | Jun 13 | 2.0 | | |
| **M1.4** | **AI Agent Instruction File Scanning** | Jun 16–17 | 8.0 | — | **New milestone** — no competitor covers this surface |
| 1.4.T1 | Unicode obfuscation scanner: detect U+202E, U+200B, U+200D in `.md` / `.txt` files | Jun 16 | 2.5 | | Go function; MITRE ATLAS AML.CS0041 |
| 1.4.T2 | Keyword/pattern match on `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `GEMINI.md`, `copilot-instructions.md` | Jun 16 | 2.0 | | OpenGrep generic-mode rules |
| 1.4.T3 | MCP schema validation: flag external URLs, HTTP non-localhost, over-broad permissions in `.mcp.json` | Jun 17 | 2.0 | | JSON schema validation; Go function |
| 1.4.T4 | Test cases: synthetic malicious instruction file + clean control | Jun 17 | 1.5 | | |
| **M1.5** | **Test Codebase + Detection Demo** | Jun 18 | 7.0 | — | |
| 1.5.T1 | AI-generate fake Spring Boot REST API — 10–15 files, ≥8 vulnerabilities including AI-specific patterns | Jun 18 | 3.5 | | Constrain to Java 8 syntax; base on real CVE patterns |
| 1.5.T2 | Run `opengrep --config rules/ .` — assert ≥6/8 detected; document FP count | Jun 18 | 2.0 | | |
| 1.5.T3 | Write `demo/run_demo.sh` with pinned version; full dry-run in fresh terminal | Jun 18 | 1.5 | | |
| **M1.6** | **Presentation Narrative** | Jun 19–20 | 5.0 | — | |
| 1.6.T1 | Pros/cons of Approach 1 + Approach 2 next-step argument | Jun 19 | 3.0 | | |
| 1.6.T2 | Speaker notes + final dry-run | Jun 19–20 | 2.0 | | |
| — | **Tech lead presentation** | Jun 20 | — | — | Approval gate for Approach 2 |

**G1 total**: ~50h · Buffer: absorbed from 10.78h core slack in original plan

---

## Goal 2 — Go Core + Ingestion + Path A
**Window**: Jun 23 – Jul 11 · ~90h

Build the Go binary core, ingestion layer (MIV + DI), and the full Path A pipeline (OpenGrep + ast-grep + Joern CPG + LLM Verifier).

| ID | Name | Dates | E (h) | Status | Notes |
|---|---|---|---|---|---|
| **M2.1** | **Go CLI Core + Finding Channel** | Jun 23–25 | 14.0 | — | |
| 2.1.T1 | Go module init + CLI flag parsing | Jun 23 | 2.0 | | |
| 2.1.T2 | Goroutine dispatcher: spawn Path A + Path B goroutines; Finding channel interface | Jun 23–24 | 5.0 | | Channel interface locked here — G3 depends on it |
| 2.1.T3 | Finding struct: `{id, path, line_range, cwe, severity_label, confidence, source_path, reason, poe_context}` | Jun 24 | 3.0 | | `poe_context` field required by Approach 3 Red Team Agent |
| 2.1.T4 | Ollama HTTP client wrapper (Go → `localhost:11434`) | Jun 25 | 4.0 | | Shared by LLM Verifier and all G3 LLM calls |
| **M2.2** | **Model Integrity Verifier + Differential Indexer** | Jun 26 – Jul 1 | 20.0 | — | |
| 2.2.T1 | SQLite state cache (`modernc.org/sqlite`): `project_id / file_path / content_hash / last_scanned_at` | Jun 26 | 3.5 | | Pure-Go; no CGo dependency |
| 2.2.T2 | DI: content-hash diff; one-hop CPG caller/callee expansion for changed files | Jun 27–28 | 5.0 | | Fallback to full scan if no prior CPG |
| 2.2.T3 | MIV: SHA256 hash of GGUF model file | Jun 29 | 2.5 | | |
| 2.2.T4 | MIV: cosign/Sigstore Rekor registry verification; bundled maintainer public key | Jun 30 | 4.0 | | Tiered: WARN (unrecognised ID), BLOCK (known ID + hash mismatch) |
| 2.2.T5 | MIV gates LLM calls only — CPG + pattern matching proceed regardless | Jul 1 | 3.0 | | Wire gate into Ollama client wrapper |
| 2.2.T6 | Integration test: verify only changed files processed on repeat scan | Jul 1 | 2.0 | | |
| **M2.3** | **Joern CPG Engine Integration** | Jul 2–8 | 26.0 | — | Highest-risk milestone; plan for 1–2 debug days |
| 2.3.T1 | Joern install + JVM (Java 11+) + version-pin; confirm server starts | Jul 2 | 2.0 | | |
| 2.3.T2 | Go subprocess: spawn Joern HTTP server (`localhost:8080`); health-check + retry; pre-start alongside MIV+DI | Jul 3 | 4.0 | | |
| 2.3.T3 | CPG generation: invoke on DI dirty-file set; enforce ≤5K LOC gate; target build < 30s | Jul 4–5 | 5.0 | | |
| 2.3.T4 | Incremental CPG: serialize to `~/.zerotrust/{project_id}.cpg`; repeat scans use `importCpg` + node/edge patch (O(changed LOC)); invalidate on Joern version change | Jul 6 | 4.0 | | New from arch; avoids full rebuild cost on repeat scans |
| 2.3.T5 | Shared CPG access interface: `QueryNodes(type)`, `QueryEdges(src, dst)`, `GetCallGraph()` | Jul 7 | 3.5 | | G3 components read from this interface |
| 2.3.T6 | Taint query layer: source/sanitizer/sink taxonomy per language (Java, Python, JS/TS, Go) | Jul 7–8 | 5.0 | | |
| 2.3.T7 | Integration test: CPG non-empty; taint paths detected on synthetic codebase | Jul 8 | 2.5 | | |
| **M2.4** | **OpenGrep + ast-grep Integration** | Jul 8–9 | 12.0 | — | |
| 2.4.T1 | OpenGrep subprocess wrapper + config file generation from G1 rules; language-partitioned routing | Jul 8 | 3.0 | | |
| 2.4.T2 | ast-grep integration for language gaps (Dart, Swift, Rust) | Jul 9 | 3.0 | | |
| 2.4.T3 | Migrate G1 instruction file scanner (Unicode scan + keyword match + MCP schema) into Go | Jul 9 | 2.5 | | |
| 2.4.T4 | Finding normalisation adapter: OpenGrep schema + Joern schema → unified Finding struct | Jul 9 | 3.5 | | |
| **M2.5** | **Python Worker IPC + LLM Verifier** | Jul 9–11 | 18.0 | — | IPC built once; reused by all G3 ML components |
| 2.5.T1 | Python worker `main.py`: NDJSON dispatcher — `llm_verify / classify / summarize / llm_scan / ping / shutdown` | Jul 9–10 | 3.5 | | |
| 2.5.T2 | Go worker-manager: spawn via `os/exec`; health-check ping; restart-on-crash; fallback to direct Ollama HTTP on second failure | Jul 10 | 3.0 | | |
| 2.5.T3 | XGrammar-2 verdict schema: `{verdict: confirmed\|false_positive\|uncertain, confidence: float, justification: ≤200 chars}` | Jul 10–11 | 3.5 | | Malformed output impossible by construction |
| 2.5.T4 | LLM Verifier: SCoT + CoD taint-flow prompt; adaptive SC on uncertain (resample ×2, majority-vote, ~1.3× overhead) | Jul 11 | 4.0 | | |
| 2.5.T5 | High-confidence rule bypass: tagged rules skip verifier → Dedup direct | Jul 11 | 2.0 | | |
| 2.5.T6 | Latency benchmark: target < 2s per finding round-trip; log p50/p95 | Jul 11 | 2.0 | | |

**G2 total**: ~90h · Primary risk: Joern JVM env setup; cut M2.5.T6 benchmark first if behind

---

## Goal 3 — Path B: Three-Tier Semantic Funnel
**Window**: Jul 14 – Jul 28 · ~84h

| ID | Name | Dates | E (h) | Status | Notes |
|---|---|---|---|---|---|
| **M3.1** | **Heuristic Targeting + Call Graph + CVE Enrichment + Resource ID Dataflow** | Jul 14–18 | 22.0 | — | |
| 3.1.T1 | CPG queries: external-input nodes (HTTP params, env vars, file reads, stdin) | Jul 14 | 2.5 | | Language-agnostic via shared CPG schema from M2.3.T5 |
| 3.1.T2 | CPG queries: auth-boundary nodes (`*auth*`, `*login*`, `@PreAuthorize`, etc.) | Jul 14–15 | 2.5 | | |
| 3.1.T3 | Call graph extraction from Joern CPG (no separate build step) | Jul 15 | 3.0 | | |
| 3.1.T4 | Trivy `fs` subprocess (Apache 2.0): manifest scan → OSV + NVD + GitHub Advisory | Jul 16 | 3.0 | | Online default; `--skip-db-update --offline-scan` flags for air-gapped |
| 3.1.T5 | CVE exact-match auto-flag: skip classifier + LLM; score from CVSS directly | Jul 16 | 2.0 | | ≥9.0→BLOCK · 7–8.9→HIGH · 4–6.9→MEDIUM · <4→LOW |
| 3.1.T6 | BOLAZ zero-trust resource ID tracking: P-API/C-API taint model; flag IDOR candidates; all IDOR candidates always escalate to LLM regardless of classifier verdict | Jul 17–18 | 4.0 | | |
| 3.1.T7 | Surface struct: `{id, file, function, node_type, call_graph_depth, cve_matches, is_idor_candidate}` | Jul 18 | 2.0 | | |
| 3.1.T8 | Tier 1 elimination measurement: assert ~95% file elimination on test codebase; document result | Jul 18 | 3.0 | | Design target pending CVEFixes benchmark |
| **M3.2** | **UniXcoder Classifier Gate** | Jul 19–22 | 19.0 | — | A-18 blocking dependency; operate in high-recall mode |
| 3.2.T1 | UniXcoder-Base-Nine model load in Python worker (extend dispatcher with `classify` type) | Jul 19–20 | 3.0 | | |
| 3.2.T2 | Go IPC: classify request/response; reuse NDJSON protocol from M2.5 | Jul 20 | 2.0 | | |
| 3.2.T3 | 3-band threshold calibration: safe / uncertain / vulnerable; target uncertain band = 15–25% of surfaces | Jul 21 | 3.0 | | Conservative threshold until CVEFixes benchmark complete |
| 3.2.T4 | Routing: high-confidence-vulnerable → Dedup direct; high-confidence-safe → dismiss; IDOR candidates always escalate regardless | Jul 21 | 2.0 | | |
| 3.2.T5 | Unsupported-language bypass: Rust / Kotlin / Swift / C# → direct LLM tier | Jul 22 | 1.5 | | |
| 3.2.T6 | A-18 gap measurement: F1/precision/recall on AI-generated code; document in `docs/benchmarks/a18_gap.md` | Jul 22 | 4.0 | | Do not claim 94.73% BigVul F1 without caveat |
| 3.2.T7 | Funnel stats: assert ≤25% of surfaces reach LLM tier | Jul 22 | 3.5 | | |
| **M3.3** | **Call Chain Context Assembler + Semantic Function Summarizer** | Jul 22–25 | 20.0 | — | Single-pass union schema replaces prior 3-pass design (~3× cheaper) |
| 3.3.T1 | Call chain traversal depth 3 from Joern CPG; callee-first (bottom-up) order | Jul 22–23 | 4.0 | | Callee-first required for SCSS correctness in M3.4 |
| 3.3.T2 | Multi-function context assembly: `CallChainContext` struct | Jul 23 | 3.0 | | |
| 3.3.T3 | Single-pass union schema per function: `{taint_flow: {...}, auth_guard: {...}, logic_flaw: {...}}` — one XGrammar-2 JSON object covers all 3 vulnerability classes; TagDispatch without recompilation | Jul 24 | 4.0 | | All `check_location` fields: `framework_annotation\|explicit_code\|middleware\|unknown` |
| 3.3.T4 | Batch inference: up to 5 surfaces per prompt; amortizes model-load + context-window overhead | Jul 24 | 3.0 | | |
| 3.3.T5 | CPG-derived fields injected as ground-truth; LLM fills semantic interpretation only; never raw code | Jul 25 | 2.5 | | |
| 3.3.T6 | Token footprint: assert ≥60% reduction vs raw call chain; log in `docs/benchmarks/token_footprint.md` | Jul 25 | 2.0 | | |
| 3.3.T7 | Multi-function vulnerability detection test: IDOR spanning caller + surface + callee | Jul 25 | 1.5 | | |
| **M3.4** | **Token Budget Controller + LLM Semantic Scan + Scan Security Context Store** | Jul 25–28 | 23.0 | — | T7–T9 (SCSS) are explicit DROP candidates |
| 3.4.T1 | Surface priority ranking: `w1×cvss + w2×(1-classifier_confidence) + w3×reachability_from_entry` | Jul 25 | 2.5 | | `reachability` = inverse hop count from external-input node |
| 3.4.T2 | Hard per-scan token cap (default 50K); exhausted surfaces → `SUPPRESSED reason:budget_exhausted`; never silent drop | Jul 26 | 2.0 | | |
| 3.4.T3 | ReAct step 1: transfer constraint (tainted data flow from caller to surface?) | Jul 26 | 2.5 | | Max 3 steps; backbone capability check at scan start; single-pass CoD+SCoT fallback |
| 3.4.T4 | ReAct step 2: callee taint (surface propagates to callees?) | Jul 27 | 2.5 | | |
| 3.4.T5 | ReAct step 3: trigger constraint at sink; XGrammar-2 output schema | Jul 27 | 2.5 | | Path A HIGH/BLOCK surfaces pre-filtered; path independence preserved |
| 3.4.T6 | `uncertain` verdicts → `SUPPRESSED reason:uncertain`; never silent drop | Jul 28 | 1.5 | | |
| 3.4.T7 | **[DROP FIRST]** SCSS: in-memory CPG-neighbor graph; inference nodes keyed by Joern function ID | Jul 28 | 3.0 | | |
| 3.4.T8 | **[DROP FIRST]** SCSS read/write hooks on each ReAct LLM call | Jul 28 | 2.0 | | |
| 3.4.T9 | **[DROP FIRST]** Cross-surface vulnerability detection test | Jul 28 | 4.5 | | SCSS saves ~9.5h if dropped — treat as de-facto buffer extension |

**G3 total**: ~84h · Primary risk: A-18 calibration surprises; SCSS drop recovers ~9.5h

---

## Goal 4 — Dedup + Report + Final Integration
**Window**: Jul 29 – Aug 6 · ~50h

Stub Dedup skeleton during G3 week (Jul 25–28) to de-risk the compressed 9-day G4 window.

| ID | Name | Dates | E (h) | Status | Notes |
|---|---|---|---|---|---|
| **M4.1** | **Dedup + SSVC-Inspired Confidence Scoring** | Jul 29 – Aug 1 | 22.0 | — | |
| 4.1.T1 | 4-gate cascaded dedup: CWE hash+file+line → code fingerprint (MD5) → embedding similarity (MiniLM-L6-v2, Python worker) → AST edit distance (last resort) | Jul 29–30 | 6.0 | | Cheapest gate first; embedding reaches only ~10–20% of findings |
| 4.1.T2 | SSVC dimension sourcing: Exploitation (CISA KEV / EPSS >0.1 / NVD) · Automatable (CWE lookup table) · Technical Impact (CVSS / CWE map) | Jul 30–31 | 5.0 | | |
| 4.1.T3 | Score → label: BLOCK ≥0.92 · HIGH 0.75–0.91 · MEDIUM 0.60–0.74 · LOW 0.30–0.59 · SUPPRESSED <0.30; CVE auto-flagged findings scored from CVSS directly | Jul 31 | 3.0 | | Path A high-confidence bypass findings get MEDIUM floor + SSVC upgrade |
| 4.1.T4 | Cross-path +15pp additive boost; capped at 1.0; BLOCK not boosted | Aug 1 | 2.0 | | |
| 4.1.T5 | Auto-suppression: test file path patterns + framework-safe per language; `reason` field always set; `.zerotrust-suppressions.yaml` sidecar for user overrides | Aug 1 | 3.0 | | Sidecar read by DI on next scan (Semgrep `.semgrepignore` pattern) |
| 4.1.T6 | `poe_context` field population: `{source_node, sink_node, taint_path_summary, required_input_conditions}` from Path B LLM output | Aug 1 | 3.0 | | Required for Approach 3 PoE Eligibility Classifier |
| **M4.2** | **HTML Report + Patch Suggestions** | Aug 1–4 | 20.0 | — | |
| 4.2.T1 | Go `html/template` + `embed`: self-contained HTML dashboard; SSVC-inspired severity labels | Aug 1–2 | 5.0 | | All free-text fields via contextual escaping; no `template.HTML()` |
| 4.2.T2 | XSS mitigations: `<meta http-equiv="Content-Security-Policy" ...>` tag + synthetic XSS test case | Aug 2 | 2.5 | | `justification` + `file_path` + `matched_code` are attacker-controlled strings |
| 4.2.T3 | Patch generation: zero-shot unified diff via Ollama | Aug 3 | 3.0 | | |
| 4.2.T4 | Patch validation: `go-gitdiff` in-memory apply; `patch_status:malformed` if hunk headers fail | Aug 3 | 3.0 | | Off-by-one hunk headers are primary LLM diff failure mode |
| 4.2.T5 | Patch scope labels: `single_hunk` (~22%) / `multi_hunk` (~12%) / `multi_file` (0–7.7%) with PatchEval-grounded reliability note | Aug 4 | 2.5 | | |
| 4.2.T6 | CVE few-shot context injection for BLOCK+HIGH CVE matches (Trivy data already available) | Aug 4 | 2.0 | | |
| 4.2.T7 | Suppression sidecar: write `.zerotrust-suppressions.yaml` on user override in report | Aug 4 | 2.0 | | |
| **M4.3** | **End-to-End Integration + Final Delivery** | Aug 5–6 | 8.0 | — | |
| 4.3.T1 | Full pipeline run: `zerotrust scan ./test-codebase`; Path A + Path B findings; Dedup; HTML report generated | Aug 5 | 3.0 | | |
| 4.3.T2 | Precision/recall vs G2 baseline; document improvement in `docs/benchmarks/` | Aug 5 | 2.0 | | |
| 4.3.T3 | Performance: total wall-clock on 5K LOC; memory peak | Aug 6 | 1.5 | | |
| 4.3.T4 | Final delivery: repo clean, `CLAUDE.md` accurate, README present | Aug 6 | 1.5 | | |

**G4 total**: ~50h · Cut sequence if behind: T6 (CVE few-shot) → T7 (sidecar write) → T4.1.T1 embedding gate

---

## Summary

| Goal | Window | E (h) | Primary Risk |
|---|---|---|---|
| G1 — OpenGrep PoC | Jun 9–20 | ~50h | M1.4 instruction file scanning is new; tight window |
| G2 — Go Core + Path A | Jun 23–Jul 11 | ~90h | Joern JVM setup; MIV cosign integration |
| G3 — Path B Funnel | Jul 14–Jul 28 | ~84h | A-18 calibration; SCSS is explicit drop (~9.5h saved if cut) |
| G4 — Dedup + Report | Jul 29–Aug 6 | ~50h | Compressed 9-day window; stub Dedup skeleton in G3 week |
| **Total** | **Jun 9 – Aug 6** | **~274h** | |

**Drop sequence** (in order): G3 SCSS T7–T9 · G4 CVE few-shot (T6) · G4 embedding dedup gate (T1 partial) · G3 A-18 deep calibration (T6).

**A-18 note**: UniXcoder operates in high-recall mode throughout. Do not publish accuracy figures until CVEFixes benchmark is complete. Document the gap honestly in all demos.
