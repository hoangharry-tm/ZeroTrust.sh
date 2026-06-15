# G3 — Path B: Three-Tier Semantic Cost Funnel
**Goal window**: 2026-07-21 → 2026-08-01 · 12 calendar days · ~87 committed hours
**Prerequisite**: G2 complete — Joern CPG operational and shared, Python worker IPC live, Path A findings flowing into Finding channel, precision/recall baseline recorded in `docs/benchmarks/g2_baseline.md`.
**Checkpoint**: Path B funnel runs end-to-end. Fewer than 25% of surfaces reach the LLM. A multi-function vulnerability (e.g., IDOR spanning caller + surface + callee) is detected and correctly attributed.

> **Highest-risk goal in the plan.** Novel work, compressed window. Primary drop candidate: M3.4 SCSS tasks (T7–T9). If those are cut, M3.4 ships as a working ReAct scan without cross-surface inference — still demo-worthy.
>
> **Pre-stub requirement**: During the M3.3/M3.4 week (Jul 28–Aug 1), stub the HTML report shell and SSVC dedup skeleton in parallel. If this is not done, G4's 5-day window will overrun into the submission deadline (R-03).
>
> **Weekend note**: M3.2 (Jul 25–28) spans a weekend. Some work on Jul 26–27 is likely necessary given the compressed window.

---

## Column Guide

| Column | Description |
|---|---|
| **ID** | `3.Mx` = milestone · `3.Mx.Ty` = task · `3.BUF` = buffer row |
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
| **3.M1** | **Heuristic Targeting + Call Graph + CVE Enrichment** | MILESTONE | 2026-07-21 | 2026-07-25 | 12 | 18 | 28 | 18.7 | | Not Started | Hoang | Reads Joern CPG from G2 (no re-parse); Trivy not used — replaced by OSV-Scanner (CVE-2026-33634 supply chain compromise) |
| 3.M1.T1 | CPG node-type queries — external-input nodes | TASK | 2026-07-21 | 2026-07-21 | — | — | — | 2.5 | | Not Started | Hoang | Query CPG for HTTP params, env vars, file reads, stdin, deserialized objects; language-agnostic via shared CPG schema |
| 3.M1.T2 | CPG node-type queries — auth-boundary nodes | TASK | 2026-07-21 | 2026-07-22 | — | — | — | 2.0 | | Not Started | Hoang | Identify authentication/authorization check points; missing guard detection starts here |
| 3.M1.T3 | CPG node-type queries — AI agent config file nodes | TASK | 2026-07-22 | 2026-07-22 | — | — | — | 2.0 | | Not Started | Hoang | MCP configs, .cursor/rules, AGENTS.md, CLAUDE.md, GEMINI.md; unique detection surface |
| 3.M1.T4 | Call graph extraction from Joern CPG | TASK | 2026-07-22 | 2026-07-23 | — | — | — | 3.0 | | Not Started | Hoang | No separate build step — call graph comes from CPG built in G2; extract caller/callee edges; output: Go CallGraph struct |
| 3.M1.T5 | OSV-Scanner Go library integration (`github.com/google/osv-scanner/v2`) | TASK | 2026-07-23 | 2026-07-24 | — | — | — | 3.0 | | Not Started | Hoang | Direct Go import — no subprocess; scan dependency manifests (go.mod, requirements.txt, pom.xml, package.json); OSV.dev + NVD + GitHub Advisory |
| 3.M1.T6 | CVE exact-match auto-flag + routing to findings | TASK | 2026-07-24 | 2026-07-24 | — | — | — | 2.0 | | Not Started | Hoang | If OSV-Scanner returns exact CVE match → write Finding directly with severity from CVSS; skip all further analysis for that surface |
| 3.M1.T7 | BOLAZ zero-trust resource ID dataflow flagging | TASK | 2026-07-24 | 2026-07-25 | — | — | — | 2.5 | | Not Started | Hoang | Flag all external IDs as untrustworthy until explicit authorization confirmed at each function boundary; targets IDOR/BOLA classes |
| 3.M1.T8 | Surface list output format for downstream classifier | TASK | 2026-07-25 | 2026-07-25 | — | — | — | 1.7 | | Not Started | Hoang | Struct: Surface{ID, File, FunctionName, NodeType, CallGraphDepth, CVEMatches}; passed to M3.2 classifier |
| **3.M2** | **UniXcoder Classifier Gate** | MILESTONE | 2026-07-25 | 2026-07-28 | 12 | 18 | 28 | 18.7 | | Not Started | Hoang | Primary LLM cost gate; A-18 calibration point — measure real precision/recall on AI-generated code; window spans weekend, some Sat/Sun work likely needed |
| 3.M2.T1 | UniXcoder model load in Python worker (extend dispatcher) | TASK | 2026-07-25 | 2026-07-26 | — | — | — | 2.5 | | Not Started | Hoang | Add `classify` type handler to Python worker from G2; load UniXcoder-Base-Nine via transformers on worker startup; pin model version |
| 3.M2.T2 | Go IPC: classify request/response type handling | TASK | 2026-07-26 | 2026-07-27 | — | — | — | 2.0 | | Not Started | Hoang | Send Surface struct as payload; receive {verdict: vulnerable/safe/uncertain, confidence: float}; reuse NDJSON protocol from 2.M3.T5 |
| 3.M2.T3 | Confidence threshold calibration (3-band classification) | TASK | 2026-07-27 | 2026-07-28 | — | — | — | 3.0 | | Not Started | Hoang | Tune thresholds: high-conf-safe (dismiss), high-conf-vulnerable (flag direct), uncertain (→ LLM); target uncertain band = 15–25% of surfaces |
| 3.M2.T4 | High-confidence-safe dismissal routing | TASK | 2026-07-28 | 2026-07-28 | — | — | — | 1.5 | | Not Started | Hoang | Surfaces below safe threshold → dropped silently; log count for cost funnel stats used in demo |
| 3.M2.T5 | High-confidence-vulnerable direct Finding flag routing | TASK | 2026-07-28 | 2026-07-28 | — | — | — | 1.5 | | Not Started | Hoang | Surfaces above vulnerable threshold → write Finding directly to channel; no LLM call; Source field = "UniXcoder" |
| 3.M2.T6 | Unsupported-language bypass (Rust, Kotlin, Swift, C# → direct LLM) | TASK | 2026-07-28 | 2026-07-28 | — | — | — | 1.5 | | Not Started | Hoang | UniXcoder trained only on Python/Java/JS/TS/Go/Ruby/PHP; unsupported languages skip classifier and go straight to M3.4 LLM ReAct |
| 3.M2.T7 | A-18 gap measurement: precision/recall on AI-generated code vs BigVul baseline | TASK | 2026-07-28 | 2026-07-28 | — | — | — | 3.2 | | Not Started | Hoang | Run classifier on test codebase (AI-generated code); record F1, precision, recall; compare to claimed F1=94.73% on BigVul C/C++; document gap in docs/benchmarks/a18_gap.md; disclose in demo — do not claim 94.73% without caveat |
| 3.M2.T8 | Classifier gate integration test: verify < 25% of surfaces reach LLM tier | TASK | 2026-07-28 | 2026-07-28 | — | — | — | 3.5 | | Not Started | Hoang | Run full surface set through gate; assert uncertain band ≤ 25%; if over, re-tune thresholds from T3; log final funnel stats |
| **3.M3** | **Call Chain Context Assembler + Semantic Function Summarizer** | MILESTONE | 2026-07-28 | 2026-07-31 | 12 | 18 | 28 | 18.7 | | Not Started | Hoang | LLM never receives raw code — only semantic summaries; aligns with IRIS ICLR 2025 design; Claude Code helps with prompt template design |
| 3.M3.T1 | Call chain traversal to depth 3 from Joern CPG (caller → surface → callee) | TASK | 2026-07-28 | 2026-07-29 | — | — | — | 4.0 | | Not Started | Hoang | Use call graph from 3.M1.T4; traverse depth 3 max; return ordered list [caller, surface, callee]; handle recursive/missing nodes gracefully |
| 3.M3.T2 | Multi-function context assembly (structured call chain representation) | TASK | 2026-07-29 | 2026-07-30 | — | — | — | 3.0 | | Not Started | Hoang | Struct: CallChainContext{functions: []FunctionContext, entryPoint, depth}; FunctionContext includes: name, params, local vars, calls made, return type |
| 3.M3.T3 | Semantic summary schema — taint-flow vulnerability class | TASK | 2026-07-30 | 2026-07-30 | — | — | — | 2.0 | | Not Started | Hoang | Fields: untrustedDataSource, sanitizersPresent[], sanitizerGaps[], sinkReached, sinkType; used by LLM prompt in M3.4 |
| 3.M3.T4 | Semantic summary schema — auth-guard vulnerability class | TASK | 2026-07-30 | 2026-07-31 | — | — | — | 2.0 | | Not Started | Hoang | Fields: resourceAccessed, authCheckPresent, authCheckLocation, principalVerified; enables IDOR + missing auth guard detection |
| 3.M3.T5 | Semantic summary schema — logic-flaw vulnerability class | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 2.0 | | Not Started | Hoang | Fields: businessConstraints[], stateTransitions[], enforcedAtBoundary; targets business logic and state machine flaws |
| 3.M3.T6 | Function-level semantic abstraction generation (Python worker call) | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 2.5 | | Not Started | Hoang | For each FunctionContext in call chain: call Python worker with `summarize` type; receive semantic summary per schema above; assemble into SummarizedCallChain struct |
| 3.M3.T7 | Token footprint measurement before/after summarization | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 1.5 | | Not Started | Hoang | Count tokens in raw call chain vs summarized version; record ratio; target ≥ 60% token reduction; log in docs/benchmarks/token_footprint.md |
| 3.M3.T8 | Multi-function vulnerability detection test (IDOR + missing auth guard) | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 1.7 | | Not Started | Hoang | Synthetic test: IDOR case spanning caller (no auth check) + surface (uses external ID) + callee (DB lookup); assert correctly detected and attributed to both functions |
| **3.M4** | **Token Budget Controller + LLM ReAct Scan + Scan Security Context Store** | MILESTONE | 2026-07-31 | 2026-08-01 | 14 | 22 | 36 | 23.0 | | Not Started | Hoang | T7–T9 are SCSS and are explicit DROP CANDIDATES — cut these first if window is tight; ReAct scan works without SCSS (per-surface reasoning only) |
| 3.M4.T1 | Surface prioritization ranking (CVE score × classifier uncertainty) | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 2.5 | | Not Started | Hoang | Rank uncertain surfaces: (CVSS score from OSV × (1 − classifier confidence)); highest ranked surfaces consume token budget first |
| 3.M4.T2 | Hard per-scan token cap enforcement | TASK | 2026-07-31 | 2026-07-31 | — | — | — | 2.0 | | Not Started | Hoang | Configurable cap (default: 50K tokens per scan); token counter incremented on each LLM call; halt further LLM calls when cap reached; log surfaces dropped |
| 3.M4.T3 | ReAct loop — Thought step | TASK | 2026-07-31 | 2026-08-01 | — | — | — | 2.5 | | Not Started | Hoang | LLM receives: semantic summary + vulnerability class schema; produces Thought: hypothesis about vulnerability + what additional context needed |
| 3.M4.T4 | ReAct loop — context-request step (call chain depth + CVE lookup) | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 3.0 | | Not Started | Hoang | LLM can request: deeper call chain (up to depth 3 from 3.M3.T1), CVE DB lookup from OSV-Scanner, or prior scan inferences from SCSS (if available); Go fulfills requests and returns context |
| 3.M4.T5 | ReAct loop — Observation → verdict step | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 2.5 | | Not Started | Hoang | Max 3 ReAct steps per surface; final step produces verdict; XGrammar-2 enforces JSON schema: {vulnerable: bool, severity: string, cwe: string, rationale: string}; write to Finding channel |
| 3.M4.T6 | XGrammar-2 schema enforcement on ReAct output (extend Python worker) | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 2.0 | | Not Started | Hoang | Add `llm_scan` type to Python worker dispatcher; XGrammar-2 JSON schema for ReAct verdict; same pattern as LLM Verifier from 2.M3.T7 |
| 3.M4.T7 | **[SCSS — DROP FIRST]** Scan Security Context Store: in-memory key-value store per scan | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 3.0 | | Not Started | Hoang | DROP if M3.4 starts late; per-scan map: {surfaceID → SecurityInference}; stores: inferred data sources, sanitizer gaps, trust boundary violations observed so far |
| 3.M4.T8 | **[SCSS — DROP FIRST]** SCSS read/write hooks on LLM calls | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 2.0 | | Not Started | Hoang | DROP if M3.4 starts late; before each ReAct Thought: inject prior inferences from SCSS into prompt; after verdict: write new inferences to SCSS |
| 3.M4.T9 | **[SCSS — DROP FIRST]** Cross-surface vulnerability detection test | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 3.5 | | Not Started | Hoang | DROP if M3.4 starts late; synthetic test: vulnerability only detectable by combining inferences from two separate surfaces; assert SCSS enables detection where per-surface scan would miss it |
| **3.BUF** | **G3 Buffer** | BUFFER | 2026-07-21 | 2026-08-01 | — | — | — | 8.0 | | | Hoang | Compressed 10% buffer (tight window); primary absorption: SCSS drop saves 8.5h — treat as de-facto buffer extension if M3.4 runs short; secondary: A-18 calibration surprises (R-04) |

---

## G3 Totals

| | O (hrs) | ML (hrs) | P (hrs) | E (hrs) |
|---|---|---|---|---|
| 3.M1 — Heuristic Targeting + Call Graph + CVE Enrichment | 12 | 18 | 28 | 18.7 |
| 3.M2 — UniXcoder Classifier Gate | 12 | 18 | 28 | 18.7 |
| 3.M3 — Call Chain Context Assembler + Semantic Function Summarizer | 12 | 18 | 28 | 18.7 |
| 3.M4 — Token Budget Controller + LLM ReAct Scan + SCSS | 14 | 22 | 36 | 23.0 |
| **Subtotal (milestones)** | **50** | **76** | **120** | **79.1** |
| 3.BUF — Buffer (explicit row) | — | — | — | 8.0 |
| **G3 Committed Total** | — | — | — | **87.1** |

> **SCSS drop scenario**: If T7+T8+T9 are dropped from M3.4, effective remaining M3.4 work = 14.5h (achievable in the 2-day window). SCSS saves 8.5h — effectively doubles the usable buffer for the rest of M3.4.

---

## Task Count

| Milestone | Tasks (committed) | Tasks (drop candidate) |
|---|---|---|
| 3.M1 | 8 | 0 |
| 3.M2 | 8 | 0 |
| 3.M3 | 8 | 0 |
| 3.M4 | 6 | 3 (T7, T8, T9 — SCSS) |
| **Total** | **30 committed + 3 stretch = 33 tasks + 4 milestones + 1 buffer = 38 rows** | |

---

## Inter-Goal Dependencies

| G3 Component | Depends on (G2) | Blocks (G4) |
|---|---|---|
| Heuristic Targeting (3.M1) | Joern CPG shared interface (2.M1.T7) | Dedup surface set (4.M1) |
| OSV-Scanner CVE enrichment (3.M1.T5–T6) | Go orchestrator binary (1.M2) | SSVC Exploitation dimension (4.M1.T4) |
| UniXcoder Classifier (3.M2) | Python worker IPC (2.M3.T2–T5), A-18 baseline (2.M4.T3) | Cost funnel stats for demo (4.M3.T5) |
| Semantic Summarizer (3.M3) | Python worker IPC (2.M3.T2–T5) | LLM ReAct prompt quality (3.M4.T3) |
| LLM ReAct Scan (3.M4) | XGrammar-2 enforcement (2.M3.T7), Summarizer (3.M3) | Path B findings in dedup (4.M1) |
| SCSS (3.M4.T7–T9) | ReAct loop (3.M4.T3–T5) | No G4 dependency — post-demo addition |

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
