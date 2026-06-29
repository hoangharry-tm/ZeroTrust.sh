# ZeroTrust.sh — TODO

> L0 ✅ · L1 ✅ · L2 ✅ · L3 ✅ · ML4.1 ✅ · ML4.2 ✅ · ML4.3 ✅ · Test audit ✅ (all complete as of Jun 24, ~6 weeks early)
> Full plan: `docs/planning/implementation-plan.md`
> **Aug 6 hard deadline** — 6 weeks of buffer remaining.

---

## Priority Order

1. **Data Pipeline** — build the corpus for testing, benchmarking, profiling, and tuning (feeds A-18 + all future evaluation)
2. **A-18 Resolution** — QLoRA fine-tuning on CVEFixes; unblocks accuracy claims and threshold recalibration
3. **Approach 3 / PoE** — LangGraph agentic scanner, Docker sandbox, BOLAZ IDOR — last, only after data is solid

---

## Next: ML-DATA — Data Collection & Pipeline (`pipeline/`)

> **Why first**: Every remaining workstream (A-18 fine-tuning, benchmark reporting, funnel calibration, regression testing, threshold recalibration) requires a labelled, multi-language corpus. The `pipeline/` directory is currently empty. Building it now unblocks everything else.
>
> Output: `tests/corpus/` (gitignored) — per-language JSONL files ready for training, eval, and profiling.

### ML-DATA.1 — CVEFixes Collector (`pipeline/collectors/`)

- [ ] **T1** — Download CVEFixes SQLite DB (`pipeline/collectors/cvefixes.py`); verify checksum; store at `~/.zerotrust/cvefixes.db` (not in repo)
- [ ] **T2** — Query `file_change` + `fixes` + `commits`; extract function-level hunks via Tree-sitter (reuse tree-sitter-languages already in project); output raw JSONL per language: `{code, label, cve_id, cwe_id, language, repo, commit}`
- [ ] **T3** — Language filter: Python / Java / JavaScript / Go only (match scanner rule coverage); discard C/C++ (BigVul territory, not our gap)
- [ ] **T4** — Dedup: drop samples where `sha256(code)` appears in both vuln and safe sets; log dropped count

**Checkpoint**: `python pipeline/collectors/cvefixes.py` produces `tests/corpus/raw/{language}.jsonl`; row counts logged.

---

### ML-DATA.2 — Normalizer (`pipeline/normalizer/`)

- [ ] **T1** — Strip comments, normalise whitespace, clip functions to 512 tokens (CodeT5+ context window); write to `tests/corpus/normalized/{language}.jsonl`
- [ ] **T2** — Class balance audit: log vuln:safe ratio per language; apply random oversampling of minority class to reach ≤ 3:1 ratio (document in `docs/benchmarks/a18_gap.md`)
- [ ] **T3** — Stratified 80/10/10 train/val/test split per language; write `{language}_{split}.jsonl`

**Checkpoint**: `python pipeline/normalizer/normalize.py` produces train/val/test splits; class distribution table written to `docs/benchmarks/corpus_stats.md`.

---

### ML-DATA.3 — Labeler & Quality Check (`pipeline/labeler/`)

- [ ] **T1** — Rule-based sanity check: samples where CWE matches a known-safe pattern (e.g. CWE-0 placeholder) are flagged and removed
- [ ] **T2** — Overlap check: assert zero overlap between train and test splits (hash-based)
- [ ] **T3** — Coverage report: for each scanner rule in `rules/`, confirm ≥ 1 CVEFixes sample covers that CWE; flag rules with no corpus coverage

**Checkpoint**: `python pipeline/labeler/check.py` exits 0 with zero overlap and coverage report written.

---

### ML-DATA.4 — Profiling & Benchmarking Harness (`scripts/benchmarks/`)

- [ ] **T1** — Benchmark script (`scripts/benchmarks/corpus_bench.py`): run classifier on the test split; record precision/recall/F1 per language; write to `docs/benchmarks/a18_gap.md` results table
- [ ] **T2** — Profiling harness (`scripts/benchmarks/profile_scan.py`): run `zerotrust scan` on a 5K-LOC synthetic codebase sampled from corpus; capture wall-clock, peak RSS, p50/p95 latency per stage; append to `docs/benchmarks/performance.md`
- [ ] **T3** — Regression gate: add `make bench` target; fails CI if F1 drops below 0.75 on any language or wall-clock exceeds 60s on 5K LOC

**Checkpoint**: `make bench` runs clean; all thresholds met or explicitly documented as known gaps.

---

## After Data Pipeline: A-18 Resolution (QLoRA Fine-Tuning)

> Unblocked by ML-DATA.3. Full task breakdown in `docs/planning/implementation-plan.md` under `[BONUS] R&D — A-18 Resolution`.

| ID     | Task                                                        | Est.                        |
| ------ | ----------------------------------------------------------- | --------------------------- |
| A18.T1 | CVEFixes data pipeline                                      | ✅ covered by ML-DATA above |
| A18.T2 | Class balancing + splits                                    | ✅ covered by ML-DATA.2     |
| A18.T3 | QLoRA fine-tune per language (RunPod A40, ~$15–25)          | 6.0h                        |
| A18.T4 | Per-language F1/precision/recall evaluation                 | 3.0h                        |
| A18.T5 | Save LoRA adapter + wire into `worker/handlers/classify.py` | 2.0h                        |
| A18.T6 | Threshold recalibration (0.80 → 0.85–0.90 per language)     | 1.0h                        |
| A18.T7 | Update accuracy claims in CLAUDE.md, README, report output  | 0.5h                        |

**Hard time-box: 12.5h post-data-pipeline.** If Go/Ruby sample counts < 1.5k, keep high-recall mode for those languages and document.

---

## Last: Approach 3 / PoE — Agentic Scanner

> Start only after the corpus is collected and A-18 is resolved (or consciously deferred past Aug 6).
> Approach 3 per CLAUDE.md: LangGraph 3-agent ensemble (Recon → Exploit → Verify), Threat Feature Extractor, Docker PoE sandbox, BOLAZ IDOR tracking.

| ID     | Task                                                    | Notes                                                                |
| ------ | ------------------------------------------------------- | -------------------------------------------------------------------- |
| PoE.T1 | LangGraph agent scaffold: Recon → Exploit → Verify loop | Replaces `llmscan.go` bounded ReAct; IPC switches to local gRPC      |
| PoE.T2 | Docker PoE sandbox (`docker/sandbox/`)                  | Isolated execution env for Exploit agent; no network egress          |
| PoE.T3 | BOLAZ IDOR tracking                                     | Resource-ID dataflow across agent turns                              |
| PoE.T4 | Threat Feature Extractor (Python)                       | Union schema over taint + auth + logic features; feeds Exploit agent |
| PoE.T5 | Wire PoE confidence into Dedup gate                     | PoE-confirmed findings bypass Gate 3 similarity check                |

**Do not start PoE until ML-DATA is done.** Agentic scanner quality is directly correlated with corpus quality — a bad corpus produces an untuned agent that overfits to the Spring Boot testbed.

---

## Completed

- [x] L0 — Go skeleton, ingestion (MIV + DI), Path A wrappers, Python worker IPC, Dedup skeleton, HTML skeleton
- [x] L1 — Heuristic Targeting (ML3.1), CodeT5+ Classifier (ML3.2), CPG Assembler (ML3.3)
- [x] L2 — OpenGrep + Joern CPG taint + instrscan + LLM Verifier (Path A complete)
- [x] L3 — Summarizer, Budget Controller, LLM Semantic Scan (Path B complete)
- [x] ML4.1 — Dedup complete: Gates 1–4, SSVC sourcing, cross-path boost, sidecar suppression
- [x] ML4.2 — HTML report + patch suggestions: XSS mitigations, CSP, go-gitdiff validation, ACK/suppress UI
- [x] ML4.3 — End-to-end integration: Spring Boot testbed, benchmarks, final delivery
- [x] Test audit — 4 new test files (patch, summarizer, output, expand); 3 vacuous tests removed/fixed; 507 tests green
