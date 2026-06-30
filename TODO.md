# ZeroTrust.sh — TODO

> L0 ✅ · L1 ✅ · L2 ✅ · L3 ✅ · ML4.1 ✅ · ML4.2 ✅ · ML4.3 ✅ · Test audit ✅ (all complete as of Jun 24, ~6 weeks early)
> Full plan: `docs/planning/revised-execution-plan.md`
> **Aug 6 hard deadline** — 6 weeks of buffer remaining.

---

## Priority Order

1. **P0 + P6** — Foundation + Path A rewrite (parallel; P6 unblocks Path A correctness before we have fine-tuned adapters)
2. **P1–P3** — Data pipeline (corpus for training, eval, calibration)
3. **P4** — LoRA fine-tuning on CVEFixes + Juliet + SARD (~$3.80 GPU)
4. **P5** — Deploy adapters, recalibrate thresholds
5. **P7** — Benchmarking + CI regression gate
6. **Approach 3 / PoE** — Last; only after corpus is solid and A-18 is resolved

---

## P0 — Pipeline Foundation (2h)

- [x] **0.1** — Shared config: paths, language list `[python, java, javascript, go, csharp]`, token limits (1024 CodeT5+/512 fallback), thresholds → `pipeline/config.py`
- [x] **0.2** — Pipeline orchestrator: sequential stages with checkpoints, resume support → `pipeline/run.py`
- [x] **0.3** — Add deps: `tree-sitter-languages`, `datasets`, `peft`, `evaluate`, `cleanlab` → `worker/pyproject.toml`

---

## P1 — Data Collection (5h)

- [x] **1.1** — Load CVEFixes via HF Datasets: `load_dataset("hitoshura25/cvefixes")` → `pipeline/collectors/cvefixes.py`
- [x] **1.2** — Filter to Python, Java, JavaScript (covers TS), Go, C# → same file
- [x] **1.3** — Load Juliet C# 1.3 (28,942 synthetic cases, perfect labels) + SARD C# → `pipeline/collectors/juliet.py`
- [x] **1.4** — Extract vulnerable/fixed paired samples: `{code, label, cve_id, cwe_id, language, repo}` → both collector files
- [x] **1.5** — Dedup: `sha256(code)` within vuln set + across vuln/safe; log dropped count → `pipeline/collectors/dedup.py`
- [x] **1.6** — Output raw per-language JSONL → `tests/corpus/raw/{language}.jsonl`

**Checkpoint**: row counts logged per language. Expected: Java (~3-6K) · Python (~2-4K) · JS/TS (~2-4K) · C# (~30K with Juliet) · Go (~0.5-1.5K, thin — document gap).

---

## P2 — Normalization & Splits (4h)

- [x] **2.1** — Strip comments, normalize whitespace, clip to 1024 tokens → `pipeline/normalizer/normalize.py`
- [x] **2.2** — Class balance audit: log vuln:safe ratio per language → same file
- [x] **2.3** — Apply weighted loss strategy (not oversampling — avoids overfitting) → same file
- [x] **2.4** — CVE-aware stratified 80/10/10 split per language → same file
- [x] **2.5** — Write normalized splits → `tests/corpus/normalized/{language}_{split}.jsonl`
- [ ] **2.6** — Write corpus statistics → `docs/benchmarks/corpus_stats.md`

---

## P3 — Label Noise Audit + Quality Checks (7h)

- [x] **3.1** — Sample 50 "vulnerable" functions per language for manual noise audit → `pipeline/labeler/noise_audit.py`
- [ ] **3.2** — Manual label verification (3 reviewers, independent) — external process
- [ ] **3.3** — Compute noise rate; log to `corpus_stats.md`
- [x] **3.4** — If noise > 40%: apply confident learning via `cleanlab` → same file
- [x] **3.5** — Rule-based sanity check: remove CWE-0 placeholders, malformed code → `pipeline/labeler/check.py`
- [x] **3.6** — Overlap check: zero train/test overlap (hash + CVE-based); exit 1 on violation → same file
- [x] **3.7** — Coverage report: for each Semgrep `p/*` ruleset we dynamically select, confirm ≥ 1 corpus CWE covered; flag gaps → `pipeline/labeler/coverage_report.py`

**Checkpoint**: `check.py` exits 0; coverage gaps documented in `docs/rules/coverage_gap.md`.

---

## P4 — LoRA Fine-Tuning of CodeT5+ (9h script + 5.5h GPU, ~$3.80)

- [x] **4.1** — Verify CodeT5+ attention module names: `model.named_modules()` → confirm `target_modules` (0.5h)
- [x] **4.2** — Training script: `LoraConfig(r=16, alpha=32, target_modules=all_attn, dropout=0.05)` + `BCEWithLogitsLoss` + fp16 mixed precision (3.0h) → `scripts/train_lora.py`
- [ ] **4.3–4.7** — Train per-language adapters: Python · Java · JavaScript · Go · C# (1.0-1.5h each, ~$0.70-1.04 each on A40 @ $0.69/h)
- [x] **4.8** — Save adapters → `~/.zerotrust/adapters/{language}/` (0.2h)
- [x] **4.9** — Evaluate per-language F1 on held-out test split (1.0h)
- [ ] **4.10** — Cross-validate on PrimeVul: `load_dataset("colin/PrimeVul", split="test")` (1.0h)
- [ ] **4.11** — Precision check on OWASP Benchmark (Java, 2,741 cases, ground truth) (1.0h)
- [ ] **4.12** — Log all results → `docs/benchmarks/a18_gap.md` (0.5h)

> If Go < 1.5K samples: keep high-recall mode, document gap.

| Language   | GPU time | Cost (A40 @ $0.69/h) |
| ---------- | -------- | -------------------- |
| Python     | 1.0h     | $0.69                |
| Java       | 1.0h     | $0.69                |
| JavaScript | 1.0h     | $0.69                |
| Go         | 1.0h     | $0.69 (or skip)      |
| C#         | 1.5h     | $1.04                |
| **Total**  | **5.5h** | **$3.80**            |

---

## P5 — Deployment Integration (4h)

- [x] **5.1** — Wire LoRA into classifier: base CodeT5+ loads once; `set_adapter(language)` per classify request → `worker/handlers/classify.py`
- [x] **5.2** — Load adapters from `~/.zerotrust/adapters/` on worker startup → same file
- [x] **5.3** — Threshold recalibration: replace hardcoded 0.85/0.15 with per-language empirical values → `worker/tuning.py`
- [x] **5.5** ⚠️ **Severity gate calibration** — `ConfBlock/High/Medium/Low` (0.92/0.75/0.60/0.30) and CVSS-band confidence values (0.95/0.82/0.68) are all judgment-based guesses with no statistical backing. After P4 produces a labeled val-set, run `scripts/calibrate.py --input val.csv --out cal.json` to fit real thresholds from model outputs, then pass `--calibration cal.json` at scan time. See `docs/planning/implementation-plan.md` A18.T8 for full details.
- [ ] **5.4** — Update accuracy claims: replace A-18 caveat with validated per-language F1 → `CLAUDE.md`, `README.md`, report output

---

## P6 — Path A Rewrite: Dynamic Tool Dispatcher Core

> Refactors Path A from a static rule-matcher into a decoupled, concurrent **Dynamic Tool Dispatcher**.
> The core engine detects the codebase stack, filters which tools apply via a `.Supports()` contract, and fans them out concurrently.
>
> - **MVP Scope (Option 2):** Dispatching a streamlined open-source trifecta: OpenGrep (handling universal/exotic syntax rules), Gitleaks (secrets), and OSV-Scanner (dependencies).
> - **Post-MVP Scope (Option 1 - Future):** Expanding this dispatcher into a "Mason-style" binary manager that pulls ecosystem-specific linters (like cargo-clippy or sobelow) dynamically.

### 6a — Deprecate Legacy Static Architectures

- [x] **6a.1** — Delete the entire `rules/` directory tree (~57 custom YAML files).
- [x] **6a.2** — Rename `internal/pattern/` to `internal/scanner/`.
- [x] **6a.3** — Drop `astgrep/` and `verifier/` sub-packages completely to remove legacy custom code matching.
- [x] **6a.4** — Strip old static ruleset registration paths out of `cmd/zerotrust/scan.go`.

### 6b — Build Stack Profiler & Orchestrator Core

- [x] **6b.1** — Implement `internal/detector/`: parses target directories for files and extensions (`go.mod`, `mix.exs`, `Cargo.toml`, etc.) to build a unified `StackProfile` struct.
- [x] **6b.2** — Define the core `Scanner` interface contract in `internal/scanner/scanner.go`:
      `go
      type Scanner interface {
          Name() string
          Supports(stack StackProfile) bool
          Scan(ctx context.Context, target string) ([]Finding, error)
      }
      `
- [x] **6b.3** — Build `internal/orchestrator/engine.go`: reads the profile, filters active scanners using `.Supports()`, and dispatches them concurrently with a context deadline timeout.

### 6c — Streamlined Open-Source Integration Wrappers (MVP Tier)

- [x] **6c.1** — **OpenGrep Dynamic Wrapper:** Read `StackProfile.Languages`. Map detected keys directly to standard registry configurations (e.g., `p/python`, `p/rust`, or fallback `p/owasp-top-ten`) inside a native Go string lookup map.
- [x] **6c.2** — **Gitleaks Wrapper:** Wire binary execution; returns `true` for all scans to perform universal hardcoded secret auditing across all target formats.
- [x] **6c.3** — **OSV-Scanner Wrapper:** Triggers fast dependency tracking against package manifest lockfiles if present.

### 6d — Pipeline Synthesis & Future Hooks (Option 1 Documentation)

- [x] **6d.1** — Adapt `internal/dedup/` to handle standardized structural inputs originating from `opengrep`, `gitleaks`, and `osv`.
- [x] **6d.2** — Wire the new orchestrator directly into your central execution pipeline, firing concurrently while the asynchronous Joern CPG compiler runs in the background.
- [x] **6d.3** — Add a `FUTURE_DEVELOPMENT.md` or code-level comments in `internal/orchestrator/` detailing how the Option 1 Mason-style tool registry yaml will eventually hook into the established `Scanner` contract to dynamically fetch ecosystem-specific linter binaries.

---

## P7 — Benchmarking + Regression Gate (3h)

- [ ] **7.1** — Post-LoRA per-language F1 on test split → `scripts/benchmarks/corpus_bench.py`
- [ ] **7.2** — Wall-clock, RSS, p50/p95 latency on 5K synthetic codebase → `scripts/benchmarks/profile_scan.py`
- [ ] **7.3** — Add `make bench` target → `Makefile`
- [ ] **7.4** — CI gate: F1 ≥ 0.75 per language, wall-clock ≤ 60s on 5K LOC → CI config

---

## Last: Approach 3 / PoE — Agentic Scanner

> Start only after corpus is collected and A-18 is resolved (or consciously deferred past Aug 6).
> Approach 3 per CLAUDE.md: LangGraph 3-agent ensemble (Recon → Exploit → Verify), Threat Feature Extractor, Docker PoE sandbox, BOLAZ IDOR tracking.

| ID     | Task                                                    | Notes                                                                |
| ------ | ------------------------------------------------------- | -------------------------------------------------------------------- |
| PoE.T1 | LangGraph agent scaffold: Recon → Exploit → Verify loop | Replaces `llmscan.go` bounded ReAct; IPC switches to local gRPC      |
| PoE.T2 | Docker PoE sandbox (`docker/sandbox/`)                  | Isolated execution env for Exploit agent; no network egress          |
| PoE.T3 | BOLAZ IDOR tracking                                     | Resource-ID dataflow across agent turns                              |
| PoE.T4 | Threat Feature Extractor (Python)                       | Union schema over taint + auth + logic features; feeds Exploit agent |
| PoE.T5 | Wire PoE confidence into Dedup gate                     | PoE-confirmed findings bypass Gate 3 similarity check                |

**Do not start PoE until P3 (corpus QC) is done.**

---

## Phase Summary

| Phase               | Hours                    | Dependencies        | Notable                                      |
| ------------------- | ------------------------ | ------------------- | -------------------------------------------- |
| P0 — Foundation     | 2h                       | None                | Config + orchestrator + deps                 |
| P1 — Collection     | 5h                       | P0                  | CVEFixes HF + Juliet C#                      |
| P2 — Normalization  | 4h                       | P1                  | CVE-aware splits, weighted loss              |
| P3 — Noise + QC     | 7h                       | P2 (partial)        | Manual audit, coverage report                |
| P4 — LoRA training  | 9h code + 5.5h GPU       | P2                  | ~$3.80 total GPU cost                        |
| P5 — Deployment     | 4h                       | P4                  | Wire adapters, recalibrate                   |
| P6 — Path A rewrite | 11h                      | P0 (parallel P1-P2) | Delete rules, add gosec/Gitleaks, heuristics |
| P7 — Benchmarking   | 3h                       | P4 + P6             | make bench, CI gate                          |
| **Total**           | **~45h code + 5.5h GPU** |                     | **~$3.80 cloud cost**                        |

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
