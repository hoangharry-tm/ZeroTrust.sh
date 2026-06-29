# ZeroTrust.sh — Revised Execution Plan (Jul 2026)

> **Architectural pivot**: Path A → tool orchestrator, not rule engine. Path B → undefined-pattern detector for logic-level flaws LLMs create. All custom rules removed. Detection delegated to community rulesets and production-grade tools.
>
> **A-18 resolution**: LoRA fine-tuning of CodeT5+ 220M on multi-language CVEFixes + Juliet + SARD corpus. Per-language adapters, hot-swappable at inference. Target: tighten thresholds from 0.85/0.15 → empirical values, reduce LLM escalation from ~85% → ~15-30%.

---

## Architecture

```
[Target codebase]
    │
    ├── Ingestion (MIV + DI) ───────────────────────── hash verify, diff index
    │
    ├── Path A — Orchestrator ───────────────────────── all tools run concurrently
    │     ├── Semgrep ───────── dynamic p/* via heuristics
    │     ├── gosec ─────────── Go SAST (when Go detected)
    │     ├── Gitleaks ──────── secret scanning (always)
    │     ├── Trivy ─────────── dependency vulns (always)
    │     └── Joern CPG ────── deep taint (Java/Python/JS)
    │            │
    │            ▼
    │     Normalizer → LLM Verifier → Dedup
    │
    ├── Path B — Semantic Funnel ────────────────────── AI-generated logic flaws
    │     ├── Heuristic Targeting ── external inputs, auth boundaries, call graph
    │     ├── CodeT5+ Classifier ─── LoRA per-language adapters (after A-18)
    │     ├── CPG Assembler ──────── call chain context + threat features
    │     ├── Budget Controller ──── token cap, priority ranking
    │     └── LLM Semantic Scan ──── ReAct: transfer → callee → trigger
    │
    └── Dedup (G1–G4 + SSVC) → HTML Report
```

---

## Phase 0 — Pipeline Foundation (2h)

| #   | Task                                                                                                                                         | File                    |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| 0.1 | Shared config: paths, language list `[python, java, javascript, go, csharp]`, token limits (1024 CodeT5+/512 UniXcoder fallback), thresholds | `pipeline/config.py`    |
| 0.2 | Pipeline orchestrator: sequential stages with checkpoints, resume support                                                                    | `pipeline/run.py`       |
| 0.3 | Add deps: `tree-sitter-languages`, `datasets`, `peft`, `evaluate`, `cleanlab`                                                                | `worker/pyproject.toml` |

---

## Phase 1 — Data Collection (5h)

| #   | Task                                                                                     | File                                |
| --- | ---------------------------------------------------------------------------------------- | ----------------------------------- |
| 1.1 | Load CVEFixes via HF Datasets: `load_dataset("hitoshura25/cvefixes")`                    | `pipeline/collectors/cvefixes.py`   |
| 1.2 | Filter to Python, Java, JavaScript (JS covers TS), Go, C#                                | Same file                           |
| 1.3 | Load Juliet C# 1.3 (28,942 synthetic cases, perfect labels) + SARD C#                    | `pipeline/collectors/juliet.py`     |
| 1.4 | Extract vulnerable/fixed paired samples: `{code, label, cve_id, cwe_id, language, repo}` | Both collector files                |
| 1.5 | Dedup: sha256(code) within vuln set + across vuln/safe. Log dropped count.               | `pipeline/collectors/dedup.py`      |
| 1.6 | Output raw per-language JSONL                                                            | `tests/corpus/raw/{language}.jsonl` |

**Checkpoint**: row counts logged per language

**Training-ready for**: Java (~3-6K) · Python (\~2-4K) · JS/TS (\~2-4K) · **C#
(\~30K with Juliet)** · Go (~0.5-1.5K, thin — document gap).

---

## Phase 2 — Normalization & Splits (4h)

| #   | Task                                                                 | File                                               |
| --- | -------------------------------------------------------------------- | -------------------------------------------------- |
| 2.1 | Strip comments, normalize whitespace, clip to 1024 tokens            | `pipeline/normalizer/normalize.py`                 |
| 2.2 | Class balance audit: log vuln:safe ratio per language                | Same file                                          |
| 2.3 | Apply weighted loss strategy (not oversampling — avoids overfitting) | Same file                                          |
| 2.4 | CVE-aware stratified 80/10/10 split per language                     | Same file                                          |
| 2.5 | Write normalized splits                                              | `tests/corpus/normalized/{language}_{split}.jsonl` |
| 2.6 | Write corpus statistics                                              | `docs/benchmarks/corpus_stats.md`                  |

---

## Phase 3 — Label Noise Audit + Quality Checks (7h)

| #   | Task                                                                                                                    | File                                  |
| --- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| 3.1 | Sample 50 "vulnerable" functions per language for manual noise audit                                                    | `pipeline/labeler/noise_audit.py`     |
| 3.2 | Manual label verification (3 reviewers, independent)                                                                    | External process                      |
| 3.3 | Compute noise rate; log to corpus_stats.md                                                                              | Same file                             |
| 3.4 | If noise > 40%: apply confident learning via `cleanlab`                                                                 | Same file                             |
| 3.5 | Rule-based sanity check: remove CWE-0 placeholders, malformed code                                                      | `pipeline/labeler/check.py`           |
| 3.6 | Overlap check: zero train/test overlap (hash + CVE-based). Exit 1 on violation.                                         | Same file                             |
| 3.7 | Coverage report: for each Semgrep `p/*` ruleset we'll dynamically select, confirm ≥ 1 corpus CWE is covered. Flag gaps. | `pipeline/labeler/coverage_report.py` |
|     | **Checkpoint**: `check.py` exits 0; coverage gaps documented in `docs/rules/coverage_gap.md`                            |                                       |

---

## Phase 4 — LoRA Fine-Tuning of CodeT5+ (9h script + 5.5h GPU, ~$3.80 total)

| #       | Task                                                                                                                                         | Est.          | Cost             |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ---------------- |
| 4.1     | Verify CodeT5+ attention module names: `model.named_modules()` → confirm `target_modules`                                                    | 0.5h          | —                |
| 4.2     | Training script: `LoraConfig(r=16, alpha=32, target_modules=all_attn, dropout=0.05)`. `Trainer` + `BCEWithLogitsLoss` + fp16 mixed precision | 3.0h          | —                |
| 4.3–4.7 | Train adapters per language (Python · Java · JavaScript · Go · C#)                                                                           | 1.0-1.5h each | ~$0.70-1.04 each |
| 4.8     | Save adapters to `~/.zerotrust/adapters/{language}/`                                                                                         | 0.2h          | —                |
| 4.9     | Evaluate per-language F1 on held-out test split                                                                                              | 1.0h          | —                |
| 4.10    | Cross-validate on PrimeVul test split: `load_dataset("colin/PrimeVul", split="test")`                                                        | 1.0h          | —                |
| 4.11    | Precision check on OWASP Benchmark (Java, 2,741 cases, ground truth)                                                                         | 1.0h          | —                |
| 4.12    | Log all results to `docs/benchmarks/a18_gap.md`                                                                                              | 0.5h          | —                |
|         | **If Go < 1.5K samples**: keep high-recall mode for Go, document.                                                                            |               |                  |

| Language   | GPU time | Cost (A40 @ $0.69/h) | Adapter size              |
| ---------- | -------- | -------------------- | ------------------------- |
| Python     | 1.0h     | $0.69                | ~8 MB                     |
| Java       | 1.0h     | $0.69                | ~8 MB                     |
| JavaScript | 1.0h     | $0.69                | ~8 MB                     |
| Go         | 1.0h     | $0.69                | ~8 MB (or skip if < 1.5K) |
| C#         | 1.5h     | $1.04                | ~8 MB                     |
| **Total**  | **5.5h** | **$3.80**            | **~40 MB**                |

---

## Phase 5 — Deployment Integration (4h)

| #   | Task                                                                                             | File                                    |
| --- | ------------------------------------------------------------------------------------------------ | --------------------------------------- |
| 5.1 | Wire LoRA into classifier: base CodeT5+ loads once; `set_adapter(language)` per classify request | `worker/handlers/classify.py`           |
| 5.2 | Load adapters from `~/.zerotrust/adapters/` on worker startup                                    | Same file                               |
| 5.3 | Threshold recalibration: replace 0.85/0.15 with per-language empirical values                    | `worker/tuning.py`                      |
| 5.4 | Update accuracy claims: replace A-18 caveat with validated per-language F1                       | `CLAUDE.md`, `README.md`, report output |

---

## Phase 6 — Path A Rewrite: Pure Orchestrator (11h)

### 6a — Remove Custom Detection (2h)

| #    | Task                                                                       |
| ---- | -------------------------------------------------------------------------- |
| 6a.1 | Delete entire `rules/` directory (~57 YAML files)                          |
| 6a.2 | Delete `internal/pattern/astgrep/` package                                 |
| 6a.3 | Delete `internal/pattern/instrscan/` package                               |
| 6a.4 | Remove ast-grep and instrscan from `cmd/zerotrust/scan.go` pipeline wiring |
| 6a.5 | Remove unused deps from `go.mod` (ast-grep Go bindings, etc.)              |

### 6b — Dynamic Semgrep Ruleset via Heuristics (5h)

| #    | Task                                                                                                                                                                                          | File                                  |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| 6b.1 | Build heuristic engine: scan target for file extensions, build files (`pom.xml`, `go.mod`, `package.json`, `requirements.txt`, `*.csproj`), content patterns (SQL keywords, API key patterns) | `internal/ingestion/heuristics/`      |
| 6b.2 | Build ruleset mapper: heuristic → Semgrep `p/*` rulesets                                                                                                                                      | `internal/pattern/semgrep/ruleset.go` |
| 6b.3 | Wire dynamic selection into Semgrep `Scan()` call                                                                                                                                             | `internal/pattern/semgrep/semgrep.go` |
| 6b.4 | Cache selection per project in DI SQLite                                                                                                                                                      | Same package                          |
| 6b.5 | Fallback: `p/owasp-top-ten` when no heuristics match                                                                                                                                          | Same package                          |

**Ruleset mapping**:

| Heuristic                      | Semgrep ruleset              |
| ------------------------------ | ---------------------------- |
| Python detected                | `p/python`, `p/flask`        |
| Java detected                  | `p/java`, `p/spring`         |
| JavaScript/TypeScript detected | `p/javascript`, `p/react`    |
| C# detected                    | `p/csharp`                   |
| SQL patterns in code           | `p/sql-injection`            |
| Web framework detected         | Framework-specific ruleset   |
| No match                       | `p/owasp-top-ten` (fallback) |

### 6c — New Tool Integrations (4.5h)

| #    | Task                                                                           | File                         |
| ---- | ------------------------------------------------------------------------------ | ---------------------------- |
| 6c.1 | gosec: Go subprocess wrapper, JSON output, normalize → unified Finding struct  | `internal/pattern/gosec/`    |
| 6c.2 | Gitleaks: binary download check, subprocess wrapper, JSON output normalization | `internal/pattern/gitleaks/` |

### 6d — Orchestrator Wiring (2h)

| #    | Task                                                       |
| ---- | ---------------------------------------------------------- |
| 6d.1 | Wire gosec into Path A (Go targets only)                   |
| 6d.2 | Wire Gitleaks into Path A (all targets)                    |
| 6d.3 | Wire dynamic Semgrep into Path A (replaces fixed rule set) |
| 6d.4 | Update dedup normalization for new tool sources            |

---

## Phase 7 — Benchmarking + Regression Gate (3h)

| #   | Task                                                        | File                                 |
| --- | ----------------------------------------------------------- | ------------------------------------ |
| 7.1 | Post-LoRA per-language F1 on test split                     | `scripts/benchmarks/corpus_bench.py` |
| 7.2 | Wall-clock, RSS, p50/p95 latency on 5K synthetic codebase   | `scripts/benchmarks/profile_scan.py` |
| 7.3 | Add `make bench` target                                     | `Makefile`                           |
| 7.4 | CI gate: F1 ≥ 0.75 per language, wall-clock ≤ 60s on 5K LOC | CI config                            |

---

## A-18 Resolution Status

| Claim          | Before                       | After                                                    |
| -------------- | ---------------------------- | -------------------------------------------------------- |
| Python F1      | Unknown (high-recall)        | ✅ Validated on test split + PrimeVul                    |
| Java F1        | Unknown (high-recall)        | ✅ Validated + OWASP Benchmark cross-check (2,741 cases) |
| JS/TS F1       | Unknown (high-recall)        | ✅ Validated                                             |
| Go F1          | Unknown (high-recall)        | ✅ Validated if ≥ 1.5K; documented gap otherwise         |
| C# F1          | Not supported (bypass → LLM) | ✅ New — validated with Juliet C# (28,942 cases)         |
| Thresholds     | 0.85/0.15 (very loose)       | ✅ Tightened to per-language empirical                   |
| LLM escalation | ~85%                         | ✅ Target: ~15-30%                                       |
| Caveat in docs | "Pending CVEFixes eval"      | ✅ Removed — replaced by per-language figures            |

---

## Files to Delete

| Path                          | Reason                                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------------------- |
| `rules/` (entire directory)   | All custom YAML rules deprecated                                                                  |
| `internal/pattern/astgrep/`   | Engine orphaned (no rules, no community registry)                                                 |
| `internal/pattern/instrscan/` | All Go-coded detection: bidi, zero-width, homoglyph, malicious directives, MCP, hallucinated deps |

## Files to Keep

| Path                            | Why                                                    |
| ------------------------------- | ------------------------------------------------------ |
| `internal/ingestion/miv/`       | Model hash verification — not a detection rule         |
| `worker/models/unixcoder.py`    | Fallback backbone if CodeT5+ LoRA fails for a language |
| `worker/models/codet5p.py`      | Primary backbone — will host LoRA adapters             |
| `worker/handlers/classify.py`   | Will be updated to support `set_adapter()`             |
| `internal/semantic/classifier/` | Go-side classifier wrapper — unchanged                 |
| `internal/pattern/joern/`       | Deep taint analysis — unchanged                        |
| `internal/pattern/opengrep/`    | Retained — will switch to dynamic `p/*` rulesets       |
| `internal/pattern/trivy/`       | Dependency vulns — unchanged                           |

---

## Summary

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
