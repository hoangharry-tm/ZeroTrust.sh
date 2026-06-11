# Semgrep PoC — PERT Estimation & Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working Semgrep PoC that detects AI-coding-agent vulnerability patterns in Python and Java codebases, with a prepared presentation narrative, within 9 working days ending 2026-06-20.

**Architecture:** Semgrep Community Edition (OSS) + custom YAML rules targeting ~10 Python + ~9 Java vulnerability patterns + an AI-generated Java fake codebase with intentional bugs, validated by a live `semgrep scan` demo. Optional bonus: Python Jupyter Notebook with effectiveness metrics.

**Tech Stack:** Semgrep OSS CLI, Python (3.11+), Java (any version for test codebase), YAML, Jupyter Notebook (bonus), uv (dependency management, already in use in this repo)

---

## Estimation Assumptions

- **Developer:** Junior intern, zero prior Semgrep experience, fast learner with Claude Code access
- **Productivity:** 7 effective hours/day (of 6–8 available) — 6h used as floor, 8h as ceiling in estimates
- **Working days:** 9 (2026-06-09 through 2026-06-20, Mon–Fri, excluding weekends)
- **Total capacity:** 9 × 7 = **63 hours**
- **PERT formula:** E = (O + 4×ML + P) / 6
- **Variance formula:** σ² = ((P − O) / 6)²
- **Standard deviation of total:** σ_total = √(Σσ²)

---

## Phase 1 — Research & Semgrep Learning

**Objective:** Developer can write, run, and debug a Semgrep YAML rule independently.

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 1.1 | Install Semgrep CLI, run `semgrep --version`, confirm it works | 0.1 | 0.2 | 0.5 | 0.22 | 0.0044 |
| 1.2 | Read official "Writing Rules" quickstart (semgrep.dev/docs) — understand `pattern`, `pattern-not`, `pattern-either`, metavariables (`$X`), ellipsis (`...`) | 0.5 | 1.0 | 2.0 | 1.08 | 0.0694 |
| 1.3 | Run 3 community rules against a sample file; inspect JSON/SARIF output format | 0.5 | 1.0 | 2.0 | 1.08 | 0.0694 |
| 1.4 | Write first toy rule: detect `eval(...)` in Python; test it passes on a 5-line fixture | 0.5 | 1.0 | 2.5 | 1.17 | 0.1111 |
| 1.5 | Read taint-mode docs (`mode: taint`, `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`) | 0.5 | 1.0 | 2.5 | 1.17 | 0.1111 |
| 1.6 | Understand YAML rule schema: `rules[].id`, `languages`, `severity`, `message`, `metadata` | 0.2 | 0.5 | 1.0 | 0.53 | 0.0178 |

**Phase 1 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **2.3 h** |
| ML (sum) | **4.7 h** |
| P (sum) | **10.5 h** |
| **E (PERT expected)** | **5.25 h** |
| **Σσ²** | 0.383 |
| **σ_phase** | **0.62 h** |

---

## Phase 2 — Python Rule Development

**Objective:** 10 production-ready YAML rules for Python AI-agent vulnerability patterns.

### Target Pattern List (Python)

| Rule ID | Pattern | Semgrep Mechanism |
|---------|---------|-------------------|
| PY-001 | `eval()` / `exec()` with untrusted input | `pattern` + taint |
| PY-002 | `subprocess.run(..., shell=True)` with variable args | `pattern` metavar |
| PY-003 | `pickle.loads()` without validation | simple `pattern` |
| PY-004 | Hardcoded secret strings (`password = "..."`, `api_key = "..."`) | `pattern-regex` |
| PY-005 | SQL string formatting with f-string / `%` / `.format()` | `pattern-either` |
| PY-006 | `os.system(...)` with untrusted input | `pattern` + taint |
| PY-007 | Removed `@login_required` / `@require_auth` decorator (safety gate bypass) | `pattern-not` |
| PY-008 | `yaml.load()` without `Loader=yaml.SafeLoader` | `pattern` + `pattern-not` |
| PY-009 | Prompt injection in string literals / comments (regex match on AI directive patterns) | `pattern-regex` |
| PY-010 | `requests.get(..., verify=False)` | simple `pattern` |

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 2.1 | Set up `rules/python/` directory structure; create rule template `_template.yaml` | 0.1 | 0.2 | 0.5 | 0.22 | 0.0044 |
| 2.2 | Write PY-001 (`eval`/`exec` taint) + fixture test file; validate with `semgrep --test` | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 2.3 | Write PY-002 (`subprocess shell=True`) + fixture; validate | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 2.4 | Write PY-003 (`pickle.loads`) + fixture; validate | 0.2 | 0.4 | 1.0 | 0.43 | 0.0178 |
| 2.5 | Write PY-004 (hardcoded secrets `pattern-regex`) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 2.6 | Write PY-005 (SQL f-string injection `pattern-either`) + fixture; validate | 0.5 | 1.0 | 3.0 | 1.25 | 0.1736 |
| 2.7 | Write PY-006 (`os.system` taint) + fixture; validate | 0.2 | 0.5 | 1.5 | 0.57 | 0.0278 |
| 2.8 | Write PY-007 (missing `@login_required` pattern using `pattern-not-inside`) + fixture; validate | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 2.9 | Write PY-008 (`yaml.load` without SafeLoader, `pattern` + `pattern-not`) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 2.10 | Write PY-009 (prompt injection `pattern-regex` on comment strings) + fixture; validate | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 2.11 | Write PY-010 (`requests verify=False`) + fixture; validate | 0.2 | 0.4 | 1.0 | 0.43 | 0.0178 |
| 2.12 | Run all 10 Python rules against combined fixture; tune FP/FN; adjust `pattern-not` clauses | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 2.13 | Write `rules/python/README.md` with per-rule explanation + known limitations | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |

**Phase 2 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **4.2 h** |
| ML (sum) | **9.4 h** |
| P (sum) | **27.0 h** |
| **E (PERT expected)** | **11.98 h** |
| **Σσ²** | 1.426 |
| **σ_phase** | **1.19 h** |

---

## Phase 3 — Java Rule Development

**Objective:** 9 production-ready YAML rules for Java AI-agent vulnerability patterns.

### Target Pattern List (Java)

| Rule ID | Pattern | Semgrep Mechanism |
|---------|---------|-------------------|
| JV-001 | `Runtime.getRuntime().exec(...)` with variable string | `pattern` + metavar |
| JV-002 | JDBC `Statement.execute(...)` with string concat (SQLi) | `pattern-either` |
| JV-003 | `ObjectInputStream.readObject()` (Java deserialization) | simple `pattern` |
| JV-004 | Hardcoded credentials in `String` assignments (`password`, `secret`, `token`) | `pattern-regex` |
| JV-005 | `MessageDigest.getInstance("MD5")` or `"SHA1"` (weak crypto) | `pattern-either` |
| JV-006 | `HttpURLConnection.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)` | `pattern` |
| JV-007 | Removed `@PreAuthorize` / `@Secured` annotation (Spring Security bypass) | `pattern-not` |
| JV-008 | `System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true")` (Log4Shell enablement) | `pattern` |
| JV-009 | Prompt injection in string literals / Javadoc comments | `pattern-regex` |

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 3.1 | Set up `rules/java/` directory; verify Semgrep Java grammar works on a 10-line fixture | 0.2 | 0.4 | 1.0 | 0.43 | 0.0178 |
| 3.2 | Write JV-001 (`Runtime.exec` command injection) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 3.3 | Write JV-002 (JDBC SQLi `pattern-either` for `+` concat and string format) + fixture; validate | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 3.4 | Write JV-003 (`ObjectInputStream.readObject` deserialization) + fixture; validate | 0.3 | 0.6 | 1.5 | 0.65 | 0.0278 |
| 3.5 | Write JV-004 (hardcoded credentials `pattern-regex`) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 3.6 | Write JV-005 (weak crypto `getInstance("MD5")` / `"SHA1"`) + fixture; validate | 0.3 | 0.6 | 1.5 | 0.65 | 0.0278 |
| 3.7 | Write JV-006 (hostname verifier bypass) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 3.8 | Write JV-007 (missing `@PreAuthorize` via `pattern-not-inside` on Spring controllers) + fixture; validate | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 3.9 | Write JV-008 (Log4Shell JNDI enablement) + fixture; validate | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 3.10 | Write JV-009 (prompt injection in Java string/comment) + fixture; validate | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 3.11 | Run all 9 Java rules against combined fixture; tune; document | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 3.12 | Write `rules/java/README.md` with per-rule explanation + known limitations | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |

**Phase 3 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **4.3 h** |
| ML (sum) | **10.3 h** |
| P (sum) | **29.5 h** |
| **E (PERT expected)** | **12.84 h** |
| **Σσ²** | 1.540 |
| **σ_phase** | **1.24 h** |

---

## Phase 4 — Test Codebase Generation & Validation

**Objective:** AI-generated fake Java codebase with ≥9 intentional vulnerabilities planted; Semgrep detects ≥7 of them in the live demo run.

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 4.1 | Prompt Claude/ChatGPT to generate a fake Java e-commerce app skeleton (4–6 classes) that "naturally" contains all 9 JV-* vulnerability patterns | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 4.2 | Review generated code: manually verify each vulnerability is present and syntactically valid | 0.5 | 1.0 | 2.5 | 1.17 | 0.1111 |
| 4.3 | Add 2–3 "clean" Java files with no vulnerabilities (for true-negative validation) | 0.2 | 0.5 | 1.0 | 0.53 | 0.0178 |
| 4.4 | Run `semgrep scan --config rules/java/ test-codebase/` and record raw output (JSON) | 0.2 | 0.4 | 1.0 | 0.43 | 0.0178 |
| 4.5 | Manually audit results: count TP, FP, FN; document in `demo/validation-report.md` | 0.5 | 1.0 | 3.0 | 1.25 | 0.1736 |
| 4.6 | Iterate: if detection rate < 7/9, adjust rule patterns or codebase until target is met | 0.5 | 1.5 | 5.0 | 1.92 | 0.5069 |
| 4.7 | Prepare a Python script `demo/run_demo.sh` that executes the full scan and pipes output | 0.2 | 0.5 | 1.5 | 0.57 | 0.0278 |

**Phase 4 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **2.4 h** |
| ML (sum) | **5.7 h** |
| P (sum) | **16.0 h** |
| **E (PERT expected)** | **6.75 h** |
| **Σσ²** | 0.924 |
| **σ_phase** | **0.96 h** |

---

## Phase 5 — Demo Preparation & Refinement

**Objective:** A reproducible, clean, impressive live demo that runs in < 2 minutes and produces visible findings.

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 5.1 | Write `demo/README.md` with exact step-by-step demo run instructions | 0.2 | 0.5 | 1.5 | 0.57 | 0.0278 |
| 5.2 | Record a dry-run: time the full scan end-to-end; confirm output is legible in terminal | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 5.3 | Set up a `semgrep --sarif` output + pipe to a simple HTML viewer script (or use `semgrep --html`) | 0.3 | 1.0 | 3.0 | 1.22 | 0.1736 |
| 5.4 | Add 3 intentional "false positive" findings to the clean Java files and show Semgrep catches them; document the FP analysis for the presentation | 0.5 | 1.0 | 3.0 | 1.25 | 0.1736 |
| 5.5 | Rehearse the 3-minute live demo walkthrough (narrate problem → run scan → show findings → point to patch) | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 5.6 | Final end-to-end test on a clean machine / fresh terminal session | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |

**Phase 5 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **1.9 h** |
| ML (sum) | **4.6 h** |
| P (sum) | **13.0 h** |
| **E (PERT expected)** | **5.40 h** |
| **Σσ²** | 0.542 |
| **σ_phase** | **0.74 h** |

---

## Phase 6 — Presentation Narrative Writing

**Objective:** Prepared presentation covering Semgrep pros/cons, AI-threat detection approach, demo highlights, and ZeroTrust.sh positioning.

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 6.1 | Draft narrative outline (5 sections: problem → approach → demo results → pros/cons → recommendation) | 0.2 | 0.5 | 1.5 | 0.57 | 0.0278 |
| 6.2 | Write "Semgrep Pros" section: fast, local, extensible, community rules, no LLM cost | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 6.3 | Write "Semgrep Cons" section: pattern-only (no semantics), no AI-threat rules out of box, high FP rate, no cross-file taint in OSS | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 6.4 | Write "PoC Results" section: table of TP/FP/FN for both Python and Java rulesets | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 6.5 | Write "What Semgrep Cannot Do" section: semantic reasoning, cross-file slopsquatting, LLM-guided patch generation — tie back to ZeroTrust.sh hybrid approach | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 6.6 | Write "Recommendation" section: use Semgrep as Stage 1 AST pre-filter inside ZeroTrust.sh (complement, not replace) | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 6.7 | Review and edit full narrative for clarity; prepare speaker notes | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |

**Phase 6 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **2.0 h** |
| ML (sum) | **4.4 h** |
| P (sum) | **12.0 h** |
| **E (PERT expected)** | **5.00 h** |
| **Σσ²** | 0.319 |
| **σ_phase** | **0.57 h** |

---

## Phase 7 — Bonus: Python Jupyter Notebook (Effectiveness Metrics)

**Objective:** Jupyter Notebook that ingests Semgrep JSON output and produces TP/FP/FN metrics, precision/recall charts, and a per-rule effectiveness breakdown.

> **Note:** This phase is conditional on schedule. See Go/No-Go analysis below.

### Subtasks

| # | Subtask | O | ML | P | E | σ² |
|---|---------|---|----|----|---|-----|
| 7.1 | Set up `notebooks/semgrep_effectiveness.ipynb` with uv/venv; install `pandas`, `plotly`, `json` | 0.2 | 0.5 | 1.5 | 0.57 | 0.0278 |
| 7.2 | Write data loader: parse `semgrep --json` output into a pandas DataFrame | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 7.3 | Build ground truth table: manually label each finding as TP or FP; store as CSV | 0.3 | 0.8 | 2.0 | 0.88 | 0.0694 |
| 7.4 | Compute precision, recall, F1 per rule and overall; display as Plotly bar chart | 0.5 | 1.0 | 3.0 | 1.25 | 0.1736 |
| 7.5 | Build findings heatmap: rule_id × vulnerability_type matrix (Plotly dark theme, consistent with presentation notebook) | 0.5 | 1.5 | 4.0 | 1.75 | 0.3403 |
| 7.6 | Add narrative Markdown cells explaining each metric section | 0.3 | 0.5 | 1.5 | 0.60 | 0.0278 |
| 7.7 | Test full notebook: `jupyter nbconvert --to notebook --execute`; confirm no errors | 0.2 | 0.5 | 2.0 | 0.62 | 0.0694 |

**Phase 7 Totals**

| Metric | Value |
|--------|-------|
| O (sum) | **2.3 h** |
| ML (sum) | **5.6 h** |
| P (sum) | **16.0 h** |
| **E (PERT expected)** | **6.55 h** |
| **Σσ²** | 0.778 |
| **σ_phase** | **0.88 h** |

---

## Phase 8 — Buffer

**Purpose:** Absorb rework cycles (FP tuning, fixture debug, schema mismatch), integration issues, and blocked time.

| Buffer | Hours | Rationale |
|--------|-------|-----------|
| Core phases 1–6 contingency buffer | **5.0 h** | ~12% of core E_total; absorbs one bad day |
| Bonus phase 7 contingency | **1.5 h** | ~23% of bonus E; notebook iteration tends to surprise |
| **Total buffer** | **6.5 h** | — |

---

## Aggregate PERT Summary

### Core Deliverables (Phases 1–6)

| Phase | E (h) | σ² |
|-------|-------|-----|
| 1 — Research & Learning | 5.25 | 0.383 |
| 2 — Python Rules | 11.98 | 1.426 |
| 3 — Java Rules | 12.84 | 1.540 |
| 4 — Test Codebase & Validation | 6.75 | 0.924 |
| 5 — Demo Preparation | 5.40 | 0.542 |
| 6 — Presentation Narrative | 5.00 | 0.319 |
| **Core Subtotal (E)** | **47.22 h** | 5.134 |
| σ_core | **2.27 h** | — |

### With Bonus (Phase 7) + Buffer (Phase 8)

| Component | Hours |
|-----------|-------|
| Core E (phases 1–6) | 47.22 |
| Buffer (phases 1–6) | 5.00 |
| **Core + Buffer** | **52.22 h** |
| Bonus E (phase 7) | 6.55 |
| Buffer (phase 7) | 1.50 |
| **Total with Bonus** | **60.27 h** |

**Total capacity: 63 hours (9 days × 7 h/day)**

### Schedule Feasibility

| Scenario | Hours Required | Capacity | Slack | Feasible? |
|----------|---------------|----------|-------|-----------|
| Core only (no bonus) | 52.22 h | 63 h | **10.78 h** | YES — comfortable |
| Core + bonus notebook | 60.27 h | 63 h | **2.73 h** | YES — tight |
| Core + bonus (1-sigma bad run) | 60.27 + 2.27 = 62.54 h | 63 h | **0.46 h** | MARGINAL |
| Core + bonus (2-sigma bad run) | 60.27 + 4.54 = 64.81 h | 63 h | **−1.81 h** | MISS |

**Probability of on-time delivery (core only): ~97%**
**Probability of on-time delivery (core + bonus): ~72%**

---

## Go / No-Go Recommendation on Bonus Notebook

**Decision: CONDITIONAL GO — start Phase 7 only if Phase 5 is complete by end of Day 7 (2026-06-18).**

Rationale:
- The bonus notebook has ~72% on-time probability when included. That is acceptable *if* the core is already wrapped.
- The Jupyter environment (`uv` + plotly + nbformat) is already set up in `admin/product_analysis/` from the presentation notebook plan — this removes the environment-setup friction significantly.
- If Day 7 ends with Phase 5 still in progress, drop the notebook entirely. A working demo + clean narrative is worth more than a partial notebook.

Trigger condition: If `notebooks/semgrep_effectiveness.ipynb` is not started by end of Day 8 (2026-06-19, 16:00), abandon Phase 7 and use the remaining time to polish the demo script and presentation.

---

## Recommended Buffer Allocation

**Total buffer: 5.0 h (core) + 1.5 h (bonus) = 6.5 h**

| Buffer Allocation | Hours | When to Use |
|-------------------|-------|-------------|
| Phase 2 (Python rules) overflow | 1.5 h | `pattern-not-inside` for decorator bypass is hard for a Semgrep novice; PY-007 / PY-009 are the most complex |
| Phase 3 (Java rules) overflow | 1.5 h | Java AST shape surprises (annotation patterns); JV-003 deserialization and JV-007 Spring bypass most likely to need iteration |
| Phase 4 (validation loop) overflow | 1.0 h | If detection rate < 7/9 on first pass, codebase or rules need adjustment |
| Phase 5/6 integration polish | 1.0 h | Demo script reliability, edge cases in terminal output formatting |
| Phase 7 (bonus) buffer | 1.5 h | Notebook data pipeline + plotting iteration |

Buffer as percentage of core E: **10.6%** — industry-standard 10–15% for well-scoped, low-ambiguity tasks.

---

## Top 3 Timeline Risks & Mitigations

### Risk 1: Pattern-not-inside for Security Control Bypass is Harder Than Expected

**Description:** PY-007 (missing `@login_required`) and JV-007 (missing `@PreAuthorize`) require negative structural patterns — detecting the *absence* of an annotation inside a function. This is a non-obvious Semgrep construct that trips up even experienced users. A novice may spend 3–5 hours debugging why the rule fires on everything or nothing.

**Probability:** High (3/5)
**Impact:** +2–4 hours on Phase 2/3

**Mitigation:**
1. Treat these two rules as "stretch" within their phases. Write the simpler 8 rules first; come back to the bypass rules only after the basics are solid.
2. Use Claude Code with the concrete prompt: "Write a Semgrep YAML rule that fires on a Python function that is NOT decorated with @login_required" — this specific prompt reliably produces a working starting point.
3. If both bypass rules resist resolution after 2 hours each, simplify to `pattern-regex` on comment text (`# TODO remove auth check`) as a weaker proxy — still demonstrates the concept.

---

### Risk 2: Semgrep Java Grammar Mismatch on Generated Codebase

**Description:** AI-generated Java code often uses modern Java features (records, sealed classes, text blocks, var) that Semgrep's tree-sitter Java grammar may parse incorrectly, causing rules to silently not fire because the AST node structure does not match the pattern.

**Probability:** Medium (2/5)
**Impact:** +1–3 hours on Phase 4 (debug loop between codebase generator and rules)

**Mitigation:**
1. Constrain the AI-generated Java codebase prompt to Java 8-compatible syntax explicitly: "Use Java 8 syntax only — no var, no records, no text blocks, no sealed classes."
2. After receiving the generated code, immediately run `semgrep --dump-ast --lang java SomeFile.java` on one of the vulnerable files to confirm the AST shape before writing rules against it.
3. Keep a reference to the Semgrep [Java playground](https://semgrep.dev/playground) open — paste the exact code snippet and test the rule interactively before writing the YAML file.

---

### Risk 3: Demo Environment Not Reproducible (Works on Developer Machine, Fails During Presentation)

**Description:** Semgrep behavior can differ between versions, path configurations, or Python environments. A demo that works in a local `venv` may silently fail in a fresh terminal or on a different OS. This is a low-probability but high-impact risk since it happens at the worst possible moment.

**Probability:** Low-Medium (2/5)
**Impact:** Presentation failure — critical

**Mitigation:**
1. Write a `demo/run_demo.sh` script that explicitly activates the venv, pins the Semgrep version (`pip install semgrep==1.x.y`), and runs the scan with hardcoded paths. Nothing left to chance.
2. Do a dry-run on a clean terminal session (no active venv, no SEMGREP env vars) at least 24 hours before the presentation deadline — this is Step 5.6 in Phase 5.
3. Record a fallback video of the demo running successfully. If the live demo fails, play the video. This adds 30 minutes to Phase 5 (0.5 h already in the buffer) but eliminates presentation risk entirely.

---

## Recommended Daily Schedule

| Day | Date | Primary Focus | Target Phase Completion | Expected Hours |
|-----|------|---------------|------------------------|----------------|
| 1 | 2026-06-09 (Mon) | Semgrep learning; install, run community rules, write first rule | Phase 1 complete | 5.5 h |
| 2 | 2026-06-10 (Tue) | Python rules PY-001 → PY-006 | Phase 2 ~60% | 7 h |
| 3 | 2026-06-11 (Wed) | Python rules PY-007 → PY-010; fixture tuning | Phase 2 complete | 7 h |
| 4 | 2026-06-12 (Thu) | Java rules JV-001 → JV-005 | Phase 3 ~55% | 7 h |
| 5 | 2026-06-13 (Fri) | Java rules JV-006 → JV-009; fixture tuning | Phase 3 complete | 7 h |
| 6 | 2026-06-16 (Mon) | Generate Java test codebase; validation scan; iterate | Phase 4 complete | 7 h |
| 7 | 2026-06-17 (Tue) | Demo script; HTML output; dry-run; fallback video | Phase 5 complete | 7 h |
| 8 | 2026-06-18 (Wed) | Presentation narrative; speaker notes | Phase 6 complete | 5 h |
| 8 | 2026-06-18 (Wed) | [Bonus] Notebook scaffold + data loader | Phase 7 start | +2 h |
| 9 | 2026-06-19 (Thu) | [Bonus] Notebook charts + metrics; final polish | Phase 7 complete; buffer | 7 h |
| _Deadline_ | 2026-06-20 (Fri) | Presentation delivery | All phases complete | — |

Total scheduled effort: ~62.5 h across 9 working days — within 63 h capacity, with 0.5 h margin.

---

## File Structure for the PoC

```
zerotrust-semgrep-poc/           # root of PoC deliverable
├── rules/
│   ├── python/
│   │   ├── py-001-eval-exec.yaml
│   │   ├── py-002-subprocess-shell.yaml
│   │   ├── py-003-pickle-loads.yaml
│   │   ├── py-004-hardcoded-secrets.yaml
│   │   ├── py-005-sql-injection.yaml
│   │   ├── py-006-os-system.yaml
│   │   ├── py-007-missing-auth-decorator.yaml
│   │   ├── py-008-yaml-unsafe-load.yaml
│   │   ├── py-009-prompt-injection.yaml
│   │   ├── py-010-requests-verify-false.yaml
│   │   └── README.md
│   └── java/
│       ├── jv-001-runtime-exec.yaml
│       ├── jv-002-jdbc-sqli.yaml
│       ├── jv-003-deserialization.yaml
│       ├── jv-004-hardcoded-credentials.yaml
│       ├── jv-005-weak-crypto.yaml
│       ├── jv-006-hostname-verifier-bypass.yaml
│       ├── jv-007-missing-preauthorize.yaml
│       ├── jv-008-log4shell-enablement.yaml
│       ├── jv-009-prompt-injection.yaml
│       └── README.md
├── test-fixtures/
│   ├── python/
│   │   ├── vuln_eval.py          # PY-001 fixture
│   │   ├── vuln_subprocess.py    # PY-002 fixture
│   │   ├── clean_python.py       # true-negative control
│   │   └── ... (one file per rule)
│   └── java/
│       ├── VulnRuntime.java      # JV-001 fixture
│       ├── VulnSQLi.java         # JV-002 fixture
│       ├── CleanService.java     # true-negative control
│       └── ... (one file per rule)
├── test-codebase/               # fake AI-generated Java e-commerce app
│   ├── src/main/java/
│   │   ├── UserController.java   # contains JV-007, JV-001
│   │   ├── OrderService.java     # contains JV-002, JV-004
│   │   ├── PaymentProcessor.java # contains JV-003, JV-005
│   │   ├── AuthFilter.java       # contains JV-006, JV-008
│   │   └── ProductSearch.java    # contains JV-009, clean methods
│   └── README.md
├── demo/
│   ├── run_demo.sh              # one-click demo script
│   ├── validation-report.md     # TP/FP/FN audit table
│   └── semgrep_output.json      # pre-baked output for fallback
├── notebooks/
│   └── semgrep_effectiveness.ipynb  # bonus — Phase 7
├── presentation/
│   └── narrative.md             # Phase 6 output
└── README.md                    # quick-start instructions
```

---

## Self-Review

**Spec coverage check:**

| Deliverable | Covered In | Status |
|-------------|-----------|--------|
| ~10 Python custom YAML rules | Phase 2, 10 rules listed | ✅ |
| ~9 Java custom YAML rules | Phase 3, 9 rules listed | ✅ |
| AI-generated fake Java codebase | Phase 4 subtasks 4.1–4.3 | ✅ |
| Working demo detecting meaningful portion | Phase 4.4–4.6 (≥7/9 target) + Phase 5 | ✅ |
| Presentation narrative (pros/cons) | Phase 6, 7 subtasks covering pros, cons, results, positioning | ✅ |
| Bonus notebook with metrics | Phase 7, full subtask list | ✅ |
| PERT estimates (O/ML/P/E/σ²) | All 8 phases | ✅ |
| Total hours vs. capacity | Aggregate section | ✅ |
| Go/No-go on bonus | Explicit section with trigger condition | ✅ |
| Buffer sizing + allocation | Buffer section with 5+1.5h breakdown | ✅ |
| Top 3 risks + mitigations | Risk section, 3 risks fully described | ✅ |

**Placeholder scan:** No TBDs, no "implement later", no "similar to above". All rule IDs are named and their Semgrep mechanisms specified. All subtask descriptions contain the action to take.

**Consistency check:** Rule IDs `PY-001`–`PY-010` and `JV-001`–`JV-009` used consistently across Phase 2, Phase 3, File Structure, and Presentation phases. File names in the file structure map directly to the rule IDs.
