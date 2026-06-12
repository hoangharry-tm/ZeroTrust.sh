# G4 — Integration, Report & Demo
**Goal window**: 2026-08-01 → 2026-08-06 · 5 days · ~34 committed hours (+ ~15h stretch)
**Demo deadline**: 2026-08-06
**Submission cutoff**: 2026-08-08
**Prerequisite**: G3 complete — Path B funnel runs end-to-end, findings flowing into Finding channel from both paths. HTML report shell and SSVC dedup skeleton must be pre-stubbed during G3's final week (Jul 28–31) in parallel with M3.3/M3.4 — if not done, this 5-day window will overrun.
**Checkpoint**: `zerotrust scan ./target` produces a valid interactive HTML report with SSVC-scored findings and patch suggestions. This is the demo artifact for 2026-08-06.

> **M4.4 PoE Layer is stretch — cut first.** Cut condition: if any G3 M3.4 task is incomplete by Aug 1, do not attempt M4.4. Static evidence output from M4.1–M4.3 is a complete, demo-worthy deliverable on its own.

---

## Column Guide

| Column | Description |
|---|---|
| **ID** | `4.Mx` = milestone · `4.Mx.Ty` = task · `4.BUF` = buffer row |
| **Name** | Plain English — no jargon |
| **Type** | `MILESTONE` · `TASK` · `BUFFER` · `STRETCH` |
| **Start Date** | `YYYY-MM-DD` |
| **End Date** | `YYYY-MM-DD` (inclusive) |
| **O** | Optimistic hours (PERT) — committed milestone rows only |
| **ML** | Most Likely hours (PERT) — committed milestone rows only |
| **P** | Pessimistic hours (PERT) — committed milestone rows only |
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
| **4.M1** | **Dedup + SSVC Confidence Scoring** | MILESTONE | 2026-08-01 | 2026-08-03 | 6 | 10 | 16 | 10.3 | | Not Started | Hoang | Skeleton should be pre-stubbed during G3 final week; merges Path A + Path B findings into unified 5-tier output |
| 4.M1.T1 | Dedup — AST edit distance comparison | TASK | 2026-08-01 | 2026-08-01 | — | — | — | 2.0 | | Not Started | Hoang | Compare evidence snippets from Path A and Path B findings; collapse duplicates above edit-distance threshold; use golang.org/x/text or simple Levenshtein |
| 4.M1.T2 | Dedup — CWE pattern hash | TASK | 2026-08-01 | 2026-08-02 | — | — | — | 1.5 | | Not Started | Hoang | Hash: CWE ID + file path + line range; collapse findings with identical hash; fastest dedup pass, runs first |
| 4.M1.T3 | Dedup — LLM semantic similarity check (Python worker call) | TASK | 2026-08-02 | 2026-08-02 | — | — | — | 2.0 | | Not Started | Hoang | For findings not collapsed by T1/T2: send both evidence snippets to Python worker; embed + cosine similarity; collapse if similarity > threshold; `dedup_check` type in NDJSON protocol |
| 4.M1.T4 | SSVC dimension mapping → 5-tier score assignment | TASK | 2026-08-02 | 2026-08-03 | — | — | — | 2.0 | | Not Started | Hoang | Dimensions: Exploitation (active/PoC/none from OSV-Scanner EPSS), Automatable (yes/no from taint path), Technical Impact (total/partial from sink type); map to BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED |
| 4.M1.T5 | Cross-path confirmation boost (+15% for findings confirmed by both paths) | TASK | 2026-08-03 | 2026-08-03 | — | — | — | 1.0 | | Not Started | Hoang | If same finding appears in Path A output and Path B output (after dedup): boost SSVC score by +15%; this is a strong signal — both independent engines flagged it |
| 4.M1.T6 | Suppression rules + dedup test suite | TASK | 2026-08-03 | 2026-08-03 | — | — | — | 1.8 | | Not Started | Hoang | Suppress: findings in test files (`_test.go`, `test_*.py`), framework-safe functions (e.g. `db.QueryRow` with parameterized query); test suite: 5+ dedup cases, 3+ suppression cases |
| **4.M2** | **HTML Report Generator + Patch Suggestions** | MILESTONE | 2026-08-03 | 2026-08-04 | 6 | 10 | 16 | 10.3 | | Not Started | Hoang | Go html/template + embed only — no Jinja2, no Python dependency; output is a single portable .html file; Claude Code helps with template generation |
| 4.M2.T1 | Go html/template structure + embed setup | TASK | 2026-08-03 | 2026-08-04 | — | — | — | 3.0 | | Not Started | Hoang | `//go:embed templates/*`; base template with header, severity sections, finding cards; CSS inlined for self-contained output; no CDN dependencies |
| 4.M2.T2 | Finding list serialization to HTML (severity groups, collapsible evidence panels) | TASK | 2026-08-04 | 2026-08-04 | — | — | — | 2.0 | | Not Started | Hoang | Group findings by SSVC tier (BLOCK first); each finding card: file + line, CWE, rationale, evidence snippet, taint path, patch suggestion; collapsible via `<details>` |
| 4.M2.T3 | Filter/sort controls (vanilla JS — no framework) | TASK | 2026-08-04 | 2026-08-04 | — | — | — | 2.5 | | Not Started | Hoang | Filter by: severity tier, CWE, file path; sort by: SSVC score, file name; ~50 lines of vanilla JS; no React/Vue/jQuery — keeps report self-contained |
| 4.M2.T4 | SSVC score visualization (severity tier badges + dimension breakdown) | TASK | 2026-08-04 | 2026-08-04 | — | — | — | 1.0 | | Not Started | Hoang | Colored badge per tier (BLOCK=red, HIGH=orange, MEDIUM=yellow, LOW=blue, SUPPRESSED=grey); tooltip shows Exploitation/Automatable/Technical Impact dimension values |
| 4.M2.T5 | Patch suggestion prompt template + unified diff output (Python worker call) | TASK | 2026-08-04 | 2026-08-04 | — | — | — | 1.8 | | Not Started | Hoang | Zero-shot LLM call via `patch_suggest` type in Python worker; prompt: finding rationale + code context; output: unified diff (`--- a/file +++ b/file`); append to each finding card in HTML |
| **4.M3** | **End-to-End Demo Run + Hardening** | MILESTONE | 2026-08-04 | 2026-08-06 | 6 | 10 | 16 | 10.3 | | Not Started | Hoang | Final gate before demo; `zerotrust scan ./target` must work end-to-end on at least 2 codebases; timing must be acceptable (< 10 min on test codebase) |
| 4.M3.T1 | Source or build 2–3 realistic AI-generated vulnerable codebases | TASK | 2026-08-04 | 2026-08-05 | — | — | — | 2.5 | | Not Started | Hoang | Languages: Python (FastAPI/Flask), Go (net/http), Java (Spring Boot); vulnerabilities: SQL injection, missing auth guard, hardcoded API key, prompt injection via agent config; use real AI-agent-generated code where possible |
| 4.M3.T2 | Full pipeline run on each target codebase | TASK | 2026-08-05 | 2026-08-05 | — | — | — | 2.0 | | Not Started | Hoang | Run `zerotrust scan ./target` end-to-end; verify: GGUF verified at startup, dirty files only re-scanned, Path A + Path B findings produced, HTML report generated |
| 4.M3.T3 | Integration break fixes | TASK | 2026-08-05 | 2026-08-06 | — | — | — | 2.0 | | Not Started | Hoang | Resolve any pipeline failures from T2; if a fix exceeds 2h, escalate as At Risk and consume buffer; do not introduce new features during fixes |
| 4.M3.T4 | Scan timing measurement (wall clock + per-component breakdown) | TASK | 2026-08-06 | 2026-08-06 | — | — | — | 1.0 | | Not Started | Hoang | Instrument: CPG build time, classifier gate time, LLM call time, total wall clock; target total < 10 min on test codebase; log in docs/benchmarks/g4_scan_timing.md |
| 4.M3.T5 | Demo script + rehearsal run | TASK | 2026-08-06 | 2026-08-06 | — | — | — | 2.8 | | Not Started | Hoang | Script covers: (1) what vulnerability was detected and where, (2) cost funnel: X% of surfaces reached LLM, (3) SSVC score explanation, (4) patch suggestion diff, (5) model integrity verification demo; rehearse 1× end-to-end |
| **4.M4** | **PoE Layer — Red Team Agent + Docker Sandbox** | STRETCH | 2026-08-04 | 2026-08-06 | — | — | — | 15.0 | | Not Started | Hoang | **STRETCH — CUT FIRST.** Do not attempt if any G3 M3.4 task is incomplete on Aug 1. Parallel with M4.3 if attempted. |
| 4.M4.T1 | LangGraph workflow setup (Recon → Exploit → Verify graph nodes) | TASK | 2026-08-04 | 2026-08-04 | — | — | — | 4.0 | | Not Started | Hoang | STRETCH; Python LangGraph v1.0; 3 nodes with typed state: Reconnaissance (gather context), Exploitation (generate exploit), Verification (confirm via sandbox); state machine transitions |
| 4.M4.T2 | Docker sandbox: container spec + seccomp profile (network isolation) | TASK | 2026-08-04 | 2026-08-05 | — | — | — | 3.5 | | Not Started | Hoang | STRETCH; Go Docker SDK; container: no network, no root, seccomp deny-list; volume mount: target codebase read-only; output: exit code + stdout + stderr |
| 4.M4.T3 | Docker sandbox: attempt-trigger logic for BLOCK/HIGH findings | TASK | 2026-08-05 | 2026-08-05 | — | — | — | 3.5 | | Not Started | Hoang | STRETCH; LangGraph Exploitation node generates exploit code; passes to sandbox container; captures execution result; timeout = 30s per attempt |
| 4.M4.T4 | Two-layer PoE output (technical trace + executive summary) | TASK | 2026-08-05 | 2026-08-06 | — | — | — | 2.5 | | Not Started | Hoang | STRETCH; technical trace: exploit code, execution log, sandbox exit code; executive summary: vulnerability name, business impact, exploitability confirmed/unconfirmed; both appended to HTML report |
| 4.M4.T5 | Static-evidence fallback when sandbox execution fails | TASK | 2026-08-06 | 2026-08-06 | — | — | — | 1.5 | | Not Started | Hoang | STRETCH; if sandbox exits non-zero or times out: emit "Static evidence only — sandbox execution failed" in PoE section; degrade gracefully, never crash the report |
| **4.BUF** | **G4 Buffer** | BUFFER | 2026-08-01 | 2026-08-06 | — | — | — | 3.0 | | | Hoang | Tight 10% buffer; primary absorption: integration breaks in M4.3; if M4.4 is not attempted, its 15h effectively become additional buffer for M4.1–M4.3 hardening |

---

## G4 Totals

| | O (hrs) | ML (hrs) | P (hrs) | E (hrs) |
|---|---|---|---|---|
| 4.M1 — Dedup + SSVC Confidence Scoring | 6 | 10 | 16 | 10.3 |
| 4.M2 — HTML Report Generator + Patch Suggestions | 6 | 10 | 16 | 10.3 |
| 4.M3 — End-to-End Demo Run + Hardening | 6 | 10 | 16 | 10.3 |
| **Subtotal committed (milestones)** | **18** | **30** | **48** | **30.9** |
| 4.BUF — Buffer (explicit row) | — | — | — | 3.0 |
| **G4 Committed Total** | — | — | — | **33.9** |
| 4.M4 — PoE Layer (stretch, if attempted) | — | — | — | 15.0 |

---

## Task Count

| Milestone | Tasks (committed) | Tasks (stretch) |
|---|---|---|
| 4.M1 | 6 | 0 |
| 4.M2 | 5 | 0 |
| 4.M3 | 5 | 0 |
| 4.M4 | 0 | 5 |
| **Total** | **16 committed + 5 stretch = 21 tasks + 4 milestones + 1 buffer = 26 rows** | |

---

## Full Plan Summary (all goals)

| Goal | Window | Working Days | Committed Hrs | Risk |
|---|---|---|---|---|
| G1 — Foundation & Detection Scaffold | Jun 11 – Jun 27 | 13 | 78 | Low |
| G2 — Path A: CPG + Taint + LLM Verifier | Jun 30 – Jul 18 | 15 | 101 | Medium |
| G3 — Path B: Semantic Cost Funnel | Jul 21 – Aug 1 | 10 | 87 | High |
| G4 — Integration, Report & Demo | Aug 1 – Aug 6 | 5 | 34 | High |
| **Total** | **Jun 11 – Aug 6** | **43** | **~300** | — |

> Gross capacity (6h/day × 56 calendar days): ~336h. Committed: ~300h. Remaining headroom: ~36h (~11%).

---

## Pre-Stub Schedule (R-03 Mitigation)

These tasks from G4 should be partially stubbed during G3's final week (Jul 28–31) in parallel with M3.3/M3.4 to avoid G4 window overrun:

| Pre-stub target | Stub during | What to pre-build |
|---|---|---|
| 4.M1 (SSVC dedup skeleton) | Jul 28–29, parallel with 3.M3 | Empty dedup function signatures + SSVC constant definitions + 5-tier score type |
| 4.M2 (HTML report shell) | Jul 30–31, parallel with 3.M3–3.M4 | Base HTML template file, Go embed setup, empty finding card template |

---

## Inter-Goal Dependencies

| G4 Component | Depends on (G3) | Final output |
|---|---|---|
| Dedup (4.M1) | Path A findings (2.M4), Path B findings (3.M4) | Unified deduplicated finding list |
| SSVC scoring (4.M1.T4) | OSV-Scanner EPSS data (3.M1.T5), taint path (2.M2), sink type (2.M2.T1) | 5-tier scored finding list |
| HTML report (4.M2) | Dedup output (4.M1), patch suggestion via Python worker (2.M3) | Single portable .html file |
| Demo targets (4.M3.T1) | Full pipeline operational | 2–3 AI-generated vulnerable codebases |
| PoE Layer (4.M4) | All of G3 M3.4 complete, Docker available | Two-layer PoE document (stretch only) |

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
