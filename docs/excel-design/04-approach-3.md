# Sheet 4 — Approach 3: Agentic Scanner with Proof-of-Exploit

**Sheet name:** `Approach 3 - Agentic Scanner`
**Goal ID:** 3
**Goal name:** Approach 3 — Agentic Scanner with Proof-of-Exploit
**Description:** Extend the Approach 2 scanner with a fully realized Path A (CodeQL + Joern taint flow in parallel with Semgrep), complete Path B (call graph + CVE enrichment fully integrated), and a Proof-of-Exploit layer — a LangGraph Red Team Agent that dispatches a Docker sandbox to attempt exploit execution and produces a two-layer PoE output (technical trace for developers, executive summary for managers).
**Date range:** 2026-07-21 → 2026-08-01
**Total milestones:** 8
**Total tasks:** 28
**Constraint:** 9 working days (54 h capacity). Total PERT E = 61.4 h — ~14% over capacity. Risk absorbed by M7 integration buffer; intern must flag blockers by day 3 if M2 is behind.

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Approach 3 — Agentic Scanner with Proof-of-Exploit` | 20pt bold white on `#1F3864`, height 50px |
| 2 | `Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Full PoE verification pipeline  ·  Deadline: 2026-08-01` | 11pt italic white on `#2E5FA3`, height 22px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers | 20pt bold white on `#2E5FA3`, height 50px |

---

## Data Entries

### Milestone 3.M1 — CodeQL + Joern Integration into Path A

| Field | Value |
|---|---|
| ID | `3.M1` |
| Name | CodeQL + Joern Integration into Path A |
| Type | MILESTONE |
| Start | 2026-07-21 |
| End | 2026-07-22 |
| PERT O | 5.5 |
| PERT ML | 11.5 |
| PERT P | 20.0 |
| PERT E | 7.92 |
| Status | Not Started |
| Notes | Runs in parallel with Semgrep. LLM Verifier extended to deduplicate and score across all three Path A sources. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M1.T1 | Install and configure CodeQL CLI; write one end-to-end QL taint-flow query that fires on the Approach 2 Java test codebase | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |
| 3.M1.T2 | Install Joern; write CPG query script detecting SQL injection and command injection taint paths in the Java test codebase | 1.5 | 3.0 | 5.0 | 3.08 | Not Started |
| 3.M1.T3 | Implement Go parallel runner that fans out Semgrep, CodeQL, and Joern concurrently and merges raw findings into the shared JSON schema from Approach 2 | 2.0 | 4.0 | 7.0 | 4.17 | Not Started |
| 3.M1.T4 | Extend LLM Verifier to deduplicate and score false-positive probability across all three Path A sources; output unified findings list | 1.0 | 2.5 | 4.0 | 2.50 | Not Started |

---

### Milestone 3.M2 — Path B: Call Graph + CVE Enrichment (Full Integration)

| Field | Value |
|---|---|
| ID | `3.M2` |
| Name | Path B — Call Graph + CVE Enrichment (Full Integration) |
| Type | MILESTONE |
| Start | 2026-07-23 |
| End | 2026-07-27 |
| PERT O | 6.5 |
| PERT ML | 13.5 |
| PERT P | 21.0 |
| PERT E | 13.58 |
| Status | Not Started |
| Notes | Joern call-graph output feeds directly into Tier-1 surface selection. CVE enrichment matches high-risk surfaces to NVD/OSV identifiers by package name and function name. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M2.T1 | Integrate Joern call-graph output as Tier-1 input to Path B Heuristic Targeting: map function call edges onto the high-risk surface list from Approach 2 | 1.5 | 3.0 | 5.0 | 3.08 | Not Started |
| 3.M2.T2 | Implement CVE enrichment module: fetch and locally cache NVD/OSV feeds; match high-risk surfaces to CVE identifiers by package name and function name | 2.0 | 4.0 | 6.0 | 4.00 | Not Started |
| 3.M2.T3 | Wire existing UniXcoder Tier-2 classifier to consume call-graph-enriched surfaces and output ranked risk scores with calibrated confidence values | 1.0 | 2.5 | 4.0 | 2.50 | Not Started |
| 3.M2.T4 | Implement Tier-3 LLM Semantic Scan: prompt template includes call-graph context and CVE cross-reference; parse structured JSON vulnerability output from local Ollama model | 2.0 | 4.0 | 6.0 | 4.00 | Not Started |

---

### Milestone 3.M3 — Red Team Agent (LangGraph Orchestration)

| Field | Value |
|---|---|
| ID | `3.M3` |
| Name | Red Team Agent (LangGraph Orchestration) |
| Type | MILESTONE |
| Start | 2026-07-27 |
| End | 2026-07-28 |
| PERT O | 4.5 |
| PERT ML | 10.5 |
| PERT P | 18.5 |
| PERT E | 10.83 |
| Status | Not Started |
| Notes | LangGraph orientation spike required before design (T1). Graph nodes: triage → exploit-gen → sandbox-dispatch → result-collect. StateAnnotation schema typed in Python. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M3.T1 | LangGraph orientation spike: install langgraph, build a two-node graph (planner → executor) against a toy task; confirm StateAnnotation wiring and local Python environment work | 0.5 | 1.5 | 3.0 | 1.58 | Not Started |
| 3.M3.T2 | Design Red Team Agent graph: define nodes (triage, exploit-gen, sandbox-dispatch, result-collect), directed edges, and the StateAnnotation schema with typed fields in Python | 1.0 | 2.5 | 4.0 | 2.50 | Not Started |
| 3.M3.T3 | Implement triage node: selects top-N candidates from dedup+scored findings list by confidence × severity product; emits exploit-plan structs to the exploit-gen node | 1.0 | 2.0 | 3.5 | 2.08 | Not Started |
| 3.M3.T4 | Implement exploit-gen node: calls local Ollama LLM with structured vulnerability context to produce a minimal exploit script or curl payload per finding | 1.5 | 3.0 | 5.0 | 3.08 | Not Started |
| 3.M3.T5 | Implement result-collect node: aggregates container exit codes, stdout/stderr, and timing from sandbox-dispatch into a structured PoE evidence struct; passes to output layer | 0.5 | 1.5 | 3.0 | 1.58 | Not Started |

---

### Milestone 3.M4 — Docker Sandbox

| Field | Value |
|---|---|
| ID | `3.M4` |
| Name | Docker Sandbox |
| Type | MILESTONE |
| Start | 2026-07-29 |
| End | 2026-07-29 |
| PERT O | 4.0 |
| PERT ML | 7.5 |
| PERT P | 13.0 |
| PERT E | 7.83 |
| Status | Not Started |
| Notes | Alpine base image: Java + Python runtimes, no outbound network, read-only rootfs except /tmp. 30-second timeout + OOM kill limit enforced per container run. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M4.T1 | Write Dockerfile for sandbox image: Alpine base with Java and Python runtimes, no outbound network, read-only rootfs except /tmp; build locally and smoke-test with a hello-world exploit script | 1.0 | 2.0 | 3.5 | 2.08 | Not Started |
| 3.M4.T2 | Implement sandbox-dispatch node: spawns sandbox container with exploit payload via Docker SDK, captures stdout/stderr, enforces 30-second timeout and OOM kill limit | 2.0 | 3.5 | 6.0 | 3.67 | Not Started |
| 3.M4.T3 | Implement exploit outcome classifier: parses container output to assign CONFIRMED, NOT_TRIGGERED, or ENVIRONMENT_ERROR status; writes structured result to agent state | 1.0 | 2.0 | 3.5 | 2.08 | Not Started |

---

### Milestone 3.M5 — Two-Layer PoE Output Generation

| Field | Value |
|---|---|
| ID | `3.M5` |
| Name | Two-Layer PoE Output Generation |
| Type | MILESTONE |
| Start | 2026-07-30 |
| End | 2026-07-30 |
| PERT O | 2.5 |
| PERT ML | 5.0 |
| PERT P | 9.0 |
| PERT E | 5.25 |
| Status | Not Started |
| Notes | Layer 1: technical trace (exploit script + container stdout + stack trace + vulnerable code). Layer 2: executive summary (plain-English, business impact, no code). Serialized to poe_report.json keyed by finding ID. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M5.T1 | Implement technical trace renderer: for each CONFIRMED finding produce a structured section containing exploit script, container stdout, stack trace excerpt, and vulnerable code snippet with line numbers | 1.0 | 2.0 | 3.5 | 2.08 | Not Started |
| 3.M5.T2 | Implement executive summary renderer: one-paragraph plain-English description per confirmed finding with business impact, reproduction steps (no code), and severity badge | 1.0 | 2.0 | 3.5 | 2.08 | Not Started |
| 3.M5.T3 | Write PoE serializer: bundle technical trace and executive summary into poe_report.json keyed by finding ID for downstream HTML template embedding | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |

---

### Milestone 3.M6 — HTML Report with PoE Evidence

| Field | Value |
|---|---|
| ID | `3.M6` |
| Name | HTML Report with PoE Evidence |
| Type | MILESTONE |
| Start | 2026-07-30 |
| End | 2026-07-31 |
| PERT O | 3.0 |
| PERT ML | 6.5 |
| PERT P | 11.0 |
| PERT E | 6.67 |
| Status | Not Started |
| Notes | Extends Approach 2 HTML template. Adds collapsible PoE evidence panel per finding. Report-level summary: CONFIRMED / NOT_TRIGGERED / UNVERIFIED counts + export button for standalone executive report. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M6.T1 | Extend Approach 2 HTML template: add a collapsible PoE evidence panel per finding that embeds the technical trace and executive summary rendered from poe_report.json | 1.5 | 3.0 | 5.0 | 3.08 | Not Started |
| 3.M6.T2 | Add report-level PoE summary section: CONFIRMED / NOT_TRIGGERED / UNVERIFIED counts, risk heat-map, and export button that generates a standalone plain-text executive report | 1.0 | 2.5 | 4.0 | 2.50 | Not Started |
| 3.M6.T3 | End-to-end smoke test: run full pipeline on fake Java test codebase; verify HTML renders in browser, all PoE panels load, and patch diffs display without errors | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |

---

### Milestone 3.M7 — Integration Buffer + Final Demo Prep

| Field | Value |
|---|---|
| ID | `3.M7` |
| Name | Integration Buffer + Final Demo Prep |
| Type | MILESTONE |
| Start | 2026-07-31 |
| End | 2026-07-31 |
| PERT O | 3.0 |
| PERT ML | 6.0 |
| PERT P | 10.5 |
| PERT E | 6.25 |
| Status | Not Started |
| Notes | Full pipeline integration test: Path A → Path B → Red Team Agent → Docker Sandbox → PoE Output → HTML Report. Single-command reproducibility via demo/run_demo_approach3.sh. 3-minute fallback recording. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M7.T1 | Full pipeline integration test: execute Path A → Path B → Red Team Agent → Docker Sandbox → PoE Output → HTML Report end-to-end on the fake Java codebase; document and fix all breakages | 2.0 | 4.0 | 7.0 | 4.17 | Not Started |
| 3.M7.T2 | Write demo/run_demo_approach3.sh with pinned dependency versions and hardcoded paths; execute a dry-run in a fresh terminal to confirm single-command reproducibility | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |
| 3.M7.T3 | Record a 3-minute fallback video of the full pipeline run including the HTML report PoE evidence panel and executive summary export | 0.5 | 1.0 | 1.5 | 1.00 | Not Started |

---

### Milestone 3.M8 — Final Presentation

| Field | Value |
|---|---|
| ID | `3.M8` |
| Name | Final Presentation |
| Type | MILESTONE |
| Start | 2026-07-31 |
| End | 2026-08-01 |
| PERT O | 1.5 |
| PERT ML | 3.0 |
| PERT P | 5.0 |
| PERT E | 3.08 |
| Status | Not Started |
| Notes | Slides: achievements, architecture walk-through, live demo, honest limitations (false PoE rate, Docker setup complexity), future roadmap. Two full rehearsal runs targeting 5 min each. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 3.M8.T1 | Write presentation slides: Approach 3 achievements, architecture diagram walk-through, live demo script, honest limitations, and future roadmap | 1.0 | 2.0 | 3.0 | 2.00 | Not Started |
| 3.M8.T2 | Rehearse live demo walkthrough end-to-end twice: scan → PoE confirmation → HTML report → executive summary export; target 5 minutes per run | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |
| 3.M8.T3 | Deliver final presentation to tech lead (2026-08-01) | 0.0 | 0.0 | 0.0 | 0.00 | Not Started |

---

## Summary

| Metric | Value |
|---|---|
| Total milestones | 8 |
| Total tasks | 28 |
| Total PERT E | 61.4 h |
| Available capacity (9 days × 6 h) | 54 h |
| Over-capacity risk | ~14% — absorbed by M7 buffer |
| Hard deadline | 2026-08-01 (intern's final day) |
