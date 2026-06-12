---
title: "ZeroTrust.sh PoC — Semgrep Custom Rule Engine: 2-Week Implementation Proposal"
author: "Ton Minh Hoang (Intern, VNG ZingPlay Studio)"
date: "2026-06-09"
---

| | |
|---|---|
| **Prepared by** | Ton Minh Hoang (Intern) |
| **Prepared for** | Tech Lead, VNG ZingPlay Studio |
| **Date** | 2026-06-09 |
| **Version** | 1.0 |

---

# 1. Objective and Scope

## 1.1 Objective

Deliver a working Semgrep-based custom rule engine that detects AI coding agent–introduced vulnerability patterns — including hallucinated package imports, security control bypasses, and prompt injection in comments — against a representative target codebase. The engine produces detection output consumable as a CLI demo and establishes **Path A** of the ZeroTrust.sh two-path scanner architecture. Source code never leaves the developer's machine.

## 1.2 In Scope

- Semgrep rule configuration composed of two components running together:
  - **Community rule packs** — referenced in config (`p/python`, `p/java`, `p/owasp-top-ten`); zero authoring effort; provides broad baseline coverage across thousands of established vulnerability classes automatically
  - **Custom rules** — 3–5 rules written from scratch targeting AI-coding-agent behavioral patterns with no community equivalent:
    - *LLM prompt injection*: unsanitized user input piped into LLM SDK calls (OpenAI, Anthropic, LangChain)
    - *AI bypass comments*: suppression annotations or bypass comments placed adjacent to security-sensitive code to silence warnings without fixing the underlying issue
    - *Hardcoded AI service API keys*: credential patterns specific to AI services (`sk-`, `sk-ant-`, `hf_`) not covered by generic secret detection rules
- A fake AI-generated Java application (Spring Boot REST API) with intentional, realistic vulnerabilities
- Semgrep detection demo: CLI scan of the test codebase using custom rules
- Presentation narrative: pros, cons, and the case for Approach 2 (Path B introduction: independent logic vulnerability detection running in parallel with Path A, plus LLM verification of Path A findings)
- (Stretch) Jupyter Notebook with effectiveness metrics — precision, recall, scan speed

## 1.3 Rule Strategy

The rule set is not a single monolithic list. It is two components working together in the same Semgrep scan:

| | Community Rule Packs | Custom Rules (ZeroTrust.sh) |
|---|---|---|
| **Source** | Semgrep registry (`p/python`, `p/java`, `p/owasp-top-ten`) | Written from scratch for this project |
| **Authoring effort** | Zero — referenced in config with one line | 3–5 rules — the primary implementation effort |
| **What they detect** | Vulnerabilities that exist in code, regardless of who wrote it | Behavioral patterns specific to AI coding agents |
| **Examples** | SQL injection, weak crypto, command injection, path traversal | LLM prompt injection, AI bypass comments, AI service API keys |
| **Community equivalent** | Yes — widely used, actively maintained | No — these patterns have no community equivalent |
| **Role in demo** | Broad baseline coverage proving general scanner capability | The project differentiator — what no existing tool catches |

The demo runs both together. Community packs demonstrate coverage breadth. Custom rules demonstrate the AI-specific signal that is the reason ZeroTrust.sh exists as a separate product.

## 1.4 Out of Scope

- LLM-based semantic verification (Approach 2)
- Packaging as a distributable binary
- CI/CD pipeline or pre-commit hook integration
- Cloud dashboard or remote upload of any kind
- Windows support

---

# 2. Deliverables

## 2.1 Committed Deliverables

| # | Deliverable | Success Criterion |
|---|---|---|
| D-01 | Semgrep rule set | Community rule packs (`p/python`, `p/java`, `p/owasp-top-ten`) configured and running + 3–5 custom rules with no community equivalent; each custom rule has a passing `bad.*` (must fire) and `ok.*` (must not fire) test file; the 3 custom rule categories (LLM prompt injection, AI bypass comments, AI service API keys) are demonstrated as the project differentiators |
| D-02 | Fake AI-generated Java test codebase | 10–15 Java files, realistic Spring Boot REST API structure, ≥8 intentional vulnerabilities embedded in context (not standalone snippets) |
| D-03 | Working Semgrep detection demo | `semgrep --config rules/ .` catches ≥6 of 8 embedded vulnerabilities; false-positive rate documented |
| D-04 | Presentation narrative | Written pros/cons section + reasoned next-step argument for Approach 2; audience: tech lead with SAST background |

## 2.2 Bonus Deliverables *(Time-Permitting — Not Committed)*

| # | Deliverable | Trigger Condition |
|---|---|---|
| B-01 | Jupyter Notebook — effectiveness metrics | Only if D-03 complete by Day 7 (2026-06-17); hard abort if notebook not started by 16:00 on Day 8 |
| B-02 | Rule test runner script (`scripts/run_tests.sh`) | Low effort; included if time allows after D-04 |

> Bonus deliverables are pre-designated as the first cut if schedule pressure arises. B-01 moves to Approach 2 scope if dropped here.

---

# 3. Milestone Plan

| Milestone | Day Range | Dates | Key Tasks | Est. Hours (PERT) | Success Criterion |
|---|---|---|---|---|---|
| **M-1: Research & Setup** | Day 1 | 2026-06-09 | Install Semgrep CLI; read operator and YAML rule docs; write one toy rule end-to-end; scaffold repo structure (`rules/`, `tests/`, `scripts/`) | 5.25h | First toy rule fires on a test snippet; repo structure committed |
| **M-2: Python Rules** | Days 2–3 | 2026-06-10–11 | Write 10 Python rules (PY-001→PY-010); tune against `bad.py` / `ok.py` pairs; focus last on bypass and f-string SQL rules (highest complexity) | 11.98h | 10 Python rules with passing test pairs; no FP on `ok.py` |
| **M-3: Java Rules** | Days 4–5 | 2026-06-12–13 | Write 9 Java rules (JV-001→JV-009); validate AST shapes with `semgrep --dump-ast` before authoring; constrain test Java to Java 8 syntax | 12.84h | 9 Java rules with passing test pairs |
| **M-4: Test Codebase** | Day 6 | 2026-06-16 | AI-generate fake Spring Boot REST API (10–15 files, 800–1200 LOC); embed ≥8 vulnerabilities mirroring real CVE patterns; run validation scan | 6.75h | Semgrep detects ≥6 of 8 embedded vulnerabilities; false-positive count documented |
| **M-5: Demo Prep** | Day 7 | 2026-06-17 | Write `demo/run_demo.sh` with pinned Semgrep version and hardcoded paths; full dry-run in a fresh terminal; record 3-minute fallback video | 5.40h | Demo runs clean in fresh shell; fallback video recorded and accessible |
| **M-6: Narrative** | Day 8 | 2026-06-18 | Write pros/cons section; draft Approach 2 next-step argument; add speaker notes | 5.00h | Presentation narrative complete and peer-readable |
| **M-7: Notebook** *(Bonus)* | Day 9 | 2026-06-19 | Precision/recall per rule; scan speed (lines/second); AI-specific detection rate; FP rate on clean codebase | 6.55h | Notebook cells run clean; five core metrics visible with charts |
| **Buffer (explicit)** | Across Days 1–9 | — | Reserved for: bypass rule debugging (M-2/M-3), Java grammar mismatch (M-3), detection rate shortfall (M-4), demo polish (M-5) | **5.00h** | Absorbed into overrunning milestones; not pre-allocated to any single task |
| **Presentation** | Day 10 | 2026-06-20 | Live demo + narrative delivery | — | Tech lead approves or provides actionable feedback |

**Total estimated hours (core + buffer): 52.22h | Available: 63h | Core slack: 10.78h**
**Total estimated hours (core + bonus + buffer): 60.27h | Bonus slack: 2.73h**

---

# 4. Estimation Methodology

## 4.1 PERT (Program Evaluation and Review Technique)

Each milestone was decomposed into atomic subtasks. Every subtask received three point estimates — Optimistic (O), Most Likely (ML), and Pessimistic (P) — accounting for learning curve, YAML syntax surprises, and Semgrep version edge cases. The PERT expected value was then computed as:

> **E = (O + 4 × ML + P) / 6**

> **σ² = ((P − O) / 6)²**

## 4.2 Worked Example — M-2: Python Rule Development

| Estimate | Hours | Rationale |
|---|---|---|
| Optimistic (O) | 4.2 | AI assistance generates clean first drafts; no metavariable scoping surprises |
| Most Likely (ML) | 9.4 | ~1 debug iteration per rule; 1–2 rules (bypass, f-string SQL) require extra passes |
| Pessimistic (P) | 27.0 | Two AI-specific rules resist for a full day each; YAML multi-line string bugs surface |

> **E = (4.2 + 4 × 9.4 + 27.0) / 6 = 68.8 / 6 ≈ 11.98h**
>
> **σ² = ((27.0 − 4.2) / 6)² ≈ 14.44 | σ ≈ 1.19h**

The buffer of **5.00h (10.6% of core estimate)** is named explicitly and is not embedded inside any individual milestone estimate.

## 4.3 AI Compression Factor

Claude Code (AI coding assistant) is available throughout implementation. AI assistance compresses Semgrep rule iteration time by an estimated 40–60% for a zero-experience developer — primarily through rule template generation and metavariable scoping explanations in context. The Most Likely estimates incorporate this factor. Buffer is not reduced because the AI factor does not eliminate blocked states — it reduces their duration.

## 4.4 Total Hours Summary

| Phase | O (h) | ML (h) | P (h) | **E (h)** | σ (h) |
|---|---|---|---|---|---|
| M-1: Research & Setup | 2.3 | 4.7 | 10.5 | **5.25** | 0.62 |
| M-2: Python Rules | 4.2 | 9.4 | 27.0 | **11.98** | 1.19 |
| M-3: Java Rules | 4.3 | 10.3 | 29.5 | **12.84** | 1.24 |
| M-4: Test Codebase | 2.4 | 5.7 | 16.0 | **6.75** | 0.96 |
| M-5: Demo Prep | 1.9 | 4.6 | 13.0 | **5.40** | 0.74 |
| M-6: Narrative | 2.0 | 4.4 | 12.0 | **5.00** | 0.57 |
| Buffer | — | — | — | **5.00** | — |
| **Core Total** | | | | **52.22** | **2.27** |
| M-7: Notebook (Bonus) | 2.3 | 5.6 | 16.0 | **6.55** | 0.88 |
| **Total incl. Bonus** | | | | **60.27** | — |

---

# 5. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Negative pattern matching harder than expected** — `pattern-not-inside` for bypass detection rules (PY-007, JV-007) fires on everything or nothing; debugging costs 3–5 hours without prior Semgrep knowledge | High | Medium — M-2/M-3 slip by up to 1 day | Write 8 of 10 easier rules first; use Claude Code with explicit prompt for `pattern-not-inside`; fall back to `pattern-regex` on comment strings as a weaker but demonstrable proxy |
| **Semgrep Java grammar mismatch with AI-generated code** — modern Java syntax (`var`, records, text blocks) misparsed by tree-sitter, rules silently do not fire | Medium | High — invalidates M-4 detection demo if discovered late | Constrain generation prompt to Java 8 syntax explicitly; run `semgrep --dump-ast --lang java` on one file before writing any Java rules to confirm AST node shapes |
| **Demo environment not reproducible at presentation** — PATH, Semgrep version, or venv mismatch causes live failure at the worst moment | Low | Critical — destroys demo credibility | Write `demo/run_demo.sh` with pinned version and hardcoded paths; full dry-run in fresh terminal ≥24 hours before deadline; 3-minute fallback video recorded during M-5 |
| **False-positive rate exceeds 25%** — patterns too broad, firing on test mocks or framework internals | Medium | Medium — weakens PoC credibility with tech lead | Add `ok.*` counterpart per rule as part of authoring, not as a post-hoc step; run rules against one clean open-source Java repo during M-4 and document the count |
| **Java test codebase too artificial to generalize** — tech lead tests rules on their own code and gets zero detections | Low | High — invalidates the concept for Approach 2 sign-off | Base vulnerability placements on real CVE patterns, not toy snippets; use realistic Spring Boot package structure (`controller` / `service` / `repository` layers); embed bypass comments matching real AI agent behavior |
| **Developer blocked for 1+ days** (illness, unrelated meeting load, blocker dependency) | Low | High — no team redundancy on a solo PoC | 5h buffer covers roughly one lost partial day; B-01 Notebook and B-02 runner script are pre-designated first cuts with zero impact on D-01–D-04 |

---

# 6. Pros and Cons of Approach 1 (Semgrep-Only)

| Pros | Cons |
|---|---|
| **Zero infrastructure.** Semgrep runs locally with a single CLI command — no server, no API key, no upload. Privacy guarantee is trivially met. | **Syntax, not semantics.** Semgrep matches AST patterns, not data flow. SQL injection assembled two function calls away from a cursor call will not be caught. |
| **Fast.** Typical scan rate of 10,000–50,000 lines/second is compatible with an agent-loop iteration cycle. Orders of magnitude faster than any cloud SAST round-trip. | **No inter-procedural taint analysis in OSS tier.** Taint tracking across function boundaries requires Semgrep Pro. Rules fire only on direct-call patterns. |
| **Auditable and extensible rules.** YAML rule files are human-readable, crowdsourceable, and submittable to the Semgrep registry. The corpus built here becomes Stage 1 of Approach 2. | **High maintenance burden as AI agents evolve.** When AI tools adopt new patterns or libraries, rules need manual updates. Rules do not generalize beyond their matched shapes. |
| **Community rule packs provide thousands of rules at zero authoring cost.** Referencing `p/python`, `p/java`, and `p/owasp-top-ten` gives broad baseline coverage instantly, letting all implementation effort focus on the 3–5 custom rules that are the actual differentiator. | **False negatives on indirect patterns.** A developer who stores `api_key` in a config dict and passes it as `cfg["api_key"]` will bypass a hardcoded-literal rule entirely. |
| **High recall is a deliberate design choice, not a flaw.** Approach 1 rules are intentionally biased toward catching more (higher recall) at the cost of some false positives. This is correct sequencing: Approach 2's LLM Verifier is specifically designed to filter that noise, restoring precision without sacrificing recall. The false positive rate in Approach 1 is the architectural argument for Approach 2 — not a failure to fix. | **Precision-recall tradeoff cannot be fully resolved at the rule level.** Broader wildcard patterns catch more variants of AI-generated vulnerable code but also match safe code with similar shapes. Tightening rules with `pattern-not` reduces false positives but risks missing real vulnerabilities written in unexpected forms. Full resolution requires the LLM semantic layer in Approach 2. |
| **Demo is self-contained and offline.** No dependency on external models, APIs, or network connectivity — reduces presentation risk and demonstrates the privacy-first value proposition directly. | **40–65% recall on real-world codebases.** Rules written against synthetic patterns achieve 85–95% recall on intentional test code, but recall drops significantly against codebases not specifically designed to match. Do not promise otherwise. |
| **PoC is not throwaway work.** The ruleset directly seeds Path A of the Approach 2 hybrid engine. Implementing Approach 1 before Approach 2 is the correct sequencing, not a detour. | **No attribution.** Semgrep detects the vulnerability pattern, not the causal agent. Establishing that a vulnerability was introduced by an AI tool (vs. a human) requires semantic reasoning — available only in Approach 2. |
| | **No logic vulnerability detection (Path B not present).** Vulnerabilities where code looks locally correct but is wrong in context — IDOR, missing authorization checks, business logic bypasses, AI-agent trust escalation — produce no syntactic pattern for Approach 1 to detect. These require reasoning about what code *should* do, not what it *looks like*. Path B, introduced in Approach 2, addresses this gap. |

> **Positioning note:** The limitations listed above are the *motivation* for Approaches 2 and 3, not a failure of Approach 1. Approach 1 proves that Path A can catch real, known vulnerability patterns today — faster and more privately than any cloud SAST tool. Approach 2 then introduces Path B alongside Path A: an independent LLM scan of high-risk code surfaces (endpoint handlers, authorization functions) that catches the logic-level vulnerabilities Approach 1 structurally cannot reach.

---

# 7. Approval Request

This plan presents a scoped, time-bounded proof of concept with four committed deliverables, a PERT-derived 9-day schedule with an explicit 5-hour buffer, and a pre-registered six-row risk register. The core estimate of 52.22 hours fits comfortably within the 63-hour available capacity (10.78h slack). The stretch Notebook deliverable is achievable at approximately 72% probability if core milestones complete on schedule.

Approval of this plan authorizes implementation to begin immediately and commits no resources beyond the 2026-06-20 presentation date.

| | |
|---|---|
| **Approved by (name)** | |
| **Title** | |
| **Date** | |
| **Signature** | |

**Please approve this plan so implementation can begin on Monday, 2026-06-09.**
