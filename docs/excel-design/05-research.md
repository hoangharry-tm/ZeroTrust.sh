# Sheet 5 — Scientific Research & Architecture Validation

**Sheet name:** `Research`
**Goal ID:** R
**Goal name:** Scientific Research & Architecture Validation
**Description:** Validate the Cascading Intelligence Pipeline architecture against published academic evidence. Map every design decision to at least one supporting paper, verify all benchmark claims, research competitor positioning, and produce an architecture justification document suitable for tech lead review and stakeholder presentations. Runs woven throughout the full 8-week internship period.
**Date range:** 2026-06-09 → 2026-08-01
**Total milestones:** 6
**Total tasks:** 30
**Current state (2026-06-11):** R.M1 In Progress (literature reading started)

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Scientific Research & Architecture Validation` | 20pt bold white on `#1F3864`, height 50px |
| 2 | `Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Evidence-backed architecture validation  ·  Runs Jun 9 – Aug 1` | 11pt italic white on `#2E5FA3`, height 22px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers | 20pt bold white on `#2E5FA3`, height 50px |

> Note: The Research sheet uses the same column schema as Approach sheets. The milestone IDs use prefix `R` (e.g. `R.M1`, `R.M1.T1`).

---

## Data Entries

### Milestone R.M1 — Literature Foundation

| Field | Value |
|---|---|
| ID | `R.M1` |
| Name | Literature Foundation |
| Type | MILESTONE |
| Start | 2026-06-09 |
| End | 2026-06-20 |
| PERT O | 20.0 |
| PERT ML | 41.0 |
| PERT P | 82.0 |
| PERT E | 44.33 |
| Status | **In Progress** |
| Notes | Read and annotate all 40 catalogued papers across 7 areas. Build a paper-to-architecture-component linkage map assigning each paper to >= 1 ZeroTrust.sh component as primary evidence. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M1.T1 | Read and annotate Area 1 (Deep Learning & ML for Vulnerability Detection, ~4 papers) and Area 2 (GNN for Vulnerability Detection, ~6 papers): record model architectures, training datasets, F1/precision benchmarks, and which ZeroTrust.sh component each paper most directly supports | 4.0 | 8.0 | 16.0 | 8.67 | In Progress |
| R.M1.T2 | Read and annotate Area 3 (LLM for Code Security Analysis, ~6 papers): note LLM prompting strategies, hybrid pipeline designs, and accuracy figures relative to ZeroTrust.sh Path B design | 6.0 | 12.0 | 22.0 | 12.67 | Not Started |
| R.M1.T3 | Read and annotate Area 4 (Hybrid Static Analysis + LLM, ~5 papers) and Area 5 (AI-Generated Code Security & Prompt Injection, ~5 papers): extract FP reduction rates and AI-specific threat taxonomies relevant to slopsquatting and prompt injection detection | 5.0 | 10.0 | 20.0 | 10.83 | Not Started |
| R.M1.T4 | Read and annotate Area 6 (Token Cost Optimization, ~4 papers) and Area 7 (Call Graph, Taint Analysis & Code Representations, ~10 papers): record cost reduction percentages, uncertainty-based routing approaches, and taint tracking accuracy figures | 4.0 | 8.0 | 18.0 | 9.00 | Not Started |
| R.M1.T5 | Build paper-to-architecture-component linkage map: assign each of the 40 papers to >= 1 ZeroTrust.sh component (Differential Indexer, Path A Semgrep, Path A CodeQL/Joern, Path A LLM Verifier, Path B Tier 1/2/3, Dedup/Confidence Scoring, PoE Layer) as primary evidence | 1.0 | 3.0 | 6.0 | 3.17 | Not Started |

---

### Milestone R.M2 — Architecture Validation Matrix

| Field | Value |
|---|---|
| ID | `R.M2` |
| Name | Architecture Validation Matrix |
| Type | MILESTONE |
| Start | 2026-06-16 |
| End | 2026-06-27 |
| PERT O | 4.0 |
| PERT ML | 8.5 |
| PERT P | 21.0 |
| PERT E | 9.83 |
| Status | Not Started |
| Notes | Map every architecture component to >= 1 supporting paper. Flag any component with no academic backing as a validation gap with a defined mitigation (benchmark proposal, practitioner reference, or novel design claim). |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M2.T1 | Map Differential Indexer and all Path A sub-components (Semgrep rules, CodeQL/Joern taint analysis, LLM Verifier CoT framework) to >= 1 supporting paper each — populate matrix with columns: component name, paper ID, claimed metric, page/section reference | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |
| R.M2.T2 | Map Path B three-tier cost funnel (Heuristic Targeting, UniXcoder-Base-Nine Classifier Gate F1=94.73% on BigVul, Token Budget Controller UCCI-style calibration, LLM Semantic Scan) to supporting papers with specific claimed performance figures recorded | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |
| R.M2.T3 | Map Dedup layer and 5-tier Confidence Scoring (BLOCK >=0.92 / HIGH 0.75-0.91 / MEDIUM 0.60-0.74 / LOW 0.30-0.59 / SUPPRESSED <0.30; +15% dual-path boost) to supporting papers — verify triple-path fusion approach (AST edit distance + LLM semantic similarity + CWE pattern hash) | 0.5 | 1.0 | 3.0 | 1.25 | Not Started |
| R.M2.T4 | Map Proof-of-Exploit Layer (Red Team Agent orchestration, Docker sandbox exploit execution, two-layer PoE output) to supporting papers on automated vulnerability verification, sandbox-based exploit confirmation, and agentic security frameworks | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| R.M2.T5 | Identify every architecture component with zero academic backing and document each as an open validation gap — for each gap specify mitigation: (a) empirical benchmark proposal, (b) industry practitioner reference, or (c) novel design claim requiring ablation study | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |

---

### Milestone R.M3 — Benchmark & Performance Claims Verification

| Field | Value |
|---|---|
| ID | `R.M3` |
| Name | Benchmark & Performance Claims Verification |
| Type | MILESTONE |
| Start | 2026-06-23 |
| End | 2026-07-04 |
| PERT O | 3.0 |
| PERT ML | 6.5 |
| PERT P | 18.0 |
| PERT E | 7.83 |
| Status | Not Started |
| Notes | Verify every quantitative claim in the architecture docs against its source paper. Produce a benchmarks reference table: claim text, source, confidence level (paper-cited / internally-estimated / unverified), and follow-up action. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M3.T1 | Verify UniXcoder-Base-Nine F1=94.73% on BigVul: locate original paper, confirm exact evaluation setup (dataset split ratio, positive/negative class balance, metric definition), and record any scope caveats (language coverage, vulnerability categories included) | 0.5 | 1.0 | 3.0 | 1.25 | Not Started |
| R.M3.T2 | Verify 88-93% false positive reduction claim for the LLM Verifier: confirm paper title, publication venue, year, experimental conditions, and whether the task is comparable to ZeroTrust.sh's SAST FP filtering use case | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| R.M3.T3 | Verify ~80-95% cost reduction claim for the Differential Indexer: determine whether this is from a cited paper or is an internal engineering estimate; if internal, document the derivation assumptions (file change frequency, typical codebase churn rate) | 0.5 | 1.0 | 3.0 | 1.25 | Not Started |
| R.M3.T4 | Verify ~15-25% LLM escalation rate (uncertain surfaces reaching Tier 3) and ~95% file elimination rate (Tier 1 heuristic targeting): locate source paper or empirical basis; if internally estimated, document the heuristic targeting precision assumption | 0.5 | 1.0 | 3.0 | 1.25 | Not Started |
| R.M3.T5 | Compile benchmarks reference table with columns: claim text as stated in architecture docs, source paper or derivation method, confidence level (paper-cited / internally-estimated / unverified), and follow-up action — this becomes the primary fact-check appendix for tech lead presentations | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |

---

### Milestone R.M4 — Competitive Landscape Research

| Field | Value |
|---|---|
| ID | `R.M4` |
| Name | Competitive Landscape Research |
| Type | MILESTONE |
| Start | 2026-06-30 |
| End | 2026-07-11 |
| PERT O | 6.0 |
| PERT ML | 12.0 |
| PERT P | 26.0 |
| PERT E | 13.33 |
| Status | Not Started |
| Notes | Research Semgrep, Snyk Code, and CodeRabbit structural gaps vs. ZeroTrust.sh. Find academic and practitioner evidence for ZeroTrust.sh's local-only + AI-specific threat detection differentiator. Compile a differentiation evidence table. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M4.T1 | Research publicly available accuracy and precision data for Semgrep OSS and Semgrep Pro: check official docs, blog posts, academic evaluations that include Semgrep as a baseline, and SAST benchmark studies (OWASP Benchmark, NIST SATE) | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |
| R.M4.T2 | Research Snyk Code (DeepCode AI engine) architecture with focus on cloud dependency and source-code-upload requirements: find documented regulatory blockers (GDPR, SOC 2, air-gapped environments), published privacy incidents, or enterprise objections that ZeroTrust.sh's local-only model directly addresses | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |
| R.M4.T3 | Research CodeRabbit's PR-gated workflow architecture: document what CodeRabbit structurally cannot do (pre-commit local scan, offline execution, ZIP archive input, CI-free developer loop, non-GitHub VCS) and map each architectural gap to the corresponding ZeroTrust.sh capability | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |
| R.M4.T4 | Search academic databases (ACM Digital Library, arXiv cs.CR, IEEE Xplore) and NIST guidelines for evidence that local-only execution with AI-specific threat detection (slopsquatting, prompt injection in comments, safety-gate bypass patterns) represents an unoccupied or under-served position in the security tooling landscape | 2.0 | 4.0 | 9.0 | 4.50 | Not Started |
| R.M4.T5 | Compile differentiation evidence table with columns: ZeroTrust.sh differentiator, evidence source, competitor it distinguishes against, and whether the gap is architectural (cannot be closed without redesign) or feature-level (could be added by competitor) | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |

---

### Milestone R.M5 — Architecture Justification Document

| Field | Value |
|---|---|
| ID | `R.M5` |
| Name | Architecture Justification Document |
| Type | MILESTONE |
| Start | 2026-07-07 |
| End | 2026-07-25 |
| PERT O | 6.5 |
| PERT ML | 13.0 |
| PERT P | 30.0 |
| PERT E | 14.75 |
| Status | Not Started |
| Notes | Formal document linking every major design decision to research evidence. Written for tech lead + stakeholders. Consumes outputs from R.M2 (validation matrix) and R.M3 (benchmarks reference table) as appendices. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M5.T1 | Write Path A justification section: why Semgrep is the correct pattern-detection engine (speed, community rules, extensibility), why CodeQL/Joern adds necessary taint-aware cross-file coverage, and why the LLM Verifier targeting 88-93% FP reduction is needed — cite supporting papers from R.M1 verified in R.M3 | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |
| R.M5.T2 | Write Path B justification section: explain the cost-funnel rationale for each tier — ~95% file elimination, UniXcoder-Base-Nine F1=94.73%, UCCI-style uncertainty calibration, CFG-based chunking, and why only ~15-25% of surfaces reach the LLM — cite papers for each sub-decision | 2.0 | 4.0 | 9.0 | 4.50 | Not Started |
| R.M5.T3 | Write Dedup and 5-tier Confidence Scoring justification: explain triple-path fusion (AST edit distance + LLM semantic similarity + CWE pattern hash), cite research for multi-tier scoring, document +15% dual-path confidence boost rationale and test-file suppression rule | 1.0 | 2.0 | 5.0 | 2.33 | Not Started |
| R.M5.T4 | Write Differential Indexer justification: explain hash-based incremental scanning design, cite evidence basis for 80-95% cost reduction claim, articulate why pre-commit developer-loop integration requires this optimization | 0.5 | 1.0 | 3.0 | 1.25 | Not Started |
| R.M5.T5 | Write PoE Layer justification and compile tech-lead narrative summary: explain phased deferral to Approach 3, summarize all major design decisions and evidence in <= 2 pages for non-technical stakeholders, attach validation matrix and benchmarks reference table as appendices | 2.0 | 4.0 | 8.0 | 4.33 | Not Started |

---

### Milestone R.M6 — Ongoing Research Monitoring

| Field | Value |
|---|---|
| ID | `R.M6` |
| Name | Ongoing Research Monitoring |
| Type | MILESTONE |
| Start | 2026-07-14 |
| End | 2026-08-01 |
| PERT O | 3.5 |
| PERT ML | 8.5 |
| PERT P | 19.0 |
| PERT E | 9.42 |
| Status | Not Started |
| Notes | Set up alert infrastructure for post-June-2026 papers. Perform forward-citation pass on top 5 most-cited papers in the catalogue. Write monitoring runbook for ongoing use beyond the internship. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| R.M6.T1 | Configure arXiv email digest alerts for all 7 research areas using category filters cs.CR (cryptography and security), cs.SE (software engineering), and cs.LG (machine learning) combined with keyword filters covering Cascading Intelligence Pipeline components | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |
| R.M6.T2 | Configure Google Scholar keyword alerts for: 'slopsquatting', 'UniXcoder vulnerability detection', 'LLM false positive reduction SAST', 'AI-generated code security', 'token budget LLM code analysis', 'differential program analysis incremental', 'proof of exploit automated' | 0.5 | 1.0 | 2.0 | 1.08 | Not Started |
| R.M6.T3 | Perform forward-citation pass on top 5 most-cited papers in the 40-paper catalogue using Google Scholar 'Cited by' — identify any 2025-2026 follow-up papers that may supersede original findings, introduce higher benchmarks, or cover gaps flagged in R.M2.T5 | 1.0 | 3.0 | 7.0 | 3.33 | Not Started |
| R.M6.T4 | Write monitoring runbook documenting: exact search queries per area, weekly arXiv digest review steps, monthly deep-search protocol, and standard checklist for integrating a newly found paper into the validation matrix (R.M2) and updating affected benchmark claims (R.M3) | 1.0 | 2.0 | 4.0 | 2.17 | Not Started |
| R.M6.T5 | Integrate newly discovered papers from R.M6.T3 into the validation matrix and architecture-to-paper linkage map; update benchmarks reference table if new figures supersede existing claims; flag remaining gaps for post-August-1 follow-up | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |

---

## Summary

| Metric | Value |
|---|---|
| Total milestones | 6 |
| Total tasks | 30 |
| Total PERT E | ~99.5 h |
| Duration | 8 weeks (woven alongside all Approaches) |
| Key output | Architecture Justification Document (R.M5) |
| Key dependency | R.M2 and R.M3 must complete before R.M5 can be written |
