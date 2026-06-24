# ZeroTrust.sh — Document Status Dashboard

All documents in this workspace are tracked here. Update this file whenever a document is created, promoted, or archived.

**Status Legend:** `Draft` — work in progress | `Review` — ready for tech-lead review | `Approved` — decision made | `Stub` — placeholder, content not yet written | `Archived` — superseded, kept for reference

---

## Document Index

| Path | Type | Status | Description | Last Updated |
|---|---|---|---|---|
| `notebooks/01_technical_deep_dive.ipynb` | Presentation | Draft | Interactive presentation notebook — needs updating after proposal docs are finalised | 2026-06-08 |
| **SPECS** | | | | |
| `specs/proposals/README.md` | Spec | Draft | Synthesis overview: two-path design principle, comparison matrix, decision flowchart, threat coverage (incl. logic vulnerabilities), dependency hierarchy | 2026-06-10 |
| `specs/proposals/tech_stack_analysis.md` | Spec | Draft | 809-line evidence-backed analysis: Go long-term viability, Rust comparison benchmarks, per-approach technology stacks with citations | 2026-06-08 |
| `specs/proposals/approach_1_ast_sast.md` | Spec | Draft | Approach 1: Path A only — uses Semgrep as engine (not built from scratch); community rule packs + 3–5 custom rules targeting AI-agent patterns (LLM prompt injection, bypass comments, AI service API keys) | 2026-06-10 |
| `specs/proposals/approach_2_hybrid_llm.md` | Spec | Draft | Approach 2: Path A expanded + Path B introduced — parallel two-path design. Path A: AST pre-filter; Path B: independent LLM heuristic scan of endpoints/auth surfaces. Patch generation, CyberSecEval analysis. Updated: 5-tier confidence scheme, UniXcoder-Base-Nine classifier reference | 2026-06-10 |
| `specs/proposals/approach_3_multi_agent.md` | Spec | Draft | Approach 3: Path A + Path B fully realized — LangGraph agents, call graph traversal, CVE cross-reference, Docker sandbox, two-layer PoE output. NOT a pentest tool — pre-deployment developer tool | 2026-06-09 |
| **ARCHITECTURE** | | | | |
| `../../docs/project_high_level_architecture.mmd` | Diagram | Draft | Consolidated current architecture — two-path design with Surface Triage + Token Budget node added to Path B | 2026-06-10 |
| `../../docs/project_architecture_cascading_intelligence.mmd` | Diagram | Draft | Research-validated evolution — Cascading Intelligence Pipeline: 7 improvements + multi-language generalization: Joern CPG Engine replaces CodeQL+Joern (Universal CPG shared between Path A taint and Path B targeting) · Semgrep+ast-grep replaces Semgrep-only (MIT · Tree-sitter · 30+ languages) · Heuristic Targeting now CPG-based (language-agnostic, no per-language rules) · Trivy replaces manual NVD refresh (Go library · OSV+NVD+GitHub Advisory) · UniXcoder language routing (unsupported langs skip classifier → LLM directly) · Fraunhofer-AISEC/cpg planned for Approach 3+ (Rust · Kotlin · Swift) | 2026-06-11 |
| ~~`specs/proposals/LEGACY_technical_proposals.md`~~ | Spec | **Deleted** | Superseded — removed 2026-06-09 | — |
| ~~`specs/architecture/LEGACY_architecture_deep_dive.md`~~ | Spec | **Deleted** | Superseded — removed 2026-06-09 | — |
| **RESEARCH** | | | | |
| `research/market_analysis/gtm_analysis.md` | Research | Draft | 7-section market analysis. Updated 2026 stats: 53% vuln rate, 1 in 5 breaches from AI code, real breach examples (CVE-2025-48757, Moltbook, The Tea App). Added Gap 3 (pentest tools different lane), Gap 4 renamed. | 2026-06-09 |
| `research/market_analysis/sizing_tam_sam.md` | Research | Draft | Bottom-up TAM ($670M–$4.2B), SAM ($134M–$1.47B), SOM estimates with comparable tool benchmarks and sensitivity analysis | 2026-06-08 |
| ~~`research/market_analysis/LEGACY_gtm_analysis.md`~~ | Research | **Deleted** | Superseded — removed 2026-06-09 | — |
| `research/competitor_teardown/comparison_matrix.md` | Research | Draft | Two-category competitive map: SAST tools (9-tool matrix) + Automated Pentest tools (Strix AI, XBOW, PentestGPT, RidgeGen — different lane). Updated differentiators for two-path design | 2026-06-09 |
| `research/competitor_teardown/teardowns/semgrep.md` | Research | Draft | Semgrep teardown: OCaml/tree-sitter architecture, $193M funding history, 6 strengths, 6 weaknesses, AI-threat handling | 2026-06-08 |
| `research/competitor_teardown/teardowns/snyk.md` | Research | Draft | Snyk Code teardown: DeepCode AI engine, $407.8M ARR, data handling policy, Local Engine trade-offs | 2026-06-08 |
| `research/competitor_teardown/teardowns/coderabbit.md` | Research | Draft | CodeRabbit teardown: GCP Cloud Run architecture, PR-gated workflow constraints, $550M valuation, offline gap | 2026-06-08 |
| `research/competitor_teardown/teardowns/trufflehog.md` | Research | Draft | TruffleHog teardown: entropy + regex + live-verification architecture, AGPL-3.0 licence, complementary (not competing) positioning | 2026-06-08 |
| `research/user_interviews/personas.md` | Research | Draft | 3 user personas (Solo Vibe Coder, Security-Conscious Team Lead, Enterprise Security Engineer) with ICP trade-off analysis | 2026-06-08 |
| `research/user_interviews/interview_template.md` | Research | Stub | 10-question structured developer interview guide — ready to use for primary research | 2026-06-08 |
| **DATA & EVIDENCE** | | | | |
| `data/evidence/market_size_sources.md` | Evidence | Draft | 100+ citations across all research documents, rated by confidence level | 2026-06-08 |
| `../../docs/architecture_evolution.md` | Reference | Draft | Baseline → Cascading Intelligence Pipeline comparison across efficiency, cost, accuracy, coverage, language support, privacy, output quality, and competitive position. Includes key metrics and resume talking points. | 2026-06-11 |
| **EXECUTION** | | | | |
| `../../docs/execution-overview.xlsx` | Plan | Draft | Executive timeline (Approach 1, Jun 9–20) + Research Papers sheet: 86 papers across 17 areas — smart paper manager with Category, Tags, Read Status, Literature Review Notes, auto-filter on all columns. Generated by `docs/generate_execution_plan_xlsx.py` | 2026-06-11 |
| `../../docs/generate_execution_plan_xlsx.py` | Script | Draft | Python/openpyxl script that generates execution-overview.xlsx — edit this file to update the workbook, then run with python3 | 2026-06-11 |
| `../../docs/project_architecture_cascading_intelligence.mmd` | Diagram | Draft | Full detailed architecture spec — Cascading Intelligence Pipeline with 12 components: Model IV · Differential Indexer · Semgrep+ast-grep · Joern CPG Engine (replaces CodeQL+Joern) · LLM Verifier · Heuristic Targeting (CPG-based, language-agnostic) · Call Graph+CVE(Trivy)+BOLAZ · Classifier (with language routing) · Call Chain Context Assembler · Threat Feature Extractor · Token Budget Controller · LLM Semantic Scan (ReAct+VULSOLVER) · Scan Security Context Store · Dedup SSVC · PoE Layer | 2026-06-11 |
| `../../docs/architecture_overview.mmd` | Diagram | Draft | Mentor-feedback simplified diagram — 1-line node labels, all structural elements preserved (CPG sharing, SCS, PoE layer, tier subgraphs); intended as the quick-read companion to architecture_detail.md | 2026-06-12 |
| `../../docs/architecture_detail.md` | Reference | Draft | Full prose architecture document — every component explained (what it does, why it exists, key technical choices); Design Principles section; self-contained; no other doc needed to understand the architecture | 2026-06-12 |
| `../../docs/project_high_level_architecture.mmd` | Diagram | Draft | Older simplified two-path overview diagram — superseded by architecture_overview.mmd for presentation use | 2026-06-10 |
| `../../docs/execution_timeline_flowchart.mmd` | Diagram | Draft | Mermaid flowchart showing phased delivery timeline across Approaches 1–3 (renamed from project_execution_plan.mmd) | 2026-06-11 |
| `../../docs/execution-plan-approach-1.md` | Plan | Draft | Detailed Approach 1 markdown plan with PERT estimates — source file for the .docx | 2026-06-10 |
| `../../docs/execution-plan-approach-1.docx` | Plan | Draft | Word document version of Approach 1 execution plan (pandoc-generated from .md) | 2026-06-10 |
| **DECISIONS** | | | | |
| `decisions/assumptions.md` | Decision | Draft | 18 assumptions register. Added A-18 (UniXcoder F1=94.73% is on BigVul C/C++, not AI-generated code — benchmark on AI-generated Python/TS/Java/Go required before publishing accuracy claims) | 2026-06-11 |
| `decisions/risk_registry.md` | Decision | Draft | 15-risk register. Added R-13 (Strix CI/CD overlap), R-14 (positioning confusion), R-15 (AI breach headlines attracting large competitors) | 2026-06-09 |

---

## Folder Completeness Summary

| Folder | Total Docs | Draft | Stub | Deleted |
|---|---|---|---|---|
| `notebooks/` | 1 | 1 | 0 | 0 |
| `specs/proposals/` | 5 | 5 | 0 | 1 |
| `specs/architecture/` | 0 | 0 | 0 | 1 |
| `research/market_analysis/` | 2 | 2 | 0 | 1 |
| `research/competitor_teardown/` | 5 | 5 | 0 | 0 |
| `research/user_interviews/` | 2 | 1 | 1 | 0 |
| `data/evidence/` | 1 | 1 | 0 | 0 |
| `decisions/` | 2 | 2 | 0 | 0 |
| **Total** | **18** | **17** | **1** | **3** |

---

## Next Steps

- [ ] Validate personas with 3+ actual developer interviews (`research/user_interviews/interview_template.md`)
- [ ] Commission hardware benchmarks to validate performance claims in `specs/proposals/tech_stack_analysis.md`
- [ ] Tech lead reviews `specs/proposals/README.md` (synthesis) and selects approach
- [ ] Update Approach docs to `Review` status before tech lead meeting
- [ ] Delete LEGACY files once content has been verified as superseded

---

*Last updated: 2026-06-12*
