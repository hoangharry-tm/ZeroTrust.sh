# Sheet 7 — Research Papers

**Sheet name:** `Research Papers`
**Status:** KEEP AS-IS — this sheet exists in the current workbook and should not be modified.
**Purpose:** Academic catalogue supporting the ZeroTrust.sh architecture. 40 papers across 7 research areas, each linked to a specific architecture component.

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Related Research Papers` | 14pt bold white on `#1F3864`, height 30px |
| 2 | `Compiled: 2026-06-10  ·  Sources: arXiv · ACM · IEEE · USENIX · Semantic Scholar` | 10pt italic white on `#2E5FA3`, height 18px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers | 11pt bold white on `#2E5FA3`, height 22px |

> Note: This sheet retains the original font sizes (14pt title, 11pt headers, 10pt data) as it predates the 20pt/12pt convention applied to the new sheets. Do not reformat it.

---

## Column Schema (existing, do not change)

| Col | Header | Width (chars) |
|---|---|---|
| A | # | 5 |
| B | Title | 62 |
| C | Authors | 22 |
| D | Year | 7 |
| E | Venue | 28 |
| F | Relevance to ZeroTrust.sh | 55 |
| G | URL | 45 |

---

## Area Structure

The sheet groups papers by research area. Each area has a full-width merged dark navy header row followed by individual paper rows.

### AREA 1 — Deep Learning & ML for Vulnerability Detection (4 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 1 | Automated Vulnerability Detection in Source Code Using Deep Representation Learning | Feng et al. | 2026 | arXiv | CNN-based deep representation learning — validates ML classifier gate in Path B Tier 2 |
| 2 | DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection | Jia et al. | 2023 | RAID 2023 / ACM | Largest diverse C/C++ vulnerability dataset (18,945 functions, 150 CWEs) — training data source for Code Vulnerability Classifier |
| 3 | Vulnerability Detection in C/C++ Code with Deep Learning | Multiple authors | 2024 | arXiv | Neural networks with program slices — informs Tier 2 classifier design |
| 4 | Deep Learning Aided Software Vulnerability Detection: A Survey | Survey authors | 2025 | arXiv | Comprehensive DL survey — baseline reference for Tier 2 classifier selection |

---

### AREA 2 — Graph Neural Networks for Vulnerability Detection (6 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 5 | Software Vulnerability Detection Using a Lightweight Graph Neural Network (VulGNN) | Zhu et al. | 2026 | arXiv | Lightweight GNN achieving LLM-parity at 100x smaller size — validates cheap local classifier concept |
| 6 | Vul-LMGNNs: Fusing Language Models and Graph Neural Networks for Code Vulnerability Detection | Rong et al. | 2024 | arXiv | Hybrid code LM + GNN — informs Call Graph + Classifier integration in Path B Tier 2 |
| 7 | Structure-Aware Code Vulnerability Analysis With Graph Neural Networks | Allamanis et al. | 2024 | arXiv | GNN-based analysis using Java vulnerability-fixing commits — informs structure-aware detection |
| 8 | Graph Neural Networks for Vulnerability Detection: A Counterfactual Explanation | Li et al. | 2024 | arXiv | Explainability analysis of GNN detection — informs confidence scoring in Dedup layer |
| 9 | ReGVD: Revisiting Graph Neural Networks for Vulnerability Detection | Nguyen et al. | 2022 | ACM/IEEE | Foundational GNN model treating source code as flat token sequences — baseline for Tier 2 classifier |
| 10 | LineVD: Statement-level Vulnerability Detection using Graph Neural Networks | Chen et al. | 2022 | arXiv | Fine-grained GNN vulnerability localization — informs line-level finding output in HTML report |

---

### AREA 3 — LLM for Code Security Analysis (6 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 11 | LLMs in Code Vulnerability Analysis: A Proof of Concept | Kochling et al. | 2026 | arXiv | Empirical PoC for LLM vulnerability analysis — validates LLM Semantic Scan role in Path B Tier 3 |
| 12 | IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities | Scanlon et al. | 2024 | arXiv | Hybrid SAST+LLM detecting 55/120 vulns + 6 new, reducing FP by 80% — directly validates ZeroTrust.sh hybrid design |
| 13 | Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead | Zhang et al. | 2025 | ACM TOSEM | Comprehensive LLM vulnerability + repair survey — informs patch generation design across all approaches |
| 14 | Understanding the Effectiveness of LLMs in Detecting Security Vulnerabilities | Steenhoek et al. | 2023 | arXiv | Systematic LLM evaluation with prompting strategy analysis — informs LLM Verifier prompt design in Path A |
| 15 | Large Language Models for Source Code Analysis: Applications, Models and Datasets | Sharma et al. | 2025 | arXiv | Survey of LLM architectures for code analysis — model selection reference for all LLM components |
| 16 | Can Large Language Models Find And Fix Vulnerable Software? | Pearce et al. | 2023 | arXiv | Empirical evaluation of LLM detection + repair — validates dual-role LLM use in Approaches 2 and 3 |

---

### AREA 4 — Hybrid Static Analysis + LLM (5 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 17 | LLM-Driven SAST-Genius: A Hybrid Static Analysis Framework for Comprehensive and Actionable Security | Multiple authors | 2024 | arXiv | Hybrid SAST+LLM reducing FP by 91% (225→20 alerts) vs Semgrep alone — strongest validation of ZeroTrust.sh architecture |
| 18 | ZeroFalse: Improving Precision in Static Analysis with LLMs | Scanlon et al. | 2024 | arXiv | LLM false positive reduction in static analysis — validates LLM Verifier design in Path A |
| 19 | Combining Large Language Models with Static Analyzers for Code Review Generation | Jaoua et al. | 2025 | arXiv | LLM + static analysis for code review — informs patch suggestion output format |
| 20 | A Contemporary Survey of LLM-Assisted Program Analysis | Survey authors | 2025 | arXiv | Comprehensive survey of LLM program analysis techniques — architecture reference for all three approaches |
| 21 | RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing | Li et al. | 2025 | arXiv | LLM-agent for repo-level auditing — informs Approach 3 multi-agent orchestration design |

---

### AREA 5 — AI-Generated Code Security & Prompt Injection (5 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 22 | Security Vulnerabilities in AI-Generated Code: A Large-Scale Analysis of Public GitHub Repositories | Zhao et al. | 2024 | IEEE/ACM | 4,241 CWE instances across AI-generated code from 4 tools — empirical validation of the core ZeroTrust.sh problem statement |
| 23 | Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis | Yang et al. | 2026 | arXiv | 85%+ attack success rates for prompt injection in agentic assistants — validates ZeroTrust.sh AI-specific threat detection |
| 24 | Security Degradation in Iterative AI Code Generation: A Systematic Analysis of the Paradox | Multiple authors | 2025 | IEEE-ISTAS | Iterative LLM interactions without human review introduce new vulnerabilities — validates vibe-coding threat model |
| 25 | Assessing the Quality and Security of AI-Generated Code: A Quantitative Analysis | Multiple authors | 2024 | arXiv | Quantitative security analysis of AI-generated code — market validation and threat taxonomy reference |
| 26 | You Still Have to Study: On the Security of LLM Generated Code | Ferrara et al. | 2024 | arXiv | 36-40% of Copilot code contains CWE vulnerabilities — key statistic for product positioning and pitch |

---

### AREA 6 — Token Cost Optimization for LLM Pipelines (4 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 27 | FrugalGPT: How to Use Large Language Models While Reducing Cost and Improving Performance | Eisingerich et al. | 2023 | arXiv | Cascade routing achieving 98% cost savings — theoretical foundation for Cascading Intelligence architecture |
| 28 | Batch Prompting: Efficient Inference with Large Language Model APIs | Rajkumar et al. | 2023 | arXiv | Batch processing reducing LLM token costs up to 5x — informs Token Budget Controller batching strategy |
| 29 | Token Sugar: Making Source Code Sweeter for LLMs through Token-Efficient Shorthand | Multiple authors | 2025 | arXiv | Token optimization for code representation — informs context chunking in Token Budget Controller |
| 30 | Learning to Focus: Context Extraction for Efficient Code Vulnerability Detection with Language Models | Dittmann et al. | 2025 | arXiv | Context filtering for reducing LLM token consumption in vulnerability detection — directly validates Token Budget Controller |

---

### AREA 7 — Call Graph, Taint Analysis & Code Representations (10 papers)

| # | Title | Authors | Year | Venue | Relevance |
|---|---|---|---|---|---|
| 31 | Vulnerability Detection with Interprocedural Context in Multiple Languages | Gharibi et al. | 2024 | arXiv | Interprocedural analysis impact on LLM detection — validates Call Graph + CVE Enrichment in Path B |
| 32 | Multi-Agent Taint Specification Extraction for Vulnerability Detection | Zhang et al. | 2026 | arXiv | Multi-agent LLM + taint analysis — informs Approach 3 multi-agent architecture with CodeQL/Joern |
| 33 | LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided LLMs | Pan et al. | 2024 | arXiv | CPG-guided LLM for context-aware detection — informs CPG integration in Path B call graph analysis |
| 34 | Bridging Code Property Graphs and Language Models for Program Analysis | Mahfouz et al. | 2026 | arXiv | Framework bridging CPG and LLMs — validates hybrid CPG+LLM design in Path B |
| 35 | Enhancing Software Vulnerability Detection Using Code Property Graphs and Convolutional Neural Networks | Multiple authors | 2025 | arXiv | CPG+CNN for local and global code structure — informs Code Classifier training |
| 36 | VulTrLM: LLM-Assisted Vulnerability Detection via AST Decomposition and Comment Enhancement | Liu et al. | 2025 | Empirical SE | LLM-assisted AST decomposition — informs AST preprocessing in Path B Tier 1 |
| 37 | Dataflow Analysis-Inspired Deep Learning for Efficient Vulnerability Detection | Cheng et al. | 2022 | arXiv | Dataflow analysis-inspired DL — validates dataflow integration in Path A CodeQL/Joern |
| 38 | Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry | Dittmann et al. | 2026 | arXiv | Industrial study on LLM FP reduction — validates LLM Verifier design at production scale |
| 39 | LSAST: Enhancing Cybersecurity through LLM-supported Static Application Security Testing | Multiple authors | 2024 | arXiv | Locally-hostable LLM for SAST without cloud APIs — validates privacy-first local LLM deployment |
| 40 | Software Vulnerability Analysis Across Programming Language and Program Representation Landscapes: A Survey | Multiple authors | 2025 | arXiv | Survey of AST, CFG, PDG, CPG representations — reference for program representation selection across all approaches |

---

## Implementation Note

This sheet is generated by the `build_research_papers()` function in `docs/generate_overview.py`. The data is hardcoded in the script as a list of `(area_name, papers_list)` tuples — identical to the original. Do not modify this sheet's content or column structure; add new papers by appending to the data list in the script and re-running.
