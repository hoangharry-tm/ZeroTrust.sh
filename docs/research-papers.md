# ZeroTrust.sh — Research Papers

87 papers across 17 research areas. **Read Status**: `Unread` · `Reading` · `Read` · `Reviewed`

---

## Area 1 — ML/DL for Vulnerability Detection

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Automated Vulnerability Detection in Source Code Using Deep Representation Learning | Feng et al. | 2026 | arXiv | Unread | CNN-based deep representation learning for vulnerability detection — validates ML classifier gate in Reasoning Tier 2 | CNN, deep representation learning, source code, vulnerability classifier | [arXiv](https://arxiv.org/abs/2602.23121) | |
| 2 | DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection | Jia et al. | 2023 | RAID 2023 / ACM | Unread | Largest diverse C/C++ vulnerability dataset (18,945 functions, 150 CWEs) — training data source for Code Vulnerability Classifier | dataset, C/C++, CWE, BigVul alternative, training data, benchmark, 18945 functions | [arXiv](https://arxiv.org/abs/2304.00409) | |
| 3 | Vulnerability Detection in C/C++ Code with Deep Learning | Multiple authors | 2024 | arXiv | Unread | Neural networks with program slices for vulnerability detection — informs Tier 2 classifier design | neural network, program slicing, C/C++, deep learning | [arXiv](https://arxiv.org/abs/2405.12384) | |
| 4 | Deep Learning Aided Software Vulnerability Detection: A Survey | Survey authors | 2025 | arXiv | Unread | Comprehensive DL survey for vulnerability detection — baseline reference for Tier 2 classifier selection | survey, deep learning, vulnerability detection, baseline comparison | [arXiv](https://arxiv.org/abs/2503.04002) | |

---

## Area 2 — Graph Neural Networks for Vulnerability Detection

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 5 | Software Vulnerability Detection Using a Lightweight Graph Neural Network (VulGNN) | Zhu et al. | 2026 | arXiv | Unread | Lightweight GNN achieving LLM-parity at 100x smaller size — validates cheap local classifier concept in new architecture | GNN, lightweight, LLM-parity, local inference, classifier, small model | [arXiv](https://arxiv.org/abs/2603.29216) | |
| 6 | Vul-LMGNNs: Fusing Language Models and Graph Neural Networks for Code Vulnerability Detection | Rong et al. | 2024 | arXiv | Unread | Hybrid code LM + GNN — informs Call Graph + Classifier integration in Reasoning Tier 2 | GNN, language model, hybrid, code representation, code LM | [arXiv](https://arxiv.org/abs/2404.14719) | |
| 7 | Structure-Aware Code Vulnerability Analysis With Graph Neural Networks | Allamanis et al. | 2024 | arXiv | Unread | GNN-based vulnerability analysis using Java vulnerability-fixing commits — informs structure-aware detection | GNN, Java, structure-aware, vulnerability fixing, commit-level | [arXiv](https://arxiv.org/abs/2307.11454) | |
| 8 | Graph Neural Networks for Vulnerability Detection: A Counterfactual Explanation | Li et al. | 2024 | arXiv | Unread | Explainability analysis of GNN detection — informs confidence scoring in Dedup layer | GNN, explainability, counterfactual, confidence scoring, interpretability | [arXiv](https://arxiv.org/abs/2404.15687) | |
| 9 | ReGVD: Revisiting Graph Neural Networks for Vulnerability Detection | Nguyen et al. | 2022 | ACM/IEEE | Unread | Foundational GNN model treating source code as flat token sequences — baseline for Tier 2 classifier | GNN, token sequence, baseline, benchmark, foundational | [ACM](https://dl.acm.org/doi/abs/10.1145/3510454.3516865) | |
| 10 | LineVD: Statement-level Vulnerability Detection using Graph Neural Networks | Chen et al. | 2022 | arXiv | Unread | Fine-grained GNN vulnerability localization — informs line-level finding output in HTML report | GNN, statement-level, line localization, fine-grained, HTML report | [arXiv](https://arxiv.org/abs/2203.05181) | |

---

## Area 3 — LLM for Code Security Analysis

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 11 | LLMs in Code Vulnerability Analysis: A Proof of Concept | Kochling et al. | 2026 | arXiv | Unread | Empirical PoC for LLM vulnerability analysis — validates LLM Semantic Scan role in Reasoning Tier 3 | LLM, empirical, proof-of-concept, zero-shot, Reasoning validation | [arXiv](https://arxiv.org/abs/2601.08691) | |
| 12 | IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities | Scanlon et al. | 2024 | arXiv | Unread | Hybrid SAST+LLM detecting 55/120 vulns + 6 new, reducing FP by 80% — directly validates ZeroTrust.sh hybrid design | hybrid SAST+LLM, false positive, 80% FP reduction, IRIS, key paper | [arXiv](https://arxiv.org/abs/2405.17238) | |
| 13 | Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead | Zhang et al. | 2025 | ACM TOSEM | Unread | Comprehensive LLM vulnerability + repair survey — informs patch generation design across all approaches | survey, LLM, vulnerability repair, patch generation, comprehensive review | [ACM](https://dl.acm.org/doi/10.1145/3708522) | |
| 14 | Understanding the Effectiveness of LLMs in Detecting Security Vulnerabilities | Steenhoek et al. | 2023 | arXiv | Unread | Systematic LLM evaluation with prompting strategy analysis — informs LLM Verifier prompt design in Deterministic | LLM, prompting strategy, systematic evaluation, false positive, prompt design | [arXiv](https://arxiv.org/abs/2311.16169) | |
| 15 | Large Language Models for Source Code Analysis: Applications, Models and Datasets | Sharma et al. | 2025 | arXiv | Unread | Survey of LLM architectures for code analysis — model selection reference for LLM components | survey, LLM architectures, code analysis, model selection, datasets | [arXiv](https://arxiv.org/abs/2503.17502) | |
| 16 | Can Large Language Models Find And Fix Vulnerable Software? | Pearce et al. | 2023 | arXiv | Unread | Empirical evaluation of LLM detection + repair — validates dual-role LLM use in Approaches 2 and 3 | LLM, detection, repair, empirical evaluation, fix generation | [arXiv](https://arxiv.org/abs/2308.10345) | |

---

## Area 4 — Hybrid SAST + LLM

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 17 | LLM-Driven SAST-Genius: A Hybrid Static Analysis Framework for Comprehensive and Actionable Security | Multiple authors | 2024 | arXiv | Unread | Hybrid SAST+LLM reducing FP by 91% (225→20 alerts) vs Semgrep alone — strongest validation of ZeroTrust.sh architecture | hybrid, SAST+LLM, false positive, 91% FP reduction, Semgrep, key paper | [arXiv](https://arxiv.org/abs/2509.15433) | |
| 18 | ZeroFalse: Improving Precision in Static Analysis with LLMs | Scanlon et al. | 2024 | arXiv | Unread | LLM false positive reduction in static analysis — validates LLM Verifier design in Deterministic | LLM, false positive reduction, static analysis, precision, ZeroFalse | [arXiv](https://arxiv.org/abs/2510.02534) | |
| 19 | Combining Large Language Models with Static Analyzers for Code Review Generation | Jaoua et al. | 2025 | arXiv | Unread | LLM + static analysis for code review — informs patch suggestion output format | LLM, static analysis, code review, patch suggestion, output format | [arXiv](https://arxiv.org/abs/2502.06633) | |
| 20 | A Contemporary Survey of LLM-Assisted Program Analysis | Survey authors | 2025 | arXiv | Unread | Comprehensive survey of LLM program analysis techniques — architecture reference for all three approaches | survey, program analysis, LLM, comprehensive, all approaches reference | [arXiv](https://arxiv.org/abs/2502.18474) | |
| 21 | RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing | Li et al. | 2025 | arXiv | Unread | LLM-agent for repo-level auditing — informs Approach 3 multi-agent orchestration design | LLM agent, repository-level, multi-agent, orchestration, Approach 3 | [arXiv](https://arxiv.org/abs/2501.18160) | |
| 38 | Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry | Dittmann et al. | 2026 | arXiv | Unread | Industrial study on LLM false positive reduction — validates LLM Verifier design in Deterministic at production scale | false positive, LLM, industrial study, production scale, empirical | [arXiv](https://arxiv.org/abs/2601.18844) | |
| 39 | LSAST: Enhancing Cybersecurity through LLM-supported Static Application Security Testing | Multiple authors | 2024 | arXiv | Unread | Locally-hostable LLM for SAST without cloud APIs — validates privacy-first local LLM deployment approach | local LLM, privacy-first, offline, SAST, no cloud API, on-device | [arXiv](https://arxiv.org/abs/2409.15735) | |

---

## Area 5 — AI-Generated Code Security

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 22 | Security Vulnerabilities in AI-Generated Code: A Large-Scale Analysis of Public GitHub Repositories | Zhao et al. | 2024 | IEEE/ACM | Unread | 4,241 CWE instances across AI-generated code from 4 tools — empirical validation of the core ZeroTrust.sh problem statement | AI-generated code, CWE, GitHub, empirical, 4241 instances, market validation | [arXiv](https://arxiv.org/abs/2510.26103) | |
| 23 | Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis | Yang et al. | 2026 | arXiv | Unread | 85%+ attack success rates for prompt injection in agentic assistants — validates ZeroTrust.sh AI-specific threat detection | prompt injection, agentic, coding assistant, attack, 85% success rate | [arXiv](https://arxiv.org/abs/2601.17548) | |
| 24 | Security Degradation in Iterative AI Code Generation: A Systematic Analysis of the Paradox | Multiple authors | 2025 | IEEE-ISTAS | Unread | Iterative LLM interactions without human review introduce new vulnerabilities — validates vibe-coding threat model | iterative generation, vibe-coding, security degradation, LLM, threat model | [arXiv](https://arxiv.org/abs/2506.11022) | |
| 25 | Assessing the Quality and Security of AI-Generated Code: A Quantitative Analysis | Multiple authors | 2024 | arXiv | Unread | Quantitative security analysis of AI-generated code — market validation and threat taxonomy reference | AI-generated code, quantitative, security assessment, quality metrics | [arXiv](https://arxiv.org/abs/2508.14727) | |
| 26 | You Still Have to Study: On the Security of LLM Generated Code | Ferrara et al. | 2024 | arXiv | Unread | 36–40% of Copilot code contains CWE vulnerabilities — key statistic for product positioning and pitch | Copilot, CWE, 36-40% vulnerability rate, LLM-generated code, pitch statistic | [arXiv](https://arxiv.org/abs/2408.07106) | |

---

## Area 6 — Token Cost Optimization

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 27 | FrugalGPT: How to Use Large Language Models While Reducing Cost and Improving Performance | Eisingerich et al. | 2023 | arXiv | Unread | Cascade routing achieving 98% cost savings — theoretical foundation for Cascading Intelligence architecture | cascade routing, cost optimization, 98% savings, LLM pipeline, FrugalGPT | [arXiv](https://arxiv.org/abs/2305.05176) | |
| 28 | Batch Prompting: Efficient Inference with Large Language Model APIs | Rajkumar et al. | 2023 | arXiv | Unread | Batch processing reducing LLM token costs up to 5x — informs Token Budget Controller batching strategy | batch processing, token cost, 5x reduction, inference efficiency | [arXiv](https://arxiv.org/abs/2301.08721) | |
| 29 | Token Sugar: Making Source Code Sweeter for LLMs through Token-Efficient Shorthand | Multiple authors | 2025 | arXiv | Unread | Token optimization for code representation — informs context chunking in Token Budget Controller | token optimization, code representation, shorthand, context compression | [arXiv](https://arxiv.org/abs/2512.08266) | |
| 30 | Learning to Focus: Context Extraction for Efficient Code Vulnerability Detection with Language Models | Dittmann et al. | 2025 | arXiv | Unread | Context filtering for reducing LLM token consumption in vulnerability detection — directly validates Token Budget Controller | context filtering, token budget, vulnerability detection, efficiency, focus extraction | [arXiv](https://arxiv.org/abs/2505.17460) | |

---

## Area 7 — Call Graph, Taint Analysis & Code Representations

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 31 | Vulnerability Detection with Interprocedural Context in Multiple Languages: Assessing Effectiveness and Cost | Gharibi et al. | 2024 | arXiv | Unread | Interprocedural analysis impact on LLM detection across languages — validates Call Graph + CVE Enrichment in Reasoning | interprocedural, multi-language, call graph, LLM detection, effectiveness | [arXiv](https://arxiv.org/abs/2604.08417) | |
| 32 | Multi-Agent Taint Specification Extraction for Vulnerability Detection | Zhang et al. | 2026 | arXiv | Unread | Multi-agent LLM + taint analysis — informs Approach 3 multi-agent architecture with CodeQL/Joern integration | taint analysis, multi-agent, CodeQL, LLM, Approach 3 | [arXiv](https://arxiv.org/abs/2601.10865) | |
| 33 | LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided LLMs | Pan et al. | 2024 | arXiv | Unread | CPG-guided LLM for context-aware detection — informs CPG integration in Reasoning call graph analysis | CPG, code property graph, context-aware, LLM, Reasoning integration | [arXiv](https://arxiv.org/abs/2507.16585) | |
| 34 | Bridging Code Property Graphs and Language Models for Program Analysis | Mahfouz et al. | 2026 | arXiv | Unread | Framework bridging CPG and LLMs — validates hybrid CPG+LLM design in Reasoning | CPG, LLM, program analysis, hybrid CPG+LLM, framework | [arXiv](https://arxiv.org/abs/2603.24837) | |
| 35 | Enhancing Software Vulnerability Detection Using Code Property Graphs and Convolutional Neural Networks | Multiple authors | 2025 | arXiv | Unread | CPG+CNN for local and global code structure — informs Code Classifier training in new architecture | CPG, CNN, local structure, global structure, code classifier training | [arXiv](https://arxiv.org/abs/2503.18175) | |
| 36 | VulTrLM: LLM-Assisted Vulnerability Detection via AST Decomposition and Comment Enhancement | Liu et al. | 2025 | Empirical Software Engineering | Unread | LLM-assisted AST decomposition for semantic enhancement — informs AST preprocessing in Reasoning Tier 1 | LLM, AST decomposition, semantic enhancement, comment, AST preprocessing | [ACM](https://dl.acm.org/doi/10.1007/s10664-025-10738-7) | |
| 37 | Dataflow Analysis-Inspired Deep Learning for Efficient Vulnerability Detection | Cheng et al. | 2022 | arXiv | Unread | Dataflow analysis-inspired DL approach — validates dataflow integration in Deterministic CodeQL/Joern | dataflow analysis, deep learning, CodeQL integration, Deterministic validation | [arXiv](https://arxiv.org/abs/2212.08108) | |
| 40 | Software Vulnerability Analysis Across Programming Language and Program Representation Landscapes: A Survey | Multiple authors | 2025 | arXiv | Unread | Survey of AST, CFG, PDG, CPG representations — reference for program representation selection across all approaches | survey, AST, CFG, PDG, CPG, program representation, multi-language | [arXiv](https://arxiv.org/abs/2503.20244) | |

---

## Area 8 — Package Hallucination & Supply Chain

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 41 | We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs | Spracklen et al. | 2024 | USENIX Security 2025 | Unread | Foundational study: 205,474 hallucinated package names across 16 LLMs — commercial at 5.2%, open-source at 21.7%. Baseline threat ZeroTrust.sh must detect. | slopsquatting, package hallucination, supply chain, npm, pip, 205474 hallucinations, foundational | [arXiv](https://arxiv.org/abs/2406.10279) | |
| 42 | Importing Phantoms: Measuring LLM Package Hallucination Vulnerabilities | Krishna et al. | 2025 | arXiv | Unread | Hallucination rates across languages, model sizes, and task specificity — identifies highest-risk agent configurations for slopsquatting detection. | slopsquatting, package hallucination, language comparison, model size, Pareto frontier | [arXiv](https://arxiv.org/abs/2501.19012) | |
| 43 | The Range Shrinks, the Threat Remains: Re-evaluating LLM Package Hallucinations on the 2026 Frontier-Model Cohort | Multiple authors | 2026 | arXiv | Unread | Frontier models (Claude Haiku 4.5 at 4.62%, GPT-5.4-mini at 6.10%) still hallucinate; 127 package names all models invent — rich target set for detection rules. | slopsquatting, frontier models, Claude, GPT-5, 127 common hallucinations, 2026 benchmark | [arXiv](https://arxiv.org/abs/2605.17062) | |
| 44 | PackMonitor: Enabling Zero Package Hallucinations Through Decoding-Time Monitoring | Liu et al. | 2026 | arXiv | Unread | Defense via decoding-time intervention constraining generation to authoritative package lists — informs ZeroTrust.sh's detection and verification strategy. | slopsquatting, decoding-time defense, PyPI, npm, authoritative package list, prevention | [arXiv](https://arxiv.org/abs/2602.20717) | |
| 45 | Secure or Suspect? Investigating Package Hallucinations of Shell Command in Original and Quantized LLMs | Haque et al. | 2025 | arXiv | Unread | Quantized models have significantly higher hallucination rates; fabricated packages mimic GitHub/golang.org URLs — relevant for sophisticated slopsquatting detection. | slopsquatting, quantized models, GGUF, shell command, realistic URL mimicry | [arXiv](https://arxiv.org/abs/2512.08213) | |

---

## Area 9 — AI Agent Trust, Privilege Escalation & Prompt Injection

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 46 | 'Your AI, My Shell': Demystifying Prompt Injection Attacks on Agentic AI Coding Editors | Liu et al. | 2025 | arXiv | Unread | First empirical analysis of Cursor via repository poisoning — attackers inject malicious instructions into dev resources to hijack shell execution. Direct ZeroTrust.sh threat model. | prompt injection, Cursor, repository poisoning, agentic editor, shell execution hijack | [arXiv](https://arxiv.org/abs/2509.22040) | |
| 47 | The Dark Side of LLMs: Agent-based Attacks for Complete Computer Takeover | Lupinacci et al. | 2025 | arXiv | Unread | 94.4% of models vulnerable to direct injection; 83.3% to inter-agent trust exploitation — key data for detecting agent-to-agent attack chains in ZeroTrust.sh. | privilege escalation, inter-agent trust, 94.4% vulnerable, agent-to-agent attack, safety bypass | [arXiv](https://arxiv.org/abs/2507.06850) | |
| 48 | VIGIL: Defending LLM Agents Against Tool Stream Injection via Verify-Before-Commit | Lin et al. | 2026 | arXiv | Unread | Defense against tool stream injection; SIREN benchmark (959 attack cases) provides test corpus for ZeroTrust.sh detection validation. | tool stream injection, SIREN benchmark, verify-before-commit, runtime poisoning, 959 attack cases | [arXiv](https://arxiv.org/abs/2601.05755) | |
| 49 | Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges | Datta et al. | 2025 | arXiv | Unread | Comprehensive survey of agentic AI threat taxonomy distinguishing autonomous execution risks from traditional LLM safety — essential scope reference for ZeroTrust.sh. | survey, agentic AI, threat taxonomy, tool use, memory, autonomy, planning | [arXiv](https://arxiv.org/abs/2510.23883) | |
| 50 | Are AI-assisted Development Tools Immune to Prompt Injection? | Multiple authors | 2026 | arXiv | Unread | First empirical analysis of MCP clients (Claude Code, Cursor, Cline, Continue, Gemini CLI) against tool-poisoning attacks — directly relevant to detecting injection in AI tool contexts. | MCP, tool poisoning, Claude Code, Cursor, Cline, Continue, Gemini CLI, coding tools benchmark | [arXiv](https://arxiv.org/abs/2603.21642) | |
| 51 | Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework | Multiple authors | 2026 | arXiv | Unread | Formal model of privilege escalation in LLM agents with SEAgent MAC framework — informs detection rules for trust boundary violations in agentic codebases. | privilege escalation, MAC framework, SEAgent, formal model, agent security policy | [arXiv](https://arxiv.org/abs/2601.11893) | |

---

## Area 10 — Logic Vulnerability Detection (IDOR, Access Control)

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 52 | BacAlarm: Mining and Simulating Composite API Traffic to Prevent Broken Access Control Violations | Multiple authors | 2025 | arXiv | Unread | Broken access control detection in REST APIs via LLM-based agent traffic simulation and ensemble anomaly detection — core to detecting authorization gaps in Reasoning. | broken access control, REST API, OWASP API, LLM agent, RAG, anomaly detection | [arXiv](https://arxiv.org/abs/2512.19997) | |
| 53 | Rethinking Broken Object Level Authorization Attacks Under Zero Trust Principle | Wu et al. | 2025 | arXiv | Unread | BOLAZ: zero-trust defense for BOLA/IDOR via resource ID data flow analysis; discovered 35 new vulnerabilities — directly validates Reasoning's IDOR detection design. | BOLA, IDOR, zero trust, resource ID dataflow, authorization interval, 35 new CVEs | [arXiv](https://arxiv.org/abs/2507.02309) | |
| 54 | VULSOLVER: Vulnerability Detection via LLM-Driven Constraint Solving | Li et al. | 2025 | arXiv | Unread | SAST + LLM semantic reasoning with progressive constraint modeling achieves 96.29% accuracy — applicable to detecting contextually-wrong authorization logic. | LLM, constraint solving, call-chain analysis, 96.29% accuracy, semantic reasoning | [arXiv](https://arxiv.org/abs/2509.00882) | |
| 55 | SAVANT: Vulnerability Detection in Application Dependencies through Semantic-Guided Reachability Analysis | Multiple authors | 2025 | arXiv | Unread | Semantic preprocessing + LLM context analysis for vulnerable API patterns; 83.8% precision — relevant to detecting missing authorization checks in library calls. | semantic preprocessing, LLM, reachability analysis, library API, 83.8% precision | [arXiv](https://arxiv.org/abs/2506.17798) | |
| 56 | Argus: Reorchestrating Static Analysis via a Multi-Agent Ensemble for Full-Chain Security Vulnerability Detection | Multiple authors | 2025 | arXiv | Unread | First multi-agent LLM framework for SAST with multi-hop reasoning — discovers zero-day vulnerabilities spanning multiple functions; applicable to detecting business logic flaws. | multi-agent, SAST, false positive reduction, multi-hop reasoning, zero-day, full-chain | [arXiv](https://arxiv.org/abs/2604.06633) | |
| 57 | Benchmarking LLMs and LLM-based Agents in Practical Vulnerability Detection for Code Repositories | Multiple authors | 2025 | ACL 2025 | Unread | JitVul benchmark (879 CVEs) requires interprocedural analysis; ReAct agents outperform LLMs on auth flaws — suggests agentic approaches for Reasoning's multi-function context. | JitVul benchmark, 879 CVEs, interprocedural, ReAct agents, authorization flaws, ACL | [arXiv](https://arxiv.org/abs/2503.03586) | |
| 58 | Prompting the Priorities: A First Look at Evaluating LLMs for Vulnerability Triage and Prioritization | Multiple authors | 2025 | arXiv | Unread | LLM evaluation on SSVC triage framework with 384 real-world vulnerabilities — methodology for prioritizing high-risk code surfaces before deep Reasoning analysis. | SSVC, triage, prioritization, 384 real-world CVEs, risk surface selection, LLM evaluation | [arXiv](https://arxiv.org/abs/2510.18508) | |
| 59 | I Can't Believe It's Not a Valid Exploit | Multiple authors | 2026 | arXiv | Unread | PoC-Gym framework shows static analysis guidance improves LLM exploit generation by 21% — informs heuristics for filtering false-positive authorization scenarios in Reasoning. | PoC-Gym, exploit generation, static analysis guidance, 21% improvement, validation limits | [arXiv](https://arxiv.org/abs/2602.04165) | |

---

## Area 11 — Local LLM Deployment & On-Device Security

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 60 | Mind the Gap: A Practical Attack on GGUF Quantization | Egashira et al. | 2025 | ICML 2025 | Unread | Backdoor injection via GGUF quantization errors — essential threat model for ZeroTrust.sh's local LLM deployment: quantized models can exhibit hidden malicious behaviors. | GGUF, quantization, backdoor injection, Ollama, llama.cpp, supply chain, ICML | [arXiv](https://arxiv.org/abs/2505.23786) | |
| 61 | Widening the Gap: Exploiting LLM Quantization via Outlier Injection | Shi et al. | 2025 | arXiv | Unread | First quantization-conditioned attack affecting AWQ/GPTQ/GGUF — demonstrates supply-chain risks in locally-deployed quantized models; complements GGUF threat model. | quantization attack, AWQ, GPTQ, GGUF, outlier injection, adversarial, supply chain | [arXiv](https://arxiv.org/abs/2605.15152) | |
| 62 | A First Look At Efficient And Secure On-Device LLM Inference Against KV Leakage | Yang et al. | 2024 | arXiv | Unread | Privacy attacks on on-device LLM inference via KV cache leakage — demonstrates how local inference can leak conversation history; relevant to ZeroTrust.sh's privacy-first design. | on-device LLM, KV cache leakage, FHE, TEE, privacy, local inference security | [arXiv](https://arxiv.org/abs/2409.04040) | |
| 63 | A Cost-Benefit Analysis of On-Premise Large Language Model Deployment: Breaking Even with Commercial LLM Services | Pan et al. | 2025 | arXiv | Unread | Quantifies breakeven for on-premise LLM vs cloud APIs — supports ZeroTrust.sh's value proposition: local deployment becomes cost-competitive at scale. | on-premise, cost analysis, breakeven, Qwen, Llama, Mistral, cloud vs local, value proposition | [arXiv](https://arxiv.org/abs/2509.18101) | |

---

## Area 12 — Exploit Automation & Proof-of-Concept Generation

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 64 | Automated Vulnerability Validation and Verification: A Large Language Model Approach | Lotfi et al. | 2025 | arXiv | Unread | End-to-end LLM pipeline for automated CVE exploitation with Docker orchestration; 70% CVE reproduction rate — directly applicable to ZeroTrust.sh's Approach 3 PoE layer design. | CVE exploitation, Docker, automated validation, 70% reproduction rate, offline LLM, PoE layer | [arXiv](https://arxiv.org/abs/2509.24037) | |
| 65 | Patch-to-PoC: A Systematic Study of Agentic LLM Systems for Linux Kernel N-Day Reproduction | Pu et al. | 2026 | arXiv | Unread | Autonomous LLM-based PoC generation from kernel patches with 50%+ success on KernelCTF — K-REPRO agent architecture with VM management informs sandbox PoE design. | PoC generation, kernel exploit, KernelCTF, VM sandbox, 50%+ success, K-REPRO agent | [arXiv](https://arxiv.org/abs/2602.07287) | |
| 66 | PentestAgent: Incorporating LLM Agents to Automated Penetration Testing | Feng et al. | 2024 | arXiv | Unread | Multi-agent framework for autonomous pentest using Docker VulHub environments — demonstrates agent architecture for reconnaissance and exploitation applicable to ZeroTrust.sh red-team layer. | penetration testing, multi-agent, VulHub, Docker, reconnaissance, exploitation, red team | [arXiv](https://arxiv.org/abs/2411.05185) | |
| 67 | Directed Greybox Fuzzing via Large Language Model | Xu et al. | 2025 | arXiv | Unread | HGFuzzer uses LLMs to transform path constraints into code generation tasks; discovered 9 new CVEs with 17/20 trigger rate — alternative exploit discovery layer for Approach 3. | LLM fuzzing, path constraint, code generation, 9 new CVEs, 17/20 trigger rate, HGFuzzer | [arXiv](https://arxiv.org/abs/2505.03425) | |
| 68 | PoCGen: Generating Proof-of-Concept Exploits for Vulnerabilities in NPM Packages | Shen et al. | 2025 | arXiv | Unread | Autonomous LLM-based PoC for npm vulnerabilities (77% on SecBench.js); 6 PoCs in official CVE disclosures — demonstrates ecosystem-specific PoE applicability for JavaScript targets. | PoC generation, npm, JavaScript, Node.js, 77% success rate, CVE disclosure, ecosystem-specific | [arXiv](https://arxiv.org/abs/2506.04962) | |

---

## Area 13 — Prompt Compression & Context Reduction

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 69 | LLMLingua: Compressing Prompts for Accelerated Inference of Large Language Models | Jiang et al. | 2023 | arXiv | Unread | Iterative token-level compression with budget control; up to 20x compression with minimal loss — directly applicable to compressing code context before LLM security scans. | prompt compression, token pruning, 20x compression, budget control, coarse-to-fine | [arXiv](https://arxiv.org/abs/2310.05736) | |
| 70 | LLMLingua-2: Data Distillation for Efficient and Faithful Task-Agnostic Prompt Compression | Jiang et al. | 2024 | arXiv | Unread | Compression as token classification via GPT-4 distillation; 3–6x faster than LLMLingua with 2–5x compression ratios — ideal for repeated scans of similar code patterns. | prompt compression, data distillation, token classification, 3-6x faster, 1.6-2.9x latency | [arXiv](https://arxiv.org/abs/2403.12968) | |
| 71 | LongLLMLingua: Accelerating and Enhancing LLMs in Long Context Scenarios via Prompt Compression | Jiang et al. | 2023 | arXiv | Unread | Question-aware compression for long-context scenarios; 94% cost reduction on LooGLE — critical for scanning large codebases and enriching prompts with vulnerability databases. | long context, question-aware compression, document reordering, 94% cost reduction, 4x fewer tokens | [arXiv](https://arxiv.org/abs/2310.06839) | |
| 72 | RECOMP: Improving Retrieval-Augmented LMs with Compression and Selective Augmentation | Xu et al. | 2023 | arXiv | Unread | Compresses retrieved documents in RAG pipelines via extractive and abstractive methods — relevant when ZeroTrust.sh augments prompts with retrieved CVE or security knowledge. | RAG, retrieval augmentation, extractive compression, abstractive compression, 6% compression rate | [arXiv](https://arxiv.org/abs/2310.04408) | |
| 73 | Pruning the Unsurprising: Efficient LLM Reasoning via First-Token Surprisal | Multiple authors | 2025 | arXiv | Unread | ASAP framework compresses chain-of-thought by 23.5% tokens and 43.5% latency — optimizes reasoning chains in vulnerability analysis without sacrificing accuracy. | CoT compression, first-token surprisal, 23.5% token reduction, 43.5% latency reduction, ASAP | [arXiv](https://arxiv.org/abs/2508.05988) | |

---

## Area 14 — Prompt Engineering & Automatic Optimization

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 74 | Large Language Models as Optimizers (OPRO) | Yang et al. | 2023 | arXiv | Unread | Automatic prompt optimization via LLM-based iterative refinement; best prompts beat human-designed by up to 50% — applicable to auto-tuning ZeroTrust.sh security scanning prompts. | automatic prompt optimization, OPRO, LLM-based refinement, in-context learning, 50% improvement | [arXiv](https://arxiv.org/abs/2309.03409) | |
| 75 | Chain of Draft: Thinking Faster by Writing Less | Xu et al. | 2025 | arXiv | Unread | Reduces CoT verbosity to 7.6% of tokens while matching CoT accuracy — practical cost/latency reduction for reasoning-heavy vulnerability analysis in Reasoning. | chain of draft, CoT efficiency, 7.6% tokens, reasoning cost reduction, latency | [arXiv](https://arxiv.org/abs/2502.18600) | |
| 76 | Which Examples to Annotate for In-Context Learning? Towards Effective and Efficient Selection | Mavromatis et al. | 2023 | arXiv | Unread | AdaICL selects maximally informative few-shot examples under token budget constraints — applicable to selecting the best security examples per scan without exceeding token limits. | few-shot selection, in-context learning, budget constraint, uncertainty sampling, diversity, AdaICL | [arXiv](https://arxiv.org/abs/2310.20046) | |
| 77 | DecoPrompt: Decoding Prompts Reduces Hallucinations when Large Language Models Meet False Premises | Xu and Ma | 2024 | arXiv | Unread | Inference-time hallucination reduction by decoding the prompt itself — cost-effective false positive reduction for ZeroTrust.sh without model retraining. | hallucination reduction, false premises, decoding prompts, inference-time, no retraining | [arXiv](https://arxiv.org/abs/2411.07457) | |

---

## Area 15 — Inference Speed & KV-Cache Optimization

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 78 | Unlocking Efficiency in Large Language Model Inference: A Comprehensive Survey of Speculative Decoding | Multiple authors | 2024 | arXiv | Unread | Comprehensive survey of speculative decoding (small draft model + large verifier) for LLM inference acceleration — core technique for optimizing local Ollama/llama.cpp execution speed. | speculative decoding, draft model, parallel verification, inference acceleration, survey | [arXiv](https://arxiv.org/abs/2401.07851) | |
| 79 | Keep the Cost Down: A Review on Methods to Optimize LLM's KV-Cache Consumption | Multiple authors | 2024 | arXiv | Unread | Survey of KV-cache optimization strategies (PagedAttention, distributed KV-cache, token pruning) — reduces VRAM footprint for quantized GGUF models in ZeroTrust.sh local inference. | KV-cache, PagedAttention, vLLM, token pruning, VRAM, memory optimization, survey | [arXiv](https://arxiv.org/abs/2407.18003) | |
| 80 | FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness | Dao et al. | 2022 | arXiv | Unread | Foundational IO-aware attention reducing memory from O(N²) to O(N) — enables processing longer code snippets with lower memory overhead during semantic analysis. | flash attention, IO-aware, O(N) memory, foundational, attention efficiency, transformer | [arXiv](https://arxiv.org/abs/2205.14135) | |
| 81 | Why Low-Precision Transformer Training Fails: An Analysis on Flash Attention | Multiple authors | 2025 | arXiv | Unread | Analyzes Flash Attention behavior under low-precision quantization — critical for understanding performance characteristics of quantized models used in ZeroTrust.sh's local deployment. | low-precision, GGUF, flash attention, quantization, performance analysis, precision limits | [arXiv](https://arxiv.org/abs/2510.04212) | |
| 82 | Optimizing LLM Inference Throughput via Memory-aware and SLA-constrained Dynamic Batching | Multiple authors | 2025 | arXiv | Unread | Memory-aware dynamic batching with SLA constraints — optimizes continuous batching for ZeroTrust.sh's parallel Deterministic/Reasoning analysis phases to maximize throughput. | dynamic batching, throughput, SLA, memory-aware, continuous batching, parallel scanning | [arXiv](https://arxiv.org/abs/2503.05248) | |

---

## Area 16 — Structured Generation & Constrained Decoding

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 83 | XGrammar: Flexible and Efficient Structured Generation Engine for Large Language Models | Multiple authors | 2024 | arXiv | Unread | Grammar-constrained decoding supporting BNF/CFG with zero overhead — enables Reasoning LLM to output structured JSON vulnerability findings without post-processing verification tokens. | grammar-constrained decoding, BNF, CFG, JSON, zero overhead, structured output, XGrammar | [arXiv](https://arxiv.org/abs/2411.15100) | |
| 84 | JSONSchemaBench: A Rigorous Benchmark of Structured Outputs for Language Models | Multiple authors | 2025 | arXiv | Unread | Benchmarks constrained-decoding frameworks (Guidance, Outlines, XGrammar) on JSON Schema compliance — validates structured generation reliability for ZeroTrust.sh vulnerability report output. | JSON schema, structured output, Guidance, Outlines, XGrammar, benchmark, compliance | [arXiv](https://arxiv.org/abs/2501.10868) | |
| 85 | SynCode: LLM Generation with Grammar Augmentation | Multiple authors | 2024 | arXiv | Unread | Grammar-augmented generation enforcing output structure via syntactic constraints — alternative to XGrammar for ensuring ZeroTrust.sh semantic output conforms to fixed schema. | grammar augmentation, syntactic constraints, output schema, structured generation, alternative to XGrammar | [arXiv](https://arxiv.org/abs/2403.01632) | |
| 87 | XGrammar-2: Efficient Structured Generation for Dynamic Agentic LLM Workloads | Multiple authors | 2026 | arXiv | Unread | Successor to XGrammar: TagDispatch enables dynamic multi-schema dispatch (LLM Verifier + Threat Feature Extractor + ReAct schemas without recompilation); cross-grammar cache; 6x faster compilation; near-zero overhead — adopted as constrained decoding engine across all LLM output points in ZeroTrust.sh. | grammar-constrained decoding, TagDispatch, cross-grammar cache, agentic LLM, structured output, XGrammar-2, dynamic schema, zero overhead | [arXiv](https://arxiv.org/abs/2601.04426) | |

---

## Area 17 — Context Window Management

| # | Title | Authors | Year | Venue | Read | Relevance to ZeroTrust.sh | Tags | URL | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 86 | Beyond RAG vs. Long-Context: Learning Distraction-Aware Retrieval for Efficient Knowledge Grounding | Multiple authors | 2024 | arXiv | Unread | Distraction-aware retrieval mitigating 'lost in the middle' effect — addresses how ZeroTrust.sh should select and contextualize code snippets rather than passing entire files to the LLM. | RAG, long context, distraction-aware, lost in the middle, retrieval, code snippet selection | [arXiv](https://arxiv.org/abs/2509.21865) | |

---

## Stats

| Metric | Count |
|---|---|
| Total papers | 87 |
| Research areas | 17 |
| Read | 0 |
| Reading | 0 |
| Reviewed | 0 |
| Unread | 87 |
