## ZeroTrust.sh — Architecture Detail

> Companion document to `docs/architecture_overview.mmd` (simplified flow diagram) and
> `docs/project_architecture_cascading_intelligence.mmd` (full annotated diagram).
> This document is the primary reference. The diagrams are supplements.

---

## Overview

ZeroTrust.sh is a local, offline CLI security scanner that audits codebases modified by AI coding agents. It accepts a directory or ZIP archive as input, runs all analysis on-device, and produces an interactive HTML vulnerability report with unified-diff patch suggestions.

The core of the system is the **Cascading Intelligence Pipeline**: two independent detection paths that run in parallel against every file set that enters the pipeline. Neither path gates the other — both produce findings independently, which are then merged at a shared deduplication and confidence scoring layer.

- **Path A (Pattern Detection)** is fast and deterministic. It uses structural pattern matching and taint analysis to find known vulnerability patterns at low computational cost.
- **Path B (Semantic Detection)** is a three-tier cost funnel. It applies progressively more expensive analysis tools to progressively smaller surface areas, so that the most expensive component (a local LLM) only ever sees the small fraction of code surfaces that the cheaper tiers could not resolve.

Before either path runs, an ingestion layer verifies the integrity of the local model and reduces the working file set to only what has changed since the last scan.

---

## Ingestion Layer

### Model Integrity Verifier

**What it does.** At startup, before any code is processed, the Model Integrity Verifier computes a SHA256 hash of the local GGUF model file and compares it against a pinned manifest shipped with the tool. If the hash does not match — indicating the model file has been modified or replaced after download — the scan is blocked and the user is alerted.

**Why it exists.** GGUF model files are opaque binary artifacts. Research published at ICML 2025 demonstrated practical backdoor injection attacks against quantized GGUF models. Because ZeroTrust.sh uses a local model for security-critical verdict generation, a tampered model is a direct attack surface: an adversary who can modify the model can cause the tool to suppress real vulnerabilities or fabricate false ones. Model integrity verification closes this supply chain attack vector before any analysis begins.

**Key technical choice.** SHA256 against a pinned release manifest. This is a startup-time check, not a per-invocation check, to keep latency low.

---

### Differential Indexer

**What it does.** The Differential Indexer hash-compares all input files against a cache from the previous scan. Only files that are new or have changed since the last scan enter the analysis pipeline. A full scan runs on the first invocation.

**Why it exists.** Running all analysis components against an entire codebase on every invocation is expensive. In a development workflow where an AI agent modifies a small subset of files per session, re-scanning unchanged files produces no new signal. The Differential Indexer eliminates that redundant work, producing approximately 80–95% cost reduction on repeat scans.

---

## Path A — Pattern Detection

Path A uses two tools in parallel — Semgrep + ast-grep for pattern matching, and Joern CPG Engine for taint analysis — followed by an LLM Verifier that filters false positives from both tools' output.

### Semgrep + ast-grep · Pattern Detection

**What it does.** Semgrep and ast-grep run in parallel against the changed file set, applying structural pattern rules to detect known vulnerability signatures. Semgrep provides community rule packs across 30+ languages, support for complex patterns including taint flow and metavariable matching, and a large existing rule ecosystem. ast-grep is Tree-sitter-based (MIT licensed), uses the same YAML rule format as Semgrep, and covers languages with weaker Semgrep community packs at zero additional runtime overhead.

**Why it exists.** Structural pattern matching is the cheapest form of static analysis. It catches well-understood vulnerability classes (hardcoded credentials, dangerous function calls, unsafe deserialization patterns) in milliseconds per file with no inference cost.

**Key technical choice — AI agent config file coverage.** The rule scope is extended beyond source code to cover AI agent configuration surfaces: MCP server configs (`.mcp.json`), agent instruction files (`.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `copilot-instructions.md`), and similar files. These files are read and executed by AI coding agents and represent a prompt injection attack surface that no competing tool scans. ZeroTrust.sh is the first tool to cover this vector.

---

### Joern CPG Engine · Taint Analysis

**What it does.** Joern builds a Universal Code Property Graph (CPG) from the changed file set. The CPG is a unified graph representation that combines abstract syntax tree, control flow graph, and call graph information into a single queryable structure. The taint query layer traverses the CPG to identify flows from untrusted input sources through zero or more sanitizers to dangerous sinks.

**Why it exists.** Pattern matching misses vulnerabilities where the exploit path spans multiple functions or requires understanding data flow. Taint analysis on the CPG finds source-to-sink paths that no single-function rule can detect.

**Key technical choices.**

- **Language support.** Joern supports C/C++, Java/Kotlin, Python, JavaScript/TypeScript, Go, Ruby, and PHP natively.
- **CPG sharing with Path B.** The CPG built by the Joern CPG Engine is shared with Path B — call graph data and reachability information are made available to Path B's Heuristic Targeting and Call Graph nodes without a second parse step. This is a deliberate architectural decision to avoid redundant computation.
- **Approach 3 extension.** Fraunhofer-AISEC/cpg is added in Approach 3 as a pluggable frontend to extend CPG coverage to Rust, Kotlin (cross-validated), and Swift.
- **Replaces CodeQL.** Joern's CPG taint analysis covers the same scope as CodeQL's query layer without CodeQL's per-scan database build step, which eliminates a major latency source.
- **Runs in parallel with Semgrep + ast-grep.** Joern and the pattern detection tools operate independently; neither waits for the other.

---

### LLM Verifier

**What it does.** The LLM Verifier receives structured findings from both Semgrep + ast-grep and the Joern taint analysis. It does not receive raw code. Each finding is presented with its taint flow path, sink type, and reachability condition. The verifier reasons over this structured representation to classify findings as confirmed or false positive.

**Why it exists.** Static analysis tools produce false positives. The false positive rate is a primary reason developers disable or ignore SAST tooling. The LLM Verifier targets an 88–93% false positive reduction by applying semantic reasoning to each finding before it reaches the deduplication layer.

**Key technical choices.**

- **Grammar-constrained decoding.** XGrammar enforces a JSON schema at generation time, meaning the model cannot produce malformed JSON output. This eliminates the need for retry logic and output parsing error handling, at zero runtime overhead beyond standard inference.
- **Structured input only.** The verifier never receives raw source code — only the structured finding representation. This reduces token footprint and prevents the verifier from reasoning about irrelevant code context.
- **Agentic CoT framework.** The verifier uses a chain-of-thought reasoning framework internally before producing its verdict.

---

## Path B — Semantic Detection · Three-Tier Cost Funnel

Path B is structured as a three-tier funnel. Each tier eliminates surfaces that can be resolved cheaply, so that only the residual uncertain cases proceed to the next, more expensive tier. The result is that approximately 95% of files and 75–85% of code surfaces never reach the LLM.

### Tier 1 — Surface Selection

#### Heuristic Targeting

**What it does.** Heuristic Targeting queries the Joern CPG (shared from Path A) to identify the small fraction of code surfaces worth deep analysis. It selects external-input nodes, auth-boundary nodes, and AI agent config file nodes from the CPG graph. The result is a ranked list of surfaces; roughly 95% of files are eliminated at this stage.

**Why it exists.** Running classifier inference and LLM reasoning over every function in a codebase is prohibitively expensive. Heuristic Targeting concentrates analysis budget on the surfaces where vulnerabilities are most likely to exist.

**Key technical choice — language-agnostic.** Because Heuristic Targeting queries the CPG rather than writing per-language rules, it works across all languages that Joern supports without additional configuration. The CPG normalizes all languages to a shared graph schema. When call graph data is unavailable (e.g., on first run before a full CPG is built), Heuristic Targeting routes directly to the Code Vulnerability Classifier as a fallback.

---

#### Call Graph + CVE Enrichment + Resource ID Dataflow

**What it does.** This node enriches each selected surface with three independent data sources before the classifier gate:

1. **Call graph data.** Extracted from the Joern CPG at no additional build cost — the graph already exists. Provides caller and callee context for each surface.
2. **CVE enrichment.** Trivy (Go library, Apache 2.0) queries OSV, NVD, and GitHub Advisory databases. An exact CVE match against a dependency or function pattern causes the surface to be auto-flagged and skipped through all remaining tiers directly to the deduplication layer — no classifier or LLM call needed.
3. **Resource ID dataflow (BOLAZ zero-trust model).** All external resource identifiers (IDs from URL parameters, request bodies, headers) are treated as untrustworthy until explicit authorization has been confirmed at every function boundary they cross. This formal model, which resulted in the discovery of 35 new CVEs in published research, allows IDOR and BOLA violations to be flagged before the classifier at zero LLM cost. When no CVE match is found, a heuristic fallback checks for dangerous function calls and unsafe sink patterns.

**Why it exists.** CVE-matched surfaces require no semantic reasoning — they are known-bad patterns. Resolving them here saves classifier and LLM budget. The BOLAZ resource ID tracking catches IDOR at the data-flow level, a class of vulnerability that pattern matching misses entirely.

---

### Tier 2 — Classifier Gate

#### Code Vulnerability Classifier

**What it does.** The Code Vulnerability Classifier applies a fine-tuned UniXcoder-Base-Nine model (~125M parameters) to each surface that was not resolved or auto-flagged in Tier 1. The model runs locally on CPU, requires milliseconds per function, and produces a confidence-scored verdict: high-confidence vulnerable, high-confidence safe, or uncertain.

- High-confidence vulnerable findings are sent directly to the deduplication layer — no LLM call needed.
- High-confidence safe surfaces are dismissed.
- Uncertain surfaces (~15–25% of the surfaces that reach this tier) are escalated to Tier 2.5 and then Tier 3.

**Why it exists.** A local CPU classifier is orders of magnitude cheaper per invocation than an LLM. Resolving the majority of surfaces here before any LLM call is made is the primary cost reduction mechanism for Path B.

**Key technical choice — language routing.** UniXcoder supports Python, Java, JavaScript/TypeScript, Go, Ruby, and PHP. For unsupported languages (Rust, Kotlin, Swift, C#), the classifier step is skipped and the surface is routed directly to the LLM. This avoids a degraded classification signal on out-of-distribution code.

---

#### Call Chain Context Assembler

**What it does.** For each uncertain surface from the classifier, the Call Chain Context Assembler traces the call chain up to depth 3 from the Joern CPG, assembling a multi-function context window: the function that calls into the surface (caller), the surface function itself, and the functions it calls (callees).

**Why it exists.** A significant class of authorization and logic vulnerabilities cannot be detected by examining a single function in isolation. Missing auth guard vulnerabilities require seeing that an auth check is absent from the call chain. IDOR violations require tracing whether an authorization check exists anywhere between the external ID entry point and the resource access point. Research published at ACL 2025 (JitVul) documented that single-function context misses a meaningful fraction of authorization flaw classes. The Call Chain Context Assembler provides the multi-hop context required to reason about these patterns.

---

#### Semantic Function Summarizer

**What it does.** The Semantic Function Summarizer takes the assembled call chain context and transforms it into structured semantic abstractions using a small, fast LLM. Each function in the chain is described in terms of: what it does with untrusted data, which sanitizers it applies, and which sinks it reaches. The output is a set of XGrammar-constrained JSON summaries, one per vulnerability class being evaluated: `taint-flow`, `auth-guard`, `logic-flaw`.

CPG-derived fields — taint source node identifiers, sanitizer node identifiers, sink node types, and call graph position — are injected directly as ground-truth data. The LLM fills only the semantic interpretation fields: reasoning about intent, missing checks, and implied trust assumptions.

**Why it exists.** The main reasoning LLM in Tier 3 should never see raw source code. Raw code maximizes token cost, introduces irrelevant syntactic noise, and risks the model focusing on implementation details rather than security-relevant semantics. Semantic summaries preserve the security-relevant information while reducing token footprint. This design aligns with the IRIS approach published at ICLR 2025.

---

### Tier 3 — LLM Reasoning

#### Token Budget Controller

**What it does.** The Token Budget Controller manages the per-scan token budget before surfaces are passed to the LLM Semantic Scan. Its primary strategy is intelligent surface selection: it ranks uncertain surfaces by CVE severity score multiplied by classifier uncertainty, and within the available budget, prioritizes the highest-risk surfaces. Compression is a secondary strategy, applied only after surface selection is exhausted.

When compression is needed, it applies CFG-based chunking (function boundary plus taint-critical sub-paths). Vulnerable code and security-critical lines — data sources, sanitizers, sinks — are positioned at the start of the prompt and preserved uncompressed. Non-security-critical context (boilerplate, import blocks) is compressed or truncated. A sensitivity filter routes prompts containing credentials or PII to a designated secure model only.

**Why it exists.** LLM inference is the most expensive operation in the pipeline. Without a hard budget cap and principled surface prioritization, cost scales linearly with codebase size. The Token Budget Controller makes the cost profile predictable and bounds the worst-case inference cost regardless of codebase size.

**Key technical choice.** Surface selection is preferred over compression because compression degrades the semantic quality of the input. Compression is only applied after all high-priority surfaces have been processed within the budget.

---

#### LLM Semantic Scan · Bounded ReAct Loop

**What it does.** The LLM Semantic Scan is the final and most expensive analysis step in Path B. It receives semantic summaries — never raw code — for the uncertain high-priority surfaces that survived all previous tiers. It does not see Tier 1 or Tier 2 dismissed surfaces. It does not see Path A results.

The scan operates as a bounded ReAct (Reason + Act) loop with a maximum of 3 steps per surface. Within each step the model may issue context requests — for additional call chain depth, a CVE database lookup, or accumulated context from the Scan Security Context Store — before producing an Observation and progressing toward a verdict. Progressive constraint modeling is applied: the model enumerates program state constraints before issuing a vulnerability verdict.

Grammar-constrained decoding (XGrammar) enforces the output JSON schema at generation time. Chain-of-Draft reasoning compresses verbose chain-of-thought to approximately 7.6% of tokens at equivalent accuracy.

**Approach 3 evolution.** In Approach 3, the single LLM scan becomes a 3-agent ensemble: Reconnaissance agent → Exploitation agent → Verification agent. This mirrors a real red-team workflow where a finding must pass independent exploitation and verification stages before it is confirmed.

---

## Scan Security Context Store

**What it does.** The Scan Security Context Store is a per-scan in-memory data structure that accumulates security inferences across all surfaces analyzed by the LLM Semantic Scan. It stores inferred data sources, observed sanitizer gaps, and trust boundary violations encountered during the scan. Before the LLM analyzes each new surface, it reads all prior inferences from the store. After each verdict, it writes new inferences back.

**Why it exists.** A vulnerability that spans multiple non-adjacent code surfaces — for example, a taint source in one module that reaches a sink in another module through an intermediate data structure — cannot be detected by per-function analysis. The Scan Security Context Store gives the LLM a memory of what it has already observed across the scan session, enabling detection of cross-surface vulnerabilities that are invisible to tools analyzing each function independently. This design is based on the RepoAudit approach published in 2025.

---

## Deduplication + Confidence Scoring · SSVC-Aligned

**What it does.** The deduplication and confidence scoring layer receives findings from three sources: Path A (LLM Verifier output), Path B high-confidence classifier findings, and Path B LLM Semantic Scan output. It deduplicates overlapping findings using a triple-path fusion strategy — AST edit distance, LLM semantic similarity, and CWE pattern hash — and assigns each unique finding a confidence score.

Confidence scoring is aligned to SSVC (Stakeholder-Specific Vulnerability Categorization) dimensions:

- **Exploitation**: active exploitation in the wild / PoC exists / no known exploitation
- **Automatable**: whether the attack can be automated (yes / no)
- **Technical Impact**: total / partial

Score thresholds and their labels:

| Score | Label | Criteria |
|---|---|---|
| ≥ 0.92 | BLOCK | Exploitable + Automatable + Total Impact |
| 0.75–0.91 | HIGH | PoC exists + automatable path + significant impact |
| 0.60–0.74 | MEDIUM | — |
| 0.30–0.59 | LOW | — |
| < 0.30 | SUPPRESSED | — |

**Cross-path boost.** A finding confirmed by both Path A and Path B independently receives a +15% score boost. This reflects the higher signal confidence when two architecturally independent detection methods agree.

**Suppression rules.** Findings located in test files or within framework-safe functions are suppressed automatically.

---

## Proof-of-Exploit Layer

The Proof-of-Exploit Layer is an Approach 3 feature. It is not active in Approaches 1 or 2. It receives the scored finding set from the deduplication layer and attempts to confirm each finding as genuinely exploitable through live execution.

### Red Team Agent

**What it does.** The Red Team Agent is a LangGraph-orchestrated agent that receives the scored findings list and drives the exploit verification workflow. It sequences the Docker Sandbox invocations and aggregates results.

**Why it exists.** Static analysis cannot distinguish between a code path that is theoretically vulnerable and one that is actually reachable and exploitable in the runtime environment. The Red Team Agent provides the orchestration layer for empirical confirmation.

---

### Docker Sandbox

**What it does.** The Docker Sandbox executes controlled exploit attempts against each finding in an isolated container environment. It attempts to actually trigger the finding — sending crafted inputs, observing outputs, and confirming whether the vulnerability manifests at runtime.

**Key technical choice.** The sandbox is designed to degrade gracefully. If sandbox execution fails (container build failure, timeout, network isolation requirement), the finding bypasses the sandbox entirely and is passed to the final report with static evidence only. The PoE layer never blocks report generation.

---

### Two-layer PoE Output

**What it does.** For each confirmed finding, the PoE layer produces two output artifacts:

1. **Technical trace.** Intended for developers. Contains the exact exploit sequence, the input that triggered the vulnerability, the observed behavior, and the code path traversed.
2. **Executive summary.** Intended for managers and security leads. Describes the risk, the exploitability assessment, and the business impact in non-technical language.

---

## Final Report

**What it does.** The HTML Report + Patch Suggestions node is the terminal output of the pipeline. It is produced by all approaches (1, 2, and 3). It generates a self-contained interactive HTML vulnerability dashboard from the scored finding set, and produces a unified Git diff patch for each confirmed finding.

In Approach 3, the report also incorporates proof-of-exploit evidence from the PoE layer when sandbox execution succeeded, or static evidence only when it did not.

---

## Design Principles

The following architectural decisions are reflected throughout the system. Each is stated explicitly here as a principle rather than scattered across component descriptions.

**Local execution — no code leaves the machine.** Every component runs on-device. The LLM is a local GGUF model served via Ollama or llama-cpp-python. CVE database queries use a locally cached copy updated at scan time via Trivy. No source code, no findings, and no telemetry are sent to any external service.

**Neither path gates the other.** Path A and Path B run concurrently against the same file set. A false negative in Path A does not suppress a finding in Path B. A false positive filtered by Path A's LLM Verifier does not affect what Path B analyzes. The two paths are architecturally independent by design; the deduplication layer is the only point where their outputs interact.

**Three-tier cost funnel — spend budget only where uncertainty exists.** The three tiers of Path B are ordered by cost: deterministic CPG queries first, local CPU classifier second, LLM reasoning last. Each tier resolves the cases it can handle cheaply and passes only the residual uncertain cases to the next tier. The result is that approximately 95% of files and 75–85% of code surfaces never reach the LLM.

**Grammar-constrained output everywhere.** Both the LLM Verifier (Path A) and the LLM Semantic Scan (Path B) use XGrammar to enforce JSON output schemas at generation time. Malformed output is impossible by construction. This eliminates retry logic, output parsing failures, and the latency spikes they cause.

**CPG shared between paths — one parse, two uses.** The Joern CPG Engine is part of Path A, but the graph it produces is consumed by Path B's Heuristic Targeting and Call Graph nodes without a second parse. This avoids redundant computation and ensures both paths reason about the same graph representation of the code.

**LLM sees summaries, never raw code.** At every point where an LLM is invoked — the LLM Verifier, the Semantic Function Summarizer, and the LLM Semantic Scan — the model receives structured representations of the code, not raw source. This reduces token cost, focuses reasoning on security-relevant semantics, and prevents the model from anchoring on irrelevant syntactic details.

**SSVC alignment for triage compatibility.** Confidence scores are expressed in SSVC dimensions (Exploitation, Automatable, Technical Impact) rather than arbitrary internal scales. This makes the output compatible with security team triage workflows that already use SSVC, and gives each score label a precise, defensible definition.

**Supply chain integrity at the model layer.** The Model Integrity Verifier treats the local GGUF model as an attack surface and verifies it at startup. This addresses the ICML 2025 threat class of backdoored quantized models, which is a realistic supply chain risk for any tool that distributes a local model binary.

**AI agent config files as a first-class attack surface.** MCP server configs, `.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `copilot-instructions.md`, and similar files are scanned by both Path A (pattern rules) and Path B (CPG node selection). No competing tool covers this surface. Prompt injection delivered through repository instruction files is a novel attack vector that becomes relevant specifically because AI coding agents read and act on these files autonomously.
