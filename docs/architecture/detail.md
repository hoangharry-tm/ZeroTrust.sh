## ZeroTrust.sh — Architecture Detail

> Companion document to `docs/architecture_overview.mmd` (simplified flow diagram) and
> `docs/project_architecture_cascading_intelligence.mmd` (full annotated diagram).
> This document is the primary reference. The diagrams are supplements.

---

## Overview

ZeroTrust.sh is a local, offline CLI security scanner that audits codebases modified by AI coding agents. It accepts a directory as input, runs all analysis on-device, and produces an interactive HTML vulnerability report with unified-diff patch suggestions.

The core of the system is the **Cascading Intelligence Pipeline**: two independent detection paths that run in parallel against every file set that enters the pipeline. Neither path gates the other — both produce findings independently, which are then merged at a shared deduplication and confidence scoring layer.

- **Path A (Pattern Detection)** is fast and deterministic. It uses structural pattern matching and taint analysis to find known vulnerability patterns at low computational cost.
- **Path B (Semantic Detection)** is a three-tier cost funnel. It applies progressively more expensive analysis tools to progressively smaller surface areas, so that the most expensive component (a local LLM) only ever sees the small fraction of code surfaces that the cheaper tiers could not resolve.

Before either path runs, two ingestion components start in parallel. The Model Integrity Verifier checks the local model's authenticity; the Differential Indexer reduces the working file set to only what has changed since the last scan. CPG construction and pattern matching proceed as soon as the Differential Indexer completes. LLM invocations are gated on the Model Integrity Verifier result.

---

## Ingestion Layer

### Model Integrity Verifier

**What it does.** At startup, in parallel with the Differential Indexer, the Model Integrity Verifier computes a SHA256 hash of the local GGUF model file and compares it against a maintainer-signed hash registry. The registry is a JSON file keyed by model ID string (e.g., `llama-3.2-3b-instruct-q4_K_M`), supporting multiple models at different quantization levels. The registry is signed using cosign (Sigstore Rekor); the signature is verified against a maintainer public key bundled with the tool binary. Forging a registry entry requires compromising the private signing key — patching the binary alone is insufficient.

**Response tiers.**

| Condition | Response | Rationale |
|---|---|---|
| Model ID not found in registry | **WARN** — user prompted to opt in | Covers user-selected alternative models, new versions not yet in the registry |
| Model ID in registry, hash matches | Silent pass | Expected case |
| Model ID in registry, hash mismatch | **BLOCK** — scan halted, discrepancy logged | Confirmed tampering of a known model |

**What it gates.** The Model Integrity Verifier gates LLM invocations only. CPG construction (Joern) and pattern matching (Semgrep, ast-grep, Heuristic Targeting) do not require the model and proceed regardless. This prevents model verification latency or failure from blocking the deterministic analysis components.

**Why it exists.** GGUF model files are opaque binary artifacts. Research published at ICML 2025 demonstrated practical backdoor injection attacks against quantized GGUF models. A tampered model used for security-critical verdict generation is a direct attack surface — an adversary can cause the tool to suppress real vulnerabilities or fabricate false ones. Model integrity verification closes this supply chain attack vector before any LLM call is made.

**Implementation note.** The maintainer signs the hash registry JSON as a release artifact; the public key is bundled with the tool binary. Verification is a startup-time check, not per-invocation, to keep startup latency near zero.

---

### Differential Indexer

**What it does.** The Differential Indexer hash-compares all files in the input directory against a SQLite state cache from the previous scan. Only files that are new or have changed since the last scan enter the analysis pipeline. Directory input only — ZIP archive support is not provided. A full scan runs on the first invocation.

**Performance scope.** The ~80–95% cost reduction claim applies to Semgrep/ast-grep pattern matching, UniXcoder classifier inference, and LLM calls on repeat scans. The Joern CPG is always rebuilt in full — CPG construction is a whole-program operation, and partial updates cannot guarantee correct cross-file call graph edges. CPG build cost is a fixed per-scan cost regardless of change set size.

**Dependency expansion.** A pure file-hash differential misses a common AI agent change pattern: a utility function is modified, but its callers are unchanged files. The Differential Indexer expands the working set by one hop using the Joern CPG call graph — immediate callers and callees of functions in changed files are added to the analysis set. This prevents missed vulnerabilities when an AI agent modifies a shared helper without touching call sites.

**State persistence.** Scan state is stored in a SQLite database at `~/.zerotrust/scans.db` using `modernc.org/sqlite` (pure-Go, no CGo dependency).

| Column | Type | Notes |
|---|---|---|
| `project_id` | TEXT | Derived from directory path; user-overridable |
| `file_path` | TEXT | Relative path within project root |
| `content_hash` | TEXT | SHA256 of file content |
| `last_scanned_at` | INTEGER | Unix timestamp |

Index on `(project_id, content_hash)` allows cache hits for files that appear unchanged across branches.

**Why it exists.** In a development workflow where an AI agent modifies a small subset of files per session, re-scanning unchanged files produces no new signal. The Differential Indexer makes repeat scan cost proportional to change set size, not total codebase size.

---

## Path A — Pattern Detection

Path A uses two tools in parallel — OpenGrep + ast-grep for pattern matching, and Joern CPG Engine for taint analysis — followed by an LLM Verifier that filters false positives from both tools' output. OpenGrep and ast-grep are language-partitioned: OpenGrep covers its strongest languages (Python, Java, JS/TS, Go, Ruby, PHP); ast-grep fills the gaps (Dart, Swift, Rust, newer languages with thin OpenGrep community packs). Neither runs the same rules on the same files.

### OpenGrep + ast-grep · Pattern Detection

**What it does.** OpenGrep (LGPL-2.1, community fork of Semgrep CE, backed by Aikido, Endor Labs, Jit, and others) restores cross-function taint analysis that Semgrep OSS removed in December 2024, while maintaining 100% rule-format compatibility with the existing Semgrep rule ecosystem. ast-grep is Tree-sitter-based (MIT), uses a compatible YAML rule format, and provides fast structural matching for languages OpenGrep covers weakly. Both tools run against the changed file set in parallel; neither waits for the other.

**Why it exists.** Structural pattern matching is the cheapest form of static analysis. It catches well-understood vulnerability classes — hardcoded credentials, dangerous function calls, unsafe deserialization — in milliseconds per file with no inference cost.

**AI agent config file coverage — three-tier analysis.** The rule scope is extended beyond source code to cover AI agent instruction files and configuration surfaces. No competing tool scans this surface. ZeroTrust.sh is the first to do so. The analysis is structured in three tiers by cost and mechanism:

- **Tier 1 (Approach 1, zero model cost):** Unicode obfuscation scan (catches Rules File Backdoor — MITRE ATLAS AML.CS0041; hidden U+202E, U+200B, U+200D characters invisible to human reviewers); keyword/pattern match on `.md` and `.txt` instruction files; JSON schema validation on `.mcp.json` configs (flag external URLs, HTTP non-localhost transports, over-broad permissions). These run as Go functions and OpenGrep generic-mode rules.
- **Tier 2 (Approach 2, Python worker):** Embedding similarity via MiniLM-L6-v2 (~22 MB, CPU, <100 ms per file) against a curated malicious-pattern library. Reports MEDIUM confidence only — distribution-shift degrades accuracy on novel attacks.
- **Tier 3 (Approach 2, constrained LLM call):** Sandboxed LLM meta-audit with no tool access and XGrammar-2 boolean-only output schema `{authority_escalation, tool_permission_escalation, instruction_override, confidence}`. Used only to confirm what Tiers 1 or 2 already flagged — never standalone.

**Cheat-detection rules.** Path A extends its rule scope to detect AI coding agent security bypass patterns — cases where an agent satisfies a functional contract while degrading or removing security controls:

| Signal | Pattern | Rule type |
|---|---|---|
| Security-node disappearance | Auth/validate/check AST nodes present in prior CPG, absent in current | CPG diff via Differential Indexer → Path B escalation |
| Hardcoded bypass | `return true/nil/0` in function named `*auth*`, `*check*`, `*verify*` | OpenGrep rule |
| Test-env bypass | `if os.Getenv("TEST") == "true" { return nil }` in security function | OpenGrep / ast-grep |
| TODO-then-skip | `// TODO: add auth` + zero auth calls in same function scope | OpenGrep metavariable rule |
| Disabled test assertions | `t.Skip(`, `@unittest.skip`, `xit(`, hardcoded `assert.True(t, true)` | OpenGrep |
| Empty security catch | `catch(AuthException) {}` | OpenGrep / ast-grep |

---

### Joern CPG Engine · Taint Analysis

**What it does.** Joern (Apache 2.0) builds a Universal Code Property Graph (CPG) from the changed file set — a unified graph combining AST, control flow graph, and call graph into a single queryable structure. The taint query layer traverses the CPG to identify flows from untrusted input sources through zero or more sanitizers to dangerous sinks, whole-program and inter-file.

**Why it exists.** Pattern matching misses vulnerabilities where the exploit path spans multiple functions or requires understanding data flow. Taint analysis on the CPG finds source-to-sink paths that no single-function rule can detect. Joern's conservative defaults produce very low false positive counts (96 FPs vs. 904 for CodeQL on the OWASP Benchmark Java dataset) — a feature for a pipeline where high-confidence signals matter more than recall, since recall is covered by OpenGrep and the Path B semantic scan.

**Key technical choices.**

- **Language support.** Joern supports C/C++, Java/Kotlin, Python, JavaScript/TypeScript, Go, Ruby, and PHP natively. **The Go frontend is community-contributed and less battle-tested than the Java/C++ frontends — CPG quality for Go codebases requires empirical validation before publishing accuracy claims (extends assumption A-18).**
- **CPG sharing with Path B.** The CPG is shared with Path B — call graph data and reachability information are available to Path B's Heuristic Targeting and Call Graph nodes without a second parse step.
- **Integration pattern.** The Go orchestrator pre-starts Joern as a long-lived HTTP server (`joern --server`, `localhost:8080`) concurrently with MIV and DI at CLI launch, eliminating JVM cold-start latency. Taint findings are exported via `joern-slice data-flow --out findings.json`. The Python ML worker queries the same server via `joern-lib` (PyPI). No Scala knowledge required in the ZeroTrust.sh codebase.
- **Approach 3 extension.** Fraunhofer-AISEC/cpg is evaluated in Approach 3 as a per-language **replacement** for Joern on Rust, Swift, and C# (not an addition) — running two CPG engines with different schemas in parallel adds integration complexity that outweighs the coverage gain.
- **Runs in parallel with OpenGrep + ast-grep.** Joern and the pattern detection tools operate independently.

---

### LLM Verifier

**What it does.** The LLM Verifier receives normalised structured findings from both OpenGrep + ast-grep and Joern taint analysis. It never receives raw code. A normalisation adapter maps the two structurally different finding schemas — OpenGrep's `{rule_id, file, line, matched_code, metavariables}` and Joern's `{source_node, sanitizer_nodes[], sink_node, taint_path}` — into a unified JSON representation before either reaches the verifier. The verifier classifies each finding as confirmed, false positive, or uncertain.

**High-confidence bypass.** Rules tagged `confidence: high` (hardcoded secrets, obviously dangerous function signatures with no sanitizer path) send their findings directly to Dedup without LLM verification. Only medium/low-confidence pattern findings and all Joern taint findings are verified. This prevents the verifier from becoming a sequential bottleneck on high-volume scans.

**Why it exists.** Static analysis tools produce false positives at rates that cause developers to disable or ignore SAST tooling entirely. The LLM Verifier applies semantic reasoning to filter false positives before findings reach the report — targeting meaningful reduction, with actual accuracy to be benchmarked against ZeroTrust.sh's rule set and target codebases before any specific figure is published.

**Key technical choices.**

- **Reasoning technique: CoD + SCoT hybrid.** The verifier uses a Structured Chain-of-Thought (SCoT) analysis schema that maps directly onto the structured JSON input fields — `TAINT SOURCE → PATH TRACE → SANITIZER NODES → SINK REACHABILITY → CWE MATCH → VERDICT` — with each step constrained to one observation + one inference (≤15 words) following Chain-of-Draft discipline. This yields approximately 40–60% token reduction vs. standard CoT on the primary reasoning path. *Note: CoD's published token savings are measured on frontier API models; performance on local 7B models requires internal benchmarking before claiming specific numbers.*
- **Output: XGrammar-2-enforced JSON.** Output schema: `{"verdict": "confirmed"|"false_positive"|"uncertain", "confidence": <float 0.0–1.0>, "justification": "<string, max 200 chars>"}`. Malformed output is impossible by construction. No retry logic required.
- **Adaptive Self-Consistency escalation.** If `verdict == "uncertain"` or `confidence < 0.60`, the verifier samples two additional times (temperature 0.4) and majority-votes the verdict, averaging confidence scores. Average overhead is bounded at approximately 1.3× rather than 3×, since most findings with structured input resolve clearly on the first call.
- **Instruction file meta-audit.** The verifier is extended to evaluate AI agent instruction files using a boolean-only output schema (Tier 3 of the three-tier instruction-file analysis). During this call the model has no tool access and XGrammar-2 enforces boolean-only output — the LLM classifies, never executes.

---

## Path B — Semantic Detection · Three-Tier Cost Funnel

Path B is structured as a three-tier funnel. Each tier eliminates surfaces that can be resolved cheaply, so that only the residual uncertain cases proceed to the next, more expensive tier. The design target is that approximately 95% of files and 75–85% of code surfaces never reach the LLM — these are design targets pending CVEFixes benchmark validation, not measured results.

### Tier 1 — Surface Selection

#### Heuristic Targeting

**What it does.** Heuristic Targeting queries the Joern CPG (shared from Path A) to identify the small fraction of code surfaces worth deep analysis. It selects two node categories from the CPG: external-input nodes (HTTP handler parameters, CLI arguments, file reads, environment variable reads) and auth-boundary nodes (methods matching `*auth*`, `*login*`, `*verify*`, `*permission*`, `*role*`, plus framework annotations such as `@PreAuthorize`). The result is a ranked list of surfaces; typically ~95% of files are eliminated at this stage. AI agent config file nodes are handled by Path A's three-tier static analysis and are not re-targeted here.

**Why it exists.** Running classifier inference and LLM reasoning over every function in a codebase is prohibitively expensive. Heuristic Targeting concentrates the analysis budget on the surfaces where vulnerabilities are most likely to exist, without requiring per-language rule sets.

**Key technical choices.**

- **Language-agnostic.** CPG queries work across all Joern-supported languages without additional configuration. The CPG normalises all languages to a shared graph schema.
- **Fallback path scope reduction.** When call graph data is unavailable (e.g., no prior CPG build), Heuristic Targeting routes directly to the Code Vulnerability Classifier — but CVE enrichment and zero-trust resource ID tracking in the next node are also bypassed. This scope reduction is flagged in the output (`reason: heuristic_fallback`) so the report accurately reflects which surfaces received full Tier 1 analysis.

---

#### Call Graph + CVE Enrichment + Resource ID Dataflow

**What it does.** This node enriches each selected surface with three independent data sources before the classifier gate:

1. **Call graph data.** Extracted from the Joern CPG at no additional build cost. Provides caller and callee context for each surface, used downstream by the Call Chain Context Assembler.

2. **CVE enrichment.** Trivy (`trivy fs`, Apache 2.0) scans dependency manifest files (`go.mod`, `requirements.txt`, `package.json`, `pom.xml`, etc.) and matches identified packages against OSV, NVD, and GitHub Advisory databases. An exact CVE match auto-flags the surface and routes it directly to the deduplication layer — no classifier or LLM call needed. Trivy runs in **online mode by default**: it checks local cache freshness and downloads an updated database from GHCR only if the cache is older than 24 hours. Source code is never sent externally in either mode — the database download is a one-way pull. For air-gapped or strict no-network environments, pass `--skip-db-update --offline-scan` (both flags required) to force fully offline operation. Trivy is invoked as a subprocess with `--format json`; the Go orchestrator parses structured findings. Note: Trivy `fs` covers direct dependencies and, in some ecosystems, indirect dependencies; indirect resolution is online-only and falls back to direct-only in offline mode.

3. **Zero-trust resource ID dataflow.** All external resource identifiers (IDs from URL path parameters, query strings, request body fields) are tracked as they flow through the call graph. A surface is flagged as a BOLA/IDOR candidate when: (a) a resource ID sourced from external input reaches a database sink (SQL execution, ORM method call), and (b) no authorization check — framework annotation, explicit ownership comparison, or authorization service call — is confirmed on the taint path between the source and the sink. This P-API/C-API taint model is implemented as Joern CPGQL queries; no published open-source implementation exists for Joern specifically, so this is original implementation work. The methodology is grounded in BolaRay (CCS 2024, peer-reviewed, PHP-focused) and extended by BolaZ (arXiv:2507.02309, July 2025‡, SpringBoot/Java, 35 vulnerability instances discovered across 10 GitHub projects — not CVE-assigned records). All IDOR candidate surfaces **always escalate to the LLM tier regardless of classifier confidence** — static IDOR false positive rates exceed 50% when authorization is implemented at framework or middleware level, making the LLM the essential final filter for this vulnerability class.

**Why it exists.** CVE-matched surfaces require no semantic reasoning — they are known-bad patterns. Resolving them here saves classifier and LLM budget. Zero-trust resource ID tracking catches BOLA/IDOR at the data-flow level before the classifier, a class of vulnerability that structural pattern matching misses entirely.

---

### Tier 2 — Classifier Gate

#### Code Vulnerability Classifier

**What it does.** The Code Vulnerability Classifier applies a fine-tuned UniXcoder-Base-Nine model (~125M parameters) to each surface that was not resolved or auto-flagged in Tier 1. The model runs locally on CPU and produces a confidence-scored verdict: high-confidence vulnerable, high-confidence safe, or uncertain.

- High-confidence vulnerable findings are sent directly to the deduplication layer — no LLM call needed.
- High-confidence safe surfaces are dismissed.
- Uncertain surfaces escalate to the Call Chain Context Assembler and then Tier 3.
- IDOR candidate surfaces from Tier 1 always escalate regardless of verdict.

**Why it exists.** A local CPU classifier is orders of magnitude cheaper per invocation than an LLM. Eliminating the majority of surfaces here before any LLM call is the primary cost reduction mechanism for Path B.

**Benchmark status and A-18 (blocking dependency).** UniXcoder's published F1 figure (measured on BigVul, a C/C++-only dataset with documented label noise and temporal leakage) is not a valid performance claim for ZeroTrust.sh's target languages (Python, Java, JavaScript/TypeScript, Go). ICSE 2025 ("How Far Are We?") demonstrated that BigVul-trained models collapse on cleaner evaluation sets, and 72.1% of all vulnerability detection research targets C/C++ exclusively (SoK, arXiv:2412.11194). No peer-reviewed benchmark of UniXcoder on multi-language or AI-generated code exists. Assumption A-18 is a **blocking dependency**: the classifier must be fine-tuned on CVEFixes (multi-language, NVD-sourced, July 2024: 277,948 entries, temporal split) and evaluated per-language before any accuracy figure is published. The 75–85% surface elimination claim is a design target contingent on this benchmark.

**Operating mode.** Until the CVEFixes benchmark is complete, UniXcoder operates in **high-recall/low-precision mode**: the uncertainty threshold is set conservatively so that borderline surfaces escalate to the LLM rather than being dismissed at the gate. A false negative (missed vulnerability silently dismissed) is worse than a false positive (extra LLM call on safe code).

**Language routing.** UniXcoder supports Python, Java, JavaScript/TypeScript, Go, Ruby, and PHP. Unsupported languages (Rust, Kotlin, Swift, C#) are routed directly to the LLM, skipping the classifier to avoid degraded out-of-distribution signal.

---

#### Call Chain Context Assembler

**What it does.** For each uncertain surface, the Call Chain Context Assembler traces the call chain up to depth 3 (configurable) from the Joern CPG, assembling a multi-function context window: the immediate caller, the surface function itself, and its immediate callees.

**Why it exists.** Authorization and logic vulnerabilities cannot be detected by examining a single function in isolation. Missing auth guard vulnerabilities require seeing that an auth check is absent from the entire call chain. IDOR violations require tracing whether an authorization check exists anywhere between the external ID entry point and the resource access point. JitVul (ACL 2025) documented that single-function context misses a meaningful fraction of authorization flaw classes.

**Analysis ordering.** Surfaces are analyzed in **callee-first (bottom-up) order**: callees are analyzed before callers. This ensures that inferences written to the Scan Security Context Store about taint propagation in a callee are available when its caller is analyzed — a prerequisite for reliable cross-surface detection.

---

#### Semantic Function Summarizer

**What it does.** The Semantic Function Summarizer transforms the assembled call chain context into structured semantic abstractions using a small, fast local LLM (Phi-3-mini 3.8B or Qwen2.5-3B on CPU; separate from the main reasoning LLM). Each function in the chain is described as: what it does with untrusted data, which sanitizers it applies, which sinks it reaches, and where authorization checks are located. The output is a set of XGrammar-2-constrained JSON summaries, one per vulnerability class:

- `taint-flow`: `{untrusted_sources, sanitizer_nodes, sink_type, taint_propagates: bool}`
- `auth-guard`: `{auth_check_present: bool, authorization_check_location: "framework_annotation" | "explicit_code" | "middleware" | "unknown"}`
- `logic-flaw`: `{resource_id_source, db_sink, authorization_check_location: "framework_annotation" | "explicit_code" | "middleware" | "unknown"}`

CPG-derived fields — taint source node identifiers, sanitizer node identifiers, sink node types, call graph position — are injected directly as ground-truth data. The LLM fills only the semantic interpretation fields. The main reasoning LLM in Tier 3 never sees raw source code — only these structured summaries.

The `authorization_check_location` field is required in both `auth-guard` and `logic-flaw` schemas so the LLM Semantic Scan can distinguish a real authorization gap from a framework-level or middleware-enforced control that is invisible to pure taint analysis.

**Why it exists.** Raw code maximises token cost, introduces irrelevant syntactic noise, and risks the model focusing on implementation details rather than security-relevant semantics. Summaries preserve security-relevant information while reducing token footprint per surface by an order of magnitude.

**Citations.** This design aligns with LLMxCPG (USENIX Security 2025, peer-reviewed — CPG-derived backward slices as LLM input, 15–40% F1 improvement, 67–91% code size reduction) and VULSOLVER (arXiv:2509.00882, Sep 2025‡ — progressive constraint reasoning over SAST-generated summaries, 96.29% accuracy on OWASP Benchmark). The Semantic Function Summarizer model size (Phi-3-mini/Qwen2.5-3B) is not validated by a published security-specific benchmark and is flagged as an open calibration task.

---

### Tier 3 — LLM Reasoning

#### Token Budget Controller

**What it does.** The Token Budget Controller manages the per-scan token budget before surfaces are passed to the LLM Semantic Scan. Its primary strategy is intelligent surface selection: it ranks uncertain surfaces by a composite priority score and, within the available budget, processes the highest-priority surfaces first. Compression is a secondary strategy, applied only after selection is exhausted.

**Priority ranking function:**
```
priority = w1 × cvss_score + w2 × (1 - classifier_confidence) + w3 × reachability_from_entry
```
Where `reachability_from_entry` is the inverse hop count from an external-input node — surfaces reachable in fewer hops from external input are higher risk regardless of CVE match. This corrects the CVE-only bias of a simpler `cvss × uncertainty` formula, ensuring novel logic flaws and missing auth guards (which have no CVE match) are not systematically underranked.

**Budget exhaustion behavior.** When the token budget is exhausted, remaining high-uncertainty surfaces are not silently dropped. Each exhausted surface emits a `SUPPRESSED` finding with `confidence: 0.0` and `reason: "budget_exhausted"` so the report is complete and the user knows which surfaces were not analyzed.

**Compression strategy.** When compression is needed, CFG-based chunking is applied: function boundaries plus taint-critical sub-paths are preserved uncompressed; security-critical lines (data sources, sanitizers, sinks) are positioned at the prompt start; boilerplate and import blocks are truncated. CFG chunking is used for code content because security relevance is structurally determined by the CPG. Prose descriptions of call chain context may additionally be compressed.

**Why it exists.** Without a hard budget cap and principled surface prioritization, LLM inference cost scales linearly with codebase size. The Token Budget Controller makes the cost profile predictable regardless of codebase size.

---

#### LLM Semantic Scan · Bounded ReAct Loop

**What it does.** The LLM Semantic Scan receives structured semantic summaries — never raw code — for the uncertain high-priority surfaces that survived all previous tiers. Surfaces where Path A already produced a HIGH or BLOCK finding are pre-filtered and skipped (they are already resolved; path independence is preserved because Path B never sees Path A's verdict, only the fact that the surface was already handled). The scan does not see Tier 1 or Tier 2 dismissed surfaces.

**ReAct loop.** The scan operates as a bounded ReAct (Reason + Act) loop with a maximum of 3 steps per surface. The 3-step bound maps to the three progressive constraint checks from VULSOLVER (arXiv:2509.00882‡): Step 1 verifies the transfer constraint (does tainted data flow from caller to surface?); Step 2 verifies callee taint (does the surface propagate taint to its callees?); Step 3 verifies the trigger constraint (are sink parameters in an exploitable state?). Early exit applies when: the model commits to a verdict in any step, context reaches 90% capacity, or two consecutive tool calls return no new information.

Within each step the model may issue context requests — for additional call chain depth, a CVE database lookup, or prior inferences from the Scan Security Context Store — before producing an Observation. XGrammar-2 enforces the output JSON schema at generation time.

**Backbone capability requirement.** ReAct amplifies capable models and does not compensate for incapable ones (Sifting the Noise, arXiv:2601.22952). At scan start, a one-shot probe verifies the configured local model's instruction-following quality. If the model fails to produce valid structured JSON reliably, the ReAct loop is replaced by a single-pass CoD + SCoT reasoning call (the same technique used in Path A's LLM Verifier). The recommended minimum for reliable agentic gains is Llama-3.3-70B or Qwen2.5-72B via Ollama.

**Approach 3 evolution.** In Approach 3, the single LLM scan becomes a 3-agent ensemble: Reconnaissance agent → Exploitation agent → Verification agent. This mirrors a real red-team workflow where a finding must pass independent exploitation and verification stages before it is confirmed.

---

## Scan Security Context Store

**What it does.** The Scan Security Context Store is a per-scan in-memory graph that accumulates security inferences across all surfaces analyzed by the LLM Semantic Scan. Inference nodes are linked to their corresponding Joern CPG nodes (function, call site, taint edge). Before the LLM analyzes each new surface, it retrieves inferences from CPG-adjacent functions (immediate callers and callees of the current surface) — not all prior inferences, only the structurally relevant ones. After each verdict, new inferences are written back as graph nodes.

**Implementation.** Graph-based CPG-neighbor retrieval: a lightweight in-memory graph keyed by Joern CPG function identifiers. Retrieval is structural (CPG-edge traversal), not semantic (no embedding required), which ensures precise retrieval and negligible token overhead (~50–200 tokens per surface at typical scan scale of 12–16 surfaces per 50k-LOC codebase).

**Analysis ordering dependency.** The store's cross-surface detection capability depends on surfaces being analyzed in callee-first order (see Call Chain Context Assembler). If a sink function is analyzed before its taint source, the store is empty at the critical moment. The Call Chain Context Assembler enforces this ordering.

**Why it exists.** A vulnerability spanning multiple non-adjacent code surfaces — a taint source in one module reaching a sink in another through an intermediate data structure — cannot be detected by per-function analysis. The store gives the LLM a memory of what it has already observed, enabling detection of cross-surface vulnerabilities invisible to tools analyzing each function independently.

**Citations.** This design is grounded in VULSOLVER (arXiv:2509.00882‡) — progressive constraint solving where transfer constraints from one function are explicitly passed to the next in call-chain order — and LLMxCPG (USENIX Security 2025, peer-reviewed) — CPG-structural context assembly for multi-function vulnerability detection. RepoAudit (ICML 2025) is cited for its per-function memoization cache design (cost reduction via function-level LLM result caching), which complements the Context Store but serves a different purpose.

---

## Deduplication + Confidence Scoring · SSVC-Aligned

**What it does.** The deduplication and confidence scoring layer receives findings from six distinct sources, deduplicates overlapping findings via a cost-cascaded strategy, derives SSVC dimension values per finding, maps them to a numeric confidence score, and emits a final scored finding set for the report.

### Input Sources

| Source | Route | Pre-assigned confidence |
|---|---|---|
| Path A high-confidence rule bypass | Direct — LLM Verifier skipped | Assigned at scoring step |
| Path A LLM Verifier output | `confirmed` or `uncertain` + float | Verifier confidence float |
| Path B CVE auto-flagged (Tier 1) | Direct — classifier + LLM skipped | Auto-scored from CVSS |
| Path B UniXcoder high-confidence vulnerable | Direct — LLM skipped | Classifier confidence float |
| Path B LLM Semantic Scan output | `confirmed` or `uncertain` + float | Scan confidence float |
| Path B budget-exhausted | SUPPRESSED · `reason: budget_exhausted` | 0.0 pass-through |

`uncertain` verdicts from both the LLM Verifier and LLM Semantic Scan are emitted as **SUPPRESSED with `reason: uncertain`** — the surface was analyzed but no verdict could be reached. They appear in the report so the user can investigate; they are never silently dropped.

### Deduplication — Cascaded Strategy

Four gates run cheapest-first. Each gate resolves what it can; survivors proceed to the next gate only.

**Gate 1 — CWE hash + file path + line range overlap** (O(N) hash lookup)
Findings with identical CWE class, same file, and overlapping line ranges are merged. Resolves ~60–70% of cross-path duplicates instantly.

**Gate 2 — Code snippet fingerprint** (O(N) hash lookup)
MD5 of normalised, whitespace-stripped matched code. Catches syntactically identical findings at different reported locations.

**Gate 3 — Embedding similarity** (MiniLM-L6-v2, Python worker)
Findings surviving Gates 1–2 are embedded and compared by cosine similarity. Pairs above threshold (≥0.85) are merged. Catches semantically equivalent findings expressed in different code forms. Realistically ~10–20% of findings reach this gate.

**Gate 4 — AST edit distance** (Zhang-Shasha, expensive — last resort)
Reserved for pairs where Gate 3 similarity is borderline (0.70–0.84). Confirms or rejects merge. Applied to a small residual set only.

### SSVC Dimension Values — Sourcing Per Finding

**Exploitation (E):**
- Matched CVE found in CISA KEV → `Active`
- Matched CVE with EPSS score >0.1 or NVD exploit reference → `PoC`
- No CVE or no evidence → `None`

**Automatable (A):**
CWE class lookup table applied first; LLM single-shot assessment only if CWE is ambiguous:
- CWE-89, -78, -22, -79, -918, -502, -611 → `Yes`
- CWE-862, -306, -287, -384 → `No`

**Technical Impact (T):**
- Matched CVE with CVSS Base Score ≥7.0 → `Total`; <7.0 → `Partial`
- No CVE → CWE class mapping (CWE-89, -78, -22, -79 → `Total`; others → `Partial`)

### Confidence Score Computation

SSVC decision tree traversal produces a discrete outcome. Position within the range is refined by the mean of all contributing source confidence floats, normalised to ±0.05.

| SSVC Outcome | Score Range | Label |
|---|---|---|
| E=Active · A=Yes · T=Total | 0.92–1.0 | BLOCK |
| E=Active or PoC · A=Yes · T=Any | 0.75–0.91 | HIGH |
| E=PoC · A=No · T=Total | 0.60–0.74 | MEDIUM |
| E=None · A=Any · T=Partial | 0.30–0.59 | LOW |
| E=None · A=No · T=Partial | < 0.30 | SUPPRESSED |

**CVE auto-flagged findings** are scored directly from CVSS: ≥9.0 → BLOCK; 7.0–8.9 → HIGH; 4.0–6.9 → MEDIUM; <4.0 → LOW.

**Path A high-confidence rule bypass findings** receive a fixed MEDIUM floor, upgraded by SSVC if CVE data is available.

### Cross-Path Boost

A finding confirmed independently by both Path A and Path B receives a **+15 percentage point additive boost**, capped at 1.0. BLOCK findings are not boosted further.

Example: score 0.65 (MEDIUM) confirmed by both paths → 0.65 + 0.15 = 0.80 (HIGH).

### Suppression Rules

Auto-suppression emits a `SUPPRESSED` finding with an explicit `reason` field — never a silent drop. Users can un-suppress individual findings in the report.

**Test file suppression** (`reason: test_file`). File path patterns:
```
*_test.go  ·  *_spec.rb  ·  **/__tests__/**  ·  **/*.test.ts  ·  **/*.spec.js
**/test/**  ·  **/tests/**  ·  **/spec/**  ·  **/__mocks__/**
```
Exception: functions in test files that are also reachable from non-test files via the CPG call graph are not suppressed — they represent production-reachable surfaces.

**Framework-safe suppression** (`reason: framework_safe`). Per-language:
- **Go**: functions matching `^(Test|Benchmark|Example)[A-Z]` in `*_test.go` files
- **Java**: methods annotated `@Test`, `@BeforeEach`, `@AfterEach` (JUnit); Mockito stub methods
- **Python**: methods inside `unittest.TestCase` subclasses; `pytest` fixture functions
- **JS/TS**: functions inside `describe()` / `it()` / `test()` blocks

---

## Proof-of-Exploit Layer

The Proof-of-Exploit Layer is an Approach 3 feature. It is not active in Approaches 1 or 2. It receives BLOCK and HIGH findings from the deduplication layer, filters them for sandbox eligibility, and attempts to confirm each eligible finding as genuinely exploitable through live execution. The PoE layer never blocks report generation — ineligible findings and sandbox failures pass directly to the HTML report with static evidence only.

---

### PoE Eligibility Classifier

**What it does.** Filters the scored finding set to the subset that sandbox execution can meaningfully confirm. Two filter criteria apply before any container is built:

1. **Severity filter.** Only BLOCK and HIGH findings enter the sandbox. MEDIUM and LOW findings are too low-value to justify container build cost. SUPPRESSED findings are excluded regardless of reason.
2. **CWE class filter.** Certain vulnerability classes are structurally not sandbox-confirmable at build-from-source time:

| CWE class | Sandbox-confirmable? | Reason |
|---|---|---|
| CWE-89 SQL injection, CWE-78 OS injection, CWE-22 path traversal | Yes | Deterministic sink behavior — observable via crafted input |
| CWE-798 hardcoded credentials | Yes | String match — static confirmation is sufficient |
| CWE-862 missing auth guard, CWE-285 IDOR/BOLA | No | Requires live database state + authenticated session context |
| Prompt injection in agent config files | No | Requires a live LLM agent runtime |
| CWE-918 SSRF | Partially | Network-isolated sandbox cannot confirm external reachability |
| CWE-1104 hallucinated package (slopsquatting) | No | Network-level check, not runtime exploit |

Ineligible findings receive `poe_status: not_attempted` and pass directly to the HTML report. They are rendered distinctly from sandbox-confirmed and sandbox-refuted findings.

**Why it exists.** FaultLine (arXiv:2507.15241) — the closest published system to this component — achieved 16% project-level success on a dataset concentrated in memory-corruption and injection classes. Auth-gap and logic-flaw findings, which are Path B's primary output, are not well-represented in sandbox-confirmable classes. Routing ineligible findings into the sandbox produces container failures and misleading timeout signals without improving finding quality.

---

### Red Team Agent

**What it does.** The Red Team Agent is a LangGraph-orchestrated agent that receives the eligibility-filtered BLOCK and HIGH findings and drives the exploit verification workflow. For each finding it reads the `poe_context` field populated by Dedup — `{source_node, sink_node, taint_path_summary, required_input_conditions}` — and uses it to generate class-specific exploit inputs rather than re-deriving the exploit path from free text.

The agent operates under explicit termination conditions: maximum 3 exploit attempts per finding; a hard wall-clock timeout per container execution; immediate escalation to `poe_status: model_refused` if the local LLM declines to generate an offensive payload.

**`poe_status` enum:**

| Value | Meaning |
|---|---|
| `confirmed` | Sandbox executed; finding triggered; evidence collected |
| `refuted` | Sandbox executed; finding did not trigger on multiple attempts |
| `not_attempted` | Ineligible CWE class or severity below threshold |
| `model_refused` | Local LLM declined to generate exploit input |
| `timeout` | Container build or execution exceeded wall-clock limit |
| `build_failed` | Container failed to build from source |
| `ambiguous` | Container executed; output is inconclusive (e.g., 500 error without confirming exploit) |

**Why it exists.** Static analysis cannot distinguish between a theoretically vulnerable code path and one that is actually reachable and exploitable in the runtime environment.

---

### Docker Sandbox

**What it does.** The Docker Sandbox builds a container from the analyzed codebase source, injects crafted exploit inputs constructed by the Red Team Agent, observes outputs, and confirms whether the vulnerability manifests at runtime.

**Minimum isolation profile (required before Approach 3 ships).** The sandbox executes adversarially constructed code — a finding classified as HIGH by ZeroTrust.sh could itself be a container escape vulnerability. CVE-2025-9074 (CVSS 9.3, August 2025) demonstrated that Docker Desktop's TCP bridge at `192.168.65.7:2375` allows any container to create new containers with full host filesystem access on macOS and Windows — ZeroTrust.sh's primary developer workstation environments.

Required isolation settings per container invocation:
- `--security-opt seccomp=<zerotrust-sandbox-profile>` — custom seccomp profile blocking `ptrace`, `mount`, `unshare`, `clone` with `CLONE_NEWUSER`
- `--network none` — no network access; prevents external data exfiltration from the sandbox
- `--read-only` — read-only root filesystem; prevents persistence
- `--user 65534:65534` — run as `nobody:nogroup`; no root privilege inside the container
- `--memory 512m --cpus 1.0` — hard resource cap; prevents denial-of-service against the host
- No Docker API socket mounted into the container; explicit block of the Docker Desktop TCP bridge address

**Recommended runtime (Linux developer machines).** `--runtime=runsc` (gVisor) provides user-space kernel syscall interception — eliminating the kernel exploit escape path shared by all standard Docker containers. Not available on macOS Docker Desktop; the seccomp profile above is the minimum viable mitigation on macOS.

**Graceful degradation.** If sandbox execution results in `build_failed`, `timeout`, or `ambiguous`, the finding bypasses the sandbox and passes to the final report with `poe_status` set to the appropriate value and static evidence only. The PoE layer never blocks report generation.

---

### Two-layer PoE Output

**What it does.** For each finding with `poe_status: confirmed`, the PoE layer produces two output artifacts with defined schemas.

**Technical trace schema** (for developers):
```json
{
  "finding_id":           "string",
  "cwe":                  "string",
  "severity_label":       "BLOCK | HIGH",
  "exploit_input":        "string (base64 or percent-encoded)",
  "sandbox_exit_code":    "int",
  "observed_output":      "string (max 500 chars)",
  "code_path_traversed":  ["string"],
  "poe_confidence":       "float (1.0=clean execution · 0.5=ambiguous · 0.0=build failure bypass)"
}
```

**Executive summary schema** (for managers and security leads). Generated by filling a constrained template rather than open-text generation — preventing hallucinated business context (fabricated downstream systems, invented financial impact figures):
```json
{
  "affected_component":        "string (max 120 chars)",
  "data_at_risk":              "string (max 80 chars)",
  "exploitation_requirement":  "string (max 80 chars)",
  "confirmed_exploitable":     "bool",
  "business_impact_tier":      "data-breach | availability | privilege-escalation | information-disclosure | no-confirmed-impact"
}
```

The `business_impact_tier` enum forces classification into a bounded vocabulary a security manager can act on. The constrained template prevents the local LLM from producing generic boilerplate ("this vulnerability could allow an attacker to…") or fabricated context not present in the finding.

---

## Final Report

**What it does.** The HTML Report + Patch Suggestions node is the terminal output of the pipeline. It is produced by all approaches (1, 2, and 3). It generates a self-contained interactive HTML vulnerability dashboard from the scored finding set and produces a patch suggestion for each confirmed finding. In Approach 3, confirmed findings with `poe_status: confirmed` include Two-layer PoE evidence; all other findings include static evidence only.

---

### Patch Suggestions

**Approach.** Zero-shot unified diff generation via the local LLM — no fix-pair trained model. PatchEval (arXiv:2511.11019, 230 CVEs, Docker-validated) puts the best LLM at 22.6% correct single-function patches; multi-file auth/permission fixes collapse to 0–7.7%. Patch suggestions are starting-point guidance, not guaranteed correct fixes.

**Patch applicability validation.** After generation, every patch is applied to a working copy in memory using Go's `go-gitdiff` library. If it fails to apply cleanly — incorrect `@@ -old,+new @@` hunk header line numbers are the primary failure mode for LLM-generated diffs — the report emits `patch_status: malformed` with the raw LLM suggestion as a text note rather than a formatted diff. A malformed diff displayed as a diff misleads the developer into treating it as ready to apply.

**Patch scope labels and reliability indicator.** Each patch is classified and displayed with a PatchEval-grounded reliability label:

| Scope | Expected success rate | Report label |
|---|---|---|
| `single_hunk` | ~22% | Low — treat as starting point |
| `multi_hunk_single_file` | ~12% | Very low — manual rework likely |
| `multi_file` | 0–7.7% | Indicative only — manual fix required |

**CVE few-shot context (BLOCK and HIGH findings with CVE match).** For findings where a CVE match exists, the public CVE fix commit is retrieved from the NVD/GitHub Advisory database (Trivy already fetches this data) and injected as a few-shot example in the patch generation prompt. This moves meaningfully toward fix-pair quality using data already in the pipeline.

---

### HTML Report — XSS Mitigations

**Risk.** The finding schema includes free-text fields (`justification`, `matched_code`, taint path node labels) derived from codebase content — attacker-controlled strings. If an analyzed file contains HTML-injectable content in a comment or identifier and Joern extracts it as a taint node label, it flows into the report. For file-system-loaded HTML, no HTTP `Content-Security-Policy` header applies — only a `<meta>` CSP tag works.

**Required mitigations:**

1. All free-text fields (`justification`, `file_path`, `matched_code`, any LLM-derived string) pass through Go `html/template` contextual escaping. No field is cast to `template.HTML()` — that type conversion bypasses autoescaping.
2. The report template includes `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';">` — blocks any injected external script tag.
3. The report generator test suite includes a synthetic finding with `justification: "<script>alert('xss')</script>"` and `file_path: "src/<img src=x onerror=alert(1)>/file.go"` to verify correct escaping before release.

---

### User-Controlled Suppression

**Suppression state persistence.** Users can override the `SUPPRESSED` verdict for individual findings in the HTML report. The override is persisted in a sidecar file `.zerotrust-suppressions.yaml` at the project root. The Differential Indexer reads this file on the next scan and carries the suppression decision forward — suppressed findings that have not changed are not re-analyzed. This mirrors Semgrep's `.semgrepignore` and SonarQube's "Won't Fix" state.

**Vocabulary note.** The output labels BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED are an SSVC-inspired confidence scoring system. The scoring dimensions (Exploitation, Automatable, Technical Impact) are drawn from SSVC, but the output label vocabulary does not match the CISA SSVC Supplier decision tree outcome vocabulary (Scheduled/Out-of-cycle/Immediate). All user-facing and external communications describe the system as "SSVC-inspired" rather than "SSVC-compliant."

---

## Design Principles

The following architectural decisions are reflected throughout the system. Each is stated explicitly here as a principle rather than scattered across component descriptions.

**Local execution — no code leaves the machine.** Every component runs on-device. The LLM is a local GGUF model served via Ollama or llama-cpp-python. CVE database queries use a locally cached copy updated at scan time via Trivy. No source code, no findings, and no telemetry are sent to any external service.

**Neither path gates the other.** Path A and Path B run concurrently against the same file set. A false negative in Path A does not suppress a finding in Path B. A false positive filtered by Path A's LLM Verifier does not affect what Path B analyzes. The two paths are architecturally independent by design; the deduplication layer is the only point where their outputs interact.

**Three-tier cost funnel — spend budget only where uncertainty exists.** The three tiers of Path B are ordered by cost: deterministic CPG queries first, local CPU classifier second, LLM reasoning last. Each tier resolves the cases it can handle cheaply and passes only the residual uncertain cases to the next tier. The result is that approximately 95% of files and 75–85% of code surfaces never reach the LLM.

**Grammar-constrained output everywhere.** Both the LLM Verifier (Path A) and the LLM Semantic Scan (Path B) use XGrammar-2 (arXiv:2601.04426, May 2026) to enforce JSON output schemas at generation time. Malformed output is impossible by construction. XGrammar-2's `TagDispatch` handles the multiple distinct output schemas across components (LLM Verifier verdict schema, Semantic Function Summarizer taint-flow/auth-guard/logic-flaw schemas, ReAct verdict schema) without recompilation per call; its cross-grammar cache reuses substructures across schemas, delivering 6× faster grammar compilation and near-zero end-to-end overhead vs. XGrammar-1.

**CPG shared between paths — one parse, two uses.** The Joern CPG Engine is part of Path A, but the graph it produces is consumed by Path B's Heuristic Targeting and Call Graph nodes without a second parse. This avoids redundant computation and ensures both paths reason about the same graph representation of the code.

**LLM sees summaries, never raw code.** At every point where an LLM is invoked — the LLM Verifier, the Semantic Function Summarizer, and the LLM Semantic Scan — the model receives structured representations of the code, not raw source. This reduces token cost, focuses reasoning on security-relevant semantics, and prevents the model from anchoring on irrelevant syntactic details.

**SSVC-inspired confidence scoring for triage compatibility.** Confidence scores are derived from SSVC dimensions (Exploitation, Automatable, Technical Impact) and mapped to an internal five-tier label set (BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED). The dimensions and their sourcing rules are drawn from SSVC, making the output compatible with security team triage workflows that use SSVC. The output label vocabulary is not the CISA SSVC Supplier decision tree vocabulary (Scheduled/Out-of-cycle/Immediate) — the system is SSVC-inspired, not SSVC-compliant.

**Supply chain integrity at the model layer.** The Model Integrity Verifier treats the local GGUF model as an attack surface and verifies it at startup. This addresses the ICML 2025 threat class of backdoored quantized models, which is a realistic supply chain risk for any tool that distributes a local model binary.

**AI agent config files as a first-class attack surface.** MCP server configs, `.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `copilot-instructions.md`, and similar files are scanned by both Path A (pattern rules) and Path B (CPG node selection). No competing tool covers this surface. Prompt injection delivered through repository instruction files is a novel attack vector that becomes relevant specifically because AI coding agents read and act on these files autonomously.
