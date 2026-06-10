# ZeroTrust.sh — AI Codebase Security Scanner

## Idea Summary

ZeroTrust.sh is a local, privacy-first CLI security scanner and patch engine designed to audit codebases modified by AI coding agents. It accepts a codebase directory path or ZIP archive as input, performs deep security analysis entirely on-device, and outputs an interactive HTML vulnerability report with patch suggestions.

## Core Problem

AI coding agents (Cursor, Cline, Aider, Copilot Workspace) generate functional code at high speed but frequently introduce security vulnerabilities — including package hallucinations (slopsquatting), indirect prompt injection risks, and degraded security controls. Traditional cloud SAST tools (Snyk, SonarQube, CodeRabbit) require uploading source code externally, are too slow for real-time agent loops, and were never designed to detect AI-specific threat vectors.

## Key Features

- **Local & Offline Execution**: Source code never leaves the developer's machine.
- **ZIP or Directory Input**: Flexible ingestion layer — no VCS dependency.
- **AI-Specific Threat Detection**: Detects hallucinated packages, security control bypasses, and prompt injection in comments.
- **Dual-Path Analysis Engine**: Path A (fast pattern detection) runs in parallel with Path B (semantic/logic detection) — neither path gates the other.
- **Logic Vulnerability Detection**: Path B independently scans high-risk surfaces (endpoint handlers, auth functions, AI-modified regions) for vulnerabilities invisible to pattern matching — IDOR, missing access controls, business logic flaws.
- **HTML Report Output**: Generates an interactive, self-contained HTML vulnerability dashboard.
- **Patch Suggestions**: Outputs unified Git diff patches for each confirmed vulnerability.
- **Proof-of-Exploitability Documentation** *(Approach 3)*: Produces PoE reports with a technical trace for developers and an executive summary for managers — confirms vulnerabilities are real and triggerable before code ships.

## Architecture: Two-Path Design

ZeroTrust.sh uses two parallel detection paths that run against every codebase input. Neither path gates the other — they produce independent findings merged and deduplicated into a unified report.

**Path A — Pattern Detection (fast, deterministic)**
Finds vulnerabilities with a syntactic signature: code that *looks wrong* in a way a rule can describe. Uses Semgrep/Tree-sitter AST rules tuned for high recall. Fast (seconds), suitable for CI/CD, portable across tech stacks at the language-primitive level.

**Path B — Semantic/Logic Detection (targeted, thorough)**
Finds vulnerabilities where code looks locally correct but is wrong in context: IDOR, missing auth guards, business logic bypasses, AI-agent trust escalation. Uses heuristic targeting (endpoint handlers, auth functions, AI-modified code regions) to identify high-risk surfaces, then routes them to a local LLM for semantic reasoning. Catches what no static pattern can describe.

```mermaid
graph TD
    Input[/"<b><i>Codebase Input</i></b>\nDirectory or ZIP"/]

    subgraph PA["PATH A — Pattern Detection"]
        direction TB
        PA_SG["<b><i><u>Semgrep YAML Rules</u></i></b>\nScans for known bad code patterns"]
        PA_CQ["<b><i><u>CodeQL + Joern</u></i></b>\nTracks how untrusted data flows through the code\nAdditional checks — runs alongside Semgrep in parallel"]
        PA_LV["<b><i><u>LLM Verifier</u></i></b>\nMerges findings from Semgrep and CodeQL\nUses AI to filter out false positives"]
        PA_SG --> PA_LV
        PA_CQ --> PA_LV
    end

    subgraph PB["PATH B — Semantic Detection · not available in the basic version"]
        direction TB
        PB_HT["<b><i><u>Heuristic Targeting</u></i></b>\nSelects which parts of the code carry the most risk\nEndpoints · auth functions · AI-modified areas"]
        PB_CG["<b><i><u>Call Graph + CVE Enrichment</u></i></b>\nMaps how functions call each other\nCross-references each surface against known vulnerability database"]
        PB_LS["<b><i><u>LLM Semantic Scan</u></i></b>\nReads each high-risk surface and reasons about vulnerabilities\nRuns independently — never sees Path A results"]
        PB_HT --> PB_CG
        PB_CG --> PB_LS
        PB_HT -.->|"When call graph data is unavailable:\ngoes directly to LLM scan"| PB_LS
    end

    Input --> PA_SG
    Input --> PA_CQ
    Input --> PB_HT

    PA_LV --> Dedup
    PB_LS --> Dedup

    Dedup["<b><i><u>Dedup + Confidence Scoring</u></i></b>\nBoth paths flagged the same issue → HIGH confidence\nOnly one path flagged it → MEDIUM confidence"]

    subgraph PoELayer["Proof-of-Exploit Layer · most advanced version only"]
        direction LR
        RTA["<b><i><u>Red Team Agent</u></i></b>\nOrchestrates the exploit verification workflow"]
        DS["<b><i><u>Docker Sandbox</u></i></b>\nAttempts to actually trigger each finding\nto confirm it is real and exploitable"]
        PoEDoc["<b><i><u>Two-layer PoE Output</u></i></b>\nTechnical trace for developers\nExecutive summary for managers"]
        RTA --> DS --> PoEDoc
    end

    Dedup -->|"most advanced version only"| RTA
    Dedup --> FinalReport
    PoEDoc --> FinalReport

    FinalReport["<b><i><u>HTML Report + Patch Suggestions</u></i></b>\nAll versions produce this report\nThe most advanced version also includes proof-of-exploit evidence"]
```

A finding confirmed by both paths is treated as high-confidence signal. A vulnerability missed by Path A remains visible to Path B.

### Phased Implementation

| Phase | Builds | Path A | Path B |
|---|---|---|---|
| **Approach 1** — Semgrep PoC | Custom Semgrep YAML rules, fake Java test codebase, CLI detection demo | Semgrep rules (Python + Java) | Not yet |
| **Approach 2** — Hybrid AST + Local LLM | Go core engine, LLM verifier, HTML report, patch suggestions | Tree-sitter + expanded rule set | Introduced: LLM independently scans endpoints and auth surfaces alongside verifying Path A findings |
| **Approach 3** — Agentic Scanner | LangGraph multi-agent orchestration, Docker sandbox, PoE documentation | Semgrep + taint-aware tools (CodeQL/Joern) | Fully realized: call graph traversal, CVE cross-referencing, sandbox exploit execution, two-layer PoE output |

## Tech Stack (Target)

- **Core Engine**: Rust or Go
- **Parser**: Tree-sitter
- **LLM Runtime**: Ollama / llama.cpp with quantized GGUF models
- **Templates**: Tera (Rust) or Jinja2 (Python)
- **Distribution**: Single standalone binary

## Market Position

- **Competitors**: CodeRabbit (cloud PR-based), Snyk (cloud SAST), Semgrep (local but rule-only, no LLM)
- **Differentiator**: Local-only execution + AI-specific threat vectors + agent-loop native speed + zero cloud token cost
- **Strategy**: Open-source core (community crowdsourced rules), optional enterprise cloud compliance dashboard

## Status

- [x] Idea validated
- [x] Market research complete
- [x] Technical architecture selected
- [ ] Repository initialized
- [ ] Core engine implementation
- [ ] Rule engine and YAML ruleset
- [ ] Local LLM integration
- [ ] HTML report generator
- [ ] Public release

## GitHub

Repository: <https://github.com/hoangharry-tm/ZeroTrust.sh>
