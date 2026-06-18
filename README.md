# ZeroTrust.sh

A local, privacy-first CLI security scanner designed to audit codebases modified by AI coding agents. Runs entirely on-device — source code never leaves your machine.

---

## The Problem

AI coding agents (Cursor, Cline, Aider, GitHub Copilot Workspace) generate functional code at high speed but routinely introduce security vulnerabilities: package hallucinations that enable supply-chain attacks, prompt injection hidden in comments or config files, and silent removal of security controls that still pass functional tests. Traditional cloud SAST tools require uploading source code externally and were never designed to detect AI-specific threat vectors.

ZeroTrust.sh treats all AI-generated and AI-modified code as untrusted by default.

---

## What It Detects

**AI-specific threats** (no competing tool covers these):

| Threat                                 | Examples                                                                                          |
| ---                                    | ---                                                                                               |
| Package hallucinations (slopsquatting) | AI agent imports `requests-auth-aws` (non-existent); attacker registers it with a payload         |
| Prompt injection in source code        | Adversarial instructions in comments, docstrings, or string literals that hijack agent behaviour  |
| AI coding agent cheat patterns         | `return True` in `*auth*` functions, `TODO: add auth` with no auth call, disabled test assertions |
| MCP server config injection            | External URLs, shell/execute capabilities, over-broad filesystem scopes in `.mcp.json`            |
| Instruction file backdoors             | Unicode obfuscation (U+202E, U+200B) in `CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, `GEMINI.md`    |
| Security-node disappearance            | Auth/validate/check AST nodes present in prior scan, silently removed in current scan             |

**Classic vulnerabilities** across 12 languages:

SQL injection · command injection · SSRF · XXE · path traversal · hardcoded credentials · insecure deserialization · broken access control (IDOR/BOLA) · XSS · unsafe TLS · empty security catch blocks

---

## Detection Architecture

ZeroTrust.sh runs two independent analysis paths in parallel against every changed file set.

```
Codebase Directory
       │
       ├── Model Integrity Verifier (cosign/Sigstore — gates LLM calls only)
       └── Differential Indexer (content-hash diff — changed files only, ~80–95% cost reduction)
              │
    ┌─────────┴──────────┐
    │                    │
Path A                 Path B
(Pattern Detection)    (Semantic Detection)
    │                    │
OpenGrep + ast-grep    Heuristic Targeting (CPG)
Joern CPG taint        CVE enrichment (Trivy)
LLM Verifier           UniXcoder classifier
                       Call Chain Assembler (depth 3)
                       Semantic Summarizer
                       LLM Semantic Scan (ReAct)
    │                    │
    └─────────┬──────────┘
              │
         Dedup + SSVC Scoring
         (BLOCK / HIGH / MEDIUM / LOW / SUPPRESSED)
              │
       HTML Report + Patch Suggestions
```

**Path A** is fast and deterministic: OpenGrep and ast-grep run structural pattern matching; Joern CPG Engine runs whole-program inter-file taint analysis. An LLM Verifier filters false positives using Chain-of-Draft + Structured Chain-of-Thought reasoning with XGrammar-2-enforced output.

**Path B** is a three-tier cost funnel: ~95% of files are eliminated by heuristic targeting; a local UniXcoder classifier gates the remainder; only the uncertain fraction (~15–25% of surfaces) reaches the bounded LLM reasoning step. The LLM never sees raw code — only CPG-derived structured summaries.

A finding confirmed by both paths receives a cross-path confidence boost. A vulnerability missed by Path A remains visible to Path B.

---

## Language Coverage

| Language                     | Path A (Pattern)     | Path A (Taint) | Path B (Semantic) |
| ---                          | :---:                | :---:          | :---:             |
| Python                       | OpenGrep             | Joern          | UniXcoder         |
| Java                         | OpenGrep             | Joern          | UniXcoder         |
| JavaScript / TypeScript      | OpenGrep + ast-grep  | Joern          | UniXcoder         |
| Go                           | OpenGrep             | Joern†         | UniXcoder         |
| Ruby                         | OpenGrep + ast-grep  | Joern          | UniXcoder         |
| PHP                          | OpenGrep + ast-grep  | Joern          | UniXcoder         |
| Kotlin                       | ast-grep             | —              | LLM direct        |
| C#                           | ast-grep             | —              | LLM direct        |
| Rust                         | ast-grep             | —              | LLM direct        |
| Swift                        | ast-grep             | —              | LLM direct        |
| Dart                         | ast-grep             | —              | LLM direct        |
| Generic (`.md`, `.mcp.json`) | OpenGrep + instrscan | —              | —                 |

† Joern Go frontend is community-contributed; CPG quality empirically validated during development.

---

## Current Status

| Milestone                         | Status                                                                                                                                 |
| ---                               | ---                                                                                                                                    |
| G1 — OpenGrep PoC                 | **Complete** — 42 rules (PY-001→010 · JV-001→009 · GN-001→007 · AG-005→016), Go instrscan, Spring Boot test codebase, dual-engine demo |
| L0 — Foundation + Fast Path       | Starts Jun 23                                                                                                                          |
| L1 — Joern Spike                  | Jul 3–7                                                                                                                                |
| L2 — Path A Complete              | Jul 7–17                                                                                                                               |
| L3 — Path B                       | Jul 17–28                                                                                                                              |
| L4 — Dedup + Report + Integration | Jul 28 – Aug 6                                                                                                                         |

Hard deadline: **August 6, 2026** (management demo + public testing release).

---

## Run the Demo (G1)

Requirements: [OpenGrep](https://github.com/opengrep/opengrep) and [ast-grep](https://ast-grep.github.io) installed and on `PATH`.

```bash
git clone https://github.com/hoangharry-tm/ZeroTrust.sh
cd ZeroTrust.sh
bash scripts/run_demo.sh
```

The demo scans `testdata/demo-app/` (21-file multi-language codebase) and `testdata/spring-boot-app/` with all 42 rules and prints a findings summary.

---

## Repository Structure

```
cmd/zerotrust/          CLI entry point (cobra)
pkg/
  cpg/                  Shared CPG Graph interface
  ollama/               Ollama HTTP client wrapper
  sqlite/               SQLite state cache (pure-Go)
internal/
  finding/              Finding struct + channel
  ingestion/
    miv/                Model Integrity Verifier
    diffindex/          Differential Indexer
  pattern/              Path A — Pattern Detection
    opengrep/           OpenGrep subprocess wrapper
    astgrep/            ast-grep subprocess wrapper
    joern/              Joern CPG HTTP client
    instrscan/          AI agent instruction file scanner
    verifier/           LLM Verifier
  semantic/             Path B — Semantic Detection
  dedup/                Dedup + SSVC confidence scoring
  report/               HTML report + patch suggestions
  worker/               Python worker manager
worker/                 Python ML worker (UniXcoder, XGrammar-2, Summarizer)
rules/
  python/               PY-001→010 OpenGrep rules
  java/                 JV-001→009 OpenGrep rules
  generic/              GN-001→007 instruction file rules
  astgrep/              AG-005→016 ast-grep rules (JS/TS, Kotlin, C#, Ruby, PHP)
testdata/
  demo-app/             21-file multi-language demo codebase
  spring-boot-app/      Spring Boot REST API (9 vulnerabilities)
  rules-tests/bad|ok/   Must-fire / must-not-fire rule test cases
docs/
  architecture/         Cascading Intelligence Pipeline spec + diagrams
  planning/             Layer-based implementation plan (L0–L4)
  research-papers.md    87 papers across 17 research areas
  report-example.html   Interactive HTML report mockup
```

---

## Tech Stack

| Layer               | Technology                                           |
| ---                 | ---                                                  |
| CLI + orchestration | Go (cobra, goroutines)                               |
| Pattern matching    | OpenGrep (LGPL-2.1) + ast-grep (MIT)                 |
| Taint analysis      | Joern CPG Engine (Apache 2.0)                        |
| ML classifier       | UniXcoder-Base-Nine (Python worker)                  |
| Structured output   | XGrammar-2 constrained decoding                      |
| LLM runtime         | Ollama HTTP API (`localhost:11434`) — model-agnostic |
| CVE enrichment      | Trivy `fs` subprocess (Apache 2.0)                   |
| State cache         | SQLite via `modernc.org/sqlite` (pure-Go)            |
| HTML report         | Go `html/template` + `embed`                         |

---

## Docs

- Architecture: [`docs/architecture/detail.md`](docs/architecture/detail.md)
- Implementation plan: [`docs/planning/implementation-plan.md`](docs/planning/implementation-plan.md)
- Research papers: [`docs/research-papers.md`](docs/research-papers.md)

---

## License

Apache 2.0
