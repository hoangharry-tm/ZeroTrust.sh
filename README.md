# ZeroTrust.sh

> **Local, offline SAST for code written by AI coding agents.**  
> Source never leaves your machine. No VCS token. No cloud upload. No trust.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](go.mod)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Status](https://img.shields.io/badge/status-active%20development-orange.svg)]()

---

## The Problem

AI coding agents (Cursor, Cline, Aider, GitHub Copilot Workspace) generate functional code at high speed. They also introduce vulnerabilities that existing SAST tools were not designed to catch.

Not classic injection bugs — those are covered. The new class:

- **Package hallucinations (slopsquatting)** — an agent imports `requests-auth-aws` (non-existent); an attacker registers it with a payload. Your scanner sees nothing because the package isn't on any CVE list yet.
- **Prompt injection in source** — adversarial instructions in comments, docstrings, or string literals that redirect the next agent that reads this file.
- **Security-node disappearance** — an auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires.
- **AI agent instruction file backdoors** — Unicode obfuscation (U+202E, U+200B) buried in `CLAUDE.md`, `.cursor/rules`, `AGENTS.md`, or MCP configs. No competitor scans this surface.
- **Agent cheat patterns** — `return True` in `*auth*` functions, `TODO: add auth` with no follow-through, disabled test assertions that an agent left in place to make the suite green.

Traditional SAST tools require cloud upload, run against CVE databases, and assume a human wrote the code. ZeroTrust.sh does not.

---

## What It Detects

### AI-Specific Threats

| Threat | Examples |
|---|---|
| Package hallucinations (slopsquatting) | Imports for packages that do not exist on PyPI/npm/Maven |
| Prompt injection in source | Adversarial instructions in comments, docstrings, string literals |
| AI coding agent cheat patterns | `return True` in auth functions · `TODO: add auth` with no call · disabled assertions |
| MCP server config injection | External URLs, shell/execute capabilities, over-broad filesystem scopes in `.mcp.json` |
| Instruction file backdoors | Unicode obfuscation in `CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, `GEMINI.md` |
| Security-node disappearance | Auth/validate/check AST nodes present in prior scan, silently removed in current scan |

### Classic Vulnerabilities — 12 Languages

SQL injection · command injection · SSRF · XXE · path traversal · hardcoded credentials · insecure deserialization · broken access control (IDOR/BOLA) · XSS · unsafe TLS · empty security catch blocks

---

## Install

```bash
# Go binary (single static binary, no runtime deps in Docker mode)
go install github.com/hoangharry-tm/zerotrust/cmd/zerotrust@latest

# Docker — no Go toolchain required
docker pull ghcr.io/hoangharry-tm/zerotrust:latest
```

---

## Quickstart

```bash
# Scan a project directory (Docker mode — default)
zerotrust scan ~/my-project

# Scan without Docker (requires Joern, OpenGrep, ast-grep, and Python worker deps on PATH)
zerotrust scan --native ~/my-project

# Output an HTML report to a custom path
zerotrust scan ~/my-project --report ~/Desktop/report.html
```

First run in Docker mode pulls the engine image (~500 MB). Subsequent runs use the cached image.

The HTML report opens automatically. It is self-contained — one file, no external dependencies, shareable offline.

---

## Architecture

Two independent detection paths run in parallel against every changed file set. Neither path gates the other. A finding confirmed by both receives a cross-path confidence boost (+15 percentage points).

```
Codebase Directory
       │
       ├── Model Integrity Verifier (cosign/Sigstore — gates LLM calls only)
       └── Differential Indexer (content-hash diff — changed files only, ~80–95% cost reduction)
              │
    ┌─────────┴──────────┐
    │                    │
Path A                 Path B
Pattern Detection      Semantic Detection
    │                    │
OpenGrep rules         Heuristic Targeting (CPG surface selection)
ast-grep rules         CVE enrichment (Trivy)
Joern CPG taint        UniXcoder classifier (local, CPU)
LLM Verifier           Call Chain Assembler (depth-3, callee-first)
(CoD + SCoT +          Threat Feature Extractor
 XGrammar-2)           Token Budget Controller
                       LLM Semantic Scan (bounded ReAct, max 3 steps)
    │                    │
    └─────────┬──────────┘
              │
         Dedup + SSVC Scoring
         BLOCK / HIGH / MEDIUM / LOW / SUPPRESSED
              │
       HTML Report + Unified Diff Patches
```

**Path A — fast, deterministic.** OpenGrep and ast-grep run structural pattern matching across 42 rules (Python, Java, JavaScript/TypeScript, Go, Ruby, PHP, Kotlin, C#, Rust, Swift, Dart). Joern CPG Engine runs whole-program inter-file taint analysis. An LLM Verifier using Chain-of-Draft + Structured Chain-of-Thought reasoning with XGrammar-2-enforced output filters false positives. High-confidence rules bypass the verifier and go directly to Dedup.

**Path B — three-tier cost funnel.** ~95% of files are eliminated by heuristic targeting (CPG surface selection + resource ID dataflow). A local UniXcoder classifier runs on CPU and gates the remainder. Only the uncertain fraction (~15–25% of surfaces) reaches the bounded LLM reasoning step. The LLM never sees raw source — only CPG-derived structured summaries. Budget-exhausted surfaces emit `SUPPRESSED`, never silent drop.

**Differential Indexer** tracks a content-hash snapshot of every scanned file in a local SQLite cache. Repeat scans process only changed files plus their one-hop CPG neighbours, cutting cost 80–95% on already-scanned codebases.

**Model Integrity Verifier** verifies every LLM model binary against a cosign/Sigstore Rekor-signed registry before the first LLM call. `WARN` on unrecognized models, `BLOCK` on hash mismatch. Pattern detection and CPG analysis are unaffected — MIV gates LLM calls only.

---

## Language Coverage

| Language | Path A — Pattern | Path A — Taint | Path B — Semantic |
|---|:---:|:---:|:---:|
| Python | OpenGrep | Joern | UniXcoder |
| Java | OpenGrep | Joern | UniXcoder |
| JavaScript / TypeScript | OpenGrep + ast-grep | Joern | UniXcoder |
| Go | OpenGrep | Joern† | UniXcoder |
| Ruby | OpenGrep + ast-grep | Joern | UniXcoder |
| PHP | OpenGrep + ast-grep | Joern | UniXcoder |
| Kotlin | ast-grep | — | LLM direct |
| C# | ast-grep | — | LLM direct |
| Rust | ast-grep | — | LLM direct |
| Swift | ast-grep | — | LLM direct |
| Dart | ast-grep | — | LLM direct |
| Generic (`.md`, `.mcp.json`) | OpenGrep + instrscan | — | — |

† Joern Go frontend is community-contributed; CPG quality empirically validated during development.

---

## Current Status

| Milestone | Window | Status |
|---|---|:---:|
| G1 — OpenGrep PoC | Jun 9–20 | **Complete** |
| L0 — Foundation + Fast Path | Jun 17–23 | **Complete** (6–11 days early) |
| L1 — Joern Spike | Jul 3–7 | Upcoming |
| L2 — Path A Complete | Jul 7–17 | Upcoming |
| L3 — Path B | Jul 17–28 | Upcoming |
| L4 — Dedup + Report + Integration | Jul 28 – Aug 6 | Upcoming |

**G1 delivered**: 42 rules (PY-001→010 · JV-001→009 · GN-001→007 · AG-005→016), Go instrscan, Spring Boot test codebase with 12 findings across 10 rule variants, 0 FP on clean controls.

**L0 delivered**: Go CLI binary, MIV with cosign/Sigstore Rekor verification, Differential Indexer with SQLite state cache, OpenGrep + ast-grep + instrscan wrappers, Python worker IPC, Finding channel, live HTML dashboard via SSE.

Hard deadline: **August 6, 2026** — management demo + public testing release.

---

## Run the Demo

```bash
git clone https://github.com/hoangharry-tm/ZeroTrust.sh
cd ZeroTrust.sh

# Build
go build -o build/zerotrust ./cmd/zerotrust

# Demo (Docker default)
./build/zerotrust scan testdata/demo-app/

# Demo without Docker
./build/zerotrust scan --native testdata/demo-app/
```

Scans `testdata/demo-app/` (21-file multi-language codebase) and `testdata/spring-boot-app/` with all 42 rules. Prints a findings summary and writes `zerotrust-report.html`.

---

## Repository Structure

```
cmd/zerotrust/          CLI entry point — cobra, Docker orchestration, direct execution
pkg/
  cpg/                  Shared CPG Graph interface
  ollama/               Ollama HTTP client (model-agnostic; MIV-gated)
  sqlite/               SQLite state cache (pure-Go, modernc.org/sqlite)
internal/
  finding/              Finding struct + channel (locked pipeline interface)
  ingestion/
    miv/                Model Integrity Verifier (cosign/Sigstore, SHA-256)
    diffindex/          Differential Indexer (content-hash diff, SQLite)
  pattern/              Path A — Pattern Detection
    opengrep/           OpenGrep subprocess wrapper
    astgrep/            ast-grep subprocess wrapper
    joern/              Joern CPG HTTP client
    instrscan/          AI agent instruction file scanner
    verifier/           LLM Verifier (CoD + SCoT + XGrammar-2)
  semantic/             Path B — Semantic Detection
    targeting/          Heuristic Targeting (CPG surface selection)
    enrichment/         CVE enrichment (Trivy) + resource ID dataflow
    classifier/         UniXcoder IPC bridge
    assembler/          Call Chain Assembler (depth-3, callee-first)
    summarizer/         Threat Feature Extractor IPC bridge
    budget/             Token Budget Controller
    llmscan/            LLM Semantic Scan (bounded ReAct)
  dedup/                Dedup + SSVC confidence scoring
  report/               HTML report + unified diff patches
  output/               Output system — MinimalRenderer + WebRenderer (SSE)
  worker/               Python worker manager (NDJSON IPC, auto-restart)
worker/                 Python ML worker (UniXcoder, XGrammar-2, TFE, LLM dispatch)
rules/
  python/               PY-001→010 OpenGrep rules
  java/                 JV-001→009 OpenGrep rules
  generic/              GN-001→007 instruction file + AI cheat pattern rules
  astgrep/              AG-005→016 ast-grep rules (JS/TS, Kotlin, C#, Ruby, PHP)
testdata/
  demo-app/             21-file multi-language demo codebase
  spring-boot-app/      Spring Boot REST API (9 vulnerabilities)
  rules-tests/          Must-fire / must-not-fire test cases per rule
docs/
  architecture/         Cascading Intelligence Pipeline spec + Mermaid diagrams
  planning/             Layer-based implementation plan (L0–L4, PERT estimates)
  research-papers.md    87 papers across 17 research areas
  report-example.html   Interactive HTML report mockup
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| CLI + orchestration | Go — cobra, goroutines, errgroup, all pipeline + Docker dispatch |
| Pattern matching | OpenGrep (LGPL-2.1) + ast-grep (MIT) |
| Taint analysis | Joern CPG Engine (Apache 2.0) |
| ML classifier | UniXcoder-Base-Nine (local Python worker, CPU inference) |
| Structured output | XGrammar-2 constrained decoding |
| LLM runtime | Ollama HTTP API — model-agnostic; host GPU passthrough to container |
| CVE enrichment | Trivy `fs` subprocess (Apache 2.0) |
| Model verification | cosign / Sigstore Rekor (ECDSA P-256 primary, Rekor best-effort) |
| State cache | SQLite — `modernc.org/sqlite` (pure-Go, no CGo) |
| HTML report | Go `html/template` + `embed`, native EventSource (no framework) |
| Distribution | Single Go binary — Docker default, `--native` opt-in |

---

## Requirements

**Docker mode (default)**
- Docker Desktop (macOS) or `docker.io` (Linux). The CLI handles `docker pull` and `docker run` transparently.
- Ollama (optional, recommended) — GPU-accelerated LLM inference. Detected automatically and passed through to the container. Without Ollama, LLM inference falls back to CPU.

**Native mode (`--native`)**
- JDK 19+, Joern, OpenGrep, ast-grep
- Python 3.11+ with worker dependencies (`pip install -r worker/requirements.txt`)

---

## Docs

- Architecture spec: [`docs/architecture/detail.md`](docs/architecture/detail.md)
- Implementation plan: [`docs/planning/implementation-plan.md`](docs/planning/implementation-plan.md)
- Research papers: [`docs/research-papers.md`](docs/research-papers.md)
- Report mockup: [`docs/report-example.html`](docs/report-example.html)

---

## Contributing

ZeroTrust.sh is in active development toward the August 6 public testing release. The highest-leverage contributions right now:

- **Rules** — new OpenGrep or ast-grep rules for AI-specific patterns. See [`rules/`](rules/) and the must-fire/must-not-fire test harness in [`testdata/rules-tests/`](testdata/rules-tests/).
- **Test codebases** — vulnerable-by-design code samples in languages with thin coverage (Kotlin, Dart, Swift).
- **Bug reports** — open an issue with the rule ID, the input that triggered it, and whether it was a false positive or false negative.

Before submitting a rule PR: run `make test` and confirm 0 FP on the clean controls in `testdata/rules-tests/ok/`.

---

## License

Apache 2.0
