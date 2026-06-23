<div align="center">

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 380 50" width="380" height="50">
  <defs>
    <linearGradient id="zt-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#58a6ff"/>
      <stop offset="50%" stop-color="#818cf8"/>
      <stop offset="100%" stop-color="#8b5cf6"/>
    </linearGradient>
  </defs>
  <text x="190" y="35" text-anchor="middle" font-family="'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', 'DejaVu Sans Mono', 'Consolas', monospace" font-size="32" font-weight="600" fill="url(#zt-gradient)">
    <tspan font-weight="900">Zero</tspan>Trust.sh
  </text>
</svg>

<p align="center">
  <strong>Local, offline SAST for code written by AI coding agents.</strong><br>
  Source never leaves your machine. No VCS token. No cloud upload. No trust.
</p>

[![Website](https://img.shields.io/badge/website-%23C2410C.svg?logo=githubpages&logoColor=white)](https://hoangharry-tm.github.io/ZeroTrust.sh/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg?logo=go)](go.mod)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Status](https://img.shields.io/badge/status-active%20development-orange)]()

---

**[Website](https://hoangharry-tm.github.io/ZeroTrust.sh/) · [Architecture](docs/architecture/detail.md) · [Plan](docs/planning/implementation-plan.md) · [Report Mockup](docs/report-example.html)**

</div>

## The Problem

AI coding agents (Cursor, Cline, Aider, GitHub Copilot Workspace) generate functional code at speed. They also introduce vulnerabilities that existing SAST tools were not designed to catch.

Not classic injection bugs — those are covered. The new class:

<details>
<summary><b>Package hallucinations (slopsquatting)</b></summary>

An agent imports <code>requests-auth-aws</code> (non-existent). An attacker registers it with a payload. Your scanner sees nothing — the package isn't on any CVE list yet.

ZeroTrust.sh flags it immediately via hallucination heuristics.
</details>

<details>
<summary><b>Prompt injection in source</b></summary>

Adversarial instructions in comments, docstrings, or string literals that redirect the next agent that reads this file.

Detected by OpenGrep pattern rules + LLM Verifier.
</details>

<details>
<summary><b>Security-node disappearance</b></summary>

An auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires.

The Differential Indexer catches the AST-node delta.
</details>

<details>
<summary><b>AI agent instruction file backdoors</b></summary>

Unicode obfuscation (U+202E, U+200B) buried in <code>CLAUDE.md</code>, <code>.cursor/rules</code>, <code>AGENTS.md</code>, or MCP configs. No competitor scans this surface.

ZeroTrust.sh's instrscan engine was built for this.
</details>

<details>
<summary><b>MCP server config injection &amp; agent cheat patterns</b></summary>

External URLs, shell/execute capabilities, and over-broad filesystem scopes injected into <code>.mcp.json</code>. `return True` in `*auth*` functions. `TODO: add auth` with no follow-through. Disabled assertions.

Pattern rules catch these reliably.
</details>

> [!NOTE]
> Traditional SAST tools require cloud upload, run against CVE databases, and assume a human wrote the code. **ZeroTrust.sh does not.**

## Quickstart

```bash
# Install (single static binary)
go install github.com/hoangharry-tm/zerotrust/cmd/zerotrust@latest

# Scan a project (Docker mode — default)
zerotrust scan ~/my-project

# Scan without Docker
zerotrust scan --native ~/my-project

# Custom report path
zerotrust scan ~/my-project --report ~/Desktop/report.html
```

> [!WARNING]
> First run in Docker mode pulls the engine image (~500 MB). Subsequent runs use the cached image.

The HTML report is self-contained — one file, no external deps, shareable offline.

### Try the demo

```bash
git clone https://github.com/hoangharry-tm/ZeroTrust.sh
cd ZeroTrust.sh
go build -o build/zerotrust ./cmd/zerotrust
./build/zerotrust scan tests/integration/demo-app/
```

Scans a 21-file multi-language codebase. Writes `zerotrust-report.html`.

## Architecture

Two independent detection paths run in parallel. Neither gates the other. A finding confirmed by both receives a +15pp confidence boost.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/diagrams/architecture-dark.svg">
  <img src="docs/architecture/diagrams/architecture-light.svg" alt="ZeroTrust.sh architecture — two parallel detection paths">
</picture>

<details>
<summary><b>Diagram source</b></summary>

```text
flowchart LR
    Input[/"Codebase Directory"/]

    subgraph Ingestion["Ingestion"]
        DI["Differential Indexer"]
        MIV["Model Integrity Verifier"]
    end

    subgraph PA["Path A — Pattern Detection"]
        PS["Pattern Scanner"]
        TA["Taint Analyzer"]
        LV["LLM Verifier"]
    end

    subgraph PB["Path B — Semantic Detection"]
        SS["Surface Selector"]
        CC["Classifier Chain"]
        LR["LLM Reasoner"]
    end

    Input --> DI
    Input --> MIV
    DI --> PS
    DI --> TA
    DI --> SS
    TA --> LV
    PS --> LV
    TA -.-> SS
    SS --> CC
    CC -->|"uncertain"| LR

    LV --> Dedup
    CC -->|"high confidence"| Dedup
    LR --> Dedup

    Dedup["Dedup + SSVC Scoring"]
    Dedup --> Report["HTML Report + Patches"]

    style Ingestion fill:#eef2ff,stroke:#c7d2fe
    style PA fill:#f0f9ff,stroke:#bae6fd
    style PB fill:#ecfdf5,stroke:#a7f3d0
```
</details>

**Path A — fast, deterministic.** OpenGrep + ast-grep pattern matching across 42 rules. Joern CPG inter-file taint analysis. LLM Verifier (Chain-of-Doubt + SCoT + XGrammar-2) filters false positives. High-confidence rules bypass the verifier directly to Dedup.

**Path B — three-tier cost funnel.** ~95% of files eliminated by heuristic targeting. Local UniXcoder classifier gates the remainder. Only uncertain surfaces reach bounded LLM reasoning (max 3 ReAct steps). Budget-exhausted surfaces emit `SUPPRESSED` — never silent drop.

> [!IMPORTANT]
> **Differential Indexer** — content-hash snapshot in local SQLite. Repeat scans process only changed files + one-hop CPG neighbours: **~80–95% cost reduction**.
>
> **Model Integrity Verifier** — cosign/Sigstore Rekor-signed registry. `WARN` on unrecognized models, `BLOCK` on hash mismatch. Gates LLM calls only — pattern + CPG analysis unaffected.

<details>
<summary><b>Full pipeline detail</b></summary>

| Step | What it does |
|---|---|
| **Differential Indexer** | Content-hash diff against SQLite cache; passes only changed + expanded files |
| **MIV** | Verifies model binary against cosign/Sigstore Rekor before first LLM call |
| **Pattern Scanner** | OpenGrep + ast-grep + instrscan — 42 rules across 12 languages |
| **Taint Analyzer** | Joern CPG — traces untrusted input to sensitive sinks |
| **LLM Verifier** | CoD + SCoT + XGrammar-2; FP filter for pattern findings |
| **Surface Selector** | CPG heuristics + Trivy CVE enrichment + BOLAZ IDOR tracking |
| **Classifier Chain** | UniXcoder (CPU) — classifies surfaces as vulnerable or safe |
| **LLM Reasoner** | Bounded ReAct (max 3 steps) — only for uncertain cases |
| **Dedup + SSVC** | Cross-path boost +15pp; BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED |
</details>

## Severity Levels

| Severity | Meaning |
|---|---|
| 🔴 **BLOCK** | Exploitation imminent — patch immediately |
| 🟡 **HIGH** | Likely exploitable — high priority |
| 🔵 **MEDIUM** | Conditional or chained exploit path |
| ⚪ **LOW** | Best practice violation, low risk |
| 🟢 **SUPPRESSED** | Budget-exhausted — not silent drop |

## Current Status

| Milestone | Window | Status |
|---|---|---|
| G1 — OpenGrep PoC | Jun 9–20 | ✅ **Complete** |
| L0 — Foundation + Fast Path | Jun 17–23 | ✅ **Complete** (6–11 days early) |
| L1 — Joern Spike | Jul 3–7 | 🔲 Upcoming |
| L2 — Path A Complete | Jul 7–17 | 🔲 Upcoming |
| L3 — Path B | Jul 17–28 | 🔲 Upcoming |
| L4 — Dedup + Report + Integration | Jul 28 – Aug 6 | 🔲 Upcoming |

**G1 delivered:** 42 rules (PY-001→010 · JV-001→009 · GN-001→007 · AG-005→016), Go instrscan, Spring Boot test codebase with 12 findings across 10 rule variants, 0 FP on clean controls.

**L0 delivered:** Go CLI binary, MIV with cosign/Sigstore Rekor verification, Differential Indexer with SQLite state cache, OpenGrep + ast-grep + instrscan wrappers, Python worker IPC, Finding channel, live HTML dashboard via SSE.

> [!CAUTION]
> Public testing release deadline: **August 6, 2026**.

## Language Coverage

<details>
<summary><b>12 languages · 3 detection axes</b></summary>

| Language | Pattern | Taint | Semantic |
|---|---|---|---|
| Python | ✅ OpenGrep | ✅ Joern | ✅ UniXcoder |
| Java | ✅ OpenGrep | ✅ Joern | ✅ UniXcoder |
| JavaScript / TypeScript | ✅ OpenGrep + ast-grep | ✅ Joern | ✅ UniXcoder |
| Go | ✅ OpenGrep | ✅ Joern† | ✅ UniXcoder |
| Ruby | ✅ OpenGrep + ast-grep | ✅ Joern | ✅ UniXcoder |
| PHP | ✅ OpenGrep + ast-grep | ✅ Joern | ✅ UniXcoder |
| Kotlin | ✅ ast-grep | — | ✅ LLM direct |
| C# | ✅ ast-grep | — | ✅ LLM direct |
| Rust | ✅ ast-grep | — | ✅ LLM direct |
| Swift | ✅ ast-grep | — | ✅ LLM direct |
| Dart | ✅ ast-grep | — | ✅ LLM direct |
| Generic (`.md`, `.mcp.json`) | ✅ OpenGrep + instrscan | — | — |

† Joern Go frontend is community-contributed; CPG quality empirically validated during development.

</details>

## Tech Stack

| Layer | Technology |
|---|---|
| CLI + orchestration | Go — cobra, goroutines, errgroup, Docker dispatch |
| Pattern matching | OpenGrep + ast-grep |
| Taint analysis | Joern CPG Engine |
| ML classifier | UniXcoder (CPU, local Python worker) |
| Structured output | XGrammar-2 constrained decoding |
| LLM runtime | Ollama HTTP API (model-agnostic, GPU passthrough) |
| CVE enrichment | Trivy `fs` subprocess |
| Model verification | cosign / Sigstore Rekor |
| State cache | SQLite — `modernc.org/sqlite` (pure-Go, no CGo) |
| HTML report | Go `html/template` + `embed`, native EventSource |
| Distribution | Single Go binary — Docker default, `--native` opt-in |

<details>
<summary><b>Repository structure</b></summary>

```
cmd/zerotrust/          CLI entry point — cobra, Docker orchestration, direct execution
pkg/                    cpg/ · ollama/ · sqlite/
internal/
  finding/              Finding struct + channel
  ingestion/            miv/ · diffindex/
  pattern/              opengrep/ · astgrep/ · joern/ · instrscan/ · verifier/
  semantic/             targeting/ · enrichment/ · classifier/ · assembler/ · summarizer/ · budget/ · llmscan/
  dedup/                Dedup + SSVC scoring
  report/               HTML report + patches
  output/               MinimalRenderer + WebRenderer (SSE)
  worker/               Python worker manager (NDJSON IPC)
worker/                 Python ML worker
rules/                  python/ · java/ · generic/ · astgrep/ — 42 rules total
tests/
  fixtures/             bad/ · ok/ · knockout/ — unit-level rule match fixtures
  integration/          demo-app/ · spring-boot-app/ · synthetic/
  corpus/               .gitignored — populated by data pipeline
pipeline/               collectors/ · normalizer/ · labeler/ · notebooks/
docs/                   architecture/ · planning/ · research-papers.md · report-example.html
site/                   SolidJS landing page — https://hoangharry-tm.github.io/ZeroTrust.sh/
```

</details>

## Requirements

**Docker mode (default)**
- Docker Desktop (macOS) or `docker.io` (Linux). The CLI handles `docker pull` and `docker run` transparently.
- Ollama (optional, recommended) — GPU-accelerated LLM inference. Detected automatically and passed through to the container.

**Native mode (`--native`)**
- JDK 19+, Joern, OpenGrep, ast-grep
- Python 3.11+ with worker dependencies (`pip install -r worker/requirements.txt`)

## Contributing

ZeroTrust.sh is in active development toward the **August 6, 2026** public testing release. Highest-leverage contributions:

- **Rules** — new OpenGrep or ast-grep rules for AI-specific patterns. See [`rules/`](rules/) and [`tests/fixtures/`](tests/fixtures/).
- **Test codebases** — vulnerable-by-design samples in Kotlin, Dart, Swift.
- **Bug reports** — open an issue with rule ID, input, and whether it was FP or FN.

Before submitting a rule PR: run `make test` and confirm 0 FP on clean controls.

---

<div align="center">

**Docs:** [Architecture](docs/architecture/detail.md) · [Implementation Plan](docs/planning/implementation-plan.md) · [Research Papers](docs/research-papers.md) · [Report Mockup](docs/report-example.html)

**Website:** [hoangharry-tm.github.io/ZeroTrust.sh](https://hoangharry-tm.github.io/ZeroTrust.sh/)

Apache 2.0

</div>
