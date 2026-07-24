<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/diagrams/logo-dark.svg">
  <img src="docs/architecture/diagrams/logo-light.svg" alt="ZeroTrust.sh" width="380">
</picture>

<p align="center">
  <strong>A privacy-preserving SAST that catches semantic and logic-level flaws at elevated frequency in AI-assisted codebases.</strong><br>
  Static analysis always runs locally. LLM reasoning can run locally (Ollama) or against a hosted API — your choice.
</p>

[![Website](https://img.shields.io/badge/website-%23C2410C.svg?logo=githubpages&logoColor=white)](https://hoangharry-tm.github.io/ZeroTrust.sh/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26+-00ADD8.svg?logo=go)](go.mod)
[![Status](https://img.shields.io/badge/status-active%20development-orange)]()

---

**[Website](https://hoangharry-tm.github.io/ZeroTrust.sh/) · [Architecture](docs/architecture.md) · [Live Report Demo](https://hoangharry-tm.github.io/ZeroTrust.sh/report.html)**

</div>

## The Problem

AI coding agents (Cursor, Cline, Aider, GitHub Copilot Workspace) generate syntactically plausible code without reasoning about security context. The result: standard semantic and logic-level flaws — IDOR, missing auth checks, business logic bypasses — appear at higher base rates. AI-generated code is a risk amplifier, not a new vulnerability class.

ZeroTrust.sh is an upgraded SAST: it scans **source code** for real, exploitable flaws regardless of authorship. The developer decides what's intentional.

<details>
<summary><b>Phantom dependencies (slopsquatting)</b></summary>

Your dependency manifest imports <code>requests-auth-aws</code> — a package that doesn't exist. An attacker registers it with a payload. No CVE list will catch this yet.

ZeroTrust.sh flags phantom imports in <code>go.mod</code>, <code>requirements.txt</code>, <code>pom.xml</code>, and <code>package.json</code> before they reach production.
</details>

<details>
<summary><b>Security regression detection</b></summary>

An auth check is present in commit N, silently absent in commit N+1. Functional tests still pass. No diff alert fires.

The Differential Indexer tracks auth/validate/sanitize AST nodes across scans; removal triggers deep semantic analysis.
</details>

<details>
<summary><b>Deep semantic taint analysis</b></summary>

Pattern-only tools miss logic-level flaws: SSRF through indirect calls, IDOR in non-obvious data flows, broken auth that passes unit tests.

ZeroTrust.sh's Reasoning runs CPG-based surface selection + LLM reasoning with static evidence injected into the prompt, to surface what regex can't.
</details>

## Quickstart

Scored findings are persisted to Postgres — there's no HTML/JSON report or CLI dashboard. Point `--db-url` (or `$DATABASE_URL`) at a running Postgres instance and query the `findings`/`scan_runs` tables directly.

```bash
# Install (single static binary)
go install github.com/hoangharry-tm/zerotrust/cmd/zerotrust@latest

# Scan a project — local Ollama by default
zerotrust scan ~/my-project --db-url postgres://user:pass@localhost:5432/zerotrust

# Scan using a hosted LLM provider instead
zerotrust scan ~/my-project --llm-provider openai --model gpt-4o --db-url postgres://...

# Query results directly
psql "$DATABASE_URL" -c "select cwe, severity, file_path, line_start from findings where severity in ('BLOCK','HIGH')"
```

### Try the demo

```bash
git clone https://github.com/hoangharry-tm/ZeroTrust.sh
cd ZeroTrust.sh
go build -o build/zerotrust ./cmd/zerotrust
./build/zerotrust scan tests/integration/demo-app/
```

## Architecture

Two independent detection paths run in parallel. Neither gates the other. A finding confirmed by both receives a +15pp confidence boost.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture/diagrams/architecture-dark.svg">
  <img src="docs/architecture/diagrams/architecture-light.svg" alt="ZeroTrust.sh architecture — two parallel detection paths">
</picture>

**Deterministic — fast, rule-based.** OpenGrep + ast-grep pattern matching. Joern CPG inter-file taint analysis. LLM Verifier filters false positives. High-confidence rules bypass the verifier directly to Dedup.

**Reasoning — semantic.** CPG-based heuristic targeting (import-boundary BFS, IDOR candidate detection) + Trivy CVE enrichment select surfaces worth deeper analysis. A lightweight triage pass drops low-signal surfaces; the rest get full LLM analysis with static evidence (security contract, control-flow predicate, AI-failure profile) injected into the prompt, plus a self-consistency re-check on high-confidence exploitable findings.

> [!IMPORTANT]
> **Differential Indexer** — content-hash snapshot in Postgres. Repeat scans process only changed files + one-hop CPG neighbours.
>
> **Model Integrity Verifier** — cosign/Sigstore Rekor-signed registry. `WARN` on unrecognized models, `BLOCK` on hash mismatch. Gates LLM calls only — pattern + CPG analysis unaffected.

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline detail.

## Severity Levels

| Severity | Meaning |
|---|---|
| 🔴 **BLOCK** | Exploitation imminent — patch immediately |
| 🟡 **HIGH** | Likely exploitable — high priority |
| 🔵 **MEDIUM** | Conditional or chained exploit path |
| ⚪ **LOW** | Best practice violation, low risk |

## Tech Stack

| Layer | Technology |
|---|---|
| CLI + orchestration | Go — cobra, goroutines, errgroup |
| Pattern matching | OpenGrep + ast-grep |
| Taint analysis | Joern CPG Engine (`internal/cpg_engine`) |
| LLM layer | Provider-agnostic (`pkg/llm`) — Ollama (default) or OpenAI-compatible API |
| CVE enrichment | Trivy `fs` subprocess |
| Model verification | cosign / Sigstore Rekor |
| Findings + state store | Postgres — GORM (`gorm.io/gorm`) + raw `pgx`/`pgxpool` for CPG bulk ingest |
| Distribution | Single native Go binary |

See [`CLAUDE.md`](CLAUDE.md) for the full repository structure and architecture rationale.

## Requirements

- JDK 19+, Joern, OpenGrep, ast-grep for local execution — the binary runs natively, no bundled Docker path
- A running Postgres instance (`--db-url` or `$DATABASE_URL`) — required, this is where scan results live
- Ollama, if using the default local LLM provider — or an API key for `--llm-provider openai`
- Docker, only if using `--verify-poc --poe-artifact <path>` (opt-in, grey-box: supply an already-built jar/bundled JS/Python script/native binary — Java, Python, JavaScript/TypeScript, and Go are supported)

## Contributing

ZeroTrust.sh is in active development. Highest-leverage contributions:

- **Rules** — new OpenGrep or ast-grep rules for AI-specific patterns. See [`docs/rules/`](docs/rules/).
- **Test codebases** — vulnerable-by-design samples in underrepresented languages (Kotlin, Dart, Swift).
- **Bug reports** — open an issue with rule ID, input, and whether it was a false positive or false negative.

Before submitting a rule PR: run `make test` and confirm 0 FP on clean controls.

---

<div align="center">

**Docs:** [Architecture](docs/architecture.md) · [CLAUDE.md](CLAUDE.md) · [Research Papers](docs/research-papers.md) · [Live Report Demo](https://hoangharry-tm.github.io/ZeroTrust.sh/report.html)

**Website:** [hoangharry-tm.github.io/ZeroTrust.sh](https://hoangharry-tm.github.io/ZeroTrust.sh/)

Apache 2.0

</div>
