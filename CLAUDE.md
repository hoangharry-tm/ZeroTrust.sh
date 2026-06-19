# ZeroTrust.sh — AI Codebase Security Scanner

Local, privacy-first CLI scanner for codebases modified by AI coding agents. Accepts a directory path, runs deep on-device security analysis, outputs an interactive HTML report with patch suggestions.

## Core Problem

AI coding agents generate functional code at speed but introduce vulnerabilities — hallucinated packages, prompt injection risks, degraded security controls. Traditional SAST tools require cloud upload, are too slow for agent loops, and weren't designed for AI-specific threat vectors.

## Key Features

- **Local & offline** — source code never leaves the machine; no VCS dependency required
- **AI-specific detection** — hallucinated packages, bypass comments, TODO-then-skip, security-node disappearance, prompt injection in AI agent config files (`.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, MCP configs) — no competitor scans this surface
- **Model Integrity Verifier** — cosign/Sigstore Rekor signed registry; WARN for unrecognized models, BLOCK on hash mismatch; gates LLM calls only
- **Security regression detection** — Differential Indexer tracks auth/validate/check AST nodes; security-control removal triggers Path B escalation
- **Dual-path engine** — Path A (pattern, fast) runs in parallel with Path B (semantic, three-tier funnel); neither gates the other
- **Three-tier cost funnel** — Heuristic Targeting → UniXcoder classifier (CPU) → bounded LLM; ~95% file elimination target; budget-exhausted surfaces emit SUPPRESSED, never silent drop
- **SSVC-aligned output** — BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED mapped to Exploitation/Automatable/Technical Impact; cross-path boost +15pp
- **HTML report + patches** — self-contained dashboard with unified diff patches per finding

> **A-18 blocking dependency**: UniXcoder F1 measured on BigVul C/C++ — not valid for Python/Java/JS/Go. CVEFixes benchmark required before publishing accuracy figures.

## Architecture

Two parallel detection paths (Path A + Path B) preceded by an integrity-checked ingestion layer. Full spec: `docs/architecture/cascading_intelligence.mmd` · `docs/architecture/detail.md`

**INGEST** — MIV + Differential Indexer run in parallel at startup. DI passes only changed files (+ one-hop CPG expansion), cutting repeat-scan cost ~80–95%. CPG serialized to `~/.zerotrust/{project_id}.cpg`; repeat scans apply depth-5 BFS patch from each changed function (hub fallback: ≥50 callers → full rebuild).

**Path A — Pattern Detection**: OpenGrep + ast-grep + Joern CPG taint analysis run in parallel. LLM Verifier (CoD + SCoT + XGrammar-2) filters FPs; high-confidence rules bypass directly to Dedup.

**Path B — Semantic Detection**: Heuristic Targeting (CPG surface selection) → CVE enrichment (Trivy) + resource ID dataflow (BOLAZ zero-trust model) → UniXcoder classifier → Call Chain Assembler (depth-3, callee-first) → Threat Feature Extractor (union schema: `taint_flow`/`auth_guard`/`logic_flaw`, batch-5, XGrammar-2 TagDispatch) → Token Budget Controller → LLM Semantic Scan (bounded ReAct, max 3 steps). Scan Security Context Store accumulates inferences across surfaces for cross-surface detection.

### Phased Implementation

| Phase | Delivers |
|---|---|
| **Approach 1** — OpenGrep PoC | OpenGrep/ast-grep rules, AI agent instruction file scanner (Unicode + keyword + MCP schema), fake Spring Boot testbed, CLI demo |
| **Approach 2** — Hybrid AST + Local LLM | Go engine, MIV, DI, Path B classifier + LLM scan, HTML report, patches |
| **Approach 3** — Agentic Scanner | LangGraph 3-agent ensemble (Recon → Exploit → Verify), Threat Feature Extractor, Docker PoE sandbox, BOLAZ IDOR tracking |

## Tech Stack

> **ADR-001 (2026-06-11): Go + Python. Rust deferred.**

| Layer | Language |
|---|---|
| CLI, orchestration, parallel path dispatch, Trivy, HTML report, dedup | **Go** |
| UniXcoder (PyTorch), XGrammar-2, LangGraph, Threat Feature Extractor | **Python** |

- **Go module**: `github.com/hoangharry-tm/zerotrust`
- **IPC**: Go spawns long-lived Python worker (`worker/main.py`); newline-delimited JSON (Approach 3: local gRPC)
- **LLM runtime**: Ollama HTTP API (`localhost:11434`); llama-cpp-python in Python worker
- **Distribution**: Single Go binary (`cmd/zerotrust`). Default: Docker mode (orchestrates engine image). `--native` flag for direct local execution.
- **Build**: `make build` · **Test**: `make test` · **Demo**: `make demo`

## Codebase

```
cmd/zerotrust/          CLI entry point (cobra; Docker orchestration + direct execution)
pkg/cpg/                Shared CPG Graph interface
pkg/ollama/             Ollama HTTP client
pkg/sqlite/             SQLite state cache (modernc.org/sqlite)
internal/finding/       Finding struct + Channel (locked pipeline interface)
internal/ingestion/
  miv/                  Model Integrity Verifier
  diffindex/            Differential Indexer
internal/pattern/       Path A
  opengrep/             OpenGrep subprocess wrapper
  astgrep/              ast-grep subprocess wrapper
  joern/                Joern CPG HTTP client
  instrscan/            AI agent instruction file scanner
  verifier/             LLM Verifier
internal/semantic/      Path B
  targeting/            Heuristic Targeting
  enrichment/           Call Graph + CVE + Resource ID dataflow
  classifier/           UniXcoder IPC bridge
  assembler/            Call Chain Context Assembler (depth-3)
  summarizer/           Threat Feature Extractor IPC bridge
  budget/               Token Budget Controller
  llmscan/              LLM Semantic Scan
internal/dedup/         Dedup + SSVC confidence scoring
internal/report/        HTML report + patches
internal/output/        Output system (Renderer interface, Event bus)
  minimal.go            MinimalRenderer — plain text, CI/pipe safe
  web/                  WebRenderer — live HTML dashboard via SSE
    renderer.go         HTTP server, URL print, event fan-out
    sse.go              SSE hub (register/broadcast/drain)
    events.go           output.Event → named SSE event + HTML fragment
    ui/index.html       Embedded dashboard (native EventSource, no framework)
internal/worker/        Python worker manager (NDJSON IPC, restart)
worker/main.py          NDJSON dispatcher
worker/handlers/        llm_verify · classify · summarize · llm_scan
worker/models/          UniXcoder wrapper · XGrammar-2 enforcer
worker/schemas/         Pydantic wire schemas
rules/python/           PY-001–017 OpenGrep rules
rules/java/             JV-001–009 OpenGrep rules
rules/generic/          AI agent instruction file rules + Go stub detection
rules/astgrep/          ast-grep rules (Rust, Kotlin, C#, Dart gaps)
testdata/spring-boot-app/   Fake Spring Boot REST API
testdata/rules-tests/       Must-fire / must-not-fire test cases
docker/engine/          Engine Docker image (multi-stage)
docker/sandbox/         PoE sandbox (seccomp + Dockerfile)
docs/architecture/      Mermaid diagrams + narrative specs
docs/design/            UI/UX prototypes (web-ui-preview.html, report-example.html, cli-output-design.md)
docs/engineering/       Integration reference notes (Joern DSL tips, Joern HTTP API)
docs/planning/          Implementation plan + status diagram
docs/presentations/     Tech-lead presentation materials
docs/rules/             Rule rationale and selling points
```

## Status

- [x] Architecture finalized (Cascading Intelligence Pipeline, fully specified)
- [x] Repository initialized — `go build ./...` clean
- [x] **Approach 1 in progress** — M1 complete; M2/M3 rules in progress; deadline 2026-06-20
- [x] Deployment model finalized — single binary with Docker (default) and --native modes
- [ ] Core engine (Approach 2 starts 2026-06-23)
- [ ] Rule engine + YAML ruleset
- [ ] Local LLM integration
- [ ] HTML report generator

**Implementation plan**: `docs/planning/implementation-plan.md` · **Research**: `docs/research-papers.md`

## GitHub

Repository: <https://github.com/hoangharry-tm/ZeroTrust.sh>
