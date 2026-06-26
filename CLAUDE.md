# ZeroTrust.sh — AI Codebase Security Scanner

Local, privacy-first CLI vulnerability scanner. Accepts a directory path, runs deep on-device source code security analysis, outputs an interactive HTML report with patch suggestions.

## Core Problem

AI coding assistants ship code faster and at higher volume — so vulnerabilities appear faster and in larger numbers. Traditional SAST tools require cloud upload, are too slow for developer loops, and lack the semantic depth to catch logic-level flaws. ZeroTrust.sh is an upgraded SAST: it scans source code for real, exploitable vulnerabilities and reports them with proof of exploitation. The developer decides what's intentional.

## Key Features

- **Local & offline** — source code never leaves the machine; no VCS dependency required
- **Phantom dependency detection** — scans dependency manifests for non-existent or typo-squatted package imports (supply-chain risk)
- **Model Integrity Verifier** — cosign/Sigstore Rekor signed registry; WARN for unrecognized models, BLOCK on hash mismatch; gates LLM calls only
- **Security regression detection** — Differential Indexer tracks auth/validate/sanitize AST nodes; removal of a security-critical function triggers Path B escalation
- **Dual-path engine** — Path A (pattern, fast) runs in parallel with Path B (semantic, three-tier funnel); neither gates the other
- **Three-tier cost funnel** — Heuristic Targeting → UniXcoder classifier (CPU) → bounded LLM; ~95% file elimination target; budget-exhausted surfaces emit SUPPRESSED, never silent drop
- **SSVC-aligned output** — BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED mapped to Exploitation/Automatable/Technical Impact; cross-path boost +15pp
- **HTML report + patches** — self-contained dashboard with unified diff patches per finding

> **A-18 blocking dependency**: UniXcoder F1 measured on BigVul C/C++ — not valid for Python/Java/JS/Go. CVEFixes benchmark required before publishing accuracy figures.

## Architecture

Two parallel detection paths (Path A + Path B) preceded by an integrity-checked ingestion layer. Full spec: `docs/architecture/cascading_intelligence.mmd` · `docs/architecture/detail.md`

**INGEST** — MIV + Differential Indexer run in parallel at startup. DI passes only changed files (+ one-hop CPG expansion), cutting repeat-scan cost ~80–95%. CPG serialized to `~/.zerotrust/{project_id}.cpg`; repeat scans apply depth-5 BFS patch from each changed function (hub fallback: ≥50 callers → full rebuild).

**Path A** — OpenGrep + ast-grep + Joern CPG taint in parallel. LLM Verifier (CoD + SCoT + XGrammar-2) filters FPs; high-confidence rules bypass to Dedup.

**Path B** — Heuristic Targeting → CVE enrichment (Trivy) + BOLAZ dataflow → UniXcoder classifier → Call Chain Assembler (depth-3) → Threat Feature Extractor (batch-5, XGrammar-2 TagDispatch) → Token Budget Controller → LLM Semantic Scan (bounded ReAct, max 3 steps). Scan Security Context Store accumulates inferences for cross-surface detection.

## Phased Implementation

| Phase | Delivers |
|---|---|
| **Approach 1** | OpenGrep/ast-grep rules, AI agent config scanner, Spring Boot testbed, CLI demo |
| **Approach 2** | Go engine, MIV, DI, Path B classifier + LLM scan, HTML report, patches |
| **Approach 3** | LangGraph 3-agent ensemble (Recon→Exploit→Verify), Threat Feature Extractor, Docker PoE sandbox, BOLAZ IDOR tracking |

## Tech Stack

> ADR-001 (2026-06-11): Go + Python. Rust deferred.

| Layer | Language |
|---|---|
| CLI, orchestration, parallel dispatch, Trivy, HTML report, dedup | **Go** |
| UniXcoder (PyTorch), XGrammar-2, LangGraph, Threat Feature Extractor | **Python** |

- Go module: `github.com/hoangharry-tm/zerotrust` · IPC: newline-delimited JSON (Approach 3: gRPC)
- LLM: Ollama HTTP API (`localhost:11434`); llama-cpp-python in Python worker
- Distribution: single Go binary; Docker default, `--native` for direct local execution
- `make build` · `make test` · `make demo`

## Codebase

`cmd/zerotrust/` — CLI entrypoint. `internal/` — all Go logic (ingestion, pattern, semantic, dedup, report, output, worker). `worker/` — Python IPC worker (handlers, models, schemas). Supporting: `rules/`, `tests/`, `pipeline/`, `scripts/`, `docker/`, `site/`, `docs/`, `product/`.

## Status

- [x] Approach 1 — 30+ rules, 0 FPs; AI agent config scanner; Spring Boot testbed
- [x] Approach 2 — Full dual-path engine (ML4.3, 2026-06-24, ~6 weeks early): Path A + Path B + Dedup + HTML report + patches
- [x] `zerotrust scan <dir> --native --report report.html` runs end-to-end
- [x] `make build` · `make test` · `make demo` all pass clean

**Implementation plan**: `docs/planning/implementation-plan.md` · **Research**: `docs/research-papers.md`

## GitHub

Repository: <https://github.com/hoangharry-tm/ZeroTrust.sh>

# Token Optimization

- **Never read entire files** to understand architecture or call hierarchies — use GitNexus MCP tools first (see below).
- When you must read a large file, always supply `offset`/`limit` to load only the relevant lines.
- Use `mcp__headroom__headroom_retrieve` for compressing large logs or extensive command output before processing.

# GitNexus — Code Intelligence

This project is indexed by GitNexus as **ZeroTrust.sh** (4998 symbols, 10079 relationships, 153 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/ZeroTrust.sh/context` | Codebase overview, check index freshness |
| `gitnexus://repo/ZeroTrust.sh/clusters` | All functional areas |
| `gitnexus://repo/ZeroTrust.sh/processes` | All execution flows |
| `gitnexus://repo/ZeroTrust.sh/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **ZeroTrust.sh** (5097 symbols, 10313 relationships, 161 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/ZeroTrust.sh/context` | Codebase overview, check index freshness |
| `gitnexus://repo/ZeroTrust.sh/clusters` | All functional areas |
| `gitnexus://repo/ZeroTrust.sh/processes` | All execution flows |
| `gitnexus://repo/ZeroTrust.sh/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
