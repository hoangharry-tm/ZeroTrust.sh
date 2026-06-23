# ZeroTrust.sh — Product Analysis Workspace

## Project Summary

ZeroTrust.sh is a local, privacy-first CLI security scanner and automated patch engine purpose-built for auditing codebases produced by AI coding agents (Cursor, Cline, Aider, Copilot Workspace). It accepts a directory path or ZIP archive, performs deep static and semantic security analysis entirely on-device, and outputs a self-contained interactive HTML vulnerability report with unified diff patch suggestions. The analysis phase is currently in progress: three distinct architectural approaches are under evaluation, and no implementation decisions have been made. This folder contains all research, proposals, benchmarks, and decision artifacts needed for tech-lead review and approach selection.

---

## Folder Map

| Folder | Purpose | Status |
|---|---|---|
| `notebooks/` | Jupyter notebooks for interactive technical deep dives, benchmarks, and visual analysis | Active |
| `research/` | All external research: user interviews, competitor teardowns, market sizing, GTM analysis | Active |
| `research/user_interviews/` | Raw interview notes, transcripts, and synthesized summaries from developer conversations | Pending |
| `research/competitor_teardown/` | Per-competitor teardown notes and aggregated feature comparison matrix | Pending |
| `research/market_analysis/` | Market sizing, TAM/SAM/SOM, GTM strategy, positioning maps | Active (legacy migrated) |
| `specs/` | All product and technical specifications | Active |
| `specs/architecture/` | Architecture diagrams, reference documents, and Architecture Decision Records (ADRs) | Active (legacy migrated) |
| `specs/architecture/adr/` | Formal ADR files (not yet written — no decisions made) | Stub |
| `specs/features/` | Feature-level specifications and acceptance criteria | Stub |
| `specs/proposals/` | Architectural approach proposals (3 competing approaches under evaluation) | Active |
| `data/` | Quantitative evidence: benchmark results, registry data, evidence citations | Pending |
| `data/benchmark_results/` | LLM accuracy benchmarks, scan speed measurements, VRAM profiling | Pending |
| `data/evidence/` | Raw citations, screenshots, links, data exports supporting research claims | Pending |
| `decisions/` | Assumptions register, risk registry, and future decision records | Active |
| `presentations/` | Slide decks, exports, and visual assets for stakeholder reviews | Stub |

---

## How to Use This Workspace

### Open JupyterLab

All notebooks are in `notebooks/`. To open JupyterLab with the project environment:

```bash
cd /Users/hoangharry/mh_code/internships/VNG_ZingPlayStudio/ZeroTrust.sh/admin/product_analysis
uv run jupyter lab
```

### Find Content by Type

| I want to... | Go to... |
|---|---|
| Understand the project and navigation | This file (`README.md`) |
| See every document with its status | `INDEX.md` |
| Restore full session context (for AI assistants) | `MEMORY.md` |
| Read the architecture proposals | `specs/proposals/` |
| Check competitor analysis | `research/competitor_teardown/` |
| Review market sizing and GTM | `research/market_analysis/` |
| Find evidence and citations | `data/evidence/` |
| Check current assumptions | `decisions/assumptions.md` |
| Review the risk register | `decisions/risk_registry.md` |
| View or run interactive analysis | `notebooks/` |

### Key Conventions

- Files prefixed `LEGACY_` are migrated from the original flat-file structure. They contain useful historical context but have not been refactored into the current proposal format.
- Files in `decisions/` track what is *assumed* and what is *at risk* — not what has been decided. ADRs (Architecture Decision Records) will be written in `specs/architecture/adr/` only after approach selection.
- `MEMORY.md` is a special file maintained for Claude Code sessions. It provides a full context map so any new AI session can immediately orient itself without re-reading the entire workspace.

---

*Last updated: 2026-06-08*
