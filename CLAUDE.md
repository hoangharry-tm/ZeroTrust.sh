# ZeroTrust.sh — AI Codebase Security Scanner

## Idea Summary
ZeroTrust.sh is a local, privacy-first CLI security scanner and patch engine designed to audit codebases modified by AI coding agents. It accepts a codebase directory path or ZIP archive as input, performs deep security analysis entirely on-device, and outputs an interactive HTML vulnerability report with patch suggestions.

## Core Problem
AI coding agents (Cursor, Cline, Aider, Copilot Workspace) generate functional code at high speed but frequently introduce security vulnerabilities — including package hallucinations (slopsquatting), indirect prompt injection risks, and degraded security controls. Traditional cloud SAST tools (Snyk, SonarQube, CodeRabbit) require uploading source code externally, are too slow for real-time agent loops, and were never designed to detect AI-specific threat vectors.

## Key Features
- **Local & Offline Execution**: Source code never leaves the developer's machine.
- **ZIP or Directory Input**: Flexible ingestion layer — no VCS dependency.
- **AI-Specific Threat Detection**: Detects hallucinated packages, security control bypasses, and prompt injection in comments.
- **Hybrid Analysis Engine**: Fast AST rule-based pre-filter combined with a local quantized LLM for semantic verification and false-positive reduction.
- **HTML Report Output**: Generates an interactive, self-contained HTML vulnerability dashboard.
- **Patch Suggestions**: Outputs unified Git diff patches for each confirmed vulnerability.

## Architecture Approach (Selected: Hybrid Heuristic + Local LLM)
1. **Stage 1 — Fast Static AST Filter**: Uses Tree-sitter to scan code for structural vulnerability patterns (high recall).
2. **Stage 2 — Local LLM Semantic Verification**: Routes flagged snippets to a local GGUF model (e.g., Qwen2.5-Coder-7B or Llama-3-8B via Ollama/llama.cpp) for false-positive filtering and contextual patch generation.
3. **Report Generation**: Produces a standalone, interactive HTML dashboard.

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
Repository: https://github.com/hoangharry-tm/ZeroTrust.sh
