# ZeroTrust.sh — AI Codebase Security Scanner

Local, privacy-first CLI SAST vulnerability scanner. Performs comprehensive, full-codebase source code security analysis for a complete spectrum of logic, semantic, and structural flaws, outputting interactive HTML reports with unified diff patches.

## Tech Stack & Architecture

- **Orchestration & CLI (Go):** Single binary, parallel dispatch, Trivy enrichment, dedup, HTML report (`cmd/zerotrust/`, `internal/`).
- **ML & Semantic Engine (Python):** CodeT5+ (`Salesforce/codet5p-220m` fine-tuned on CVEFixes), XGrammar-2, LangGraph 3-agent ensemble, Threat Feature Extractor (`worker/`).
- **Data Flow & Escalation:** Ingestion (Integrity Verifier + Differential Indexer) tracks AST changes for ultra-fast incremental routing on massive codebases. Passes to Parallel Detection (Path A: Fast rules + Path B: 3-tier cost funnel/Classifier/LLM semantic check) for exhaustive deep analysis.
- **Inter-process Communication:** Newline-delimited JSON (moving to gRPC).
- **LLM Layer:** Ollama HTTP API (`localhost:11434`), `llama-cpp-python` in worker.

## Project Structure

- `cmd/zerotrust/` - CLI entrypoint
- `internal/` - Go backend logic (ingestion, pattern routing, dedup, reporting)
- `worker/` - Python IPC worker (handlers, CodeT5+ models, schemas)
- `rules/`, `docs/` - Supporting rules and documentation

## Token Optimization & Navigation Guidelines

- **Native Navigation:** Use native grep and line-range reading (`offset`/`limit`) instead of loading whole files.
- **Large Logs:** Pipe extensive terminal/command outputs through `mcp__headroom__headroom_compress` when context optimization is required.
