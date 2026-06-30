# ZeroTrust.sh — AI Codebase Security Scanner
Local, privacy-first CLI SAST vulnerability scanner. Performs comprehensive, full-codebase source code security analysis for a complete spectrum of logic, semantic, and structural flaws, outputting interactive HTML reports with unified diff patches.

## Tech Stack & Architecture
- **Orchestration & CLI (Go):** Single binary, parallel dispatch, Trivy enrichment, dedup, HTML report (`cmd/zerotrust/`, `internal/`).
- **ML & Semantic Engine (Python):** CodeT5+ (`Salesforce/codet5p-220m` fine-tuned on CVEFixes), XGrammar-2, LangGraph 3-agent ensemble, Threat Feature Extractor (`worker/`).
- **Data Flow & Escalation:** Ingestion (Integrity Verifier + Differential Indexer) tracks AST changes for ultra-fast incremental routing on massive codebases. Passes to Parallel Detection (Path A: Fast rules + Path B: 3-tier cost funnel/Classifier/LLM semantic check) for exhaustive deep analysis.
- **Inter-process Communication:** Newline-delimited JSON (moving to gRPC).
- **LLM Layer:** Ollama HTTP API (`localhost:11434`), `llama-cpp-python` in worker.

## Commands
- **Build Core Binary:** `make build` (outputs to `build/zerotrust`)
- **Unit & Package Tests:** `make test` (uses `gotestsum`)
- **Rule Engine Tests:** `make test-rules` (runs OpenGrep validations)
- **Full Integration Scan:** `make run-integration` (wipes caches, builds, and executes end-to-end scan against Spring Boot testbed app with verbose Joern routing)
- **Graph/Joern Go Integration Tests:** `make test-integration` (runs race-detector enabled Go tests with 10m timeout against `./internal/pattern/joern/...`)
- **Verify Joern Setup:** `make joern-check`
- **Execute Raw Scan:** `zerotrust scan <dir> --native --report report.html`

## Project Structure
- `cmd/zerotrust/` - CLI entrypoint
- `internal/` - Go backend logic (ingestion, pattern routing, dedup, reporting)
- `worker/` - Python IPC worker (handlers, CodeT5+ models, schemas)
- `rules/`, `tests/`, `docs/`, `pipeline/` - Supporting rules and testbeds

## Token Optimization & Navigation Guidelines
- **Native Navigation:** Use native grep and line-range reading (`offset`/`limit`) instead of loading whole files.
- **Large Logs:** Pipe extensive terminal/command outputs through `mcp__headroom__headroom_compress` when context optimization is required.
- **GitNexus Status:** Local indexing active (5k+ symbols, 10k+ relations). If indexing is required/stale, run: `node .gitnexus/run.cjs analyze` (or `npm i -g gitnexus` if npm 11 crashes). Before editing critical symbols, manually trace upstream blast radius using native search.
