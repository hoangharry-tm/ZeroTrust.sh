# ADR-001 — Language Stack: Go + Python

**Status:** Accepted — 2026-06-11  
**Deciders:** Hoang (intern)  
**Context doc:** `product/specs/proposals/tech_stack_analysis.md`

---

## Context

ZeroTrust.sh requires:
- A fast CLI binary with near-zero startup latency (pre-commit tool use case)
- Parallel orchestration of Path A (Semgrep/Joern/ast-grep subprocesses) and Path B (heuristic targeting → classifier → LLM)
- ML inference for UniXcoder-Base-Nine (PyTorch)
- Grammar-constrained LLM output via XGrammar (Python/C++ binding)
- LangGraph multi-agent orchestration in Approach 3
- Single-binary distribution for Approaches 1 and 2
- Native Trivy Go library for CVE enrichment (Approach 3)
- Docker API for PoE sandbox (Approach 3)

Three language candidates were evaluated: **Go**, **Python**, and **Rust**.

---

## Decision

**Use Go + Python as the two-language stack. Rust is deferred.**

| Role | Language | Rationale |
|---|---|---|
| CLI entrypoint, config, arg parsing | Go | Zero-dep, fast startup, single binary |
| Parallel Path A / B dispatch | Go | Goroutines map directly to the two-path model |
| Differential Indexer (file hashing) | Go | Fast native I/O, no overhead |
| External tool invocation (Semgrep, Joern, ast-grep) | Go | `os/exec` orchestration |
| Trivy CVE enrichment | Go | Native Go library — no subprocess needed |
| Docker API (PoE sandbox) | Go | Official Go Docker SDK |
| SSVC deduplication + confidence scoring | Go | Algorithmic; no ML library needed |
| HTML report + patch generation | Go | `html/template` + `embed` |
| UniXcoder classifier (Tier 2) | Python | PyTorch — no Go port exists |
| XGrammar constrained decoding | Python | Python/C++ binding — no Go equivalent |
| LangGraph 3-agent ensemble (Approach 3) | Python | Python-only framework |
| LLMLingua-2 / Token Budget compression | Python | HuggingFace — native Python |
| Threat Feature Extractor | Python | Runs alongside classifier in Python worker |

**Integration boundary:** Go spawns a long-lived Python worker process at scan startup. Communication is via stdin/stdout newline-delimited JSON (or local gRPC for Approach 3). Go orchestrates everything; Python infers.

**Distribution story:** Go binary + bundled Python venv (Approaches 1–2: Go binary is primary deliverable; Python venv activated on first run). Approach 3: Docker image is the primary distribution unit.

---

## Alternatives Considered

### Rust instead of Go
- Does not eliminate Python (no PyTorch/XGrammar/LangGraph equivalent exists in Rust)
- 3–8 minute cold CI build times add friction on a June–August intern timeline
- Performance gains are marginal for an I/O-bound CLI; Go wins on HTTP server workloads
- Deferred: worth revisiting if ZeroTrust.sh matures post-internship and binary size / in-process LLM embedding becomes a priority

### Python-only
- 200–800ms interpreter startup is too slow for a pre-commit hook
- No single-binary distribution story
- Eliminated in favour of Go for the orchestration layer

### Go-only
- Eliminated because UniXcoder, XGrammar, and LangGraph are Python-only; no viable Go ports exist as of 2026

---

## Consequences

- **Positive:** Clean language boundary (orchestration vs inference), proven Go ecosystem for security tooling (Trivy, Gosec), LangGraph unlocks Approach 3 agentic patterns, single Go binary preserves distribution story for Approaches 1–2
- **Negative:** Users need Python installed for ML features; venv bootstrap adds ~5s on first run; two languages means two test suites and two CI jobs
- **Risk:** If XGrammar or LangGraph gain Go support, the Go-only path becomes viable — monitor annually
