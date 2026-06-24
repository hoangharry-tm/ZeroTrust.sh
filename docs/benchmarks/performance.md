# Performance Benchmark

**Date**: 2026-06-24  
**Binary**: `build/zerotrust` (go build -o, no additional optimisation flags)  
**Mode**: `--native` (Path A: OpenGrep + ast-grep + instrscan; Path B: skipped, no Joern)  
**Machine**: macOS Darwin 25.3.0 (Apple Silicon)

## Spring Boot Test App (240 LOC Java)

| Run | Wall-clock | Peak RSS | Findings |
|---|---|---|---|
| Cold (first scan, DI cache empty) | **3.7s** | **111 MB** | 24 raw → 10 after dedup |
| Warm (DI cache hit, no changed files) | **2.2s** | **22 MB** | 0 (no delta) |

Cold scan breakdown (approximate):
- Ingestion (MIV + DI): ~0.5s
- CPG build attempt (non-fatal skip): ~0.3s
- Path A (OpenGrep + ast-grep parallel): ~2.5s
- Dedup + SSVC scoring: ~0.1s
- Report render: ~0.1s

Warm scan peak RSS is dramatically lower (22 MB vs 111 MB) because OpenGrep and ast-grep are never invoked — the DI changeset is empty.

## Notes on 5K LOC Target

The `tests/integration/synthetic/` directory contains ~1,044 LOC across Python + Node.js apps. A dedicated 5K LOC synthetic codebase was not generated for this milestone. Based on the linear scaling observed in previous benchmarks (`docs/benchmarks/latency_path_a.md`), estimated cold scan at 5K LOC:

| LOC | Estimated wall-clock | Estimated peak RSS |
|---|---|---|
| 240 (measured) | 3.7s | 111 MB |
| 1,044 (synthetic) | ~8s | ~180 MB |
| 5,000 (estimate) | ~25–35s | ~300–400 MB |

These are linear extrapolations. Actual performance depends on rule match density and OpenGrep subprocess overhead per file.

## Path B Impact (with Joern)

When Joern CPG is available (`--joern-bin`), Path B adds:
- CPG build: +10–30s (one-time; cached on warm scans)
- Targeting + enrichment: +2–5s
- LLM scan (Ollama, llama3.2): +30–120s depending on surface count and `--token-cap`

Total cold scan with Path B enabled: **~60–180s** on a 5K LOC codebase.
