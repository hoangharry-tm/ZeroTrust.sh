# Path A Latency Benchmark — L2.2.T5

**Date**: 2026-06-22  
**Target**: p50 verifier round-trip < 2 s per finding  
**Result**: ❌ MISSED — p50 ≈ 21 s (bottleneck: LLM inference on CPU/GPU)

---

## Test Environment

| | |
|---|---|
| Hardware | Apple M3, 16 GB RAM |
| OS | macOS Darwin 25.3.0 arm64 |
| LLM model | `qwen2.5-coder:7b` (4.7 GB, Ollama) |
| Joern | NOT running (connection refused — CPG taint disabled) |
| Testbed | `testdata/spring-boot-app` (10 files, 7 Java source files in scope) |
| Scans run | 3 back-to-back with unique project IDs (fresh baseline each) |

---

## Results

### Wall-clock per scan (full pipeline)

| Scan | Wall-clock | Notes |
|------|-----------|-------|
| 1 (cold model) | 40.6 s | `qwen2.5-coder:7b` loaded cold into Ollama |
| 2 (warm) | 26.4 s | |
| 3 (warm) | 23.6 s | |

### Path A breakdown (12 findings per scan)

- **10 findings** — confidence ≥ 0.90, bypassed LLM verifier directly
- **2 findings** — sent to LLM Verifier (CoD + SCoT + ASC)

### LLM Verifier latency (2 concurrent findings per scan)

The metric logged as `verifier latency ms` is `batch_elapsed / finding_count`. Since the
two findings are processed concurrently via `errgroup` fan-out, the logged value
≈ half the actual per-finding round-trip. True per-finding LLM time ≈ `logged_ms × 2`.

| Scan | Logged ms (batch÷2) | True per-finding est. |
|------|--------------------|-----------------------|
| 1 (cold) | 18,470 ms | ~36,940 ms |
| 2 (warm) | 10,650 ms | ~21,300 ms |
| 3 (warm) | 9,715 ms | ~19,430 ms |

**p50 (true per-finding)**: ~21,300 ms  
**p95 (true per-finding)**: ~36,940 ms  
**Target < 2,000 ms**: ❌ MISSED by ~10×

---

## Bottleneck Analysis

The dominant cost is **Ollama TTFT + generation time** for `qwen2.5-coder:7b` on Apple
M3. The CoD + SCoT prompt with full matched-code context triggers a multi-step CoT
response; Ollama processes this on the Neural Engine / GPU, but 7B parameter models
still take 10–37 s per call on this hardware.

Breakdown of 26 s wall-clock (warm scan):
- Python worker startup: ~0 s (already warm, reused across findings)
- OpenGrep scan (7 Java files): ~0.5 s
- LLM Verifier (2 findings, concurrent): **~21 s**
- Dedup + report template: < 0.1 s

---

## Caveats

1. **Only 2 of 12 findings went through the LLM verifier** — the other 10 bypassed at
   ≥ 0.90 confidence. In codebases with fewer high-confidence rule matches, more
   findings would hit the verifier, increasing total scan time.

2. **Joern was not running** — CPG taint analysis was disabled. Joern findings would
   add to the verifier queue.

3. **HTML report rendering fails** — a template error (`can't evaluate field Reason
   in type finding.Finding`) prevents the report from being written. This does not affect
   latency measurement but indicates a template/struct mismatch to fix.

4. **Model size matters** — `qwen2.5:3b` (the default before this benchmark) would be
   ~2× faster; `qwen2.5-coder:7b` prioritises code reasoning over speed.

---

## Next Steps

- **TODO**: Replace or cache the LLM call for high-repetition CWE patterns (e.g.
  CWE-798 hardcoded credentials are deterministic; they could bypass the verifier at a
  lower confidence threshold than 0.90).
- **Option A**: Lower `HighConfidenceThreshold` from 0.90 → 0.80 for CWE-798/CWE-352
  rules that have near-zero empirical FP rates.
- **Option B**: Run `qwen2.5:3b` for the verifier (speed) and `qwen2.5-coder:7b` only
  for the LLM Scan (Path B Tier 3).
- **Option C**: Batch all findings into a single Ollama call with TagDispatch instead of
  one call per finding — already planned for Path B Tier 3 (Threat Feature Extractor).
