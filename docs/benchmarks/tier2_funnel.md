# Tier 2 Classifier Funnel Stats

**Test codebase**: tests/integration/demo-app
**Model**: microsoft/unixcoder-base-nine (high-recall mode, A-18 pending)
**Date**: 2026-06-24

## Results

| Metric | Value |
|--------|-------|
| Total surfaces | 23 |
| → Dedup (vulnerable) | 0 |
| → Assembler (uncertain/IDOR/unsupported) | 23 |
| → Dismissed (safe) | 0 |
| Escalation rate (dedup+assembler)/total | 100.0% |
| Design target | ≤25% |
| Status | ⚠️ exceeds cap (>25%) |

## Notes

- A-18: CodeT5+ operates in high-recall mode (ThresholdVulnerable=0.80).
  Without CVEFixes fine-tuning, the model rarely commits to "safe" — expect
  a high escalation rate until A-18 is resolved.
- "Surfaces" here are full source files, not CPG function nodes. Real funnel
  stats (post-ML3.1) will be lower once Heuristic Targeting pre-filters to
  ~5% of files before the classifier runs.
- Unsupported-language files (.rs, .kt, .swift, .cs) are counted in
  ToAssembler with BypassedClassifier=true.
