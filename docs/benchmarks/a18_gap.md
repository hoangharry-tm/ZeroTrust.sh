# A-18 Gap Measurement — Classifier Multi-Language F1 (UniXcoder → CodeT5+ transition)

**Status: PENDING** — Run `python scripts/benchmarks/a18_eval.py` to populate.

---

## Context

The CodeT5+ model's commonly cited F1=94.73% was measured on the
**BigVul C/C++ dataset only**. ZeroTrust.sh targets Python, Java, JavaScript,
TypeScript, and Go — none of which are in BigVul's primary evaluation corpus.

This document records the measured F1/precision/recall on the 50-snippet
A-18 evaluation dataset (`tests/a18-eval/`) and the gap vs the BigVul baseline.

**A-18 blocking rule**: Do not publish F1 claims or tighten classifier
thresholds until the per-language numbers below have been filled in.

---

## Dataset

| Metric | Value |
|--------|-------|
| Total snippets | 50 |
| Vulnerable | 25 |
| Safe | 25 |
| Languages | Python, Java, Go, JavaScript |
| Source | AI-agent-generated patterns typical of ZeroTrust.sh targets |
| Location | `tests/a18-eval/snippets/` |

Snippets were written manually to represent realistic AI coding agent output:
SQL injection via f-strings, command injection via `shell=True`, path traversal
without normalization, hardcoded secrets, IDOR without ownership checks,
insecure deserialization, and their secure counterparts with parameterized
queries, allowlists, ownership checks, and env-var secrets.

---

## Results

> **Not yet measured.** Run the eval script and paste the table here.

```
python scripts/benchmarks/a18_eval.py
```

Expected output format:

| Language   |  TP |  FP |  FN |  TN | Precision | Recall |    F1 |
|------------|-----|-----|-----|-----|-----------|--------|-------|
| go         |   — |   — |   — |   — |         — |      — |     — |
| java       |   — |   — |   — |   — |         — |      — |     — |
| javascript |   — |   — |   — |   — |         — |      — |     — |
| python     |   — |   — |   — |   — |         — |      — |     — |
| **OVERALL**|   — |   — |   — |   — |         — |      — |     — |

**BigVul C/C++ baseline: F1=0.947** ← not valid for the languages above.

---

## Interpretation

The classifier runs in **high-recall mode** (ThresholdVulnerable=0.80,
ThresholdSafe=0.20). "Uncertain" predictions are treated as vulnerable for
the F1 calculation — false negatives are more costly than false positives in
a security scanner.

A per-language F1 below **0.65** indicates the model is not reliably detecting
vulnerabilities in that language at the current threshold. The recommended
remediation is QLoRA fine-tuning on the CVEFixes dataset (see
`docs/planning/implementation-plan.md` §A-18 Resolution).

---

## Gap Analysis

| Claim | Status |
|-------|--------|
| BigVul C/C++ F1=94.73% reproduced | Not tested (C/C++ not in scope) |
| Python F1 ≥ 0.80 | **Pending measurement** |
| Java F1 ≥ 0.80 | **Pending measurement** |
| JavaScript F1 ≥ 0.80 | **Pending measurement** |
| Go F1 ≥ 0.80 | **Pending measurement** |

Until these are measured and confirmed, all accuracy claims must include the
caveat: *"F1 measured on BigVul C/C++ only; multi-language accuracy pending
CVEFixes evaluation."*

---

## Remediation Path (if F1 < 0.80)

1. Download CVEFixes SQLite DB and filter function-level samples.
2. QLoRA fine-tune `microsoft/unixcoder-base-nine` per language (rank=16,
   alpha=32, target query+value, 5 epochs, ~30–90 min/language on A40).
3. Raise `ThresholdVulnerable` from 0.80 → empirically validated value.
4. Re-run this eval and update the table above.

Full plan: `docs/planning/implementation-plan.md` §[BONUS] R&D — A-18 Resolution.
