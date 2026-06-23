#!/usr/bin/env python3
"""A-18 gap measurement: runs the UniXcoder classifier on 50 labeled snippets.

Usage:
    cd <repo-root>
    uv run --project worker python scripts/benchmarks/a18_eval.py [--labels PATH]

Outputs per-language F1 / precision / recall to stdout.

A-18 note: BigVul F1=94.73% is C/C++ only. This script measures the
multi-language gap that must be closed before accuracy claims can be published.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------

def _args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="A-18 UniXcoder gap measurement")
    p.add_argument(
        "--labels",
        default="tests/a18-eval/labels.json",
        help="Path to labels.json (default: tests/a18-eval/labels.json)",
    )
    p.add_argument(
        "--model",
        default="microsoft/unixcoder-base-nine",
        help="UniXcoder model name (default: microsoft/unixcoder-base-nine)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def _load_classifier(model_name: str):
    # Inline import so the script fails fast if the worker env is not active.
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent.parent / "worker"))
    from models.unixcoder import UniXcoderClassifier  # noqa: PLC0415
    clf = UniXcoderClassifier(model_name=model_name)
    clf.load(device="cpu")
    return clf


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _args()
    labels_path = Path(args.labels)
    if not labels_path.exists():
        print(f"error: labels file not found: {labels_path}", file=sys.stderr)
        sys.exit(1)

    entries = json.loads(labels_path.read_text())
    repo_root = Path(__file__).parent.parent.parent

    clf = _load_classifier(args.model)

    # Per-language counters: {lang: {tp, fp, fn, tn}}
    lang_tp: dict[str, int] = defaultdict(int)
    lang_fp: dict[str, int] = defaultdict(int)
    lang_fn: dict[str, int] = defaultdict(int)
    lang_tn: dict[str, int] = defaultdict(int)

    overall_tp = overall_fp = overall_fn = overall_tn = 0

    for entry in entries:
        file_path = repo_root / entry["file"]
        if not file_path.exists():
            print(f"warning: snippet not found: {file_path}", file=sys.stderr)
            continue
        code = file_path.read_text()
        lang = entry["language"]
        true_label = entry["label"]  # "vuln" or "safe"

        out = clf.classify(code, language=lang)
        # Treat "uncertain" as "vuln" (high-recall mode — no false negatives).
        predicted_vuln = out.label in ("vulnerable", "uncertain")
        actual_vuln = true_label == "vuln"

        if actual_vuln and predicted_vuln:
            lang_tp[lang] += 1
            overall_tp += 1
        elif not actual_vuln and predicted_vuln:
            lang_fp[lang] += 1
            overall_fp += 1
        elif actual_vuln and not predicted_vuln:
            lang_fn[lang] += 1
            overall_fn += 1
        else:
            lang_tn[lang] += 1
            overall_tn += 1

    # ---------------------------------------------------------------------------
    # Print results
    # ---------------------------------------------------------------------------
    print("\n=== A-18 UniXcoder Gap Measurement ===\n")
    print(f"Model: {args.model}")
    print(f"Dataset: {labels_path}  ({len(entries)} snippets)\n")

    print(f"{'Language':<14} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print("-" * 62)

    langs = sorted({e["language"] for e in entries})
    for lang in langs:
        tp = lang_tp[lang]
        fp = lang_fp[lang]
        fn = lang_fn[lang]
        tn = lang_tn[lang]
        m = _metrics(tp, fp, fn)
        print(
            f"{lang:<14} {tp:>4} {fp:>4} {fn:>4} {tn:>4}"
            f" {m['precision']:>10.3f} {m['recall']:>8.3f} {m['f1']:>8.3f}"
        )

    print("-" * 62)
    m = _metrics(overall_tp, overall_fp, overall_fn)
    print(
        f"{'OVERALL':<14} {overall_tp:>4} {overall_fp:>4} {overall_fn:>4} {overall_tn:>4}"
        f" {m['precision']:>10.3f} {m['recall']:>8.3f} {m['f1']:>8.3f}"
    )
    print()
    print("BigVul C/C++ baseline: F1=0.947 (NOT valid for the above languages — see A-18)")
    print()


if __name__ == "__main__":
    main()
