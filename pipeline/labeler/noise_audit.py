#!/usr/bin/env python3
"""Noise audit: sample 50 vulnerable entries per language; prune with cleanlab if >40% noise.

Writes the pruned JSONL back in-place and logs summary to stderr.
"""
from __future__ import annotations

import json
import pathlib
import random
import sys

NORMALIZED_DIR = pathlib.Path("tests/corpus/normalized")
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]
SAMPLE_N = 50
NOISE_THRESHOLD = 0.40


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(l) for l in f if l.strip()]


def _write_jsonl(path: pathlib.Path, records: list[dict]) -> None:
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _estimate_noise(samples: list[dict]) -> float:
    """Heuristic: records with empty cve_id AND empty cwe_id are suspect in the 'vulnerable' class."""
    suspect = sum(1 for r in samples if not r.get("cve_id") and not r.get("cwe_id"))
    return suspect / len(samples) if samples else 0.0


def _cleanlab_prune(records: list[dict]) -> list[dict]:
    """Use cleanlab confident learning to prune label errors from training split."""
    try:
        import numpy as np
        from cleanlab.filter import find_label_issues  # type: ignore[import-untyped]
        from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
    except ImportError:
        print("  cleanlab/sklearn required for pruning — skipping (pip install cleanlab scikit-learn)", file=sys.stderr)
        return records

    codes = [r["code"] for r in records]
    labels = [r["label"] for r in records]

    if len(set(labels)) < 2:
        return records

    vec = TfidfVectorizer(max_features=5000, sublinear_tf=True)
    X = vec.fit_transform(codes)
    clf = LogisticRegression(max_iter=500)
    clf.fit(X, labels)
    pred_probs = clf.predict_proba(X)

    issue_idx = find_label_issues(
        labels=np.array(labels),
        pred_probs=pred_probs,
        return_indices_ranked_by="self_confidence",
    )
    issue_set = set(issue_idx)
    pruned = [r for i, r in enumerate(records) if i not in issue_set]
    print(f"    cleanlab pruned {len(issue_idx)} / {len(records)} label issues", file=sys.stderr)
    return pruned


def audit_language(lang: str, normalized_dir: pathlib.Path) -> None:
    train_path = normalized_dir / f"{lang}_train.jsonl"
    if not train_path.exists():
        print(f"  {lang}: no train split found — skipped", file=sys.stderr)
        return

    records = _load_jsonl(train_path)
    vulnerable = [r for r in records if r.get("label") == 1]

    if not vulnerable:
        print(f"  {lang}: no vulnerable samples", file=sys.stderr)
        return

    rng = random.Random(42)
    sample = rng.sample(vulnerable, min(SAMPLE_N, len(vulnerable)))
    noise_rate = _estimate_noise(sample)

    print(f"  {lang}: sampled {len(sample)}, estimated noise rate {noise_rate:.1%}", file=sys.stderr)

    if noise_rate > NOISE_THRESHOLD:
        print(f"  {lang}: noise rate {noise_rate:.1%} > {NOISE_THRESHOLD:.0%} — running cleanlab pruning", file=sys.stderr)
        records = _cleanlab_prune(records)
        _write_jsonl(train_path, records)
    else:
        print(f"  {lang}: noise rate acceptable", file=sys.stderr)


def audit_all(normalized_dir: pathlib.Path = NORMALIZED_DIR) -> None:
    for lang in LANGUAGES:
        audit_language(lang, normalized_dir)


if __name__ == "__main__":
    audit_all()
