#!/usr/bin/env python3
"""Pull CVEFixes dataset and emit unified internal schema JSONL per language."""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Iterator

SUPPORTED_LANGUAGES = {"python", "java", "javascript", "typescript", "go", "c#"}
OUT_DIR = pathlib.Path("tests/corpus/raw")

# Unified schema: {"code": str, "label": int, "cve_id": str, "cwe_id": str, "language": str}
# label: 1 = vulnerable (before patch), 0 = safe (after patch)


def _norm_lang(lang: str) -> str:
    return lang.lower().strip()


def _iter_pairs(dataset) -> Iterator[dict]:
    for row in dataset:
        lang = _norm_lang(row.get("programming_language", ""))
        if lang not in SUPPORTED_LANGUAGES:
            continue
        cve_id = row.get("cve_id", "")
        cwe_id = row.get("cwe_id", "")
        # CVEFixes has before/after patch code
        before = row.get("func_before", "") or ""
        after = row.get("func_after", "") or ""
        if before.strip():
            yield {"code": before, "label": 1, "cve_id": cve_id, "cwe_id": cwe_id, "language": lang}
        if after.strip():
            yield {"code": after, "label": 0, "cve_id": cve_id, "cwe_id": cwe_id, "language": lang}


def collect(out_dir: pathlib.Path = OUT_DIR) -> None:
    try:
        from datasets import load_dataset  # type: ignore[import-untyped]
    except ImportError:
        print("datasets package required: pip install datasets", file=sys.stderr)
        sys.exit(1)

    print("loading hitoshura25/cvefixes …", file=sys.stderr)
    ds = load_dataset("hitoshura25/cvefixes", split="train", trust_remote_code=True)

    buckets: dict[str, list[dict]] = {lang: [] for lang in SUPPORTED_LANGUAGES}
    for record in _iter_pairs(ds):
        buckets[record["language"]].append(record)

    out_dir.mkdir(parents=True, exist_ok=True)
    for lang, records in buckets.items():
        if not records:
            print(f"  {lang}: 0 records — skipped", file=sys.stderr)
            continue
        path = out_dir / f"{lang}.jsonl"
        with path.open("w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        print(f"  {lang}: {len(records)} records → {path}", file=sys.stderr)


if __name__ == "__main__":
    collect()
