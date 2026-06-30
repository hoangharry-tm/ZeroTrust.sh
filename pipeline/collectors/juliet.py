#!/usr/bin/env python3
"""Pull Juliet C# 1.3 / SARD C# samples and emit unified internal schema JSONL."""
from __future__ import annotations

import json
import pathlib
import sys

OUT_DIR = pathlib.Path("tests/corpus/raw")

_HF_DATASETS = [
    # Primary: Juliet C# from HF
    ("SonarSource/juliet-csharp", "train"),
]


def _iter_hf(dataset_name: str, split: str):
    try:
        from datasets import load_dataset  # type: ignore[import-untyped]
    except ImportError:
        print("datasets package required: pip install datasets", file=sys.stderr)
        sys.exit(1)

    print(f"loading {dataset_name} …", file=sys.stderr)
    try:
        ds = load_dataset(dataset_name, split=split, trust_remote_code=True)
    except Exception as exc:
        print(f"  warning: could not load {dataset_name}: {exc}", file=sys.stderr)
        return

    for row in ds:
        code = row.get("code", "") or row.get("func", "") or ""
        if not code.strip():
            continue
        # label: flawed = 1 (vulnerable), fixed = 0 (safe)
        label = 1 if str(row.get("flaw", row.get("label", ""))).lower() in {"1", "true", "flawed", "bad"} else 0
        cwe_id = str(row.get("cwe_id", row.get("cwe", ""))).upper()
        yield {
            "code": code,
            "label": label,
            "cve_id": "",
            "cwe_id": cwe_id,
            "language": "c#",
        }


def collect(out_dir: pathlib.Path = OUT_DIR) -> None:
    records: list[dict] = []
    for name, split in _HF_DATASETS:
        for rec in _iter_hf(name, split):
            records.append(rec)

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "c#.jsonl"
    existing: list[dict] = []
    if path.exists():
        with path.open() as f:
            existing = [json.loads(l) for l in f if l.strip()]

    combined = existing + records
    with path.open("w") as f:
        for r in combined:
            f.write(json.dumps(r) + "\n")
    print(f"  c# (juliet): {len(records)} records appended → {path}", file=sys.stderr)


if __name__ == "__main__":
    collect()
