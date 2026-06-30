#!/usr/bin/env python3
"""Exact SHA-256 deduplication over raw JSONL corpus files.

Reads tests/corpus/raw/{language}.jsonl, drops exact code duplicates,
logs per-language drop counts, writes deduplicated files in-place.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

RAW_DIR = pathlib.Path("tests/corpus/raw")
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]


def dedup_file(path: pathlib.Path) -> tuple[int, int]:
    """Return (original_count, kept_count)."""
    records: list[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    seen: set[str] = set()
    kept: list[dict] = []
    for r in records:
        h = hashlib.sha256(r.get("code", "").encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            kept.append(r)

    with path.open("w") as f:
        for r in kept:
            f.write(json.dumps(r) + "\n")

    return len(records), len(kept)


def dedup_all(raw_dir: pathlib.Path = RAW_DIR) -> None:
    if not raw_dir.exists():
        print(f"raw dir not found: {raw_dir}", file=sys.stderr)
        sys.exit(1)

    total_in = total_out = 0
    for lang in LANGUAGES:
        path = raw_dir / f"{lang}.jsonl"
        if not path.exists():
            print(f"  {lang}: file not found — skipped", file=sys.stderr)
            continue
        n_in, n_out = dedup_file(path)
        dropped = n_in - n_out
        total_in += n_in
        total_out += n_out
        print(f"  {lang}: {n_in} → {n_out} (dropped {dropped})", file=sys.stderr)

    print(f"total: {total_in} → {total_out} (dropped {total_in - total_out})", file=sys.stderr)


if __name__ == "__main__":
    dedup_all()
