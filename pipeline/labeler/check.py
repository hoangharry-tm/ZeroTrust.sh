#!/usr/bin/env python3
"""Safety check: assert no code hash or CVE ID leaks from train into val/test.

Exits non-zero on any violation. Run after normalize.py and noise_audit.py.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

NORMALIZED_DIR = pathlib.Path("tests/corpus/normalized")
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(l) for l in f if l.strip()]


def check_language(lang: str, normalized_dir: pathlib.Path) -> list[str]:
    violations: list[str] = []
    splits = {}
    for split in ("train", "val", "test"):
        path = normalized_dir / f"{lang}_{split}.jsonl"
        if path.exists():
            splits[split] = _load_jsonl(path)
        else:
            splits[split] = []

    train_hashes = {hashlib.sha256(r["code"].encode()).hexdigest() for r in splits["train"]}
    train_cves = {r["cve_id"] for r in splits["train"] if r.get("cve_id")}

    for split in ("val", "test"):
        for r in splits[split]:
            h = hashlib.sha256(r["code"].encode()).hexdigest()
            if h in train_hashes:
                violations.append(f"{lang}/{split}: code hash leak (cve={r.get('cve_id', '')})")
            cve = r.get("cve_id", "")
            if cve and cve in train_cves:
                violations.append(f"{lang}/{split}: CVE ID leak ({cve})")

    return violations


def check_all(normalized_dir: pathlib.Path = NORMALIZED_DIR) -> None:
    all_violations: list[str] = []
    for lang in LANGUAGES:
        v = check_language(lang, normalized_dir)
        if v:
            for msg in v:
                print(f"VIOLATION: {msg}", file=sys.stderr)
            all_violations.extend(v)
        else:
            print(f"  {lang}: OK", file=sys.stderr)

    if all_violations:
        print(f"\n{len(all_violations)} safety violations found — aborting", file=sys.stderr)
        sys.exit(1)

    print("all splits clean — no hash or CVE leakage detected", file=sys.stderr)


if __name__ == "__main__":
    check_all()
