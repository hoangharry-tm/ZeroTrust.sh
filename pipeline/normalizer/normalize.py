#!/usr/bin/env python3
"""Normalize raw corpus and produce CVE-aware stratified splits.

For each language:
  - Strip comments (regex-based, language-aware)
  - Normalize whitespace
  - Clip to 1024 tokens via CodeT5+ tokenizer
  - Compute inverse-frequency class weights (no oversampling for thin languages)
  - CVE-aware stratified 80/10/10 split (same CVE ID never spans train+val/test)

Output: tests/corpus/normalized/{language}_{train|val|test}.jsonl
"""
from __future__ import annotations

import json
import math
import pathlib
import random
import re
import sys
from collections import defaultdict

RAW_DIR = pathlib.Path("tests/corpus/raw")
OUT_DIR = pathlib.Path("tests/corpus/normalized")
MAX_TOKENS = 1024
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]

# Per-language comment stripping patterns
_COMMENT_PATTERNS: dict[str, list[re.Pattern]] = {
    "python": [re.compile(r"#.*$", re.MULTILINE), re.compile(r'"""[\s\S]*?"""'), re.compile(r"'''[\s\S]*?'''")],
    "java":   [re.compile(r"//.*$", re.MULTILINE), re.compile(r"/\*[\s\S]*?\*/")],
    "javascript": [re.compile(r"//.*$", re.MULTILINE), re.compile(r"/\*[\s\S]*?\*/")],
    "typescript": [re.compile(r"//.*$", re.MULTILINE), re.compile(r"/\*[\s\S]*?\*/")],
    "go":     [re.compile(r"//.*$", re.MULTILINE), re.compile(r"/\*[\s\S]*?\*/")],
    "c#":     [re.compile(r"//.*$", re.MULTILINE), re.compile(r"/\*[\s\S]*?\*/")],
}


def _strip_comments(code: str, lang: str) -> str:
    for pat in _COMMENT_PATTERNS.get(lang, []):
        code = pat.sub("", code)
    return code


def _normalize_ws(code: str) -> str:
    # Collapse runs of blank lines to one, strip trailing whitespace per line
    lines = [l.rstrip() for l in code.splitlines()]
    out, prev_blank = [], False
    for line in lines:
        blank = not line
        if blank and prev_blank:
            continue
        out.append(line)
        prev_blank = blank
    return "\n".join(out).strip()


def _tokenize(tokenizer, code: str) -> list[int]:
    return tokenizer(code, truncation=False, add_special_tokens=False)["input_ids"]


def _clip(tokenizer, code: str) -> str:
    ids = _tokenize(tokenizer, code)
    if len(ids) <= MAX_TOKENS:
        return code
    clipped_ids = ids[:MAX_TOKENS]
    return tokenizer.decode(clipped_ids, skip_special_tokens=True)


def _class_weights(records: list[dict]) -> dict[int, float]:
    """Inverse-frequency weights — no oversampling."""
    counts: dict[int, int] = defaultdict(int)
    for r in records:
        counts[r["label"]] += 1
    total = len(records)
    return {label: total / (len(counts) * count) for label, count in counts.items()}


def _cve_aware_split(records: list[dict], seed: int = 42) -> tuple[list[dict], list[dict], list[dict]]:
    """CVE-aware stratified 80/10/10 split.

    Records with the same cve_id are kept in one partition so the model
    cannot memorize CVE-specific patterns from train and leak to val/test.
    Records without a cve_id are assigned a synthetic group per code hash.
    """
    import hashlib

    rng = random.Random(seed)

    # Group by cve_id (or synthetic group for no-CVE rows)
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        key = r.get("cve_id") or hashlib.md5(r["code"].encode()).hexdigest()[:8]
        groups[key].append(r)

    # Separate vuln / safe groups to stratify
    vuln_groups = [g for g in groups.values() if any(r["label"] == 1 for r in g)]
    safe_groups = [g for g in groups.values() if all(r["label"] == 0 for r in g)]

    def _split_groups(gs: list[list[dict]]) -> tuple[list[dict], list[dict], list[dict]]:
        rng.shuffle(gs)
        n = len(gs)
        n_val = max(1, math.ceil(n * 0.10))
        n_test = max(1, math.ceil(n * 0.10))
        test_gs = gs[:n_test]
        val_gs = gs[n_test : n_test + n_val]
        train_gs = gs[n_test + n_val :]
        flatten = lambda ll: [r for g in ll for r in g]
        return flatten(train_gs), flatten(val_gs), flatten(test_gs)

    vtr, vva, vte = _split_groups(vuln_groups)
    str_, sva, ste = _split_groups(safe_groups)
    return vtr + str_, vva + sva, vte + ste


def normalize_language(tokenizer, lang: str, raw_dir: pathlib.Path, out_dir: pathlib.Path) -> None:
    src = raw_dir / f"{lang}.jsonl"
    if not src.exists():
        print(f"  {lang}: missing raw file — skipped", file=sys.stderr)
        return

    records: list[dict] = []
    with src.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            code = _strip_comments(r.get("code", ""), lang)
            code = _normalize_ws(code)
            code = _clip(tokenizer, code)
            if not code:
                continue
            r["code"] = code
            records.append(r)

    weights = _class_weights(records)
    train, val, test = _cve_aware_split(records)

    out_dir.mkdir(parents=True, exist_ok=True)
    for split_name, split in [("train", train), ("val", val), ("test", test)]:
        path = out_dir / f"{lang}_{split_name}.jsonl"
        with path.open("w") as f:
            for r in split:
                f.write(json.dumps(r) + "\n")

    vuln_w = weights.get(1, 1.0)
    safe_w = weights.get(0, 1.0)
    print(
        f"  {lang}: {len(records)} samples | train={len(train)} val={len(val)} test={len(test)}"
        f" | class_weights={{1: {vuln_w:.3f}, 0: {safe_w:.3f}}}",
        file=sys.stderr,
    )

    # Write weights file for train_lora.py to consume
    weights_path = out_dir / f"{lang}_weights.json"
    weights_path.write_text(json.dumps({"vuln": vuln_w, "safe": safe_w}, indent=2))


def normalize_all(raw_dir: pathlib.Path = RAW_DIR, out_dir: pathlib.Path = OUT_DIR) -> None:
    try:
        from transformers import AutoTokenizer  # type: ignore[import-untyped]
    except ImportError:
        print("transformers required: pip install transformers", file=sys.stderr)
        sys.exit(1)

    print("loading tokenizer …", file=sys.stderr)
    tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5p-220m")

    for lang in LANGUAGES:
        normalize_language(tokenizer, lang, raw_dir, out_dir)


if __name__ == "__main__":
    normalize_all()
