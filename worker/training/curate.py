"""Extract high-confidence findings from the state DB, generate patches via Ollama,
and write instruction-tuning JSONL files to .tmp/.

Usage:
    python -m worker.training.curate [--db PATH] [--min-confidence 0.80] [--out-dir .tmp]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sqlite3
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

_OLLAMA_URL = os.getenv("ZEROTRUST_OLLAMA_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("ZEROTRUST_MODEL", "qwen2.5-coder:7b")
_PATCH_TIMEOUT = 60  # seconds per Ollama call

_PATCH_SYSTEM = (
    "You are a security engineer. Output ONLY a valid unified git diff patch that fixes "
    "the vulnerability. No prose, no markdown fences — raw diff only."
)


def _generate_patch(file_path: str, cwe: str, code: str) -> str:
    """Call Ollama to generate a unified diff patch. Returns empty string on failure."""
    prompt = (
        f"Fix the following {cwe or 'security'} vulnerability in {file_path}.\n\n"
        f"Vulnerable code:\n{code}\n\nOutput a unified git diff patch only."
    )
    try:
        resp = httpx.post(
            f"{_OLLAMA_URL}/api/chat",
            json={
                "model": _OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": _PATCH_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=_PATCH_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()
    except Exception as exc:
        log.warning("patch generation failed for %s: %s", file_path, exc)
        return ""


def curate(db_path: Path, min_confidence: float, out_dir: Path) -> tuple[int, int]:
    """Return (train_count, val_count)."""
    out_dir.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_path)
    rows = con.execute(
        """
        SELECT finding_id, file_path, COALESCE(cwe,''), COALESCE(matched_code,''),
               confidence, COALESCE(patch,''), COALESCE(patch_status,'')
        FROM findings
        WHERE confidence >= ? AND matched_code IS NOT NULL AND matched_code != ''
        ORDER BY confidence DESC
        """,
        (min_confidence,),
    ).fetchall()
    # Keep con open; we may write back generated patches below.

    log.info("found %d candidate findings (confidence >= %.2f)", len(rows), min_confidence)

    records: list[dict] = []
    for finding_id, file_path, cwe, code, _, cached_patch, _ in rows:
        if cached_patch:
            patch = cached_patch
            log.debug("cache hit: %s", finding_id)
        else:
            patch = _generate_patch(file_path, cwe, code)
            if patch:
                con.execute(
                    "UPDATE findings SET patch = ?, patch_status = 'generated' WHERE finding_id = ?",
                    (patch, finding_id),
                )
                con.commit()
        if not patch:
            continue
        records.append({
            "instruction": (
                f"Fix the following vulnerability ({cwe or 'security issue'}) "
                "in the provided code snippet by generating a valid unified git diff patch."
            ),
            "input": f"File: {file_path}\nCode:\n{code}",
            "output": patch,
        })

    con.close()
    random.shuffle(records)
    split = int(len(records) * 0.8)
    train, val = records[:split], records[split:]

    for name, subset in (("train_data", train), ("val_data", val)):
        out = out_dir / f"{name}.jsonl"
        out.write_text("\n".join(json.dumps(r) for r in subset) + "\n")
        log.info("wrote %d records → %s", len(subset), out)

    return len(train), len(val)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Curate instruction-tuning dataset from scan DB")
    ap.add_argument("--db", default=None, help="Path to scans.db (default: <cwd>/.zerotrust/scans.db)")
    ap.add_argument("--min-confidence", type=float, default=0.80)
    ap.add_argument("--out-dir", default=".tmp")
    args = ap.parse_args()

    db = Path(args.db) if args.db else Path.cwd() / ".zerotrust" / "scans.db"
    if not db.exists():
        raise SystemExit(f"DB not found: {db}")

    train_n, val_n = curate(db, args.min_confidence, Path(args.out_dir))
    print(f"train={train_n} val={val_n}")


if __name__ == "__main__":
    main()
