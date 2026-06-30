#!/usr/bin/env python3
"""Cross-reference corpus CWE coverage against active Semgrep rule sets.

Prints gaps to docs/rules/coverage_gap.md.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

NORMALIZED_DIR = pathlib.Path("tests/corpus/normalized")
RULES_DIR = pathlib.Path("rules")
GAP_DOC = pathlib.Path("docs/rules/coverage_gap.md")
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]


def _corpus_cwes(normalized_dir: pathlib.Path) -> dict[str, set[str]]:
    """Return {language: {cwe_id, ...}} from all splits."""
    cwes: dict[str, set[str]] = {}
    for lang in LANGUAGES:
        cwe_set: set[str] = set()
        for split in ("train", "val", "test"):
            path = normalized_dir / f"{lang}_{split}.jsonl"
            if not path.exists():
                continue
            with path.open() as f:
                for line in f:
                    r = json.loads(line)
                    cid = r.get("cwe_id", "").strip().upper()
                    if cid:
                        cwe_set.add(cid)
        cwes[lang] = cwe_set
    return cwes


def _rule_cwes(rules_dir: pathlib.Path) -> set[str]:
    """Parse CWE references from Semgrep YAML rule files (metadata.cwe field)."""
    cwe_pattern = re.compile(r"CWE-?(\d+)", re.IGNORECASE)
    cwes: set[str] = set()
    for yaml_file in rules_dir.rglob("*.yml"):
        for m in cwe_pattern.finditer(yaml_file.read_text(errors="replace")):
            cwes.add(f"CWE{m.group(1)}")
    for yaml_file in rules_dir.rglob("*.yaml"):
        for m in cwe_pattern.finditer(yaml_file.read_text(errors="replace")):
            cwes.add(f"CWE{m.group(1)}")
    return cwes


def generate(normalized_dir: pathlib.Path = NORMALIZED_DIR, rules_dir: pathlib.Path = RULES_DIR) -> None:
    corpus_cwes = _corpus_cwes(normalized_dir)
    rule_cwes = _rule_cwes(rules_dir)

    all_corpus_cwes: set[str] = set()
    for s in corpus_cwes.values():
        all_corpus_cwes.update(s)

    in_corpus_not_rules = sorted(all_corpus_cwes - rule_cwes)
    in_rules_not_corpus = sorted(rule_cwes - all_corpus_cwes)

    lines = [
        "# CWE Coverage Gap Report",
        "",
        f"Corpus CWEs: {len(all_corpus_cwes)}  |  Rule CWEs: {len(rule_cwes)}",
        "",
        "## In corpus but no Semgrep rule",
        "",
    ]
    if in_corpus_not_rules:
        for cwe in in_corpus_not_rules:
            lines.append(f"- {cwe}")
    else:
        lines.append("_(none)_")

    lines += ["", "## Semgrep rules with no corpus coverage", ""]
    if in_rules_not_corpus:
        for cwe in in_rules_not_corpus:
            lines.append(f"- {cwe}")
    else:
        lines.append("_(none)_")

    lines += ["", "## Per-language CWE coverage", ""]
    for lang in LANGUAGES:
        cwes = sorted(corpus_cwes.get(lang, set()))
        lines.append(f"### {lang}")
        lines.append(", ".join(cwes) if cwes else "_(no data)_")
        lines.append("")

    GAP_DOC.parent.mkdir(parents=True, exist_ok=True)
    GAP_DOC.write_text("\n".join(lines))
    print(f"coverage gap report written to {GAP_DOC}", file=sys.stderr)
    print(f"  corpus-only CWEs: {len(in_corpus_not_rules)}  rule-only CWEs: {len(in_rules_not_corpus)}", file=sys.stderr)


if __name__ == "__main__":
    generate()
