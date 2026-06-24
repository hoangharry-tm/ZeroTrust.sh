"""Dedup Gate 4 — AST token edit-distance handler.

Tokenises two code snippets via tree-sitter leaf nodes, then computes
normalised Levenshtein distance on the token sequences.  Returns a
similarity score in [0, 1] (1 = identical token sequence).

tree-sitter-languages is optional; falls back to regex tokenisation so
Gate 4 degrades gracefully rather than erroring when the package is absent.
"""

from __future__ import annotations

import re
from typing import Any

_tsl: object | None = None
try:
    import tree_sitter_languages as _tsl_mod  # type: ignore[import-untyped]

    _tsl = _tsl_mod
except ImportError:
    pass


# ponytail: regex fallback when tree-sitter-languages not installed
_TOKEN_RE = re.compile(r"\w+|[^\w\s]")


def _tokenize_fallback(code: str) -> list[str]:
    return _TOKEN_RE.findall(code)


def _tokenize(code: str, language: str) -> list[str]:
    if _tsl is None:
        return _tokenize_fallback(code)
    try:
        parser = _tsl.get_parser(language)  # type: ignore[union-attr]
        tree = parser.parse(code.encode())
        tokens: list[str] = []

        def _collect(node: Any) -> None:
            if node.child_count == 0:
                text = code[node.start_byte : node.end_byte].strip()
                if text:
                    tokens.append(text)
            else:
                for child in node.children:
                    _collect(child)

        _collect(tree.root_node)
        return tokens or _tokenize_fallback(code)
    except Exception:
        return _tokenize_fallback(code)


def _levenshtein(a: list[str], b: list[str]) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), prev[j + 1] + 1, curr[j] + 1))
        prev = curr
    return prev[-1]


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle an ``ast_edit`` request.

    Expected payload:
        code1 (str): first code snippet.
        code2 (str): second code snippet.
        language (str, optional): tree-sitter language name (default: "python").

    Returns:
        similarity (float): 1.0 − normalised_levenshtein_distance ∈ [0, 1].
    """
    code1: str = payload["code1"]
    code2: str = payload["code2"]
    language: str = payload.get("language", "python")

    t1 = _tokenize(code1, language)
    t2 = _tokenize(code2, language)
    denom = max(len(t1), len(t2), 1)
    dist = _levenshtein(t1, t2)
    return {"similarity": 1.0 - dist / denom}
