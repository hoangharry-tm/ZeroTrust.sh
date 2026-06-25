"""Dedup Gate 3 — MiniLM-L6-v2 embedding handler.

Returns float embeddings for a batch of code snippets so that the Go
dedup layer can compute cosine similarity between near-duplicate findings.
Skips heavy model load when sentence-transformers is unavailable.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

_SentenceTransformer: type | None = None
try:
    from sentence_transformers import SentenceTransformer as _ST  # type: ignore[import-untyped]

    _SentenceTransformer = _ST
except ImportError:
    pass

_lock = threading.Lock()
_model: Any = None

_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def _get_model() -> Any:
    global _model  # noqa: PLW0603
    if _model is not None:
        return _model
    with _lock:
        if _model is None:
            if _SentenceTransformer is None:
                raise RuntimeError(
                    "sentence-transformers not installed; Gate 3 embedding unavailable"
                )
            logger.debug("embed: loading SentenceTransformer (model=%s)", _MODEL_NAME)
            _model = _SentenceTransformer(_MODEL_NAME)
            logger.info("embed: model loaded (model=%s)", _MODEL_NAME)
    return _model


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle an ``embed`` request.

    Expected payload:
        codes (list[str]): code snippets to embed.

    Returns:
        embeddings (list[list[float]]): one float vector per input snippet.
    """
    codes: list[str] = payload["codes"]
    if not codes:
        logger.debug("embed: empty codes list, returning empty embeddings")
        return {"embeddings": []}
    logger.debug("embed: encoding", extra={"num_codes": len(codes)})
    model = _get_model()
    vecs = model.encode(codes, convert_to_numpy=True)
    logger.debug("embed: done", extra={"num_embeddings": len(vecs)})
    return {"embeddings": [v.tolist() for v in vecs]}
