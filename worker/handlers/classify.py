"""Code understanding classifier handler (CodeT5+ default, UniXcoder fallback).

A-18: high-recall mode until CVEFixes multi-language benchmark is complete.
See ``models/codet5p.py`` / ``models/unixcoder.py`` for full accuracy disclosure.

Selects the model backbone via ``ZEROTRUST_CLASSIFIER_MODEL`` env var:
    ``"codet5p"``   (default) → ``models.codet5p.CodeT5PClassifier``
    ``"unixcoder"``           → ``models.unixcoder.UniXcoderClassifier``
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

log = logging.getLogger(__name__)

# ── Environment-driven model selection ────────────────────────────────────────

_CLASSIFIER_BACKEND: str = os.getenv("ZEROTRUST_CLASSIFIER_MODEL", "codet5p").lower()


def _new_classifier():
    """Construct the classifier instance based on *ZEROTRUST_CLASSIFIER_MODEL*."""
    if _CLASSIFIER_BACKEND == "unixcoder":
        from models.unixcoder import UniXcoderClassifier

        model_name = os.getenv("ZEROTRUST_UNIXCODER_MODEL", "microsoft/unixcoder-base-nine")
        log.debug("initialising UniXcoderClassifier (model=%s)", model_name)
        return UniXcoderClassifier(model_name=model_name)

    # Default: CodeT5+ (A-18 fix — multilingual, CVEFixes fine-tune target).
    from models.codet5p import CodeT5PClassifier

    model_name = os.getenv("ZEROTRUST_CODET5P_MODEL", "Salesforce/codet5p-220m")
    log.debug("initialising CodeT5PClassifier (model=%s)", model_name)
    return CodeT5PClassifier(model_name=model_name)


# ── Module-level lazy singleton ───────────────────────────────────────────────

_init_lock = threading.Lock()
_initialised = False
_classifier: Any = None


def _get_classifier():
    """Return the module-level classifier, loading it on first call."""
    global _classifier, _initialised  # noqa: PLW0603

    if _initialised:
        assert _classifier is not None  # noqa: S101
        return _classifier

    with _init_lock:
        if _initialised:
            assert _classifier is not None  # noqa: S101
            return _classifier

        instance = _new_classifier()
        instance.load(device="cpu")

        _classifier = instance
        _initialised = True
        return _classifier


# ── Public handler ────────────────────────────────────────────────────────────


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle a ``classify`` request from the Go orchestrator.

    Expected payload fields:
        surfaces (list): Each item is a dict with:
            surface_id (str): Opaque ID echoed back in the response.
            code (str): Source code snippet to classify.
            language (str): Optional language hint (e.g. ``"python"``).

    Returns:
        A dict with a ``results`` list where each item contains
        ``surface_id``, ``label`` (``"vulnerable"|"safe"|"uncertain"``),
        and ``confidence`` (float 0–1).

    Raises:
        RuntimeError: Model failed to load (propagated from classifier.load()).
        KeyError: ``surfaces`` key missing from payload.
    """
    surfaces: list[dict[str, Any]] = payload["surfaces"]

    if not surfaces:
        log.debug("classify: empty surfaces list, returning empty results")
        return {"results": []}

    log.debug("classify: handle", extra={"num_surfaces": len(surfaces)})
    classifier = _get_classifier()
    results = classifier.classify_batch(surfaces)
    log.debug("classify: done", extra={"num_results": len(results)})
    return {"results": results}
