"""UniXcoder-Base-Nine classifier handler.

A-18: high-recall mode until CVEFixes multi-language benchmark is complete.
See ``models/unixcoder.py`` for full accuracy disclosure.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from models.unixcoder import UniXcoderClassifier

log = logging.getLogger(__name__)

# ── Environment-driven configuration ─────────────────────────────────────────

UNIXCODER_MODEL: str = os.getenv(
    "ZEROTRUST_UNIXCODER_MODEL", "microsoft/unixcoder-base-nine"
)

# ── Module-level lazy singleton ───────────────────────────────────────────────

_init_lock = threading.Lock()
_initialised = False
_classifier: UniXcoderClassifier | None = None


def _get_classifier() -> UniXcoderClassifier:
    """Return the module-level classifier, loading it on first call."""
    global _classifier, _initialised  # noqa: PLW0603

    if _initialised:
        # Fast path — no lock needed after first init.
        assert _classifier is not None  # noqa: S101 — guaranteed by init block below
        return _classifier

    with _init_lock:
        if _initialised:
            assert _classifier is not None  # noqa: S101
            return _classifier

        log.debug("initialising UniXcoderClassifier (model=%s)", UNIXCODER_MODEL)
        instance = UniXcoderClassifier(model_name=UNIXCODER_MODEL)
        # RuntimeError propagates to the dispatcher → status=error response.
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
        RuntimeError: Model failed to load (propagated from ``UniXcoderClassifier.load()``).
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
