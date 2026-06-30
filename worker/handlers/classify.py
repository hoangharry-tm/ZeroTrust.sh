"""Code understanding classifier handler (CodeT5+ default, UniXcoder fallback).

A-18: high-recall mode until CVEFixes multi-language benchmark is complete.
See ``models/codet5p.py`` / ``models/unixcoder.py`` for full accuracy disclosure.

Selects the model backbone via ``ZEROTRUST_CLASSIFIER_MODEL`` env var:
    ``"codet5p"``   (default) → ``models.codet5p.CodeT5PClassifier``
    ``"unixcoder"``           → ``models.unixcoder.UniXcoderClassifier``

Multi-language LoRA adapters are loaded from ``~/.zerotrust/adapters/{language}/``
when present. Adapter swaps are serialised through ``_adapter_lock`` to prevent
concurrent T5EncoderModel state corruption.
"""

from __future__ import annotations

import logging
import os
import pathlib
import threading
from typing import Any

log = logging.getLogger(__name__)

_CLASSIFIER_BACKEND: str = os.getenv("ZEROTRUST_CLASSIFIER_MODEL", "codet5p").lower()
_ADAPTERS_DIR = pathlib.Path.home() / ".zerotrust" / "adapters"


def _new_classifier():
    """Construct the classifier instance based on *ZEROTRUST_CLASSIFIER_MODEL*."""
    if _CLASSIFIER_BACKEND == "unixcoder":
        from models.unixcoder import UniXcoderClassifier

        model_name = os.getenv("ZEROTRUST_UNIXCODER_MODEL", "microsoft/unixcoder-base-nine")
        log.debug("initialising UniXcoderClassifier (model=%s)", model_name)
        return UniXcoderClassifier(model_name=model_name)

    from models.codet5p import CodeT5PClassifier

    model_name = os.getenv("ZEROTRUST_CODET5P_MODEL", "Salesforce/codet5p-220m")
    log.debug("initialising CodeT5PClassifier (model=%s)", model_name)
    return CodeT5PClassifier(model_name=model_name)


# ── Module-level lazy singleton ───────────────────────────────────────────────

_init_lock = threading.Lock()
_initialised = False
_classifier: Any = None

# ── Adapter state ─────────────────────────────────────────────────────────────

# Serialises hot-swaps so only one thread mutates the PEFT adapter at a time.
_adapter_lock = threading.Lock()
_current_adapter_lang: str = ""


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


def _maybe_swap_adapter(classifier: Any, language: str) -> None:
    """Load and activate a language-specific LoRA adapter when one exists.

    No-op if the adapter directory is absent or the classifier does not expose
    a ``load_adapter`` method (i.e. base model without PEFT wrapping yet).

    Must be called while holding ``_adapter_lock``.
    """
    global _current_adapter_lang  # noqa: PLW0603

    if not language or language == _current_adapter_lang:
        return

    adapter_path = _ADAPTERS_DIR / language
    if not adapter_path.exists():
        log.debug("no LoRA adapter for language=%s, keeping current adapter", language)
        return

    if not hasattr(classifier, "_model") or classifier._model is None:
        return

    try:
        from peft import PeftModel  # type: ignore[import-untyped]

        # Wrap the base T5EncoderModel with the language adapter if not already wrapped.
        if not isinstance(classifier._model, PeftModel):
            classifier._model = PeftModel.from_pretrained(
                classifier._model, str(adapter_path), adapter_name=language
            )
        else:
            # PEFT already wrapping — load additional adapter or switch active one.
            try:
                classifier._model.set_adapter(language)
            except ValueError:
                classifier._model.load_adapter(str(adapter_path), adapter_name=language)
                classifier._model.set_adapter(language)

        # Load matching linear probe weights if present.
        probe_path = adapter_path / "probe.pt"
        if probe_path.exists() and hasattr(classifier, "_probe") and classifier._probe is not None:
            import torch
            classifier._probe.load_state_dict(
                torch.load(str(probe_path), map_location=classifier._device)
            )
            classifier._probe.eval()

        _current_adapter_lang = language
        log.debug("LoRA adapter activated (language=%s)", language)

    except Exception:
        log.warning("adapter swap failed for language=%s — falling back to base model", language, exc_info=True)


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

    # Group surfaces by language so we minimise adapter swaps.
    lang_groups: dict[str, list[dict]] = {}
    for s in surfaces:
        lang = (s.get("language") or "").lower()
        lang_groups.setdefault(lang, []).append(s)

    results_by_id: dict[str, dict] = {}
    for lang, lang_surfaces in lang_groups.items():
        with _adapter_lock:
            _maybe_swap_adapter(classifier, lang)
            batch_results = classifier.classify_batch(lang_surfaces)
        for r in batch_results:
            results_by_id[r["surface_id"]] = r

    # Restore original order
    ordered = [results_by_id[s["surface_id"]] for s in surfaces if s.get("surface_id") in results_by_id]
    log.debug("classify: done", extra={"num_results": len(ordered)})
    return {"results": ordered}
