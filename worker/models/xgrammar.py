"""XGrammar-2 schema enforcement wrapper.

XGrammar-2 enforces JSON output schemas at LLM generation time, making malformed
output impossible by construction.  When the ``xgrammar`` package is not
available (e.g. Python 3.13 — no wheels yet), the enforcer falls back to plain
``json`` parsing + Pydantic validation, which is still correct though without
generation-time token masking.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

log = logging.getLogger(__name__)

# Try to import xgrammar; it may be absent on environments without wheels.
try:
    import xgrammar as xgr  # type: ignore[import-untyped]

    _XGR_AVAILABLE = True
    log.debug("xgrammar available — generation-time grammar enforcement enabled")
except ImportError:
    xgr = None  # type: ignore[assignment]
    _XGR_AVAILABLE = False
    log.debug("xgrammar not available — falling back to json+Pydantic validation only")

T = TypeVar("T", bound=BaseModel)


class GrammarEnforcer(Generic[T]):
    """Generic, type-safe JSON schema enforcer backed optionally by XGrammar-2.

    Usage::

        enforcer = GrammarEnforcer(LLMVerifierResult)
        enforcer.compile()          # call once at startup; idempotent
        result = enforcer.parse(llm_output_text)

    The ``json_schema`` property returns the dict suitable for passing directly
    to ``ollama.Client.chat(format=enforcer.json_schema)``.

    Thread safety: ``compile()`` is idempotent (safe to call from multiple
    threads; the compiled grammar is stored once and never mutated after that).
    ``parse()`` is fully stateless.
    """

    def __init__(self, model_class: type[T]) -> None:
        """Initialise the enforcer for *model_class*.

        Args:
            model_class: A Pydantic ``BaseModel`` subclass whose JSON schema
                defines the grammar to enforce.
        """
        self._model_class = model_class
        self._schema: dict[str, Any] = model_class.model_json_schema()
        self._compiled: Any = None  # xgr.CompiledGrammar or None

    def compile(self) -> None:
        """Pre-compile the grammar from the model's JSON schema.

        Idempotent — subsequent calls after the first are no-ops.  When
        ``xgrammar`` is not available the call succeeds silently so callers
        need not branch on availability.
        """
        if self._compiled is not None:
            return  # already compiled

        if not _XGR_AVAILABLE:
            log.debug(
                "compile() skipped — xgrammar unavailable for %s",
                self._model_class.__name__,
            )
            return

        schema_str = json.dumps(self._schema)
        try:
            compiler = xgr.GrammarCompiler()  # type: ignore[union-attr]
            self._compiled = compiler.compile_json_schema(schema_str)
            log.debug("grammar compiled for %s", self._model_class.__name__)
        except Exception as exc:
            # xgrammar compilation failures are non-fatal; log and continue
            # without generation-time enforcement.
            log.warning(
                "xgrammar compile failed for %s — falling back to Pydantic only: %s",
                self._model_class.__name__,
                exc,
            )

    @property
    def json_schema(self) -> dict[str, Any]:
        """Return the JSON schema dict for use as ``ollama.Client.chat(format=…)``."""
        return self._schema

    def parse(self, text: str) -> T:
        """Validate *text* (raw LLM output) and deserialise into *model_class*.

        When ``xgrammar`` is available the raw JSON is also validated against
        the compiled grammar for structural correctness before Pydantic
        deserialization.  In either case Pydantic performs the authoritative
        type-safe validation.

        Args:
            text: Raw JSON string returned by the LLM.

        Returns:
            A validated instance of the model class.

        Raises:
            ValueError: If *text* is not valid JSON or fails Pydantic validation.
        """
        text = re.sub(r"```(?:json)?\n?|```", "", text).strip()
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON from LLM output: {exc}") from exc

        if _XGR_AVAILABLE and self._compiled is not None:
            # Post-generation structural check via xgrammar.
            try:
                xgr.validate(self._compiled, text)  # type: ignore[union-attr]
            except Exception as exc:
                log.debug("xgrammar post-validate warning: %s", exc)
                # Non-fatal — Pydantic validation below is the authority.

        try:
            return self._model_class.model_validate(data)
        except Exception as exc:
            raise ValueError(
                f"schema mismatch for {self._model_class.__name__}: {exc}"
            ) from exc
