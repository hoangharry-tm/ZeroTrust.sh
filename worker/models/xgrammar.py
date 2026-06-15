"""XGrammar-2 schema enforcement wrapper.

XGrammar-2 enforces JSON output schemas at LLM generation time, making malformed
output impossible by construction. TagDispatch handles multiple distinct schemas
(LLM Verifier, Summarizer union schema, ReAct verdict) without recompilation;
cross-grammar cache delivers ~6× faster compilation vs XGrammar-1.
"""

from __future__ import annotations

from typing import Any


class GrammarEnforcer:
    """Wraps XGrammar-2 to enforce a JSON schema at generation time."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self._compiled: Any = None

    def compile(self) -> None:
        """Pre-compile the grammar. Call once at worker startup per schema."""
        # implemented in G2.M2.5
        raise NotImplementedError

    def enforce(self, llm_output: str) -> dict[str, Any]:
        """Parse and validate llm_output against the compiled grammar."""
        # implemented in G2.M2.5
        raise NotImplementedError
