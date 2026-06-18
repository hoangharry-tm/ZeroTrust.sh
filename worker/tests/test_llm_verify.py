"""Unit tests for the llm_verify handler.

Ollama is mocked throughout — no real LLM calls are made.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from models.xgrammar import GrammarEnforcer
from schemas.verdict import LLMVerdict, LLMVerifierResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_PAYLOAD: dict[str, Any] = {
    "finding_id": "test-001",
    "rule_id": "PY-001",
    "cwe": "CWE-89",
    "matched_code": "cursor.execute(query % user_input)",
    "justification": "opengrep match: sql injection pattern",
    "file_path": "src/db.py",
    "asc_max_rounds": 2,
    "asc_confidence_threshold": 0.70,
}


def _make_response(verdict: str, confidence: float, justification: str = "test") -> Any:
    """Return a mock Ollama response with .message.content set to JSON."""
    body = json.dumps(
        {"verdict": verdict, "confidence": confidence, "justification": justification}
    )
    msg = SimpleNamespace(content=body)
    return SimpleNamespace(message=msg)


# ---------------------------------------------------------------------------
# Tests: handle()
# ---------------------------------------------------------------------------

class TestHandleConfirmed:
    """Initial call returns confirmed — no ASC triggered."""

    def test_handle_confirmed(self) -> None:
        import handlers.llm_verify as mod

        with patch.object(mod, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            mock_client.chat.return_value = _make_response("confirmed", 0.92)

            mod._initialised = False  # noqa: SLF001
            mod._client = None  # noqa: SLF001
            mod._enforcer = GrammarEnforcer(LLMVerifierResult)
            mod._enforcer.compile()

            result = mod.handle(BASE_PAYLOAD.copy())

        assert result["verdict"] == "confirmed"
        assert result["confidence"] == pytest.approx(0.92)
        assert result["asc_rounds"] == 0
        assert result["finding_id"] == "test-001"
        mock_client.chat.assert_called_once()


class TestHandleFalsePositive:
    """Initial call returns false_positive above threshold — no ASC."""

    def test_handle_false_positive(self) -> None:
        import handlers.llm_verify as mod

        with patch.object(mod, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            mock_client.chat.return_value = _make_response("false_positive", 0.85)

            mod._initialised = False  # noqa: SLF001
            mod._client = None  # noqa: SLF001
            mod._enforcer = GrammarEnforcer(LLMVerifierResult)
            mod._enforcer.compile()

            payload = {**BASE_PAYLOAD, "finding_id": "test-002"}
            result = mod.handle(payload)

        assert result["verdict"] == "false_positive"
        assert result["asc_rounds"] == 0
        mock_client.chat.assert_called_once()


class TestHandleUncertainTriggersASC:
    """Initial uncertain verdict triggers ASC; non-uncertain majority wins."""

    def test_handle_uncertain_triggers_asc(self) -> None:
        import handlers.llm_verify as mod

        responses = [
            _make_response("uncertain", 0.50),    # round 0 — initial
            _make_response("confirmed", 0.88),    # ASC round 1
            _make_response("confirmed", 0.82),    # ASC round 2
        ]

        with patch.object(mod, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            mock_client.chat.side_effect = responses

            mod._initialised = False  # noqa: SLF001
            mod._client = None  # noqa: SLF001
            mod._enforcer = GrammarEnforcer(LLMVerifierResult)
            mod._enforcer.compile()

            result = mod.handle(BASE_PAYLOAD.copy())

        assert result["verdict"] == "confirmed"
        assert result["asc_rounds"] == 2
        assert mock_client.chat.call_count == 3


class TestHandleASCAllUncertain:
    """All ASC samples uncertain — verdict stays uncertain, asc_rounds=2."""

    def test_handle_asc_all_uncertain(self) -> None:
        import handlers.llm_verify as mod

        responses = [
            _make_response("uncertain", 0.50),
            _make_response("uncertain", 0.45),
            _make_response("uncertain", 0.48),
        ]

        with patch.object(mod, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            mock_client.chat.side_effect = responses

            mod._initialised = False  # noqa: SLF001
            mod._client = None  # noqa: SLF001
            mod._enforcer = GrammarEnforcer(LLMVerifierResult)
            mod._enforcer.compile()

            result = mod.handle(BASE_PAYLOAD.copy())

        assert result["verdict"] == "uncertain"
        assert result["asc_rounds"] == 2
        assert mock_client.chat.call_count == 3


class TestHandleOllamaError:
    """Ollama connection error surfaces as RuntimeError with finding_id."""

    def test_handle_ollama_error(self) -> None:
        import handlers.llm_verify as mod

        with patch.object(mod, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_get_client.return_value = mock_client
            mock_client.chat.side_effect = ConnectionError("connection refused")

            mod._initialised = False  # noqa: SLF001
            mod._client = None  # noqa: SLF001
            mod._enforcer = GrammarEnforcer(LLMVerifierResult)
            mod._enforcer.compile()

            with pytest.raises(RuntimeError) as exc_info:
                mod.handle(BASE_PAYLOAD.copy())

        assert "test-001" in str(exc_info.value)
        assert "ollama unreachable" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Tests: GrammarEnforcer directly
# ---------------------------------------------------------------------------

class TestGrammarEnforcer:
    """Unit tests for GrammarEnforcer independent of the handler."""

    def test_parse_valid(self) -> None:
        enforcer: GrammarEnforcer[LLMVerifierResult] = GrammarEnforcer(LLMVerifierResult)
        enforcer.compile()
        text = json.dumps(
            {"verdict": "confirmed", "confidence": 0.91, "justification": "clear sql injection"}
        )
        result = enforcer.parse(text)
        assert isinstance(result, LLMVerifierResult)
        assert result.verdict == LLMVerdict.CONFIRMED
        assert result.confidence == pytest.approx(0.91)

    def test_parse_invalid_json_raises_value_error(self) -> None:
        enforcer: GrammarEnforcer[LLMVerifierResult] = GrammarEnforcer(LLMVerifierResult)
        enforcer.compile()
        with pytest.raises(ValueError, match="invalid JSON"):
            enforcer.parse("{ not valid json }")

    def test_parse_schema_mismatch_raises_value_error(self) -> None:
        enforcer: GrammarEnforcer[LLMVerifierResult] = GrammarEnforcer(LLMVerifierResult)
        enforcer.compile()
        # Missing required field 'verdict'
        with pytest.raises(ValueError, match="schema mismatch"):
            enforcer.parse(json.dumps({"confidence": 0.5, "justification": "x"}))

    def test_json_schema_property(self) -> None:
        enforcer: GrammarEnforcer[LLMVerifierResult] = GrammarEnforcer(LLMVerifierResult)
        schema = enforcer.json_schema
        assert isinstance(schema, dict)
        assert "properties" in schema

    def test_compile_is_idempotent(self) -> None:
        enforcer: GrammarEnforcer[LLMVerifierResult] = GrammarEnforcer(LLMVerifierResult)
        enforcer.compile()
        compiled_after_first = enforcer._compiled  # noqa: SLF001
        enforcer.compile()
        assert enforcer._compiled is compiled_after_first  # same object — no recompile
