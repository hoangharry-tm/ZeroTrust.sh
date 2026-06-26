"""LLM Semantic Scan handler — bounded ReAct loop, max 3 steps per surface."""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

import ollama

import tuning

log = logging.getLogger(__name__)

OLLAMA_URL: str = os.getenv("ZEROTRUST_OLLAMA_URL", "http://localhost:11434")
MODEL: str = os.getenv("ZEROTRUST_MODEL", "qwen2.5-coder:7b")

_init_lock = threading.Lock()
_initialised = False
_client: ollama.Client | None = None

_STEP_ACTIONS = {
    1: "Does tainted data flow from an untrusted caller into this surface?",
    2: "Does this surface propagate tainted data to any callee or sink?",
    3: "Can an attacker trigger the vulnerability at the sink? Provide final verdict.",
}

_SINGLE_PASS_ACTION = (
    "Analyze the full taint path, authorization guards, and logic flaws. "
    "Determine if this surface is vulnerable. Provide final verdict."
)


def _get_client() -> ollama.Client:
    global _client, _initialised  # noqa: PLW0603
    if _initialised:
        assert _client is not None  # noqa: S101
        return _client
    with _init_lock:
        if _initialised:
            assert _client is not None  # noqa: S101
            return _client
        log.debug("llm_scan: initialising Ollama client (url=%s, model=%s)", OLLAMA_URL, MODEL)
        _client = ollama.Client(host=OLLAMA_URL, timeout=tuning.OLLAMA_TIMEOUT_SECONDS)
        _initialised = True
        return _client


def _build_context_block(payload: dict[str, Any]) -> str:
    taint = payload.get("taint_flow", {})
    auth = payload.get("auth_guard", {})
    logic = payload.get("logic_flaw", {})
    prior_steps: list[dict[str, Any]] = payload.get("prior_steps", [])
    prior_ctx: list[dict[str, Any]] = payload.get("prior_context", [])

    parts: list[str] = [
        f"Taint flow: sources={taint.get('untrusted_sources', [])}, "
        f"sanitizers={taint.get('sanitizer_nodes', [])}, "
        f"sink={taint.get('sink_type', '')}, "
        f"propagates={taint.get('taint_propagates', False)}",
        f"Auth guard: present={auth.get('check_present', False)}, "
        f"location={auth.get('check_location', 'unknown')}",
        f"Logic flaw: resource_id_source={logic.get('resource_id_source', '')}, "
        f"db_sink={logic.get('db_sink', '')}, "
        f"check_location={logic.get('check_location', 'unknown')}",
    ]

    if prior_steps:
        parts.append("Prior reasoning steps:")
        for s in prior_steps:
            parts.append(
                f"  Step {s.get('StepNum', '?')}: {s.get('Thought', '')} → {s.get('Observation', '')}"
            )

    if prior_ctx:
        parts.append("Cross-surface context:")
        for inf in prior_ctx:
            parts.append(f"  [{inf.get('Kind', '')}] {inf.get('Narrative', '')}")

    return "\n".join(parts)


def _build_prompt(payload: dict[str, Any], action: str, is_final: bool) -> str:
    ctx = _build_context_block(payload)
    surface_id: str = payload.get("surface_id", "")

    prompt = (
        f"You are a security code analyzer reviewing surface: {surface_id}\n\n"
        f"SECURITY CONTEXT:\n{ctx}\n\n"
        f"TASK: {action}\n\n"
    )

    if is_final:
        prompt += (
            "Respond ONLY with JSON:\n"
            '{"thought": "<one sentence reasoning>", '
            '"action": "<what you checked>", '
            '"observation": "<1-3 sentence conclusion>", '
            '"verdict": "<confirmed|uncertain>", '
            '"confidence": <0.0-1.0>, '
            '"cwe": "<CWE-NNN or empty>", '
            '"early_exit": false}'
        )
    log.debug("llm_scan: final_prompt:\n%s", prompt)
    return prompt


def _call_step(client: ollama.Client, payload: dict[str, Any], step: int, is_final: bool) -> dict[str, Any]:
    mode: str = payload.get("mode", "react")
    action = _SINGLE_PASS_ACTION if mode == "single_pass" else _STEP_ACTIONS.get(step, _STEP_ACTIONS[3])
    prompt = _build_prompt(payload, action, is_final=(is_final or mode == "single_pass"))

    log.debug(
        "llm_scan: ollama request: %s",
        json.dumps({"model": MODEL, "messages": [{"role": "user", "content": prompt}], "format": "json"}, indent=2),
    )
    try:
        resp = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": 0.1, "num_predict": tuning.LLM_VERIFY_MAX_PREDICT},
        )
        log.debug("llm_scan: ollama raw response: %s", resp.message.content)
        result: dict[str, Any] = json.loads(resp.message.content or "{}")
    except Exception as exc:
        log.warning("llm_scan: step %d failed: %s", step, exc)
        result = {}

    return {
        "thought": result.get("thought", ""),
        "action": result.get("action", ""),
        "observation": result.get("observation", ""),
        "verdict": result.get("verdict", "uncertain"),
        "confidence": float(result.get("confidence", 0.0)),
        "cwe": result.get("cwe", ""),
        "early_exit": bool(result.get("early_exit", False)),
    }


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle an ``llm_scan`` request from the Go orchestrator.

    Two request shapes:
    1. Backbone probe: ``{"type": "backbone_probe"}`` → ``{"ok": true}``
    2. Scan step: ``{"surface_id": ..., "step": 1|2|3, "mode": "react"|"single_pass",
                     "taint_flow": {...}, "auth_guard": {...}, "logic_flaw": {...},
                     "prior_steps": [...], "prior_context": [...]}``
       → ``{"thought": ..., "action": ..., "observation": ..., "verdict": ...,
             "confidence": ..., "cwe": ..., "early_exit": bool}``
    """
    if payload.get("type") == "backbone_probe":
        log.debug("llm_scan: backbone probe")
        return {"ok": True}

    surface_id: str = payload.get("surface_id", "")
    step: int = int(payload.get("step", 1))
    mode: str = payload.get("mode", "react")
    is_final = (step == 3) or (mode == "single_pass")
    log.debug("llm_scan: handle", extra={"surface_id": surface_id, "step": step, "mode": mode})

    client = _get_client()
    result = _call_step(client, payload, step, is_final)
    log.debug(
        "llm_scan: step done",
        extra={"surface_id": surface_id, "step": step, "verdict": result.get("verdict"), "early_exit": result.get("early_exit")},
    )
    return result
