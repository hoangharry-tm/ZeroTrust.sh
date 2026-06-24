"""LLM Verifier handler — CoD + SCoT reasoning with XGrammar-2 output enforcement.

Receives a finding from the Go orchestrator, calls a local Ollama model with a
Chain-of-Draft + Structured-Chain-of-Thought prompt, parses the result through
GrammarEnforcer, and runs Adaptive Self-Consistency (ASC) if the initial verdict
is uncertain or below the confidence threshold.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

import ollama

from models.xgrammar import GrammarEnforcer
from schemas.verdict import LLMVerdict, LLMVerifierResult

import tuning

log = logging.getLogger(__name__)

# ── Environment-driven configuration ─────────────────────────────────────────

OLLAMA_URL: str = os.getenv("ZEROTRUST_OLLAMA_URL", "http://localhost:11434")
MODEL: str = os.getenv("ZEROTRUST_MODEL", "qwen2.5:3b")

# ── Module-level lazy singletons ──────────────────────────────────────────────

_init_lock = threading.Lock()
_initialised = False
_client: ollama.Client | None = None
_enforcer: GrammarEnforcer[LLMVerifierResult] | None = None

# ASC resampling temperatures for rounds 1 and 2 (index 0 = first extra round).
_ASC_TEMPERATURES: list[float] = tuning.ASC_TEMPERATURES


def _get_client() -> ollama.Client:
    """Return the module-level Ollama client, initialising it on first call."""
    global _client, _enforcer, _initialised  # noqa: PLW0603

    if _initialised:
        # Fast path — no lock needed after first init.
        assert _client is not None  # noqa: S101 — guaranteed by init block below
        return _client

    with _init_lock:
        if _initialised:
            assert _client is not None  # noqa: S101
            return _client

        log.debug("initialising Ollama client (url=%s, model=%s)", OLLAMA_URL, MODEL)
        _client = ollama.Client(host=OLLAMA_URL, timeout=tuning.OLLAMA_TIMEOUT_SECONDS)

        log.debug("initialising GrammarEnforcer for LLMVerifierResult")
        _enforcer = GrammarEnforcer(LLMVerifierResult)
        _enforcer.compile()

        _initialised = True
        return _client


def _get_enforcer() -> GrammarEnforcer[LLMVerifierResult]:
    """Return the module-level GrammarEnforcer, guaranteed initialised."""
    _get_client()  # ensures _enforcer is set
    assert _enforcer is not None  # noqa: S101
    return _enforcer


# ── Prompt construction ───────────────────────────────────────────────────────

def _build_prompt(payload: dict[str, Any]) -> str:
    """Build the CoD + SCoT prompt for the given finding payload.

    Chain of Draft keeps each reasoning step to a single sentence.
    SCoT structures the flow: SOURCE → FLOW → GUARD → VERDICT.
    """
    rule_id: str = payload.get("rule_id", "")
    cwe: str = payload.get("cwe", "")
    file_path: str = payload.get("file_path", "")
    matched_code: str = payload.get("matched_code", "")
    justification: str = payload.get("justification", "")

    justification_context = (
        f"Context: {justification}" if justification else ""
    )

    return (
        "You are a security code analyzer. "
        "Determine whether the following code pattern is a real vulnerability.\n\n"
        "FINDING\n"
        f"Rule: {rule_id}  CWE: {cwe}\n"
        f"File: {file_path}\n"
        "Code:\n"
        f"{matched_code}\n"
        f"{justification_context}\n\n"
        "ANALYSIS — one sentence per step:\n"
        "1. SOURCE: What is the untrusted input entering this code?\n"
        "2. FLOW: Does tainted data reach the dangerous operation?\n"
        "3. GUARD: Is there sanitization, encoding, or parameterization between source and sink?\n"
        "4. VERDICT: confirmed / false_positive / uncertain — and why in ≤20 words.\n\n"
        "Respond ONLY with JSON."
    )


# ── Single Ollama call ────────────────────────────────────────────────────────

def _call_ollama(
    client: ollama.Client,
    enforcer: GrammarEnforcer[LLMVerifierResult],
    prompt: str,
    finding_id: str,
    temperature: float = tuning.LLM_VERIFY_TEMPERATURE,
) -> LLMVerifierResult:
    """Make one Ollama chat call and parse the result through the enforcer.

    On JSON parse failure retries once in plain ``format="json"`` mode.

    Raises:
        RuntimeError: Ollama is unreachable.
        ValueError: Schema mismatch after both attempts.
    """
    options = {"temperature": temperature, "num_predict": tuning.LLM_VERIFY_MAX_PREDICT}

    def _chat(fmt: Any) -> str:
        try:
            response = client.chat(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                format=fmt,
                options=options,
            )
        except (ConnectionError, OSError) as exc:
            raise RuntimeError(
                f"llm_verify: ollama unreachable (finding_id={finding_id}): {exc}"
            ) from exc
        return response.message.content or ""

    raw = _chat(enforcer.json_schema)
    try:
        return enforcer.parse(raw)
    except ValueError:
        log.warning(
            "llm_verify: JSON parse failed on first attempt (finding_id=%s)"
            " — retrying with format=json",
            finding_id,
        )
        raw2 = _chat("json")
        try:
            return enforcer.parse(raw2)
        except ValueError as exc:
            raise ValueError(
                f"llm_verify: schema mismatch (finding_id={finding_id}): {exc}"
            ) from exc


# ── Adaptive Self-Consistency ─────────────────────────────────────────────────

def _run_asc(
    client: ollama.Client,
    enforcer: GrammarEnforcer[LLMVerifierResult],
    prompt: str,
    initial: LLMVerifierResult,
    finding_id: str,
    asc_max_rounds: int,
) -> LLMVerifierResult:
    """Run Adaptive Self-Consistency if the initial verdict warrants it.

    Collects up to *asc_max_rounds* additional samples at escalating temperatures,
    then applies majority voting.  The ``asc_rounds`` field on the returned result
    records how many extra rounds were actually executed.

    When all samples (including initial) are ``uncertain``, the returned verdict
    is ``uncertain`` with the average confidence.
    """
    samples: list[LLMVerifierResult] = [initial]
    rounds_done = 0

    for i in range(min(asc_max_rounds, len(_ASC_TEMPERATURES))):
        temp = _ASC_TEMPERATURES[i]
        log.debug(
            "llm_verify: ASC round %d (temp=%.2f, finding_id=%s)",
            i + 1,
            temp,
            finding_id,
        )
        try:
            sample = _call_ollama(client, enforcer, prompt, finding_id, temperature=temp)
        except (RuntimeError, ValueError) as exc:
            log.warning("llm_verify: ASC round %d failed: %s", i + 1, exc)
            break
        samples.append(sample)
        rounds_done += 1

    # Majority vote — exclude uncertain when any non-uncertain exists.
    non_uncertain = [s for s in samples if s.verdict != LLMVerdict.UNCERTAIN]
    avg_conf = sum(s.confidence for s in samples) / len(samples)

    if non_uncertain:
        # Tally non-uncertain verdicts.
        from collections import Counter

        tally: Counter[LLMVerdict] = Counter(s.verdict for s in non_uncertain)
        majority_verdict, _ = tally.most_common(1)[0]
        majority_conf = sum(
            s.confidence for s in non_uncertain if s.verdict == majority_verdict
        ) / sum(1 for s in non_uncertain if s.verdict == majority_verdict)
        # Pick the justification from the highest-confidence majority sample.
        best = max(
            (s for s in non_uncertain if s.verdict == majority_verdict),
            key=lambda s: s.confidence,
        )
        return LLMVerifierResult(
            verdict=majority_verdict,
            confidence=majority_conf,
            justification=best.justification,
            asc_rounds=rounds_done,
        )

    # All uncertain — average confidence, keep justification from initial.
    return LLMVerifierResult(
        verdict=LLMVerdict.UNCERTAIN,
        confidence=avg_conf,
        justification=initial.justification,
        asc_rounds=rounds_done,
    )


# ── Public handler ────────────────────────────────────────────────────────────

def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle an ``llm_verify`` request from the Go orchestrator.

    Expected payload fields:
        finding_id (str): Unique ID for this finding — used in error messages.
        rule_id (str): OpenGrep/ast-grep rule that triggered the finding.
        cwe (str): CWE identifier (e.g. ``"CWE-89"``).
        matched_code (str): The code snippet that matched the rule.
        justification (str): Optional context from the pattern matcher.
        file_path (str): Source file that contains the matched code.
        asc_max_rounds (int): Maximum extra ASC rounds (default 2).
        asc_confidence_threshold (float): Trigger ASC when confidence is below this (default 0.70).

    Returns:
        A dict matching :class:`schemas.verdict.LLMVerifierResult` plus ``finding_id``.

    Raises:
        RuntimeError: Ollama is unreachable.
        ValueError: The LLM response does not conform to the expected schema.
    """
    finding_id: str = str(payload.get("finding_id", ""))
    asc_max_rounds: int = int(payload.get("asc_max_rounds", tuning.ASC_MAX_ROUNDS))
    asc_confidence_threshold: float = float(payload.get("asc_confidence_threshold", tuning.ASC_CONFIDENCE_THRESHOLD))

    client = _get_client()
    enforcer = _get_enforcer()
    prompt = _build_prompt(payload)

    log.debug("llm_verify: initial call (finding_id=%s)", finding_id)
    initial = _call_ollama(client, enforcer, prompt, finding_id, temperature=tuning.LLM_VERIFY_TEMPERATURE)

    needs_asc = (
        initial.verdict == LLMVerdict.UNCERTAIN
        or initial.confidence < asc_confidence_threshold
    )

    if needs_asc and asc_max_rounds > 0:
        log.debug(
            "llm_verify: triggering ASC (verdict=%s, confidence=%.2f, finding_id=%s)",
            initial.verdict,
            initial.confidence,
            finding_id,
        )
        result = _run_asc(
            client,
            enforcer,
            prompt,
            initial,
            finding_id,
            asc_max_rounds,
        )
    else:
        result = initial

    out = result.model_dump()
    out["finding_id"] = finding_id
    return out
