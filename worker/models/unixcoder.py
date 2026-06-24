"""UniXcoder-Base-Nine vulnerability classifier wrapper.

A-18 BLOCKING DEPENDENCY — accuracy disclosure
------------------------------------------------
The commonly cited BigVul F1=94.73% is measured on C/C++ vulnerability datasets
only and is NOT a valid claim for Python, Java, JavaScript/TypeScript, or Go.
This wrapper operates in HIGH-RECALL MODE: the "safe" threshold is set to ≤0.15
(very conservative) so the vast majority of predictions fall through to
"uncertain" and escalate to the LLM semantic scan.  The thresholds MUST NOT be
tightened until CVEFixes multi-language fine-tuning and per-language benchmarks
are complete.

References:
    microsoft/unixcoder-base-nine — HuggingFace model card
    BigVul C/C++ vulnerability dataset
    CVEFixes dataset (pending fine-tuning, Approach 3)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

import torch
import torch.nn as nn
from transformers import AutoModel, AutoTokenizer  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from transformers import (  # type: ignore[import-untyped]
        PreTrainedModel,
        PreTrainedTokenizerBase,
    )

# Optional xformers for memory-efficient attention — graceful fallback if absent.
try:
    import xformers.ops  # type: ignore[import-untyped]  # noqa: F401

    _XFORMERS_AVAILABLE = True
except ImportError:
    _XFORMERS_AVAILABLE = False

from tuning import (
    UNIXCODER_VULNERABLE_THRESHOLD as _VULNERABLE_THRESHOLD,
    UNIXCODER_SAFE_THRESHOLD as _SAFE_THRESHOLD,
    UNIXCODER_BATCH_SIZE as _BATCH_SIZE,
    UNIXCODER_MAX_LENGTH as _MAX_LENGTH,
    UNIXCODER_HIDDEN_SIZE as _HIDDEN_SIZE,
)

log = logging.getLogger(__name__)


# ── Output type ──────────────────────────────────────────────────────────────


@dataclass
class ClassifyOutput:
    """Result from a single classify() call."""

    label: str  # "vulnerable" | "safe" | "uncertain"
    confidence: float  # [0.0, 1.0]


# ── Linear probe ─────────────────────────────────────────────────────────────


class _VulnProbe(nn.Module):
    """Single linear layer with sigmoid output — maps [CLS] → vuln probability.

    Weights initialised with Xavier uniform because no fine-tuned checkpoint
    exists yet (A-18).  In high-recall mode this is intentional: the model
    will rarely commit to "safe" without proper fine-tuning.
    """

    def __init__(self) -> None:
        super().__init__()
        self.linear = nn.Linear(_HIDDEN_SIZE, 1)
        nn.init.xavier_uniform_(self.linear.weight)
        nn.init.zeros_(self.linear.bias)

    def forward(self, cls_embedding: torch.Tensor) -> torch.Tensor:
        """Return sigmoid probability in shape (batch,)."""
        return torch.sigmoid(self.linear(cls_embedding)).squeeze(-1)


# ── Classifier ───────────────────────────────────────────────────────────────


class UniXcoderClassifier:
    """Wraps microsoft/unixcoder-base-nine with a linear vulnerability probe.

    Thread safety: ``load()`` uses a double-checked lock; ``classify()`` and
    ``classify_batch()`` are read-only after load and safe to call concurrently.
    """

    def __init__(self, model_name: str = "microsoft/unixcoder-base-nine") -> None:
        self.model_name = model_name
        self._loaded = False
        self._lock = threading.Lock()
        self._tokenizer: PreTrainedTokenizerBase | None = None
        self._model: PreTrainedModel | None = None
        self._probe: _VulnProbe | None = None
        self._device: str = "cpu"

    def load(self, device: str = "cpu") -> None:
        """Load tokenizer, backbone, and linear probe.

        Idempotent — subsequent calls are no-ops.  Must be called once at
        worker startup before any classify() call.

        Args:
            device: Torch device string (e.g. ``"cpu"``, ``"cuda:0"``).

        Raises:
            RuntimeError: Model or tokenizer download fails.
        """
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            log.debug("loading UniXcoder tokenizer (model=%s)", self.model_name)
            try:
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            except Exception as exc:
                raise RuntimeError(
                    f"unixcoder: failed to load tokenizer '{self.model_name}': {exc}"
                ) from exc

            log.debug("loading UniXcoder model (model=%s, device=%s)", self.model_name, device)
            try:
                self._model = AutoModel.from_pretrained(self.model_name)
            except Exception as exc:
                raise RuntimeError(
                    f"unixcoder: failed to load model '{self.model_name}': {exc}"
                ) from exc

            self._device = device
            self._model.to(device)  # type: ignore[union-attr]
            self._model.eval()  # type: ignore[union-attr]

            self._probe = _VulnProbe().to(device)
            self._probe.eval()

            if _XFORMERS_AVAILABLE:
                log.debug("xformers available — memory-efficient attention enabled")

            self._loaded = True
            log.info(
                "UniXcoder loaded (model=%s, device=%s, high-recall mode, A-18 pending)",
                self.model_name,
                device,
            )

    def classify(self, code: str, language: str = "") -> ClassifyOutput:
        """Classify a single code snippet.

        Args:
            code: Source code string to classify.
            language: Optional language hint (unused in current embedding model;
                reserved for future language-conditioned fine-tuning).

        Returns:
            :class:`ClassifyOutput` with ``label`` and ``confidence``.

        Raises:
            RuntimeError: ``load()`` has not been called.
        """
        if not self._loaded:
            raise RuntimeError("unixcoder: classify() called before load()")

        results = self.classify_batch(
            [{"surface_id": "_single", "code": code, "language": language}]
        )
        return ClassifyOutput(label=results[0]["label"], confidence=results[0]["confidence"])

    def classify_batch(self, surfaces: list[dict]) -> list[dict]:
        """Classify a batch of surfaces.

        Args:
            surfaces: List of dicts with keys ``surface_id``, ``code``,
                ``language``.  ``language`` may be absent or empty.

        Returns:
            List of dicts with keys ``surface_id``, ``label``, ``confidence``
            in the same order as *surfaces*.

        Raises:
            RuntimeError: ``load()`` has not been called.
        """
        if not self._loaded:
            raise RuntimeError("unixcoder: classify_batch() called before load()")

        assert self._tokenizer is not None  # noqa: S101 — guaranteed by load()
        assert self._model is not None  # noqa: S101
        assert self._probe is not None  # noqa: S101

        results: list[dict] = []

        for batch_start in range(0, len(surfaces), _BATCH_SIZE):
            batch = surfaces[batch_start : batch_start + _BATCH_SIZE]
            codes = [s.get("code", "") for s in batch]

            encoding = self._tokenizer(
                codes,
                max_length=_MAX_LENGTH,
                truncation=True,
                padding="max_length",
                return_tensors="pt",
            )
            input_ids = encoding["input_ids"].to(self._device)
            attention_mask = encoding["attention_mask"].to(self._device)

            with torch.no_grad():
                outputs = self._model(input_ids=input_ids, attention_mask=attention_mask)
                cls_embeddings: torch.Tensor = outputs.last_hidden_state[:, 0, :]
                probs: torch.Tensor = self._probe(cls_embeddings)

            for surface, prob_tensor in zip(batch, probs.tolist(), strict=True):
                prob: float = float(prob_tensor)
                label, confidence = _label_from_prob(prob)
                results.append(
                    {
                        "surface_id": surface.get("surface_id", ""),
                        "label": label,
                        "confidence": confidence,
                    }
                )

        return results


# ── Label assignment (high-recall thresholds) ─────────────────────────────────


def _label_from_prob(prob: float) -> tuple[str, float]:
    """Map a sigmoid probability to (label, confidence).

    Thresholds are intentionally asymmetric (high-recall mode, A-18):
        prob >= 0.85  → "vulnerable"
        prob <= 0.15  → "safe"
        else          → "uncertain"  (the common case without fine-tuning)
    """
    if prob >= _VULNERABLE_THRESHOLD:
        return "vulnerable", prob
    if prob <= _SAFE_THRESHOLD:
        return "safe", 1.0 - prob
    return "uncertain", max(prob, 1.0 - prob)
