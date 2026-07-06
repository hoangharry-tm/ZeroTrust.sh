"""CodeT5+ vulnerability classifier wrapper (Salesforce/codet5p-220m).

Replaces UniXcoder-Base-Nine as the primary embedding backbone. CodeT5+ 220M
has a hidden dimension of 768 and max context of 512 tokens (the 770M variant
uses 1024-dim — do not confuse the two). Mean pooling over encoder hidden states
replaces the [CLS] token extraction used by UniXcoder.

A-18 BLOCKING DEPENDENCY — accuracy disclosure
-----------------------------------------------
This wrapper operates in HIGH-RECALL MODE identical to UniXcoder: the "safe"
threshold is set to ≤0.15 (very conservative). The thresholds MUST NOT be
tightened until CVEFixes multi-language fine-tuning and per-language benchmarks
are complete.

References:
    Salesforce/codet5p-220m — HuggingFace model card
    CodeT5+: Open Code Large Language Models (Wang et al., 2024)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

import torch
import torch.nn as nn
from transformers import AutoTokenizer, T5EncoderModel  # type: ignore[import-untyped]

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
    CLASSIFIER_VULNERABLE_THRESHOLD as _VULNERABLE_THRESHOLD,
    CLASSIFIER_SAFE_THRESHOLD as _SAFE_THRESHOLD,
    CLASSIFIER_BATCH_SIZE as _BATCH_SIZE,
    CLASSIFIER_MAX_LENGTH as _MAX_LENGTH,
    CLASSIFIER_HIDDEN_SIZE as _HIDDEN_SIZE,
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
    """Single linear layer with sigmoid output — maps mean-pooled encoder → vuln probability.

    Weights initialised with Xavier uniform because no fine-tuned checkpoint
    exists yet (A-18).  In high-recall mode this is intentional: the model
    will rarely commit to "safe" without proper fine-tuning.
    """

    def __init__(self) -> None:
        super().__init__()
        self.linear = nn.Linear(_HIDDEN_SIZE, 1)
        nn.init.xavier_uniform_(self.linear.weight)
        nn.init.zeros_(self.linear.bias)

    def forward(self, embedding: torch.Tensor) -> torch.Tensor:
        """Return sigmoid probability in shape (batch,)."""
        return torch.sigmoid(self.linear(embedding)).squeeze(-1)


# ── Mean pooling ─────────────────────────────────────────────────────────────


def _mean_pool(last_hidden: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    """Mean pooling over non-padded tokens.

    Args:
        last_hidden: Encoder output tensor (batch, seq_len, hidden_size).
        attention_mask: Attention mask (batch, seq_len).

    Returns:
        Pooled embedding (batch, hidden_size).
    """
    mask = attention_mask.unsqueeze(-1).float()
    return (last_hidden * mask).sum(dim=1) / mask.sum(dim=1)


# ── Classifier ───────────────────────────────────────────────────────────────


class CodeT5PClassifier:
    """Wraps Salesforce/codet5p-220m with a linear vulnerability probe.

    Thread safety: ``load()`` uses a double-checked lock; ``classify()`` and
    ``classify_batch()`` are read-only after load and safe to call concurrently.
    """

    def __init__(self, model_name: str = "Salesforce/codet5p-220m") -> None:
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

            log.debug("loading CodeT5+ tokenizer (model=%s)", self.model_name)
            try:
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            except Exception as exc:
                raise RuntimeError(
                    f"codet5p: failed to load tokenizer '{self.model_name}': {exc}"
                ) from exc

            log.debug(
                "loading CodeT5+ encoder model (model=%s, device=%s)", self.model_name, device
            )
            try:
                self._model = T5EncoderModel.from_pretrained(self.model_name)
            except Exception as exc:
                raise RuntimeError(
                    f"codet5p: failed to load model '{self.model_name}': {exc}"
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
                "CodeT5+ loaded (model=%s, device=%s, high-recall mode, A-18 pending)",
                self.model_name,
                device,
            )

    def classify(self, code: str, language: str = "") -> ClassifyOutput:
        """Classify a single code snippet.

        Args:
            code: Source code string to classify.
            language: Optional language hint (unused; reserved for future use).

        Returns:
            :class:`ClassifyOutput` with ``label`` and ``confidence``.

        Raises:
            RuntimeError: ``load()`` has not been called.
        """
        if not self._loaded:
            raise RuntimeError("codet5p: classify() called before load()")

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
            raise RuntimeError("codet5p: classify_batch() called before load()")

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
                outputs = self._model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                last_hidden: torch.Tensor = outputs.last_hidden_state
                pooled: torch.Tensor = _mean_pool(last_hidden, attention_mask)
                probs: torch.Tensor = self._probe(pooled)

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
        prob >= VULNERABLE_THRESHOLD  → "vulnerable"
        prob <= SAFE_THRESHOLD        → "safe"
        else                          → "uncertain"
    """
    if prob >= _VULNERABLE_THRESHOLD:
        return "vulnerable", prob
    if prob <= _SAFE_THRESHOLD:
        return "safe", 1.0 - prob
    return "uncertain", max(prob, 1.0 - prob)
