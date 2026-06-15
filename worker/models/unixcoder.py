"""UniXcoder-Base-Nine vulnerability classifier wrapper.

A-18 blocking dependency: BigVul F1 (94.73%) is measured on C/C++ only and is
not a valid claim for Python/Java/JS/Go. Operates in high-recall mode until the
CVEFixes multi-language benchmark is complete.
"""

from __future__ import annotations


class UniXcoderClassifier:
    """Wraps the microsoft/unixcoder-base-nine model via HuggingFace transformers."""

    def __init__(self, model_name: str = "microsoft/unixcoder-base-nine") -> None:
        self.model_name = model_name
        self._model = None
        self._tokenizer = None

    def load(self) -> None:
        """Load model and tokenizer. Call once at worker startup."""
        # implemented in G3.M3.2
        raise NotImplementedError

    def classify(self, code: str) -> dict[str, object]:
        """Return {"verdict": "vulnerable"|"safe"|"uncertain", "confidence": float}."""
        # implemented in G3.M3.2
        raise NotImplementedError
