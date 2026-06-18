"""Unit tests for the UniXcoder classify handler and model wrapper.

Transformers is mocked throughout — no model download occurs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import torch
import torch.nn as nn

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_tokenizer() -> MagicMock:
    """Return a mock tokenizer whose __call__ produces valid token tensors."""
    tok = MagicMock()

    def _tokenize(texts: list[str], **kwargs: Any) -> dict[str, torch.Tensor]:
        batch = len(texts)
        seq = kwargs.get("max_length", 8)
        return {
            "input_ids": torch.zeros(batch, seq, dtype=torch.long),
            "attention_mask": torch.ones(batch, seq, dtype=torch.long),
        }

    tok.side_effect = _tokenize
    return tok


def _make_fake_model(hidden_size: int = 768) -> MagicMock:
    """Return a mock backbone whose forward() emits a last_hidden_state tensor."""
    model = MagicMock(spec=nn.Module)

    def _forward(
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> MagicMock:
        batch = input_ids.shape[0]
        seq = input_ids.shape[1]
        hs = torch.zeros(batch, seq, hidden_size)
        out = MagicMock()
        out.last_hidden_state = hs
        return out

    model.side_effect = _forward
    # eval() and to() must be no-ops that return the mock itself.
    model.eval.return_value = model
    model.to.return_value = model
    return model


def _reset_classifier_singleton() -> None:
    """Reset the module-level singleton so each test gets a fresh load()."""
    import handlers.classify as mod

    mod._initialised = False  # noqa: SLF001
    mod._classifier = None  # noqa: SLF001


# ---------------------------------------------------------------------------
# Tests: UniXcoderClassifier.classify() — label bands
# ---------------------------------------------------------------------------


class TestClassifyLabelBands:
    """Verify the three label thresholds using a controlled probe output."""

    def _make_classifier_with_probe_output(self, prob: float) -> Any:
        """Build a loaded classifier whose probe always returns *prob*."""
        from models.unixcoder import UniXcoderClassifier

        clf = UniXcoderClassifier(model_name="microsoft/unixcoder-base-nine")

        fake_tok = _make_fake_tokenizer()
        fake_model = _make_fake_model()

        with (
            patch("models.unixcoder.AutoTokenizer.from_pretrained", return_value=fake_tok),
            patch("models.unixcoder.AutoModel.from_pretrained", return_value=fake_model),
        ):
            clf.load(device="cpu")

        # Override the probe to always return the desired probability.
        assert clf._probe is not None  # noqa: SLF001
        clf._probe = MagicMock()  # noqa: SLF001
        clf._probe.side_effect = lambda emb: torch.full((emb.shape[0],), prob)  # noqa: SLF001
        return clf

    def test_high_prob_returns_vulnerable(self) -> None:
        clf = self._make_classifier_with_probe_output(0.90)
        out = clf.classify("x = eval(user_input)")
        assert out.label == "vulnerable"
        assert out.confidence == pytest.approx(0.90)

    def test_low_prob_returns_safe(self) -> None:
        clf = self._make_classifier_with_probe_output(0.05)
        out = clf.classify("x = int(a) + int(b)")
        assert out.label == "safe"
        assert out.confidence == pytest.approx(0.95)

    def test_mid_prob_returns_uncertain(self) -> None:
        clf = self._make_classifier_with_probe_output(0.50)
        out = clf.classify("result = db.query(f'SELECT {col}')")
        assert out.label == "uncertain"
        assert out.confidence == pytest.approx(0.50)

    def test_uncertain_confidence_uses_max(self) -> None:
        """Uncertain confidence = max(prob, 1-prob) — verified for asymmetric case."""
        clf = self._make_classifier_with_probe_output(0.30)
        out = clf.classify("some code")
        assert out.label == "uncertain"
        assert out.confidence == pytest.approx(0.70)  # max(0.30, 0.70)


# ---------------------------------------------------------------------------
# Tests: classify_batch()
# ---------------------------------------------------------------------------


class TestClassifyBatch:
    """classify_batch() preserves surface_id mapping and result count."""

    def _loaded_classifier(self, prob: float = 0.50) -> Any:
        from models.unixcoder import UniXcoderClassifier

        clf = UniXcoderClassifier()
        fake_tok = _make_fake_tokenizer()
        fake_model = _make_fake_model()

        with (
            patch("models.unixcoder.AutoTokenizer.from_pretrained", return_value=fake_tok),
            patch("models.unixcoder.AutoModel.from_pretrained", return_value=fake_model),
        ):
            clf.load(device="cpu")

        assert clf._probe is not None  # noqa: SLF001
        clf._probe = MagicMock()  # noqa: SLF001
        clf._probe.side_effect = lambda emb: torch.full((emb.shape[0],), prob)  # noqa: SLF001
        return clf

    def test_batch_length_matches_input(self) -> None:
        clf = self._loaded_classifier(0.90)
        surfaces = [
            {"surface_id": f"s{i}", "code": f"code_{i}", "language": "python"}
            for i in range(5)
        ]
        results = clf.classify_batch(surfaces)
        assert len(results) == 5

    def test_batch_surface_ids_preserved_in_order(self) -> None:
        clf = self._loaded_classifier(0.90)
        surfaces = [
            {"surface_id": "alpha", "code": "foo()", "language": "go"},
            {"surface_id": "beta", "code": "bar()", "language": "java"},
        ]
        results = clf.classify_batch(surfaces)
        assert results[0]["surface_id"] == "alpha"
        assert results[1]["surface_id"] == "beta"

    def test_batch_label_and_confidence_present(self) -> None:
        clf = self._loaded_classifier(0.90)
        surfaces = [{"surface_id": "x", "code": "eval(x)", "language": "python"}]
        result = clf.classify_batch(surfaces)[0]
        assert "label" in result
        assert "confidence" in result
        assert result["label"] == "vulnerable"


# ---------------------------------------------------------------------------
# Tests: handle()
# ---------------------------------------------------------------------------


class TestHandle:
    """Tests for handlers.classify.handle()."""

    def setup_method(self) -> None:
        _reset_classifier_singleton()

    def _patch_classifier(self, prob: float = 0.90) -> Any:
        """Context manager that replaces UniXcoderClassifier with a controlled fake."""
        from models.unixcoder import UniXcoderClassifier

        fake_clf = MagicMock(spec=UniXcoderClassifier)
        fake_clf.classify_batch.side_effect = lambda surfaces: [
            {
                "surface_id": s["surface_id"],
                "label": "vulnerable",
                "confidence": prob,
            }
            for s in surfaces
        ]
        return patch("handlers.classify._get_classifier", return_value=fake_clf)

    def test_handle_valid_payload(self) -> None:
        import handlers.classify as mod

        payload: dict[str, Any] = {
            "surfaces": [
                {"surface_id": "s1", "code": "eval(x)", "language": "python"},
                {"surface_id": "s2", "code": "safe_call()", "language": "python"},
            ]
        }
        with self._patch_classifier():
            result = mod.handle(payload)

        assert "results" in result
        assert len(result["results"]) == 2
        assert result["results"][0]["surface_id"] == "s1"

    def test_handle_empty_surfaces_returns_immediately(self) -> None:
        """Empty surfaces must short-circuit without touching the classifier."""
        import handlers.classify as mod

        with patch("handlers.classify._get_classifier") as mock_get:
            result = mod.handle({"surfaces": []})

        assert result == {"results": []}
        mock_get.assert_not_called()

    def test_handle_missing_surfaces_key_raises(self) -> None:
        import handlers.classify as mod

        with self._patch_classifier():
            with pytest.raises(KeyError):
                mod.handle({})

    def test_handle_model_load_failure_raises_runtime_error(self) -> None:
        import handlers.classify as mod

        with patch(
            "handlers.classify.UniXcoderClassifier",
        ) as MockCls:
            instance = MockCls.return_value
            instance.load.side_effect = RuntimeError("unixcoder: failed to load model")
            with pytest.raises(RuntimeError, match="failed to load model"):
                mod.handle({"surfaces": [{"surface_id": "x", "code": "x", "language": "py"}]})


# ---------------------------------------------------------------------------
# Tests: load() idempotency
# ---------------------------------------------------------------------------


class TestLoadIdempotency:
    """load() called twice must not re-download the model."""

    def test_load_twice_is_idempotent(self) -> None:
        from models.unixcoder import UniXcoderClassifier

        clf = UniXcoderClassifier()
        fake_tok = _make_fake_tokenizer()
        fake_model = _make_fake_model()

        with (
            patch(
                "models.unixcoder.AutoTokenizer.from_pretrained", return_value=fake_tok
            ) as mock_tok,
            patch(
                "models.unixcoder.AutoModel.from_pretrained", return_value=fake_model
            ) as mock_model,
        ):
            clf.load(device="cpu")
            clf.load(device="cpu")  # second call must be a no-op

        mock_tok.assert_called_once()
        mock_model.assert_called_once()
