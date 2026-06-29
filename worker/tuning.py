# Single source of truth for all numeric tuning parameters in the Python worker.
# Change values here; no other file needs to be touched.
# At startup, ZT_CALIBRATION env var (set by the Go host) overrides the thresholds below
# if a valid calibration JSON file exists (produced by scripts/calibrate.py).

import json as _json
import os as _os
import pathlib as _pathlib

# ── Classifier model ──────────────────────────────────────────────────────────
# Shared thresholds used by all backbones (UniXcoder, CodeT5+, etc.).
CLASSIFIER_VULNERABLE_THRESHOLD = 0.85
CLASSIFIER_SAFE_THRESHOLD = 0.15
CLASSIFIER_BATCH_SIZE = 8
CLASSIFIER_MAX_LENGTH = 1024
# Architecture constant — change only when retraining with a different backbone.
# CodeT5+ 220M: 1024 | UniXcoder (fallback): 768
CLASSIFIER_HIDDEN_SIZE = 1024
# Deprecated aliases kept for legacy model code.
UNIXCODER_VULNERABLE_THRESHOLD = CLASSIFIER_VULNERABLE_THRESHOLD
UNIXCODER_SAFE_THRESHOLD = CLASSIFIER_SAFE_THRESHOLD
UNIXCODER_BATCH_SIZE = 16
UNIXCODER_MAX_LENGTH = 512
UNIXCODER_HIDDEN_SIZE = 768

# ── LLM verify / ASC ─────────────────────────────────────────────────────────
LLM_VERIFY_TEMPERATURE = 0.1
LLM_VERIFY_MAX_PREDICT = 300
ASC_TEMPERATURES = [0.35, 0.6]
ASC_MAX_ROUNDS = 2
ASC_CONFIDENCE_THRESHOLD = 0.70

# ── Ollama client ─────────────────────────────────────────────────────────────
OLLAMA_TIMEOUT_SECONDS = 30

# ── Verdict schema validation ─────────────────────────────────────────────────
VERDICT_MAX_JUSTIFICATION_LEN = 200

# ── Runtime calibration override ──────────────────────────────────────────────
# Applied at import time; any downstream module that imports these names gets
# the calibrated values automatically.
_cal_path = _os.getenv("ZT_CALIBRATION", "")
if _cal_path and _pathlib.Path(_cal_path).exists():
    _cal = _json.loads(_pathlib.Path(_cal_path).read_text())
    CLASSIFIER_VULNERABLE_THRESHOLD = float(_cal.get("classifier_vulnerable_threshold", CLASSIFIER_VULNERABLE_THRESHOLD))
    CLASSIFIER_SAFE_THRESHOLD = float(_cal.get("classifier_safe_threshold", CLASSIFIER_SAFE_THRESHOLD))
    UNIXCODER_VULNERABLE_THRESHOLD = float(_cal.get("classifier_vulnerable_threshold", UNIXCODER_VULNERABLE_THRESHOLD))
    UNIXCODER_SAFE_THRESHOLD = float(_cal.get("classifier_safe_threshold", UNIXCODER_SAFE_THRESHOLD))
    ASC_CONFIDENCE_THRESHOLD = float(_cal.get("asc_confidence_threshold", ASC_CONFIDENCE_THRESHOLD))
