# Single source of truth for all numeric tuning parameters in the Python worker.
# Change values here; no other file needs to be touched.
# At startup, ZT_CONFIG_PATH env var (set by the Go host) loads ALL parameters
# from calibration.json — the same file that governs the Go side.

import json as _json
import os as _os
import pathlib as _pathlib

# ── Classifier model ──────────────────────────────────────────────────────────
CLASSIFIER_VULNERABLE_THRESHOLD = 0.80
CLASSIFIER_SAFE_THRESHOLD = 0.20
CLASSIFIER_BATCH_SIZE = 8
CLASSIFIER_MAX_LENGTH = 1024
# Architecture constant — change only when retraining with a different backbone.
# CodeT5+ 220M: 1024 | UniXcoder (fallback): 768
CLASSIFIER_HIDDEN_SIZE = 768  # codet5p-220m actual hidden dim; 770m variant uses 1024
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

# ── Runtime override from calibration.json (ZT_CONFIG_PATH) ──────────────────
# Applied at import time; any downstream module that imports these names gets
# the calibrated values automatically.
_cfg_path = _os.getenv("ZT_CONFIG_PATH", "")
if _cfg_path and _pathlib.Path(_cfg_path).exists():
    _cfg = _json.loads(_pathlib.Path(_cfg_path).read_text())
    CLASSIFIER_VULNERABLE_THRESHOLD = float(_cfg.get("classifier_vulnerable_threshold", CLASSIFIER_VULNERABLE_THRESHOLD))
    CLASSIFIER_SAFE_THRESHOLD = float(_cfg.get("classifier_safe_threshold", CLASSIFIER_SAFE_THRESHOLD))
    CLASSIFIER_BATCH_SIZE = int(_cfg.get("classifier_batch_size", CLASSIFIER_BATCH_SIZE))
    CLASSIFIER_MAX_LENGTH = int(_cfg.get("classifier_max_length", CLASSIFIER_MAX_LENGTH))
    CLASSIFIER_HIDDEN_SIZE = int(_cfg.get("classifier_hidden_size", CLASSIFIER_HIDDEN_SIZE))
    UNIXCODER_VULNERABLE_THRESHOLD = CLASSIFIER_VULNERABLE_THRESHOLD
    UNIXCODER_SAFE_THRESHOLD = CLASSIFIER_SAFE_THRESHOLD
    LLM_VERIFY_TEMPERATURE = float(_cfg.get("llm_verify_temperature", LLM_VERIFY_TEMPERATURE))
    LLM_VERIFY_MAX_PREDICT = int(_cfg.get("llm_verify_max_predict", LLM_VERIFY_MAX_PREDICT))
    ASC_TEMPERATURES = _cfg.get("asc_temperatures", ASC_TEMPERATURES)
    ASC_MAX_ROUNDS = int(_cfg.get("asc_max_rounds", ASC_MAX_ROUNDS))
    ASC_CONFIDENCE_THRESHOLD = float(_cfg.get("asc_confidence_threshold", ASC_CONFIDENCE_THRESHOLD))
    OLLAMA_TIMEOUT_SECONDS = int(_cfg.get("ollama_timeout_seconds", OLLAMA_TIMEOUT_SECONDS))
    VERDICT_MAX_JUSTIFICATION_LEN = int(_cfg.get("verdict_max_justification_len", VERDICT_MAX_JUSTIFICATION_LEN))
