# Single source of truth for all numeric tuning parameters in the Python worker.
# Change values here; no other file needs to be touched.

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
