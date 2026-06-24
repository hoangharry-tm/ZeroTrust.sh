# Single source of truth for all numeric tuning parameters in the Python worker.
# Change values here; no other file needs to be touched.

# ── UniXcoder model ───────────────────────────────────────────────────────────
UNIXCODER_VULNERABLE_THRESHOLD = 0.85
UNIXCODER_SAFE_THRESHOLD = 0.15
UNIXCODER_BATCH_SIZE = 16
UNIXCODER_MAX_LENGTH = 512
# Architecture constant — change only when retraining with a different backbone.
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
