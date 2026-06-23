# PY-006 EDGE: API key variable names but with placeholder values that should be excluded
# "test", "your_api_key_here", "<YOUR_KEY>" etc. are in the exclusion regex
# This SHOULD NOT fire because values match placeholder regex
import os

# These use placeholder values — excluded by the metavariable-regex for $CRED
# (They DON'T match the OpenAI/Anthropic/HF key format regex either)
api_key = "your_api_key_here"        # placeholder — won't match sk-proj- prefix
secret_token = "changeme"             # excluded by placeholder regex
anthropic_api_key = "YOUR_KEY_HERE"  # placeholder — won't match sk-ant- prefix

# This one uses os.environ — explicitly excluded by pattern-not
api_token = os.environ.get("MY_SERVICE_API_TOKEN", "fallback_not_a_real_key")

print("Loaded configuration with placeholder keys — safe for template repos")
