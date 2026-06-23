# PY-001 EDGE/SAFE: taint-like patterns that should NOT fire
# input() and os.environ used but NOT flowing to LLM sink
import openai
import os
import sys

client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def safe_input_usage():
    """input() reads data but it's used for non-LLM purposes."""
    filename = input("Enter filename: ")
    with open(filename) as f:
        content = f.read()
    return content


def safe_environ_usage():
    """os.environ used for config, not tainted to LLM."""
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    debug_mode = os.environ.get("DEBUG", "false")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Tell me a joke."},  # Static, not tainted
        ],
    )
    return response.choices[0].message.content


def safe_stdin_usage():
    """sys.stdin.read used for internal config, not LLM."""
    config_data = sys.stdin.read()
    import json
    config = json.loads(config_data)
    port = config.get("port", 8080)
    return port
