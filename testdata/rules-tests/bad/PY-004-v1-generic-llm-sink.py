# PY-004 V1: user input → generic LLM-named function (chat_with_model)
# Realistic AI-generated sentiment analysis service — generic LLM sink detection
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
COHERE_API_KEY = os.environ.get("COHERE_API_KEY")


def chat_with_model(user_prompt: str, max_tokens: int = 200) -> str:
    """Generic wrapper around Cohere generate API."""
    headers = {
        "Authorization": f"Bearer {COHERE_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "command",
        "prompt": user_prompt,
        "max_tokens": max_tokens,
        "temperature": 0.5,
    }
    resp = requests.post(
        "https://api.cohere.ai/v1/generate",
        headers=headers,
        json=payload,
        timeout=30,
    )
    return resp.json()["generations"][0]["text"]


@app.route("/sentiment", methods=["POST"])
def analyze_sentiment():
    """Analyze text sentiment — unsanitized input flows to LLM via chat_with_model."""
    data = request.get_json()
    text_input = data.get("text", "")  # user-controlled

    # VULN: user input flows into chat_with_model (matches LLM-named sink pattern)
    result = chat_with_model(f"Analyze the sentiment of this text: {text_input}")
    return jsonify({"sentiment": result})


if __name__ == "__main__":
    app.run(port=5007)
