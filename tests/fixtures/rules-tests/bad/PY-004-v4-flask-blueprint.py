# PY-004 V4: Flask blueprint with generic LLM function (Vertex AI pattern)
# Realistic AI-generated product description generator
import os
import requests
from flask import Blueprint, request, jsonify

llm_bp = Blueprint("llm", __name__)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")


def query_model(user_prompt: str) -> str:
    """Query Gemini Pro via REST API."""
    url = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
    resp = requests.post(
        url,
        json={
            "contents": [{"parts": [{"text": user_prompt}]}],
        },
        timeout=30,
    )
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]


@llm_bp.route("/generate-description", methods=["POST"])
def generate_description():
    """Generate product description from keywords."""
    data = request.get_json()
    product_name = data.get("product_name", "")
    keywords = data.get("keywords", [])
    tone = data.get("tone", "professional")

    full_prompt = f"Write a {tone} product description for '{product_name}' with keywords: {', '.join(keywords)}"
    result = query_model(full_prompt)
    return jsonify({"description": result})
