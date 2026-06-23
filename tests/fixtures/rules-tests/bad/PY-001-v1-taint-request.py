# PY-001 V1: taint from request.get_json() flows into openai chat completion
# Realistic AI-generated Flask endpoint — vulnerable to prompt injection
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)
openai.api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"

SYSTEM_PROMPT = """You are a helpful customer support assistant for AcmeCorp.
Answer questions politely and escalate to human support if needed."""


@app.route("/api/support", methods=["POST"])
def support_chat():
    """Customer support chatbot endpoint."""
    data = request.get_json()
    user_message = data.get("message", "")

    # Build messages for the LLM — user content flows directly here
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},  # VULN: unsanitized user input
    ]

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=messages,  # tainted via user_message
        max_tokens=500,
        temperature=0.7,
    )

    reply = response.choices[0].message.content
    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run(debug=False)
