# PY-002 SAFE: Anthropic client with fully static system prompt, user input in user role
import anthropic
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

SYSTEM_PROMPT = (
    "You are a helpful legal research assistant. "
    "Summarize case law concisely and flag relevant precedents."
)


@app.route("/research", methods=["POST"])
def safe_legal_research():
    """Safe: static system prompt, user data structurally in user-role message."""
    payload = request.get_json()
    query = payload.get("query", "")[:4000]  # length-limited

    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        system=SYSTEM_PROMPT,       # Static — never contains user data
        messages=[
            {"role": "user", "content": query},  # User data in user role only
        ],
    )
    return jsonify({"result": response.content[0].text})


if __name__ == "__main__":
    app.run()
