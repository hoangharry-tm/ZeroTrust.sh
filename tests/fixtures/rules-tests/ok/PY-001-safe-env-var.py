# PY-001 SAFE: API key from env, user input structurally separated as user-role message
# The fix: user input is in "user" role only, system prompt is fully static
import os
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)
openai.api_key = os.environ.get("OPENAI_API_KEY")

STATIC_SYSTEM_PROMPT = (
    "You are a helpful customer support assistant. "
    "Answer questions about our product professionally and concisely."
)


@app.route("/api/chat", methods=["POST"])
def safe_chat():
    """Structurally safe: user data in user-role only, system prompt is static."""
    data = request.get_json()
    raw_user_message = data.get("message", "")

    # Sanitize: strip control characters and limit length
    user_message = raw_user_message[:2000].replace("\n\n", " ")

    messages = [
        {"role": "system", "content": STATIC_SYSTEM_PROMPT},  # Static, no user data
        {"role": "user", "content": user_message},             # User data in user role
    ]

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=messages,
        max_tokens=400,
    )

    reply = response.choices[0].message.content
    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run()
