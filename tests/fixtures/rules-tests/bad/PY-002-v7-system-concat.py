# PY-002 V7: string concatenation in system= — Rule B5
# Exercises system=$A + $B pattern
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/system-concat", methods=["POST"])
def system_concat():
    """Rule B5: system= with string concatenation of user data."""
    data = request.get_json()
    role = data.get("role", "assistant")
    domain = data.get("domain", "general")

    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=300,
        system="You are a " + role + " specializing in " + domain + ".",
        messages=[
            {"role": "user", "content": "Help me."},
        ],
    )
    return jsonify({"result": response.content[0].text})
