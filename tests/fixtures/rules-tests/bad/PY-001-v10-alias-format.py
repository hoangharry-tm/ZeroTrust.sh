# PY-001 V10: alias import + .format() — Rule C2
# Exercises `from openai import OpenAI as X` with `.format()` in messages
from openai import OpenAI as Client
from flask import Flask, request, jsonify

app = Flask(__name__)
ai = Client(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/alias-format", methods=["POST"])
def alias_format():
    """Aliased client with .format() in messages content."""
    data = request.get_json()
    article = data.get("article", "")
    style = data.get("style", "formal")

    response = ai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You summarize articles."},
            {"role": "user", "content": "Summarize in {style}: {text}".format(style=style, text=article)},
        ],
    )
    return jsonify({"summary": response.choices[0].message.content})
