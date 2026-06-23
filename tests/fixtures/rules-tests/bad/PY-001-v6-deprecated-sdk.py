# PY-001 V6: Legacy openai.Completion.create with user prompt
# Realistic migration-era code still using the old SDK API
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)
openai.api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"


@app.route("/translate", methods=["POST"])
def translate():
    """Translate text using legacy Completion API."""
    data = request.get_json()
    source_text = data.get("text", "")
    target_lang = data.get("target_lang", "French")

    prompt = f"Translate the following English text to {target_lang}: {source_text}"

    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=200,
    )

    translation = response.choices[0].text.strip()
    return jsonify({"translation": translation, "language": target_lang})
