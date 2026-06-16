# PY-006 V1/A: hardcoded OpenAI API key assigned to a variable
# Realistic AI-generated content moderation service — key leaked in source
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULN: hardcoded OpenAI key — will be flagged by PY-006-openai
OPENAI_API_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh"
openai.api_key = OPENAI_API_KEY

MODERATION_SYSTEM_PROMPT = (
    "You are a content moderation assistant. Classify the given text as "
    "SAFE, BORDERLINE, or UNSAFE. Return only the classification."
)


@app.route("/moderate", methods=["POST"])
def moderate_content():
    """Moderate user-submitted content."""
    data = request.get_json()
    content = data.get("content", "")

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": MODERATION_SYSTEM_PROMPT},
            {"role": "user", "content": content},
        ],
        max_tokens=10,
    )
    verdict = response.choices[0].message.content.strip()
    return jsonify({"verdict": verdict})


if __name__ == "__main__":
    app.run(port=5008)
