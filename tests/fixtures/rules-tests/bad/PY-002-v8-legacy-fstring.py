# PY-002 V8: legacy HUMAN_PROMPT with f-string and variable assembly
# Exercises Rule C2 (HUMAN_PROMPT f-string) and C3 (var assembly + completions)
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/legacy-fstring", methods=["POST"])
def legacy_fstring():
    """Rule C2: f-string with anthropic.HUMAN_PROMPT."""
    data = request.get_json()
    text = data.get("text", "")
    language = data.get("language", "French")

    prompt = f"{anthropic.HUMAN_PROMPT} Translate to {language}: {text}{anthropic.AI_PROMPT}"

    response = client.completions.create(
        model="claude-2",
        max_tokens_to_sample=200,
        prompt=prompt,
    )
    return jsonify({"translation": response.completion})


@app.route("/var-assembly", methods=["POST"])
def var_assembly():
    """Rule C3: variable assembly then completions.create(prompt=...)."""
    data = request.get_json()
    question = data.get("question", "")

    assembled = anthropic.HUMAN_PROMPT + f" Answer this: {question}" + anthropic.AI_PROMPT

    response = client.completions.create(
        model="claude-instant-1",
        max_tokens_to_sample=300,
        prompt=assembled,
    )
    return jsonify({"answer": response.completion})
