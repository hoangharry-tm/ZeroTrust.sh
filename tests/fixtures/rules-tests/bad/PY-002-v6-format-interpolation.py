# PY-002 V6: .format() in messages and system= — Rules B2, B4
# Exercises both .format() in messages content and system= kwarg
import anthropic
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/format-messages", methods=["POST"])
def format_in_messages():
    """Rule B2: .format() in messages content."""
    data = request.get_json()
    topic = data.get("topic", "")

    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        messages=[
            {"role": "user", "content": "Explain {topic} simply.".format(topic=topic)},
        ],
    )
    return jsonify({"explanation": response.content[0].text})


@app.route("/format-system", methods=["POST"])
def format_in_system():
    """Rule B4: .format() in system= kwarg."""
    data = request.get_json()
    expertise = data.get("expertise", "general")

    response = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=512,
        system="You are an expert in {field}.".format(field=expertise),
        messages=[
            {"role": "user", "content": "Help me with a question."},
        ],
    )
    return jsonify({"answer": response.content[0].text})
