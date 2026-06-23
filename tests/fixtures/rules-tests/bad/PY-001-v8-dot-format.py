# PY-001 V8: .format() interpolation variants — Rules B2, B4
# Exercises both legacy and new SDK with .format() in messages
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)
client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/legacy-format", methods=["POST"])
def legacy_format():
    """Legacy SDK: openai.ChatCompletion.create with .format() content."""
    data = request.get_json()
    user_input = data.get("text", "")

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a translator."},
            {"role": "user", "content": "Translate this: {input}".format(input=user_input)},
        ],
    )
    return jsonify({"result": response.choices[0].message.content})


@app.route("/new-sdk-format", methods=["POST"])
def new_sdk_format():
    """New SDK: client.chat.completions.create with .format() content."""
    data = request.get_json()
    query = data.get("query", "")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You answer questions."},
            {"role": "user", "content": "Answer: {q}".format(q=query)},
        ],
    )
    return jsonify({"result": response.choices[0].message.content})
