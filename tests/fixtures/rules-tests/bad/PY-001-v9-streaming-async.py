# PY-001 V9: streaming variants (B5, B6) + async legacy acreate sink
# Exercises Rules B5, B6 and the openai.ChatCompletion.acreate sink
import openai
from flask import Flask, request, jsonify, Response
import asyncio

app = Flask(__name__)


@app.route("/legacy-stream", methods=["POST"])
def legacy_stream():
    """Legacy SDK streaming with f-string — Rule B5."""
    data = request.get_json()
    prompt = data.get("prompt", "")

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Tell me about: {prompt}"},
        ],
        stream=True,
    )

    def generate():
        for chunk in response:
            if chunk.choices[0].delta.get("content"):
                yield chunk.choices[0].delta.content

    return Response(generate(), mimetype="text/plain")


@app.route("/new-sdk-stream", methods=["POST"])
def new_sdk_stream():
    """New SDK streaming with f-string — Rule B6."""
    data = request.get_json()
    query = data.get("query", "")

    client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")
    stream = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Answer: {query}"},
        ],
        stream=True,
    )

    def generate():
        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    return Response(generate(), mimetype="text/plain")


async def async_legacy_sink():
    """Async legacy sink: openai.ChatCompletion.acreate — covers Rule A sink variant."""
    response = await openai.ChatCompletion.acreate(
        model="gpt-4",
        messages=[
            {"role": "user", "content": "test"},
        ],
    )
    return response.choices[0].message.content
