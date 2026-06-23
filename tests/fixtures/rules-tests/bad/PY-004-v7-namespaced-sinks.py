# PY-004 V7: additional namespaced sink variants
# Exercises more openai.$ANY and anthropic sink patterns
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/openai-chat-create", methods=["POST"])
def openai_chat():
    """openai.ChatCompletion.create as openai.$ANY sink."""
    import openai
    data = request.get_json()
    message = data.get("message", "")
    openai.api_key = "sk-test"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": message}],
    )
    return jsonify({"reply": response.choices[0].message.content})


@app.route("/openai-embed", methods=["POST"])
def openai_embed():
    """openai.Embedding.create as openai.$ANY sink."""
    import openai
    data = request.get_json()
    text = data.get("text", "")
    openai.api_key = "sk-test"
    response = openai.Embedding.create(
        model="text-embedding-ada-002",
        input=text,
    )
    return jsonify({"embedding": response.data[0].embedding})


@app.route("/anthropic-async-sink", methods=["POST"])
def anthropic_async_sink():
    """AsyncAnthropic sink pattern with import anthropic."""
    import anthropic
    client = anthropic.AsyncAnthropic(api_key="sk-ant-test")
    data = request.get_json()
    query = data.get("query", "")

    async def call():
        resp = await client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=256,
            messages=[{"role": "user", "content": query}],
        )
        return resp.content[0].text

    import asyncio
    result = asyncio.run(call())
    return jsonify({"result": result})
