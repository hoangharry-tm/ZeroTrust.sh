# PY-002 V5: AsyncAnthropic client with user input in system= and messages
# Alternative SDK pattern with streaming response
import anthropic
from flask import Flask, request, jsonify, Response
import json

app = Flask(__name__)
client = anthropic.AsyncAnthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/chat-stream", methods=["POST"])
async def chat_stream():
    """Streaming chat with user input in both system and messages."""
    data = request.get_json()
    user_query = data.get("query", "")
    persona = data.get("persona", "helpful assistant")

    stream = await client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        system=f"You are a {persona}. Answer user questions concisely.",  # VULN
        messages=[
            {"role": "user", "content": user_query},
        ],
        stream=True,
    )

    async def generate():
        async for chunk in stream:
            if chunk.type == "content_block_delta":
                yield chunk.delta.text

    return Response(generate(), mimetype="text/event-stream")
