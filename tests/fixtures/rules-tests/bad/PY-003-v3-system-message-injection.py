# PY-003 V/C: SystemMessage constructed with f-string containing user-controlled data
# Realistic AI-generated roleplay assistant — system prompt injection
from langchain.schema import SystemMessage, HumanMessage, AIMessage
from langchain.chat_models import ChatOpenAI
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(model_name="gpt-4", openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/roleplay", methods=["POST"])
def roleplay_session():
    """Interactive roleplay session with custom persona."""
    data = request.get_json()
    persona = data.get("persona", "assistant")
    initial_scene = data.get("scene", "")
    user_message = data.get("message", "")

    # VULN: user-controlled 'persona' and 'initial_scene' injected into SystemMessage
    system_msg = SystemMessage(content=f"You are a {persona}. Scene: {initial_scene}")

    messages = [
        system_msg,  # VULN: user data in system role
        HumanMessage(content=user_message),
    ]

    response = llm(messages)
    return jsonify({"response": response.content})


if __name__ == "__main__":
    app.run(port=5006)
