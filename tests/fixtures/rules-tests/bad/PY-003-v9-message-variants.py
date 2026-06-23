# PY-003 V9: Message object variants — Rules C2 through C6
# Exercises positional SystemMessage, .format(), concat, HumanMessage, AIMessage
from langchain.schema import SystemMessage, HumanMessage, AIMessage
from langchain.chat_models import ChatOpenAI
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(model_name="gpt-4", openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/positional-system", methods=["POST"])
def positional_system():
    """Rule C2: SystemMessage(f"...") with positional arg."""
    data = request.get_json()
    persona = data.get("persona", "assistant")

    msg = SystemMessage(f"You are a {persona}. Be helpful.")
    response = llm([msg, HumanMessage(content="Hello")])
    return jsonify({"response": response.content})


@app.route("/format-system", methods=["POST"])
def format_system():
    """Rule C3: SystemMessage(content="...".format(...))."""
    data = request.get_json()
    role = data.get("role", "expert")

    msg = SystemMessage(content="You are an {role} in this domain.".format(role=role))
    response = llm([msg, HumanMessage(content="Help me.")])
    return jsonify({"response": response.content})


@app.route("/concat-system", methods=["POST"])
def concat_system():
    """Rule C4: SystemMessage(content=$A + $B) concatenation."""
    data = request.get_json()
    specialization = data.get("specialization", "general")

    msg = SystemMessage(content="You are an expert in " + specialization + ".")
    response = llm([msg, HumanMessage(content="Advise me.")])
    return jsonify({"response": response.content})


@app.route("/human-message", methods=["POST"])
def human_message():
    """Rule C5: HumanMessage(content=f"...")."""
    data = request.get_json()
    user_text = data.get("text", "")

    msg = HumanMessage(content=f"Analyze this: {user_text}")
    response = llm([SystemMessage(content="You are an analyst."), msg])
    return jsonify({"analysis": response.content})


@app.route("/ai-message", methods=["POST"])
def ai_message():
    """Rule C6: AIMessage(content=f"...") — prefill injection."""
    data = request.get_json()
    prefill = data.get("prefill", "")

    msg = AIMessage(content=f"I will respond as follows: {prefill}")
    response = llm([HumanMessage(content="Tell me something."), msg])
    return jsonify({"response": response.content})
