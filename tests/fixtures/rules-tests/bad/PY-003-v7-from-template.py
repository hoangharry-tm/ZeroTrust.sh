# PY-003 V7: PromptTemplate.from_template and ChatPromptTemplate.from_template
# Exercises Rules B1 (PromptTemplate.from_template f-string) and B4 (ChatPromptTemplate.from_template)
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/from-template", methods=["POST"])
def from_template():
    """Rule B1: PromptTemplate.from_template with f-string."""
    data = request.get_json()
    subject = data.get("subject", "")
    tone = data.get("tone", "professional")

    template = PromptTemplate.from_template(
        f"Write a {tone} email about {subject}. Sign off with regards."
    )
    prompt = template.format()
    response = llm([HumanMessage(content=prompt)])
    return jsonify({"email": response.content})


@app.route("/chat-template", methods=["POST"])
def chat_template():
    """Rule B4: ChatPromptTemplate.from_template with f-string."""
    data = request.get_json()
    topic = data.get("topic", "")

    prompt = ChatPromptTemplate.from_template(
        f"Answer questions about {topic} concisely."
    )
    messages = prompt.format_messages()
    response = llm(messages)
    return jsonify({"answer": response.content})
