# PY-003 V8: .format() in PromptTemplate and ChatPromptTemplate.from_messages
# Exercises Rules B3 (PromptTemplate .format()) and B6 (ChatPromptTemplate .format() tuple)
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(temperature=0.7, openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/format-template", methods=["POST"])
def format_template():
    """Rule B3: PromptTemplate(template="...".format(...))."""
    data = request.get_json()
    name = data.get("name", "customer")
    product = data.get("product", "product")

    template = PromptTemplate(
        input_variables=[],
        template="Generate a sales pitch for {name} about {product}.".format(name=name, product=product),
    )
    prompt = template.format()
    response = llm([HumanMessage(content=prompt)])
    return jsonify({"pitch": response.content})


@app.route("/format-messages", methods=["POST"])
def format_messages_tuple():
    """Rule B6: ChatPromptTemplate.from_messages with .format() in tuple."""
    data = request.get_json()
    context = data.get("context", "")
    question = data.get("question", "")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("human", "Context: {ctx}\nQuestion: {q}".format(ctx=context, q=question)),
    ])
    messages = prompt.format_messages()
    response = llm(messages)
    return jsonify({"answer": response.content})
