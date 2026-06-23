# PY-003 V11: format_messages and format_prompt taint sinks — Rule A variants
# Exercises $PROMPT.format_messages(...) and $PROMPT.format_prompt(...) sinks
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/format-messages", methods=["POST"])
def format_messages_sink():
    """Rule A sink: $PROMPT.format_messages(tainted)."""
    data = request.get_json()
    user_input = data.get("input", "")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You answer questions."),
        ("human", "{input}"),
    ])
    messages = prompt.format_messages(input=user_input)
    response = llm(messages)
    return jsonify({"answer": response.content})


@app.route("/format-prompt", methods=["POST"])
def format_prompt_sink():
    """Rule A sink: $PROMPT.format_prompt(tainted)."""
    data = request.get_json()
    question = data.get("question", "")

    template = PromptTemplate(
        input_variables=["question"],
        template="Answer: {question}",
    )
    prompt_value = template.format_prompt(question=question)
    response = llm([HumanMessage(content=prompt_value.to_string())])
    return jsonify({"answer": response.content})


@app.route("/chain-call", methods=["POST"])
def chain_call_sink():
    """Rule A sink: $CHAIN(tainted) with LLM-named callable."""
    from langchain.chains import LLMChain

    template = PromptTemplate(
        input_variables=["query"],
        template="Respond to: {query}",
    )
    chain = LLMChain(llm=llm, prompt=template)
    data = request.get_json()
    query = data.get("query", "")
    result = chain(query)
    return jsonify({"result": result})
