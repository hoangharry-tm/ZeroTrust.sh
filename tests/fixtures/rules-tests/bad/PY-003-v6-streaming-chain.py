# PY-003 V6: LangChain streaming chain with user input via chain.stream
# Alternative pattern: .stream() and .invoke() with user-controlled data
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema import StrOutputParser
from flask import Flask, request, jsonify, Response
import os

app = Flask(__name__)
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/stream-chat", methods=["POST"])
def stream_chat():
    """Streaming chat with user input in prompt template."""
    data = request.get_json()
    user_input = data.get("message", "")
    context = data.get("context", "")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("human", f"Context: {context}\n\nUser: {user_input}"),
    ])

    chain = prompt | llm | StrOutputParser()

    def generate():
        for chunk in chain.stream({}):
            yield chunk

    return Response(generate(), mimetype="text/event-stream")


@app.route("/invoke-chain", methods=["POST"])
def invoke_chain():
    """Invoke chain with user data in input dict."""
    data = request.get_json()
    query = data.get("query", "")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "Answer the user's query."),
        ("human", "{query}"),
    ])
    chain = prompt | llm | StrOutputParser()
    result = chain.invoke({"query": query})
    return jsonify({"result": result})
