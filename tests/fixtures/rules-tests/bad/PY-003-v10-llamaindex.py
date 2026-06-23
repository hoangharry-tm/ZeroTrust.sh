# PY-003 V10: LlamaIndex query variants — Rules D1 through D4
# Exercises $ENGINE.query(), $INDEX.query(), .format(), concat variants
from langchain.chat_models import ChatOpenAI
from flask import Flask, request, jsonify
import os

app = Flask(__name__)


class MockQueryEngine:
    """Minimal mock to exercise LlamaIndex sink patterns."""

    def query(self, query_str: str):
        return {"result": f"queried: {query_str}"}


class MockIndex:
    """Minimal mock to exercise LlamaIndex sink patterns."""

    def query(self, query_str: str):
        return {"result": f"indexed: {query_str}"}

    def as_query_engine(self):
        return MockQueryEngine()


engine = MockQueryEngine()
index = MockIndex()


@app.route("/engine-query-fstring", methods=["POST"])
def engine_query_fstring():
    """Rule D1: $ENGINE.query(f"...")."""
    data = request.get_json()
    query_text = data.get("query", "")

    result = engine.query(f"Search for: {query_text}")
    return jsonify(result)


@app.route("/engine-query-format", methods=["POST"])
def engine_query_format():
    """Rule D2: $ENGINE.query("...".format(...))."""
    data = request.get_json()
    search_term = data.get("term", "")

    result = engine.query("Find documents about {term}.".format(term=search_term))
    return jsonify(result)


@app.route("/index-as-query-engine", methods=["POST"])
def index_as_query_engine():
    """Rule D3: $INDEX.as_query_engine().query(f"...")."""
    data = request.get_json()
    topic = data.get("topic", "")

    result = index.as_query_engine().query(f"Summarize: {topic}")
    return jsonify(result)


@app.route("/index-query-concat", methods=["POST"])
def index_query_concat():
    """Rule D4: $INDEX.query($A + $B)."""
    data = request.get_json()
    prefix = data.get("prefix", "Find")
    subject = data.get("subject", "")

    result = index.query(prefix + " documents about " + subject)
    return jsonify(result)
