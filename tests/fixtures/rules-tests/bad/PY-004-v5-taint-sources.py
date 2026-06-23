# PY-004 V5: taint source variants for generic LLM rule
# Exercises input(), sys.stdin, argparse, request.GET, request.POST, request.values
import sys
import argparse
from flask import Flask, request, jsonify

app = Flask(__name__)


def query_llm(prompt: str) -> str:
    """Generic LLM-named function."""
    return f"response to: {prompt[:50]}"


def chat_terminal():
    """input() as taint source → generic LLM sink."""
    user_text = input("> ")
    return query_llm(f"You said: {user_text}")


def pipe_processor():
    """sys.stdin.read() as taint source."""
    data = sys.stdin.read()
    return query_llm(f"Process: {data}")


@app.route("/get-endpoint", methods=["GET"])
def get_handler():
    """request.GET.get as taint source."""
    q = request.GET.get("q", "")
    result = query_llm(f"Search: {q}")
    return jsonify({"result": result})


@app.route("/post-endpoint", methods=["POST"])
def post_handler():
    """request.POST.get as taint source."""
    message = request.POST.get("message", "")
    result = query_llm(f"Reply: {message}")
    return jsonify({"result": result})


@app.route("/values-endpoint", methods=["POST"])
def values_handler():
    """request.values.get as taint source."""
    data = request.values.get("data", "")
    result = query_llm(f"Process: {data}")
    return jsonify({"result": result})


def cli_argparse():
    """argparse parse_args as taint source."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", type=str, default="")
    parser.add_argument("--mode", type=str, default="default")
    args = parser.parse_args()
    return query_llm(f"{args.mode}: {args.prompt}")
