# PY-004 V8: request.$ANY as generic taint source
# Exercises the catch-all request.$ANY source pattern
from flask import Flask, request, jsonify

app = Flask(__name__)


def generate_text(prompt: str) -> str:
    """LLM-named function matching $FUNC regex."""
    return f"output: {prompt}"


@app.route("/request-user", methods=["POST"])
def request_user():
    """request.$ANY via .user attribute."""
    current_user = request.user
    if current_user:
        result = generate_text(f"Hello {current_user}")
        return jsonify({"result": result})
    return jsonify({"error": "no user"}), 401


@app.route("/request-headers", methods=["POST"])
def request_headers():
    """request.$ANY via .headers attribute."""
    lang = request.headers.get("Accept-Language", "en")
    result = generate_text(f"Respond in {lang}")
    return jsonify({"result": result})


@app.route("/request-cookies", methods=["POST"])
def request_cookies():
    """request.$ANY via .cookies attribute."""
    session_data = request.cookies.get("session_data", "")
    result = generate_text(f"Session: {session_data}")
    return jsonify({"result": result})


@app.route("/request-form", methods=["POST"])
def request_form():
    """request.form.get as taint source."""
    comment = request.form.get("comment", "")
    result = generate_text(f"Comment: {comment}")
    return jsonify({"result": result})
