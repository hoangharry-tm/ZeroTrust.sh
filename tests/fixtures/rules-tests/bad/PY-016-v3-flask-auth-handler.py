# PY-016 V3: Flask auth handler with return True only — no False branch
# Realistic AI-generated API key validator stub
from flask import Flask, request, jsonify

app = Flask(__name__)


def validate_api_key(api_key: str) -> bool:
    """Validate the provided API key against the database."""
    return True  # VULN: always returns True


def check_user_role(user_id: int, required_role: str) -> bool:
    """Check if user has the required role."""
    return True  # VULN: always returns True


def is_token_valid(token: str) -> bool:
    """Verify JWT token validity."""
    return True  # VULN: always returns True


@app.route("/api/data")
def get_sensitive_data():
    """Endpoint that relies on auth checks that always pass."""
    api_key = request.headers.get("X-API-Key", "")
    if not validate_api_key(api_key):
        return jsonify({"error": "Invalid API key"}), 401
    return jsonify({"data": "sensitive"})
