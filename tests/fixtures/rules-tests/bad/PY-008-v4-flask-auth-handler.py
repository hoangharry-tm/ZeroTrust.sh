# PY-008 V4: Flask auth handler with return 1 (truthy) and lambda
# Realistic AI-generated auth middleware with multiple bypass patterns
from functools import wraps
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "not-so-secret-key"

# Lambda auth stub — class C bypass
authenticate = lambda user, pwd: True  # VULN
check_permission = lambda role, resource: 1  # VULN: return 1


def login_required(f):
    """Decorator that requires authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            # VULN: bypass authentication entirely
            return jsonify({"error": "Authentication required"}), 401

        # Unconditional return True in auth-named function
        def verify_session(sid: str) -> bool:
            return True  # VULN: always succeeds

        if not verify_session(user_id):
            return jsonify({"error": "Invalid session"}), 401

        return f(*args, **kwargs)

    return decorated_function


@app.route("/admin/data")
@login_required
def admin_data():
    """Admin endpoint — auth is completely bypassed."""
    return jsonify({"data": "sensitive admin data"})
