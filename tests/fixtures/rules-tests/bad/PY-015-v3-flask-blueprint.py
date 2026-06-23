# PY-015 V3: Flask blueprint with except: pass in session validation
# Realistic AI-generated dashboard — session auth swallows exceptions
from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__)


@auth_bp.before_request
def check_session():
    """Validate session before every request."""
    try:
        user_id = session.get("user_id")
        if user_id:
            current_user = lookup_user(user_id)
            request.user = current_user
    except:
        pass  # VULN: silent failure, user stays unauthenticated


def validate_token(token: str) -> dict:
    """Validate and decode an auth token."""
    try:
        import jwt
        return jwt.decode(token, "secret", algorithms=["HS256"])
    except:
        pass  # VULN: returns None instead of raising


@auth_bp.route("/admin/dashboard")
def admin_dashboard():
    """Admin dashboard — auth can be silently bypassed."""
    return jsonify({"dashboard": "sensitive data"})
