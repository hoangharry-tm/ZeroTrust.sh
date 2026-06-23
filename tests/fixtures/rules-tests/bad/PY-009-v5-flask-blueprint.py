# PY-009 V5: Flask blueprint with pass-only security functions
# Realistic AI-generated API gateway — security hooks never wired
from flask import Blueprint, request, jsonify

api_bp = Blueprint("api", __name__)


def validate_payload(payload: dict) -> bool:
    """Validate incoming API payload against schema."""
    pass  # VULN: pass-only


def check_content_type(request) -> bool:
    """Verify Content-Type header is application/json."""
    pass  # VULN: pass-only


def filter_sensitive_fields(data: dict) -> dict:
    """Remove sensitive fields like password, ssn from response."""
    pass  # VULN: pass-only


@api_bp.route("/users", methods=["POST"])
def create_user():
    """Create a new user — no validation occurs."""
    payload = request.get_json()
    validate_payload(payload)
    check_content_type(request)
    return jsonify({"status": "created"}), 201
