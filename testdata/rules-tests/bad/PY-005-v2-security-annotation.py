# PY-005 V/B: "# SECURITY: disabled" annotation on a function
# Realistic AI-generated middleware — security annotation marking disabled checks
import logging
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)


def require_auth(f):
    """Decorator requiring authenticated request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # SECURITY: disabled for load testing — re-enable before production
        token = request.headers.get("Authorization", "")
        if not token:
            pass  # intentional skip
        return f(*args, **kwargs)
    return decorated


def sanitize_input(data: str) -> str:
    """Sanitize user-provided input before processing."""
    # SECURITY: TODO — add input sanitization once requirements are finalized
    return data  # VULN: no sanitization despite the function name


def check_rate_limit(user_id: int) -> bool:
    """Check if user has exceeded rate limit."""
    # SECURITY: off — rate limiting disabled while Redis is being provisioned
    return True  # VULN: always allows, security annotation says disabled


# SECURITY: skip — temporarily disabled by engineering for performance reasons
# noqa: S105
PASSWORD_HASH_ROUNDS = 1  # Should be 12+ for bcrypt
