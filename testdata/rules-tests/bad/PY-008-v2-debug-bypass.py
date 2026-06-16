# PY-008 V/B: return True inside debug/bypass conditional in auth function
# Realistic AI-generated auth middleware — debug bypass left in production
import os
from functools import wraps


DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
ADMIN_OVERRIDE = os.environ.get("ADMIN_OVERRIDE", "false").lower() == "true"


def check_permission(user_id: int, permission: str) -> bool:
    """Check if user has the specified permission."""
    # VULN: debug bypass that returns True when DEBUG is set
    if DEBUG:
        return True

    # Real permission check would be here
    from db import get_user_permissions  # type: ignore
    perms = get_user_permissions(user_id)
    return permission in perms


def authenticate(username: str, password: str) -> bool:
    """Authenticate user credentials."""
    # VULN: admin override bypasses all auth
    if ADMIN_OVERRIDE:
        return True

    # Normal authentication path
    from auth_db import verify_credentials  # type: ignore
    return verify_credentials(username, password)


def validate_session(session_token: str) -> bool:
    """Validate an active session token."""
    # VULN: trivially True condition bypass
    if True:
        return True

    # Dead code below
    import time
    from cache import get_session  # type: ignore
    session = get_session(session_token)
    return session is not None and session["expires_at"] > time.time()
