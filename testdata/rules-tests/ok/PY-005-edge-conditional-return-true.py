# PY-005 EDGE/SAFE: return True inside a proper conditional in auth function
# This is legitimate: `if token_valid: return True` should NOT be flagged
import hmac
import hashlib
import os
import time
from typing import Optional


SECRET = os.environ["AUTH_SECRET"].encode()


def validate_token(token: str, expected_user_id: str) -> bool:
    """
    Validate an HMAC token.
    return True only when token is cryptographically verified.
    """
    if not token or "." not in token:
        return False

    try:
        user_id, ts_str, signature = token.split(".", 2)
    except ValueError:
        return False

    if user_id != expected_user_id:
        return False

    ts = int(ts_str)
    if abs(time.time() - ts) > 3600:
        return False  # expired

    message = f"{user_id}.{ts_str}".encode()
    expected_sig = hmac.new(SECRET, message, hashlib.sha256).hexdigest()

    if hmac.compare_digest(expected_sig, signature):
        return True   # SAFE: inside a proper conditional check

    return False


def check_permission(user_id: str, resource: str) -> bool:
    """Check permissions from a database lookup."""
    from some_db import db  # type: ignore[import]
    perm = db.get_permission(user_id, resource)
    if perm and perm.is_active:
        return True   # SAFE: guarded by real condition
    return False
