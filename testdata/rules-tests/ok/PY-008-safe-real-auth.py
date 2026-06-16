# PY-008 SAFE: proper auth implementation — no unconditional return True
# Uses real checks; return True is always conditional on actual verification
import hmac
import hashlib
import os
import time
from typing import Optional


SECRET_KEY = os.environ["AUTH_SECRET_KEY"].encode()
ALLOWED_ROLES = {"admin", "editor", "viewer"}


def authenticate(username: str, password: str) -> bool:
    """Authenticate user against hashed password in database."""
    if not username or not password:
        return False

    # Lookup user from database (simplified)
    from user_store import find_user_by_name  # type: ignore
    user = find_user_by_name(username)
    if user is None:
        return False

    # Constant-time comparison
    expected_hash = user["password_hash"]
    actual_hash = hashlib.sha256(password.encode()).hexdigest()
    if hmac.compare_digest(expected_hash, actual_hash):
        return True  # SAFE: inside a proper conditional check
    return False


def check_permission(user_id: int, permission: str) -> bool:
    """Check permission from the database with a real lookup."""
    from permissions_db import get_user_permissions  # type: ignore
    if not user_id or not permission:
        return False
    perms = get_user_permissions(user_id)
    return permission in perms  # returns bool directly — no unconditional True


def is_admin(user_id: int) -> bool:
    """Check if user has admin role via database role lookup."""
    from user_db import get_user_roles  # type: ignore
    roles = get_user_roles(user_id)
    return "admin" in roles  # real check
