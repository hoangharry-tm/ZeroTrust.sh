# PY-016 EDGE/SAFE: functions with both return True and return False
# return True is always inside if blocks, plus return False exists
from django.http import HttpRequest


def check_user_has_role(user_id: int, role: str) -> bool:
    """Role check with conditional return True and return False."""
    user = get_user(user_id)
    if user is None:
        return False
    if "admin" in user.get("roles", []):
        return True
    return role in user.get("roles", [])


def verify_login(username: str, password: str) -> bool:
    """Login verification with both True and False."""
    if not username or not password:
        return False
    if len(password) < 8:
        return False
    if password == get_stored_hash(username):
        return True
    return False


def has_permission(user: dict, resource: str) -> bool:
    """Permission check with return True inside conditionals."""
    if not user or not user.get("roles"):
        return False
    if "admin" in user["roles"]:
        return True
    return resource in user.get("permissions", [])
