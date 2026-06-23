# PY-008 EDGE/SAFE: valid auth patterns that should NOT fire
# Functions with return True inside meaningful conditionals, return False exists, etc.
from flask import Flask, request, jsonify

app = Flask(__name__)


def is_staff(user_id: int) -> bool:
    """Auth function with both True and False paths."""
    if user_id == 0:
        return False
    role = get_role(user_id)
    if role == "admin":
        return True
    return role == "staff"


def can_access(resource: str, user_id: int) -> bool:
    """Access check with proper conditional return True."""
    if user_id is None:
        return False
    allowed = get_allowed_resources(user_id)
    return resource in allowed


def is_allowed(ip_address: str) -> bool:
    """IP check with return True inside real conditional."""
    allowed_ips = {"10.0.0.1", "10.0.0.2"}
    if ip_address in allowed_ips:
        return True
    return False
