# PY-008 EDGE/SAFE: Auth function with return True inside a meaningful conditional
# Near-miss: does return True but only when a real condition is met
from flask import Flask, request, jsonify

app = Flask(__name__)


def check_user_access(user_id: int, resource_owner_id: int) -> bool:
    """Proper access check: returns True only when user owns the resource."""
    if user_id == resource_owner_id:
        return True
    if is_admin_user(user_id):
        return True
    return False


def validate_ip_address(ip: str) -> bool:
    """Validate IP format — not an auth function despite 'validate' prefix."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
