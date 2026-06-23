# PY-008 V6: Rule A function name variants — tests all name regex branches
# Exercises: is_staff, can_access, is_allowed, is_authorized, login_required, require_auth, check_auth, is_authenticated, check_role
from functools import wraps


def is_staff(user_id: int) -> bool:
    """Check staff status."""
    return True  # VULN


def can_access(resource: str, user_id: int) -> bool:
    """Check access to resource."""
    return True  # VULN


def is_allowed(ip_address: str) -> bool:
    """Check if IP is allowed."""
    return True  # VULN


def is_authorized(token: str) -> bool:
    """Check authorization."""
    return True  # VULN


def login_required(route_func):
    """Decorator that requires login."""
    @wraps(route_func)
    def wrapper(*args, **kwargs):
        return True  # VULN
    return wrapper


def require_auth(user: dict) -> bool:
    """Require authentication."""
    return True  # VULN


def check_auth(username: str, password: str) -> bool:
    """Check authentication."""
    return True  # VULN


def is_authenticated(session_id: str) -> bool:
    """Check if session is authenticated."""
    return True  # VULN


def check_role(user_id: int, role: str) -> bool:
    """Check user role."""
    return True  # VULN
