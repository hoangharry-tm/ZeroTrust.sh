# PY-016 V4: function name variants not yet covered
# Exercises: login*, has_role, check*, verify*, validate* with return True but no return False
from django.http import HttpRequest


def login_user(username: str, password: str) -> bool:
    """Login with return True only."""
    return True  # VULN: no return False


def has_role(user_id: int, role_name: str) -> bool:
    """Role check with return True only."""
    return True  # VULN: no return False


def check_password_strength(password: str) -> bool:
    """Password strength check with return True only."""
    return True  # VULN: no return False


def verify_user_email(email: str) -> bool:
    """Email verification with return True only."""
    return True  # VULN: no return False


def validate_session_token(token: str) -> dict:
    """Session validation with return True only. Not flagged (return type is dict)."""
    return True  # VULN for PY-016, return True in validate function
