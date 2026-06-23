# PY-016 SAFE: Django auth function with both return True and return False
# Safe: has proper conditional logic with both branches
from django.http import HttpRequest


def check_api_key(request: HttpRequest) -> bool:
    """Proper API key validation with True and False branches."""
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        return False
    if len(api_key) < 32:
        return False
    if api_key.startswith("sk-"):
        return True
    return False


def authenticate_user(username: str, password: str) -> bool:
    """Proper user authentication with both outcomes."""
    if not username or not password:
        return False
    if len(password) < 8:
        return False
    return verify_credentials(username, password)
