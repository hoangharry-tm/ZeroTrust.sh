# PY-015 V4: except Exception: pass variant
# Rule also matches named Exception, not just bare except
from django.http import HttpRequest


def authenticate_login(request: HttpRequest) -> bool:
    """Login handler with named except."""
    try:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        user = decode_jwt(token)
        request.user = user
        return True
    except Exception:
        pass  # VULN: named except with pass
    return False


def admin_check(request: HttpRequest) -> bool:
    """Admin check with except: pass."""
    try:
        role = request.headers.get("X-Role", "")
        return role == "admin"
    except:
        pass  # VULN: bare except with pass
    return False


def authorize_access(user_id: int, resource: str) -> bool:
    """Auth function with except Exception: pass."""
    try:
        perms = get_permissions(user_id)
        return resource in perms
    except Exception:
        pass  # VULN: named except
    return False
