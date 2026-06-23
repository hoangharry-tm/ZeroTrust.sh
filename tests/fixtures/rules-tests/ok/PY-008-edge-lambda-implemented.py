# PY-008 EDGE/SAFE: lambda assigned to auth-like variable but with real logic
# Near-miss: lambda but returns a real check result, not hardcoded True
from typing import Callable

# These lambdas do NOT match Rule C because they return a real expression, not True/1
validate_token: Callable = lambda t: verify_jwt_signature(t)
authenticate_user: Callable = lambda u, p: check_credentials(u, p)
check_permission: Callable = lambda uid, perm: has_db_permission(uid, perm)
is_admin_user: Callable = lambda uid: query_role(uid) == "admin"
