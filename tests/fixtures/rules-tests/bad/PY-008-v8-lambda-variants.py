# PY-008 V8: Rule C lambda variants
# Exercises all lambda → True/1 patterns with various auth names
from typing import Callable

# Lambda stubs — all VULN
authenticate_user: Callable = lambda u, p: True
is_admin_user = lambda user_id: True
verify_auth_token = lambda token: True
check_user_permission = lambda uid, perm: True
has_resource_access = lambda user, res: True
check_authenticated = lambda: True
permission_check = lambda role: 1
access_control = lambda user, action: 1
