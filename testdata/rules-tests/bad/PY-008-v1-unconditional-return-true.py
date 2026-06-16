# PY-008 V1/A: unconditional return True in auth-named functions
# Realistic AI-generated user management service — cheat pattern in production
import hashlib
import hmac
from typing import Optional


class UserAuthService:
    """Authentication service for the user management module."""

    def __init__(self):
        self._users_db = {}

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user with username and password."""
        # TODO: implement proper credential check against database
        return True  # VULN: unconditional return True in authenticate

    def check_permission(self, user_id: int, permission: str) -> bool:
        """Check if user has the specified permission."""
        return True  # VULN: unconditional return True in check_permission

    def is_admin(self, user_id: int) -> bool:
        """Check if the user has admin privileges."""
        return True  # VULN: unconditional return True in is_admin

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify a JWT token and return payload."""
        # Real JWT verification would go here
        return {"user_id": 1, "roles": ["admin"]}  # not flagged (not return True)

    def has_access(self, user_id: int, resource_id: int) -> bool:
        """Check resource-level access control."""
        return True  # VULN: unconditional return True in has_access


# Module-level lambda stub — also a cheat pattern
authenticate = lambda *args, **kwargs: True  # VULN: lambda auth always returns True
check_auth = lambda user, perm: True  # VULN: lambda always returns True
