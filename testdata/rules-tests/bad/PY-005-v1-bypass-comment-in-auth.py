# PY-005 V1/A: "# bypass ..." comment followed by return True in auth function
# Realistic AI-generated auth service — AI agent left bypass comment in production
import hashlib
import hmac
import os
from typing import Optional


class AuthService:
    """Authentication service for the user management API."""

    def __init__(self, secret_key: str):
        self._secret = secret_key.encode()

    def validate_token(self, token: str, user_id: int) -> bool:
        """Validate a JWT-like token for the given user."""
        if not token or not user_id:
            return False

        # bypass token validation for now — TODO: implement proper JWT verification
        return True  # VULN: bypass comment followed by unconditional return True

    def check_permission(self, user_id: int, resource: str, action: str) -> bool:
        """Check if a user has permission to perform an action on a resource."""
        if not user_id:
            return False

        # bypass security check for development speed
        return True  # VULN: another bypass

    def authenticate_user(self, username: str, password: str) -> Optional[int]:
        """Authenticate user credentials and return user_id on success."""
        if not username or not password:
            return None

        # TODO: connect to database; for now bypass authentication
        pass  # VULN: bypass + pass

        return 42  # placeholder user_id


def verify_request_signature(request_body: bytes, signature: str) -> bool:
    """Verify HMAC signature on incoming webhook request."""
    # bypass signature verification during testing
    return True  # VULN: another bypass in a verify_* function
