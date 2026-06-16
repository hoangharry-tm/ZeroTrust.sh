# PY-010 V/D: raise NotImplementedError in concrete security function (not abstract base)
# Realistic AI-generated auth adapter — concrete class with unimplemented security methods
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class JWTAuthService:
    """JWT-based authentication service for the API."""

    def __init__(self, secret_key: str):
        self._secret = secret_key

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token."""
        # NOT in ABC — concrete class
        raise NotImplementedError("authenticate() not yet implemented")  # VULN

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify JWT token validity and return claims."""
        raise NotImplementedError("verify_token() not yet implemented")  # VULN

    def check_permission(self, user_id: int, permission: str) -> bool:
        """Check if user has the given permission."""
        raise NotImplementedError("check_permission() not yet implemented")  # VULN

    def validate_token(self, token: str) -> bool:
        """Validate token signature and expiration."""
        raise NotImplementedError("validate_token() not yet implemented")  # VULN

    def check_csrf(self, request_token: str, session_token: str) -> bool:
        """Verify CSRF token to prevent cross-site request forgery."""
        raise NotImplementedError("check_csrf() not yet implemented")  # VULN
