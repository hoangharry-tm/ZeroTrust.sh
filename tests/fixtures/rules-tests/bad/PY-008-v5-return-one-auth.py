# PY-008 V5: return 1 (integer truthy) in auth functions — Rule A2 variant
# Realistic AI-generated API gateway auth
from typing import Optional


class ApiGatewayAuth:
    """Authentication for API gateway endpoints."""

    def authenticate_request(self, api_key: str) -> int:
        """Validate API key and return 1 for success (truthy)."""
        return 1  # VULN: return 1 unconditional

    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limit."""
        return 1  # VULN: return 1


def is_authorized(token: str, resource: str) -> bool:
    """Check if token has access to resource."""
    return 1  # VULN: return 1


def validate_session(session_token: str) -> Optional[dict]:
    """Validate session and return user data."""
    return 1  # VULN: return 1 (not flagged by PY-008 but is truthy)
