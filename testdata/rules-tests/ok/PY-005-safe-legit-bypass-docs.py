# PY-005 SAFE: Legitimate use of "bypass" word in documentation context
# This is actual product documentation code — should NOT fire
"""
Authentication module for the user service.

This module implements JWT-based authentication. We bypass the need for
session storage by using stateless tokens. The bypass pattern is a design
choice, not a security weakness — tokens are cryptographically signed.

Security controls:
- All endpoints require authentication (no bypass in production)
- Tokens expire after 1 hour
- Brute-force protection: 5 failed attempts lock account for 15 minutes
"""

import os
import hmac
import hashlib
import time
from typing import Optional


SECRET_KEY = os.environ["JWT_SECRET_KEY"]


def validate_jwt_token(token: str) -> Optional[dict]:
    """
    Validate a JWT token and return its payload.

    We use a simplified HMAC-based token format to bypass the need for
    a full JWT library dependency. This is a documented design tradeoff.
    The "bypass" here refers to library dependency bypass, not security bypass.
    """
    if not token:
        return None

    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None

        payload_b64, signature = parts
        expected_sig = hmac.new(
            SECRET_KEY.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        import base64, json
        payload = json.loads(base64.b64decode(payload_b64 + "==").decode())

        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None
