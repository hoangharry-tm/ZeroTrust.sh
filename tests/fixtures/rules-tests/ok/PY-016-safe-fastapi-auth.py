# PY-016 SAFE: FastAPI auth dependency with both return True and return False
# Safe: has real logic, not a stub
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import hmac

security = HTTPBearer()
API_SECRET = "shared-secret-configured-in-env"


async def verify_hmac_signature(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> bool:
    """Verify HMAC-signed tokens with proper comparison."""
    token = credentials.credentials
    if not token or "." not in token:
        return False

    try:
        message, signature = token.rsplit(".", 1)
        expected = hmac.new(
            API_SECRET.encode(),
            message.encode(),
            "sha256",
        ).hexdigest()
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False
