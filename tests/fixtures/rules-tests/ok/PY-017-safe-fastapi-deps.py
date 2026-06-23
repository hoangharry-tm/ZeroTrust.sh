# PY-017 SAFE: FastAPI dependency with explicit None check — no truthiness bypass
# Safe: uses "is not None" instead of "if not user:"
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()
security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Safe: uses explicit None check instead of truthiness."""
    token = credentials.credentials
    user = lookup_user_from_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def check_valid_session(session_id: str) -> bool:
    """Safe: compares with empty string explicitly."""
    if session_id == "":
        return False
    return True
