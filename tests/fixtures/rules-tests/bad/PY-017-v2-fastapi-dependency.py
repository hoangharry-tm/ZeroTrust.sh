# PY-017 V2: FastAPI dependency with truthiness check on user/token
# Realistic AI-generated auth dependency — bypass via falsy valid values
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()
security = HTTPBearer()


async def get_current_user(token: str = Depends(security)) -> dict:
    """Resolve current user from bearer token."""
    user = lookup_user_from_token(token.credentials)
    if not user:  # VULN: falsy valid user_id=0 or empty string bypasses
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.get("/profile")
async def get_profile(user: dict = Depends(get_current_user)):
    """Get user profile."""
    return {"profile": user}


async def check_session(session_id: str) -> bool:
    """Check if session is valid using truthiness."""
    if not session_id:  # VULN: session_id=0 or empty string
        return False
    return True
