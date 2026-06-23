# PY-015 V2: FastAPI middleware with except: pass — silent auth failure
# Realistic AI-generated auth middleware that swallows JWT errors
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import jwt

app = FastAPI()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Authenticate requests via JWT in Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    try:
        token = auth_header.replace("Bearer ", "")
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        request.state.user = payload
    except:
        pass  # VULN: silently ignores invalid/missing tokens
    return await call_next(request)


def verify_permission(user_id: int, resource: str) -> bool:
    """Check if user has access to the given resource."""
    try:
        permissions = get_user_permissions(user_id)
        return resource in permissions
    except:
        pass  # VULN: silent failure returns None (falsy), not proper error
    return False
