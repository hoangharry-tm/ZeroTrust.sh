# PY-015 SAFE: FastAPI middleware with proper error handling — no except:pass
# Safe: exceptions are logged and reraised, not silently swallowed
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import jwt

app = FastAPI()
logger = logging.getLogger(__name__)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Safe auth middleware with proper error handling and logging."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return await call_next(request)

    try:
        token = auth_header.replace("Bearer ", "")
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        request.state.user = payload
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token used for %s", request.url.path)
        return JSONResponse({"detail": "Token expired"}, status_code=401)
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token: %s", str(e))
        return JSONResponse({"detail": "Invalid token"}, status_code=401)

    return await call_next(request)
