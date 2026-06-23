# PY-009 SAFE: FastAPI dependency with implemented validation
# Safe: validation functions have real logic, not pass stubs
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field
import re

app = FastAPI()


def validate_input_length(value: str, max_len: int = 1000) -> str:
    """Validate and truncate input to maximum length."""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail="Input must be a string")
    return value[:max_len]


def sanitize_html(content: str) -> str:
    """Sanitize HTML content by removing dangerous tags."""
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
    sanitized = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized)
    return sanitized


class CommentRequest(BaseModel):
    content: str = Field(..., max_length=5000)


@app.post("/comment")
async def create_comment(req: CommentRequest):
    """Safe: input validated and sanitized before processing."""
    validated = validate_input_length(req.content)
    safe_content = sanitize_html(validated)
    return {"comment": safe_content, "status": "created"}
