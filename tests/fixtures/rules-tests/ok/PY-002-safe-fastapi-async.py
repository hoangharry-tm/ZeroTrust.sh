# PY-002 SAFE: FastAPI async with Pydantic validation, static system
# Safe: user data length-limited, static system prompt
import anthropic
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import os

app = FastAPI()
client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

ANALYSIS_SYSTEM = "You are a code review assistant. Identify bugs and security issues."


class CodeReviewRequest(BaseModel):
    code: str = Field(..., max_length=5000)
    language: str = Field(default="python", max_length=20)


@app.post("/review")
async def review_code(req: CodeReviewRequest):
    """Safe code review with validated input."""
    if req.language not in {"python", "javascript", "typescript", "go", "rust"}:
        raise HTTPException(status_code=400, detail="Unsupported language")

    response = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1024,
        system=ANALYSIS_SYSTEM,
        messages=[
            {"role": "user", "content": f"Review this {req.language} code:\n{req.code}"},
        ],
    )
    return {"review": response.content[0].text}
