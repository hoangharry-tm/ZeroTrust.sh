# PY-004 SAFE: FastAPI with generic LLM-named function but sanitized input
# User input is validated and sanitized before reaching the LLM function
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import os

app = FastAPI()


def query_llm(prompt: str) -> str:
    """Generic LLM query function — but only called with sanitized input."""
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


class SummaryRequest(BaseModel):
    text: str = Field(..., max_length=5000)


@app.post("/summarize")
async def summarize_text(req: SummaryRequest):
    """Safe: input validated, content sanitized before LLM call."""
    import re
    sanitized = re.sub(r'[<>{}\\]', '', req.text)[:5000]

    prompt = f"Summarize the following text concisely:\n\n{sanitized}"
    result = query_llm(prompt)
    return {"summary": result}
