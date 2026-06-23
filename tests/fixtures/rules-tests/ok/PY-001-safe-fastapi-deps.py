# PY-001 SAFE: FastAPI with proper input validation via Pydantic + Depends
# User data structurally separated, sanitized before reaching LLM
import openai
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
import os

app = FastAPI()
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

STATIC_SYSTEM_PROMPT = "You are a helpful assistant. Answer concisely and accurately."


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=2000)
    context: str = Field(default="", max_length=500)


def validate_chat_request(req: ChatRequest) -> ChatRequest:
    """Validate and sanitize chat input before passing to LLM."""
    sanitized = req.message.replace("<", "&lt;").replace(">", "&gt;")[:2000]
    req.message = sanitized
    return req


@app.post("/chat")
async def chat_endpoint(req: ChatRequest = Depends(validate_chat_request)):
    """Safe chat: user data validated and in user-role message only."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": STATIC_SYSTEM_PROMPT},
            {"role": "user", "content": req.message},
        ],
        max_tokens=400,
    )
    return {"reply": response.choices[0].message.content}
