# PY-004 V2: FastAPI async with generic LLM-named function (Cohere)
# Realistic AI-generated sentiment analysis — generic LLM sink match
import os
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
COHERE_API_KEY = os.environ.get("COHERE_API_KEY")


async def chat_with_model(user_prompt: str) -> str:
    """Generic LLM wrapper around Cohere generate API."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.cohere.ai/v1/generate",
            headers={
                "Authorization": f"Bearer {COHERE_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "command",
                "prompt": user_prompt,
                "max_tokens": 200,
            },
            timeout=30,
        )
        return resp.json()["generations"][0]["text"]


@app.post("/sentiment")
async def analyze_sentiment(request: Request):
    """Analyze sentiment — user input flows to LLM-named function."""
    payload = await request.json()
    text_input = payload.get("text", "")

    result = await chat_with_model(f"Analyze the sentiment of: {text_input}")
    return JSONResponse({"sentiment": result})
