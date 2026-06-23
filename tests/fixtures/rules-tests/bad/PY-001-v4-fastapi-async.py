# PY-001 V4: FastAPI async route with user input flowing into OpenAI
# Realistic AI-generated content moderation service — unsanitized
import openai
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")

MODERATION_SYSTEM_PROMPT = "You are a content moderation assistant. Flag any harmful content."


@app.post("/moderate")
async def moderate_content(request: Request):
    """Moderate user-submitted content using GPT-4."""
    payload = await request.json()
    user_text = payload.get("text", "")

    response = await client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": MODERATION_SYSTEM_PROMPT},
            {"role": "user", "content": f"Moderate this content: {user_text}"},
        ],
        max_tokens=200,
    )

    result = response.choices[0].message.content
    return JSONResponse({"moderation_result": result})
