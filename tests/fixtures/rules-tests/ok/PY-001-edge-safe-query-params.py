# PY-001 EDGE/SAFE: query_params and args used but NOT flowing to LLM sink
# Near-miss: taint source present but no sink reachable
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import openai
import os

app = FastAPI()
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])


@app.get("/search")
async def safe_search(request: Request):
    """query_params.get used, but only for DB query, not LLM."""
    q = request.query_params.get("q", "")
    results = database_search(q)
    return JSONResponse({"results": results})


@app.get("/greet")
async def safe_greet(request: Request):
    """args.get used but only for response, not LLM."""
    from flask import request as flask_req
    name = flask_req.args.get("name", "World")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Say hello."},  # Static
        ],
    )
    return JSONResponse({"greeting": f"Hello {name}", "ai": response.choices[0].message.content})
