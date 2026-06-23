# PY-001 V11: FastAPI query_params.get and body() as taint sources
# Exercises Rule A source patterns for FastAPI-specific APIs
import openai
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.get("/search")
async def search_query(request: Request):
    """FastAPI: query_params.get as taint source."""
    q = request.query_params.get("q", "")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Answer about: {q}"},
        ],
    )
    return JSONResponse({"answer": response.choices[0].message.content})


@app.post("/raw-body")
async def raw_body(request: Request):
    """FastAPI: body() as taint source."""
    raw = await request.body()
    text = raw.decode("utf-8")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Process this: {text}"},
        ],
    )
    return JSONResponse({"result": response.choices[0].message.content})


@app.get("/flask-args")
async def flask_args_source(request: Request):
    """Flask-style request.args.get with aliased import source pattern."""
    from flask import request as flask_req
    name = flask_req.args.get("name", "")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Greet: {name}"},
        ],
    )
    return JSONResponse({"greeting": response.choices[0].message.content})
