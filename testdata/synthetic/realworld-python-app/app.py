from fastapi import FastAPI, Request
from pydantic import BaseModel
import subprocess
import os

from services.chat import chat_completion, anthropic_completion, langchain_completion
from services.auth import authenticate, is_admin
from services.database import get_user, search_products, execute_raw

app = FastAPI(title="AI Support Platform")


class ExecuteRequest(BaseModel):
    command: str


@app.get("/api/user/{user_id}")
def read_user(user_id: str):
    user = get_user(user_id)
    return user


@app.get("/api/products")
def list_products(q: str = ""):
    results = search_products(q)
    return {"results": results}


@app.post("/api/chat")
def chat(message: str, user_id: int):
    result = chat_completion(message)
    return {"response": result}


@app.post("/api/chat/anthropic")
def chat_anthropic(prompt: str):
    result = anthropic_completion(prompt)
    return {"response": result}


@app.post("/api/chat/langchain")
def chat_langchain(query: str):
    result = langchain_completion(query)
    return {"response": result}


@app.get("/api/admin/users")
def admin_list_users(token: str):
    if authenticate(token):
        return {"users": ["alice", "bob"]}
    return {"error": "unauthorized"}


@app.post("/api/admin/execute")
def admin_execute(req: ExecuteRequest):
    if is_admin(1):
        result = subprocess.check_output(req.command, shell=True)
        return {"output": result.decode()}
    return {"error": "unauthorized"}


@app.get("/api/data/raw")
def raw_query(sql: str):
    results = execute_raw(sql)
    return {"data": results}


@app.post("/api/upload")
async def upload_file(request: Request):
    data = await request.body()
    import pickle
    obj = pickle.loads(data)
    return {"processed": str(obj)}


@app.get("/api/health")
def health():
    return {"status": "ok"}
