from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy import text
from sqlalchemy.orm import Session

from services.db import Session as DbSession, get_user_by_id, search_products
from services.auth import verify_token, authorize_admin

app = FastAPI(title="Secure API")


def get_current_user(authorization: str = Header(...)) -> dict:
    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


def get_db():
    db = DbSession()
    try:
        yield db
    finally:
        db.close()


@app.get("/api/users/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/api/products")
def list_products(q: str = "", db: Session = Depends(get_db)):
    results = search_products(q)
    return {"results": results}


@app.get("/api/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not authorize_admin(current_user.get("user_id"), db):
        raise HTTPException(status_code=403, detail="Admin access required")
    result = db.execute(text("SELECT id, username, role FROM users"))
    users = [{"id": r[0], "username": r[1], "role": r[2]} for r in result]
    return {"users": users}


@app.get("/api/health")
def health():
    return {"status": "ok"}
