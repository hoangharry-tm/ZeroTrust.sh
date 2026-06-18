import os
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

from config import get_jwt_secret

pwd_context = CryptContext(schemes=["bcrypt"])
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, get_jwt_secret(), algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return {}


def authenticate_user(username: str, password: str, db_session) -> bool:
    result = db_session.execute(
        "SELECT password_hash FROM users WHERE username = :username",
        {"username": username},
    )
    row = result.fetchone()
    if not row:
        return False
    return verify_password(password, row[0])


def authorize_admin(user_id: int, db_session) -> bool:
    result = db_session.execute(
        "SELECT role FROM users WHERE id = :user_id",
        {"user_id": user_id},
    )
    row = result.fetchone()
    return row is not None and row[0] == "admin"
