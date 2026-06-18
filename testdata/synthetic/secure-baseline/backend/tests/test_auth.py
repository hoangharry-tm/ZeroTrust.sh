import pytest
from jose import jwt

from services.auth import (
    verify_password,
    hash_password,
    create_access_token,
    verify_token,
)


def test_password_hashing():
    password = "secure-password-123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)


def test_password_hashing_wrong_password():
    hashed = hash_password("correct-password")
    assert not verify_password("wrong-password", hashed)


def test_token_creation_and_verification():
    data = {"user_id": 1, "role": "admin"}
    token = create_access_token(data)
    payload = verify_token(token)
    assert payload["user_id"] == 1
    assert payload["role"] == "admin"


def test_invalid_token():
    payload = verify_token("invalid-token")
    assert payload == {}


def test_expired_token():
    import time
    from datetime import datetime, timedelta

    secret = "test-secret"
    expired = jwt.encode(
        {"exp": datetime.utcnow() - timedelta(hours=1)},
        secret,
        algorithm="HS256",
    )
    payload = verify_token(expired)
    assert payload == {}
