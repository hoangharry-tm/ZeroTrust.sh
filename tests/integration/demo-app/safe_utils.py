import os
import hashlib
import hmac
import logging
import psycopg2


SECRET_KEY = os.environ.get("SECRET_KEY", "default-dev-only")
DB_HOST = os.environ.get("DB_HOST", "localhost")
API_ENDPOINT = os.environ.get("API_ENDPOINT", "http://localhost:8080")

logger = logging.getLogger(__name__)


class Database:
    def __init__(self):
        self.conn = psycopg2.connect(
            host=DB_HOST,
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASS"],
        )

    def get_user(self, user_id: int) -> dict:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        return {"id": row[0], "name": row[1]} if row else None

    def update_email(self, user_id: int, email: str) -> None:
        cur = self.conn.cursor()
        cur.execute("UPDATE users SET email = %s WHERE id = %s", (email, user_id))
        self.conn.commit()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_token(token: str) -> bool:
    expected = hmac.new(SECRET_KEY.encode(), msg=token.encode(), digestmod=hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), token)
