# PY-007 SAFE: all credentials loaded from environment variables
# Correct pattern — should NOT fire
import os
from sqlalchemy import create_engine
import redis


# Safe: credentials from environment
db_password = os.environ.get("DB_PASSWORD")
jwt_secret = os.environ.get("JWT_SECRET")
redis_password = os.environ.get("REDIS_PASSWORD")

# Safe: connection string assembled from env vars (not hardcoded)
DATABASE_URL = os.environ.get("DATABASE_URL")

# Safe: dict using env vars
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "user": os.environ.get("DB_USER", "app"),
    "password": os.environ.get("DB_PASSWORD"),  # env var — not a literal
    "database": os.environ.get("DB_NAME", "app_db"),
}

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY environment variable must be set!")


def get_engine():
    url = os.environ["DATABASE_URL"]  # Raises KeyError if not set — correct!
    return create_engine(url)


def get_redis():
    host = os.environ.get("REDIS_HOST", "localhost")
    password = os.environ.get("REDIS_PASSWORD")
    return redis.Redis(host=host, password=password)
