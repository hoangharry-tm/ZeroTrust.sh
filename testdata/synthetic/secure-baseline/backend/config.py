import os
from dotenv import load_dotenv

load_dotenv()


def get_database_url() -> str:
    return os.environ["DATABASE_URL"]


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def get_openai_api_key() -> str:
    return os.environ["OPENAI_API_KEY"]
