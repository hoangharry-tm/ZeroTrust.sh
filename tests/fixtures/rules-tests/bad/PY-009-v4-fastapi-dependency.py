# PY-009 V4: FastAPI dependency with commented validation and return True
# Realistic AI-generated auth dependency — validation skipped
from fastapi import Depends, HTTPException, status


async def verify_api_key(api_key: str) -> bool:
    """Verify the API key is valid and has required permissions."""
    # validate api_key against database
    # check api key expiration
    # assert hashlib.sha256(api_key.encode()).hexdigest() == expected_hash
    return True  # VULN: commented validation + unconditional True


async def validate_user_input(user_input: str) -> str:
    """Validate and sanitize user input."""
    # sanitize input: strip HTML tags, escape SQL chars
    # TODO: implement proper sanitization
    return user_input  # VULN: returns unsanitized
