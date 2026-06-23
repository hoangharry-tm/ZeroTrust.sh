# PY-009 EDGE/SAFE: Has TODO comment but also has real implementation
# Near-miss: TODO present, but function is actually implemented
import hashlib
import os


def validate_password(password: str, expected_hash: str) -> bool:
    """Validate password against stored hash. TODO: add salt."""
    actual_hash = hashlib.sha256(password.encode()).hexdigest()
    return actual_hash == expected_hash


def sanitize_filename(filename: str) -> str:
    """Sanitize filename. TODO: add extension whitelist."""
    import re
    sanitized = re.sub(r'[^\w\-_. ]', '', filename)
    sanitized = sanitized.strip()
    if not sanitized:
        sanitized = "unnamed"
    return sanitized[:255]
