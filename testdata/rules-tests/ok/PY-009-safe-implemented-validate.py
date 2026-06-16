# PY-009 SAFE: security functions with real implementations — no stubs
# These should NOT fire — they have actual logic, not pass/TODO/return None
import re
import html
from typing import Any


def validate_email(email: str) -> bool:
    """Validate email format using regex and length constraints."""
    if not email or len(email) > 254:
        return False
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def sanitize_html_content(content: str) -> str:
    """Sanitize HTML to prevent XSS — use html.escape()."""
    if not content:
        return ""
    # Escape all HTML special characters
    escaped = html.escape(content, quote=True)
    return escaped[:10_000]  # also enforce length limit


def validate_integer_range(value: Any, min_val: int, max_val: int) -> bool:
    """Validate that value is an integer in [min_val, max_val]."""
    try:
        int_val = int(value)
        return min_val <= int_val <= max_val
    except (TypeError, ValueError):
        return False


def filter_non_printable(text: str) -> str:
    """Remove non-printable and control characters from text input."""
    return "".join(ch for ch in text if ch.isprintable() and ord(ch) >= 0x20)


def check_input_length(value: str, min_len: int = 1, max_len: int = 255) -> bool:
    """Check input is within required length bounds."""
    if not isinstance(value, str):
        return False
    return min_len <= len(value) <= max_len
